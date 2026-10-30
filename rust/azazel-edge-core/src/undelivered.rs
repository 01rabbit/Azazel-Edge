//! The Edge-owned spool of decisions the intake did not take (S-10).
//!
//! Every line the forwarder could not deliver to the AI/intake socket (no
//! listener, refused, timed out) or could not even queue (queue full) is
//! kept here, whatever `AZAZEL_FORWARD_LOG` says and in every enforcement
//! mode, observe-only included. While the intake is up nothing is written.
//! It lives beside the release ledger by default, inside the core's one
//! writable directory.
//!
//! Kept simple so that every line is accounted for exactly:
//! * each undelivered line is one `write` (no user-space buffer), so a line
//!   is counted `spooled` only when the kernel took it and `lost` when it
//!   did not; data is synced every five seconds, never per decision;
//! * the file never grows past its cap: at the cap it is rotated (one old
//!   segment kept); if rotation or reopening fails, lines are counted lost
//!   and nothing more is written until a later rotation succeeds;
//! * a state file beside it keeps, across restarts, the counts, the time
//!   range, and how many lines were still on their way to the spool (queued
//!   or being delivered) at the last state write: after an unclean stop that
//!   number and the interval since that write are recorded as the gap;
//! * a run with any write, sync or state failure is never recorded as a
//!   clean stop.
//! If the spool cannot be opened at all, the core keeps running and says on
//! stderr, once a minute, how many undelivered lines were not kept.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const STATE_SCHEMA: &str = "azazel-edge/undelivered-spool/v2";
pub const SPOOL_CAP_BYTES: u64 = 8 * 1024 * 1024;
pub const SPOOL_FILE: &str = "undelivered-decisions.jsonl";
const HANDOFF: usize = 4096;
const STATE_EVERY: Duration = Duration::from_secs(1);
const SYNC_EVERY: Duration = Duration::from_secs(5);
const UNAVAILABLE_NOTICE_EVERY: Duration = Duration::from_secs(60);

/// Undelivered lines not handed to the writer (hand-off full). Folded into
/// the state by the writer.
static LOST_HANDOFF: AtomicU64 = AtomicU64::new(0);
/// Undelivered lines with no spool at all (it could not be set up).
static UNAVAILABLE_LOST: AtomicU64 = AtomicU64::new(0);
static UNAVAILABLE_NOTICE: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
static SPOOL: OnceLock<SyncSender<Msg>> = OnceLock::new();

enum Msg {
    Line(String),
    /// Record `lost_at_shutdown`, sync, mark the stop clean if the run had
    /// no failure, answer, end.
    Stop(u64, SyncSender<bool>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpoolState {
    pub schema: String,
    pub first_run_epoch: f64,
    pub runs: u64,
    /// Runs that ended without a clean stop, or with a write, sync or state
    /// failure.
    pub unclean_stops: u64,
    pub clean_shutdown: bool,
    /// Lines the kernel took into the spool file.
    pub spooled_total: u64,
    /// Lines that never reached the file: hand-off full, write failed, the
    /// file at its cap and not rotatable, or still on their way (queued or
    /// being delivered) when the process stopped cleanly.
    pub lost_total: u64,
    /// Spooled, then dropped by the cap (the overwritten rotated segment).
    pub rotated_out_total: u64,
    pub segment_records: u64,
    pub previous_segment_records: u64,
    /// Failed syncs of the spool or writes of this state, in all runs; lines
    /// spooled since the last good sync may not be durable.
    pub sync_failures: u64,
    /// Lines on their way to the spool (queued for the forwarder or being
    /// delivered) when the state was last written, and when that was.
    pub pending_at_last_write: u64,
    pub last_write_epoch: f64,
    /// After unclean stops: at least this many lines were on their way and
    /// are gone (sum of `pending_at_last_write` of each such run), and the
    /// last such gap: from the last state write to the next start.
    pub unclean_pending_lost_total: u64,
    pub last_unclean_gap: Option<(f64, f64)>,
    pub first_undelivered_epoch: Option<f64>,
    pub last_undelivered_epoch: Option<f64>,
}

impl SpoolState {
    fn new(now: f64) -> Self {
        SpoolState {
            schema: STATE_SCHEMA.to_string(),
            first_run_epoch: now,
            runs: 0,
            unclean_stops: 0,
            clean_shutdown: true,
            spooled_total: 0,
            lost_total: 0,
            rotated_out_total: 0,
            segment_records: 0,
            previous_segment_records: 0,
            sync_failures: 0,
            pending_at_last_write: 0,
            last_write_epoch: now,
            unclean_pending_lost_total: 0,
            last_unclean_gap: None,
            first_undelivered_epoch: None,
            last_undelivered_epoch: None,
        }
    }
}

/// The default spool path: beside the release ledger, the core's writable
/// state directory (in the Nexus unit, its only `ReadWritePaths`).
pub fn default_path(ledger_path: &str) -> PathBuf {
    Path::new(ledger_path).with_file_name(SPOOL_FILE)
}

pub fn state_path(spool: &Path) -> PathBuf {
    let name = spool.file_name().and_then(|n| n.to_str()).unwrap_or(SPOOL_FILE);
    let stem = name.strip_suffix(".jsonl").unwrap_or(name);
    spool.with_file_name(format!("{stem}.state.json"))
}

fn now_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// The state at start. A run that did not end cleanly is counted, and the
/// lines it had on their way, with the interval since its last state write,
/// are recorded as its gap.
fn load_state(path: &Path, now: f64) -> SpoolState {
    let loaded = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<SpoolState>(&raw).ok())
        .filter(|s| s.schema == STATE_SCHEMA);
    match loaded {
        Some(mut state) => {
            if !state.clean_shutdown {
                state.unclean_stops += 1;
                state.unclean_pending_lost_total += state.pending_at_last_write;
                state.last_unclean_gap = Some((state.last_write_epoch, now));
            }
            state.pending_at_last_write = 0;
            state
        }
        None => SpoolState::new(now),
    }
}

fn write_state(path: &Path, state: &SpoolState) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    file.write_all(&serde_json::to_vec(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn open_segment(path: &Path) -> std::io::Result<File> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "spool path is a symlink"));
        }
    }
    OpenOptions::new().create(true).append(true).mode(0o600).open(path)
}

/// The writer's file handling, apart from the thread so its failure paths
/// can be driven in tests.
pub(crate) struct Writer {
    path: PathBuf,
    cap: u64,
    file: Option<File>,
    pub state: SpoolState,
    /// A failure in this run: the stop is then not recorded as clean.
    pub failed: bool,
}

impl Writer {
    pub(crate) fn new(path: PathBuf, cap: u64, state: SpoolState) -> Self {
        let file = open_segment(&path).ok();
        let failed = file.is_none();
        Writer { path, cap, file, state, failed }
    }

    /// Make room for `incoming` bytes: rotate at the cap, reopen after an
    /// earlier failure. Leaves no segment open (so nothing is written past
    /// the cap) when that is not possible.
    fn ensure_room(&mut self, incoming: u64) {
        let size = match &self.file {
            Some(file) => file.metadata().map(|m| m.len()).unwrap_or(u64::MAX),
            None => fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
        };
        if size.saturating_add(incoming) <= self.cap {
            if self.file.is_none() {
                self.file = open_segment(&self.path).ok();
                if self.file.is_none() {
                    self.failed = true;
                }
            }
            return;
        }
        self.file = None;
        let mut rotated = self.path.as_os_str().to_owned();
        rotated.push(".1");
        if fs::rename(&self.path, &rotated).is_err() {
            self.failed = true;
            return;
        }
        if let Some(dir) = self.path.parent() {
            let _ = File::open(dir).and_then(|d| d.sync_all());
        }
        self.state.rotated_out_total += self.state.previous_segment_records;
        self.state.previous_segment_records = self.state.segment_records;
        self.state.segment_records = 0;
        match open_segment(&self.path) {
            Ok(file) => self.file = Some(file),
            Err(_) => self.failed = true,
        }
    }

    /// Write one line; counted spooled only if the kernel took all of it.
    pub(crate) fn write_line(&mut self, line: &str) {
        self.ensure_room(line.len() as u64);
        let ok = match self.file.as_mut() {
            Some(file) => file.write_all(line.as_bytes()).is_ok(),
            None => false,
        };
        if ok {
            self.state.spooled_total += 1;
            self.state.segment_records += 1;
        } else {
            self.state.lost_total += 1;
            self.failed = true;
            // Drop the handle: the next line reopens (or rotates) afresh.
            self.file = None;
        }
        self.note_time();
    }

    pub(crate) fn sync(&mut self) {
        if let Some(file) = &self.file {
            if file.sync_data().is_err() {
                self.state.sync_failures += 1;
                self.failed = true;
            }
        }
    }

    fn note_time(&mut self) {
        let now = now_epoch();
        if self.state.first_undelivered_epoch.is_none() {
            self.state.first_undelivered_epoch = Some(now);
        }
        self.state.last_undelivered_epoch = Some(now);
    }
}

/// Start the writer for `path` (once per process). `pending` says how many
/// lines are still on their way (queued for the forwarder or in delivery).
/// If the spool cannot be set up, the core runs on and reports on stderr.
pub fn start(path: PathBuf, cap_bytes: u64, pending: fn() -> u64) {
    if SPOOL.get().is_some() {
        return;
    }
    let state_file = state_path(&path);
    let setup = (|| -> std::io::Result<SpoolState> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut state = load_state(&state_file, now_epoch());
        state.runs += 1;
        state.clean_shutdown = false;
        state.last_write_epoch = now_epoch();
        write_state(&state_file, &state)?;
        open_segment(&path)?;
        Ok(state)
    })();
    let state = match setup {
        Ok(state) => state,
        Err(e) => {
            eprintln!("undelivered spool unavailable ({}): {}; undelivered decisions are counted on stderr only", path.display(), e);
            return;
        }
    };
    let (tx, rx) = sync_channel::<Msg>(HANDOFF);
    if SPOOL.set(tx).is_err() {
        return;
    }
    thread::spawn(move || {
        let mut writer = Writer::new(path, cap_bytes, state);
        let mut last_state = Instant::now();
        let mut last_sync = Instant::now();
        loop {
            let msg = rx.recv_timeout(STATE_EVERY);
            let lost = LOST_HANDOFF.swap(0, Ordering::Relaxed);
            if lost > 0 {
                writer.state.lost_total += lost;
                writer.note_time();
            }
            match msg {
                Ok(Msg::Line(line)) => writer.write_line(&line),
                Ok(Msg::Stop(lost_at_shutdown, ack)) => {
                    writer.state.lost_total += lost_at_shutdown + LOST_HANDOFF.swap(0, Ordering::Relaxed);
                    if lost_at_shutdown > 0 {
                        writer.note_time();
                    }
                    writer.sync();
                    writer.state.pending_at_last_write = 0;
                    writer.state.last_write_epoch = now_epoch();
                    writer.state.clean_shutdown = !writer.failed;
                    let wrote = write_state(&state_file, &writer.state).is_ok();
                    let _ = ack.try_send(wrote && !writer.failed);
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if last_sync.elapsed() >= SYNC_EVERY {
                writer.sync();
                last_sync = Instant::now();
            }
            if last_state.elapsed() >= STATE_EVERY {
                writer.state.pending_at_last_write = pending();
                writer.state.last_write_epoch = now_epoch();
                if write_state(&state_file, &writer.state).is_err() {
                    writer.state.sync_failures += 1;
                    writer.failed = true;
                }
                last_state = Instant::now();
            }
        }
    });
}

/// Keep one undelivered line. Never waits: a full hand-off is counted; with
/// no spool at all the count goes to stderr once a minute.
pub fn record(line: &str) {
    match SPOOL.get() {
        Some(tx) => match tx.try_send(Msg::Line(line.to_string())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                LOST_HANDOFF.fetch_add(1, Ordering::Relaxed);
            }
        },
        None => {
            let lost = UNAVAILABLE_LOST.fetch_add(1, Ordering::Relaxed) + 1;
            let mut last = UNAVAILABLE_NOTICE.lock().unwrap_or_else(|e| e.into_inner());
            if last.map_or(true, |at| at.elapsed() >= UNAVAILABLE_NOTICE_EVERY) {
                eprintln!("undelivered spool unavailable: {} undelivered decision(s) not kept since start", lost);
                *last = Some(Instant::now());
            }
        }
    }
}

/// At a clean stop: record `lost_at_shutdown` (lines still on their way),
/// sync, and mark the stop clean only if this run had no failure. Returns
/// whether it was recorded as clean within `wait`.
pub fn stop(lost_at_shutdown: u64, wait: Duration) -> bool {
    let Some(tx) = SPOOL.get() else {
        let lost = UNAVAILABLE_LOST.load(Ordering::Relaxed);
        if lost > 0 {
            eprintln!("undelivered spool unavailable: {} undelivered decision(s) not kept", lost);
        }
        return false;
    };
    let (ack, done) = sync_channel::<bool>(1);
    let deadline = Instant::now() + wait;
    let mut msg = Msg::Stop(lost_at_shutdown, ack);
    loop {
        match tx.try_send(msg) {
            Ok(()) => break,
            Err(TrySendError::Full(back)) if Instant::now() < deadline => {
                msg = back;
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return false,
        }
    }
    done.recv_timeout(deadline.saturating_duration_since(Instant::now())).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("az-undelivered-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_unclean_stop_records_the_lines_on_their_way_and_the_gap() {
        let d = dir("state");
        let path = d.join("state.json");
        let mut state = SpoolState::new(10.0);
        state.runs = 2;
        state.spooled_total = 7;
        state.clean_shutdown = false;
        state.pending_at_last_write = 5;
        state.last_write_epoch = 50.0;
        write_state(&path, &state).unwrap();
        let loaded = load_state(&path, 99.0);
        assert_eq!(loaded.unclean_stops, 1);
        assert_eq!(loaded.unclean_pending_lost_total, 5);
        assert_eq!(loaded.last_unclean_gap, Some((50.0, 99.0)));
        assert_eq!(loaded.spooled_total, 7);
        state.clean_shutdown = true;
        write_state(&path, &state).unwrap();
        assert_eq!(load_state(&path, 99.0).unclean_stops, 0);
        fs::write(&path, "garbage").unwrap();
        assert_eq!(load_state(&path, 5.0), SpoolState::new(5.0));
        assert_eq!(default_path("/var/lib/azazel/edge-core/release-ledger.json"), PathBuf::from("/var/lib/azazel/edge-core/undelivered-decisions.jsonl"));
        let _ = fs::remove_dir_all(&d);
    }

    fn segment_sizes(path: &Path) -> u64 {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        fs::metadata(path).map(|m| m.len()).unwrap_or(0) + fs::metadata(PathBuf::from(rotated)).map(|m| m.len()).unwrap_or(0)
    }

    /// Re521c-05: a rotation that cannot happen stops the writing; nothing
    /// grows past the cap, and every line is spooled or counted lost.
    #[test]
    fn a_failed_rotation_never_lets_the_spool_grow_past_its_cap() {
        let d = dir("rot");
        let path = d.join("spool.jsonl");
        let line = format!("{}\n", "x".repeat(99));
        let mut w = Writer::new(path.clone(), 1000, SpoolState::new(0.0));
        for _ in 0..10 {
            w.write_line(&line);
        }
        assert_eq!(w.state.spooled_total, 10);
        // A non-empty directory where the rotated segment goes: the rename
        // at the cap fails (for root too).
        let rotated = d.join("spool.jsonl.1");
        fs::create_dir_all(rotated.join("block")).unwrap();
        for _ in 0..50 {
            w.write_line(&line);
        }
        assert!(fs::metadata(&path).unwrap().len() <= 1000, "{}", fs::metadata(&path).unwrap().len());
        assert_eq!((w.state.spooled_total, w.state.lost_total), (10, 50));
        assert!(w.failed);
        // The obstacle gone: the next line rotates and is spooled.
        fs::remove_dir_all(&rotated).unwrap();
        w.write_line(&line);
        assert_eq!(w.state.spooled_total, 11);
        assert!(segment_sizes(&path) <= 2000);
        let _ = fs::remove_dir_all(&d);
    }

    /// Re521c-06: a line is spooled only when written; a failed write is
    /// lost, and the run is not clean.
    #[test]
    fn a_failed_write_is_counted_lost_and_marks_the_run_unclean() {
        let d = dir("wfail");
        let path = d.join("spool.jsonl");
        let mut w = Writer::new(path.clone(), 1 << 20, SpoolState::new(0.0));
        w.write_line("a\n");
        assert!(!w.failed);
        // A read-only handle stands in for a device that refuses the write.
        w.file = Some(OpenOptions::new().read(true).open(&path).unwrap());
        w.write_line("b\n");
        assert_eq!((w.state.spooled_total, w.state.lost_total), (1, 1));
        assert!(w.failed);
        assert_eq!(fs::read_to_string(&path).unwrap(), "a\n");
        let _ = fs::remove_dir_all(&d);
    }
}
