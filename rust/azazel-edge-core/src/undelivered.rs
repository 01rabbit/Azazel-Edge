//! The Edge-owned spool of decisions the intake did not take (S-10).
//!
//! Every line the forwarder could not deliver to the AI/intake socket (no
//! listener, refused, timed out) or could not even queue (queue full) is
//! kept here, whatever `AZAZEL_FORWARD_LOG` says and in every enforcement
//! mode, observe-only included. While the intake is up nothing is written.
//!
//! Bounded for a small device: lines are buffered and flushed once a second
//! and synced every five (never an fsync per decision); the file is capped
//! with one rotation. What the cap or a full hand-off loses is not silent: a
//! small state file beside it keeps, across restarts, the counts and the
//! time range of what was spooled and what was lost, and how many runs
//! stopped without a clean shutdown (whose last second may be missing).

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const STATE_SCHEMA: &str = "azazel-edge/undelivered-spool/v1";
pub const SPOOL_CAP_BYTES: u64 = 8 * 1024 * 1024;
const HANDOFF: usize = 4096;
const FLUSH_EVERY: Duration = Duration::from_secs(1);
const SYNC_EVERY: Duration = Duration::from_secs(5);

/// Lines the hand-off to the spool writer refused (it was full): counted,
/// written to the state at the next flush.
static LOST_HANDOFF: AtomicU64 = AtomicU64::new(0);
static SPOOL: OnceLock<SyncSender<Msg>> = OnceLock::new();

enum Msg {
    Line(String),
    /// Flush, sync, mark a clean stop with `lost_at_shutdown`, answer, end.
    Stop(u64, SyncSender<()>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpoolState {
    pub schema: String,
    /// When the first run of this spool started (epoch seconds).
    pub first_run_epoch: f64,
    pub runs: u64,
    /// Runs that ended without a clean stop (crash, SIGKILL, power): up to
    /// the last second of such a run may be missing from the spool.
    pub unclean_stops: u64,
    pub clean_shutdown: bool,
    pub spooled_total: u64,
    /// Lost before reaching the file: hand-off full, or still queued for
    /// the forwarder when the process stopped.
    pub lost_before_spool_total: u64,
    /// Spooled, then dropped by the cap (the overwritten rotated segment).
    pub rotated_out_total: u64,
    pub segment_records: u64,
    pub previous_segment_records: u64,
    /// Wall-clock range of the undelivered lines kept or lost.
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
            lost_before_spool_total: 0,
            rotated_out_total: 0,
            segment_records: 0,
            previous_segment_records: 0,
            first_undelivered_epoch: None,
            last_undelivered_epoch: None,
        }
    }
}

pub fn state_path(spool: &Path) -> PathBuf {
    let name = spool.file_name().and_then(|n| n.to_str()).unwrap_or("undelivered-decisions.jsonl");
    let stem = name.strip_suffix(".jsonl").unwrap_or(name);
    spool.with_file_name(format!("{stem}.state.json"))
}

fn now_epoch() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn load_state(path: &Path, now: f64) -> SpoolState {
    let loaded = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<SpoolState>(&raw).ok())
        .filter(|s| s.schema == STATE_SCHEMA);
    match loaded {
        Some(mut state) => {
            if !state.clean_shutdown {
                state.unclean_stops += 1;
            }
            state
        }
        None => SpoolState::new(now),
    }
}

fn write_state(path: &Path, state: &SpoolState, sync: bool) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    file.write_all(&serde_json::to_vec(state).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?)?;
    if sync {
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if sync {
        if let Some(dir) = path.parent() {
            File::open(dir)?.sync_all()?;
        }
    }
    Ok(())
}

fn open_segment(path: &Path) -> std::io::Result<BufWriter<File>> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "spool path is a symlink"));
        }
    }
    let file = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
    Ok(BufWriter::new(file))
}

/// Start the writer for `path` (once per process). On any error the spool
/// is off and says so on stderr; forwarding and decisions are unaffected.
pub fn start(path: PathBuf, cap_bytes: u64) {
    if SPOOL.get().is_some() {
        return;
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("undelivered spool disabled ({}): {}", path.display(), e);
            return;
        }
    }
    let (tx, rx) = sync_channel::<Msg>(HANDOFF);
    let state_file = state_path(&path);
    let mut state = load_state(&state_file, now_epoch());
    state.runs += 1;
    state.clean_shutdown = false;
    if let Err(e) = write_state(&state_file, &state, true) {
        eprintln!("undelivered spool disabled ({}): {}", state_file.display(), e);
        return;
    }
    let mut segment = match open_segment(&path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("undelivered spool disabled ({}): {}", path.display(), e);
            return;
        }
    };
    if SPOOL.set(tx).is_err() {
        return;
    }
    thread::spawn(move || {
        let mut last_flush = Instant::now();
        let mut last_sync = Instant::now();
        let mut dirty = false;
        loop {
            let msg = rx.recv_timeout(FLUSH_EVERY);
            let lost = LOST_HANDOFF.swap(0, Ordering::Relaxed);
            if lost > 0 {
                state.lost_before_spool_total += lost;
                note_time(&mut state);
                dirty = true;
            }
            match msg {
                Ok(Msg::Line(line)) => {
                    let size = segment.get_ref().metadata().map(|m| m.len()).unwrap_or(0) + segment.buffer().len() as u64;
                    if size >= cap_bytes {
                        let _ = segment.flush();
                        let mut rotated = path.as_os_str().to_owned();
                        rotated.push(".1");
                        if fs::rename(&path, &rotated).is_ok() {
                            if let Some(dir) = path.parent() {
                                let _ = File::open(dir).and_then(|d| d.sync_all());
                            }
                            state.rotated_out_total += state.previous_segment_records;
                            state.previous_segment_records = state.segment_records;
                            state.segment_records = 0;
                            match open_segment(&path) {
                                Ok(w) => segment = w,
                                Err(e) => eprintln!("undelivered spool reopen failed: {}", e),
                            }
                        }
                    }
                    if segment.write_all(line.as_bytes()).is_ok() {
                        state.spooled_total += 1;
                        state.segment_records += 1;
                    } else {
                        state.lost_before_spool_total += 1;
                    }
                    note_time(&mut state);
                    dirty = true;
                }
                Ok(Msg::Stop(lost_at_shutdown, ack)) => {
                    state.lost_before_spool_total += lost_at_shutdown + LOST_HANDOFF.swap(0, Ordering::Relaxed);
                    if lost_at_shutdown > 0 {
                        note_time(&mut state);
                    }
                    let _ = segment.flush();
                    let _ = segment.get_ref().sync_data();
                    state.clean_shutdown = true;
                    let _ = write_state(&state_file, &state, true);
                    let _ = ack.try_send(());
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            if dirty && last_flush.elapsed() >= FLUSH_EVERY {
                let _ = segment.flush();
                let sync = last_sync.elapsed() >= SYNC_EVERY;
                if sync {
                    let _ = segment.get_ref().sync_data();
                    last_sync = Instant::now();
                }
                let _ = write_state(&state_file, &state, sync);
                last_flush = Instant::now();
                dirty = !sync;
            }
        }
    });
}

fn note_time(state: &mut SpoolState) {
    let now = now_epoch();
    if state.first_undelivered_epoch.is_none() {
        state.first_undelivered_epoch = Some(now);
    }
    state.last_undelivered_epoch = Some(now);
}

/// Keep one undelivered line. Never waits: a full hand-off is counted.
pub fn record(line: &str) {
    if let Some(tx) = SPOOL.get() {
        match tx.try_send(Msg::Line(line.to_string())) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                LOST_HANDOFF.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// At a clean stop: flush, sync, record `lost_at_shutdown` (lines still
/// queued for the forwarder) and mark the stop clean, waiting at most `wait`.
pub fn stop(lost_at_shutdown: u64, wait: Duration) -> bool {
    let Some(tx) = SPOOL.get() else {
        return false;
    };
    let (ack, done) = sync_channel::<()>(1);
    // A blocking send: the hand-off may be full; bounded by `wait` below
    // only once queued, so try first and fall back to a bounded wait.
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
    done.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_survives_a_restart_and_counts_an_unclean_stop() {
        let dir = std::env::temp_dir().join(format!("az-undelivered-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let mut state = SpoolState::new(10.0);
        state.runs = 2;
        state.spooled_total = 7;
        state.clean_shutdown = false;
        write_state(&path, &state, true).unwrap();
        let loaded = load_state(&path, 99.0);
        assert_eq!(loaded.unclean_stops, 1);
        assert_eq!(loaded.spooled_total, 7);
        assert_eq!(loaded.first_run_epoch, 10.0);
        state.clean_shutdown = true;
        write_state(&path, &state, true).unwrap();
        assert_eq!(load_state(&path, 99.0).unclean_stops, 0);
        // An unreadable state starts a new one rather than failing.
        fs::write(&path, "garbage").unwrap();
        assert_eq!(load_state(&path, 5.0), SpoolState::new(5.0));
        assert_eq!(state_path(Path::new("/x/undelivered-decisions.jsonl")), PathBuf::from("/x/undelivered-decisions.state.json"));
        let _ = fs::remove_dir_all(&dir);
    }
}
