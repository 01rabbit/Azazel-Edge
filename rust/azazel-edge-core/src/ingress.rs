//! The Core's EVE ingress bound (Edge#414 OF-06).
//!
//! Before this module the reader took every new EVE line on each poll and
//! decided it before the release sweep could run, so a flood delayed lease
//! expiry by however long the flood took to read. The owner's decision on
//! Edge#414 (OF-06), as revised in review of #452, is what this implements:
//!
//! * **Alerts are never shed and never rate-limited.** An alert is admitted
//!   whenever it is reached. The only limits on alerts are per poll: at most
//!   `alerts_per_poll` alerts, `examine_per_poll` lines and `poll_work_limit`
//!   of work, so the release sweep runs between polls. Alerts beyond that are
//!   read on the next poll, and the main loop does not sleep after a poll that
//!   stopped on a budget, so alert throughput stays at the Core's capacity.
//! * **The declared quota is a non-alert quota.** Non-alert lines draw from a
//!   token bucket (`non_alert_per_sec`, capacity `non_alert_burst`). A
//!   non-alert line that finds the bucket too low is shed at once, in priority
//!   order: `flow` needs the fullest bucket, then `dns`, then `stats`, then
//!   every other non-alert type (unparseable lines last, counted apart).
//! * **Backlog escalation is a second line.** Past `backlog_bound_bytes` of
//!   unread file, `flow` is shed whatever the bucket holds; each further
//!   multiple of the bound adds the next class.
//! * **A bound on work, not data loss.** The offset moves only past lines that
//!   were handled (admitted, shed and counted, or skipped and counted). A line
//!   without its newline yet is left for the next poll. A line longer than
//!   `max_line_bytes` is skipped up to its newline and counted; it is never
//!   buffered whole.
//! * **Never silent.** Shed lines are counted by class and by reason and leave
//!   the Core as at most one `ingress_shed` summary per audit interval, with
//!   cumulative totals. When the process stops, whatever the last (shorter)
//!   interval holds is written once more in the same shape, marked
//!   `interval_end: "shutdown"`, and never again. A backlog past `alert_backlog_bound_bytes` is recorded
//!   as `ingress_alert_backlog`. A truncated or replaced EVE file that still
//!   held unread bytes is counted.
//!
//! None of this decides anything about enforcement: it only decides which
//! lines reach the decider and when. The limits are compile-time constants;
//! there is no environment variable to raise or disable them.

use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

pub const INGRESS_SHED_SCHEMA: &str = "azazel-edge/ingress-shed/v1";
pub const INGRESS_ALERT_BACKLOG_SCHEMA: &str = "azazel-edge/ingress-alert-backlog/v1";
pub const INGRESS_SOURCE: &str = "core_ingress";
pub const INGRESS_PIPELINE: &str = "rust_ingress_v1";

/// The ingress limits. Production uses [`IngressLimits::DECLARED`], which
/// `config/service_objectives/ingress_quota.json` mirrors (a test keeps the
/// two equal); tests use smaller values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IngressLimits {
    /// The declared quota: admitted non-alert EVE lines per second.
    pub non_alert_per_sec: u64,
    /// The non-alert token bucket's capacity.
    pub non_alert_burst: u64,
    /// Alerts decided per poll. Not a rate: the next poll follows at once.
    pub alerts_per_poll: u64,
    /// Lines looked at per poll, shed ones included.
    pub examine_per_poll: u64,
    /// Wall time one poll may spend reading and deciding.
    pub poll_work_limit: Duration,
    /// Longest line read; a longer one is skipped and counted.
    pub max_line_bytes: u64,
    /// Unread bytes past which the lowest class is shed whatever the bucket holds.
    pub backlog_bound_bytes: u64,
    /// Unread bytes past which an alert backlog is recorded (never shed).
    pub alert_backlog_bound_bytes: u64,
    /// At most one summary of each kind per this interval.
    pub audit_interval: Duration,
    /// `ingress-audit.jsonl` is rotated to `.1` past this size.
    pub audit_log_cap_bytes: u64,
}

impl IngressLimits {
    pub const DECLARED: IngressLimits = IngressLimits {
        non_alert_per_sec: 2500,
        non_alert_burst: 1500,
        alerts_per_poll: 1000,
        examine_per_poll: 6000,
        poll_work_limit: Duration::from_millis(500),
        max_line_bytes: 1024 * 1024,
        backlog_bound_bytes: 8 * 1024 * 1024,
        alert_backlog_bound_bytes: 256 * 1024 * 1024,
        audit_interval: Duration::from_secs(1),
        audit_log_cap_bytes: 16 * 1024 * 1024,
    };
}

/// Shed classes, in the order they are shed. Alerts have no class: they are
/// never shed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShedClass {
    Flow,
    Dns,
    Stats,
    Other,
    Unparseable,
}

pub const SHED_CLASSES: [ShedClass; 5] =
    [ShedClass::Flow, ShedClass::Dns, ShedClass::Stats, ShedClass::Other, ShedClass::Unparseable];

/// The highest backlog shed level: every non-alert class.
pub const MAX_SHED_LEVEL: u8 = 4;

impl ShedClass {
    /// Lower is shed first. An unparseable line (invalid JSON or UTF-8, or
    /// cut short) cannot be decided, but it might have been an alert, so it
    /// is never shed ahead of flow, dns or stats: it shares the last rank with
    /// "other" and is counted under its own key.
    fn rank(self) -> u8 {
        match self {
            ShedClass::Flow => 0,
            ShedClass::Dns => 1,
            ShedClass::Stats => 2,
            ShedClass::Other | ShedClass::Unparseable => 3,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            ShedClass::Flow => "flow",
            ShedClass::Dns => "dns",
            ShedClass::Stats => "stats",
            ShedClass::Other => "other",
            ShedClass::Unparseable => "unparseable",
        }
    }

    fn index(self) -> usize {
        match self {
            ShedClass::Flow => 0,
            ShedClass::Dns => 1,
            ShedClass::Stats => 2,
            ShedClass::Other => 3,
            ShedClass::Unparseable => 4,
        }
    }

    /// Tokens that must remain in the bucket after admitting a line of this
    /// class: flow keeps 3/8 of the burst in reserve, dns 2/8, stats 1/8,
    /// other and unparseable none. Under overload the bucket hovers near
    /// empty, so flow is shed first, then dns, then stats.
    fn reserve(self, burst: u64) -> f64 {
        (3 - self.rank().min(3)) as f64 * burst as f64 / 8.0
    }
}

/// `None` is an alert. The audit keys are this closed set, so a sensor
/// cannot grow the summary by inventing event types.
pub fn classify(parsed: Option<&Value>) -> Option<ShedClass> {
    let value = match parsed {
        Some(v) => v,
        None => return Some(ShedClass::Unparseable),
    };
    match value.get("event_type").and_then(Value::as_str) {
        Some("alert") => None,
        Some("flow") | Some("netflow") => Some(ShedClass::Flow),
        Some("dns") => Some(ShedClass::Dns),
        Some("stats") => Some(ShedClass::Stats),
        _ => Some(ShedClass::Other),
    }
}

/// How many classes are shed at this backlog regardless of the bucket: none
/// up to the bound, then one more per further multiple of it.
pub fn shed_level(backlog_bytes: u64, bound_bytes: u64) -> u8 {
    if bound_bytes == 0 || backlog_bytes <= bound_bytes {
        return 0;
    }
    (((backlog_bytes - 1) / bound_bytes).min(MAX_SHED_LEVEL as u64)) as u8
}

pub fn is_shed(class: ShedClass, level: u8) -> bool {
    class.rank() < level
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollStop {
    /// No EVE file, or it could not be opened or read.
    NoFile,
    /// Everything complete was read.
    CaughtUp,
    /// The last line has no newline yet; it is read once it is complete.
    PartialLine,
    /// `alerts_per_poll` alerts were decided.
    AlertBudget,
    /// `examine_per_poll` lines were looked at.
    ExamineBudget,
    /// `poll_work_limit` was spent.
    WorkTime,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PollReport {
    pub admitted: u64,
    pub alerts_admitted: u64,
    pub examined: u64,
    pub shed: [u64; 5],
    pub shed_rate: u64,
    pub shed_backlog: u64,
    pub oversized: u64,
    pub backlog_before: u64,
    pub backlog_after: u64,
    pub level: u8,
    pub stop: Option<PollStop>,
}

impl PollReport {
    pub fn shed_total(&self) -> u64 {
        self.shed.iter().sum()
    }

    /// The poll stopped with work left: the next one should follow at once.
    pub fn budget_exhausted(&self) -> bool {
        matches!(self.stop, Some(PollStop::AlertBudget) | Some(PollStop::ExamineBudget) | Some(PollStop::WorkTime))
    }
}

#[derive(Debug, Clone, Default)]
struct Pending {
    polls: u64,
    shed: [u64; 5],
    shed_rate: u64,
    shed_backlog: u64,
    admitted: u64,
    alerts_admitted: u64,
    examined: u64,
    max_backlog: u64,
    max_level: u8,
    oversized: u64,
    oversized_possible_alerts: u64,
    truncation_resets: u64,
    file_replacements: u64,
    unread_bytes_lost: u64,
    alert_backlog_polls: u64,
    alert_backlog_max: u64,
    alert_backlog_alerts_admitted: u64,
}

impl Pending {
    fn shed_side_nonzero(&self) -> bool {
        self.shed.iter().sum::<u64>() > 0 || self.oversized > 0 || self.truncation_resets > 0 || self.file_replacements > 0
    }
}

#[derive(Debug)]
pub struct IngressReader {
    pub offset: u64,
    pub limits: IngressLimits,
    last_len: u64,
    inode: Option<(u64, u64)>,
    /// Inside a line longer than `max_line_bytes`: skip to its newline.
    skipping: bool,
    tokens: f64,
    last_refill: Option<Instant>,
    pending: Pending,
    last_shed_emit: Option<Instant>,
    last_alert_emit: Option<Instant>,
    cumulative_shed: [u64; 5],
    cumulative_oversized: u64,
    cumulative_alert_backlog_polls: u64,
    cumulative_resets: u64,
    /// The last interval was written at shutdown; nothing more is emitted.
    shutdown_flushed: bool,
}

const ALERT_MARKER: &[u8] = b"\"event_type\":\"alert\"";

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

impl IngressReader {
    pub fn new(offset: u64, limits: IngressLimits) -> Self {
        IngressReader {
            offset,
            limits,
            last_len: offset,
            inode: None,
            skipping: false,
            tokens: limits.non_alert_burst as f64,
            last_refill: None,
            pending: Pending::default(),
            last_shed_emit: None,
            last_alert_emit: None,
            cumulative_shed: [0; 5],
            cumulative_oversized: 0,
            cumulative_alert_backlog_polls: 0,
            cumulative_resets: 0,
            shutdown_flushed: false,
        }
    }

    fn refill(&mut self, now: Instant) {
        let cap = self.limits.non_alert_burst as f64;
        if let Some(last) = self.last_refill {
            let dt = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + dt * self.limits.non_alert_per_sec as f64).min(cap);
        } else {
            self.tokens = cap;
        }
        self.last_refill = Some(now);
    }

    fn restart(&mut self, replaced: bool) {
        // Whatever was unread in the old file is gone; count it.
        if replaced {
            self.pending.file_replacements += 1;
        } else {
            self.pending.truncation_resets += 1;
        }
        self.cumulative_resets += 1;
        self.pending.unread_bytes_lost += self.last_len.saturating_sub(self.offset);
        self.offset = 0;
        self.skipping = false;
    }

    fn shed(&mut self, report: &mut PollReport, class: ShedClass, by_backlog: bool) {
        report.shed[class.index()] += 1;
        if by_backlog {
            report.shed_backlog += 1;
        } else {
            report.shed_rate += 1;
        }
    }

    /// Read at most one poll's worth of the EVE file at `path`, handing each
    /// admitted, parseable line to `decide`. Returns what was done.
    pub fn poll<F: FnMut(&Value)>(&mut self, path: &Path, now: Instant, mut decide: F) -> PollReport {
        let started = Instant::now();
        let mut report = PollReport::default();
        self.refill(now);
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                report.stop = Some(PollStop::NoFile);
                return report;
            }
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(_) => {
                report.stop = Some(PollStop::NoFile);
                return report;
            }
        };
        let len = meta.len();
        let id = (meta.dev(), meta.ino());
        match self.inode {
            Some(old) if old != id => self.restart(true),
            _ if self.offset > len => self.restart(false),
            _ => {}
        }
        self.inode = Some(id);
        self.last_len = len;
        let backlog = len - self.offset;
        report.backlog_before = backlog;
        report.level = shed_level(backlog, self.limits.backlog_bound_bytes);
        let alert_backlog = backlog > self.limits.alert_backlog_bound_bytes;

        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.offset)).is_err() {
            report.stop = Some(PollStop::NoFile);
            return report;
        }

        let max_line = self.limits.max_line_bytes;
        let mut buf: Vec<u8> = Vec::new();
        // Bytes of an oversized line discarded this poll: progress that the
        // work-time limit must count, or a long skip would ignore it.
        let mut skipped_bytes: u64 = 0;
        let stop = loop {
            if report.examined >= self.limits.examine_per_poll {
                break PollStop::ExamineBudget;
            }
            if report.alerts_admitted >= self.limits.alerts_per_poll {
                break PollStop::AlertBudget;
            }
            if (report.examined > 0 || skipped_bytes > 0) && started.elapsed() >= self.limits.poll_work_limit {
                break PollStop::WorkTime;
            }
            if self.skipping {
                // The rest of an oversized line: discard up to its newline
                // without holding more than the reader's own buffer.
                let (used, done) = match reader.fill_buf() {
                    Ok([]) => break PollStop::CaughtUp,
                    Ok(avail) => match avail.iter().position(|b| *b == b'\n') {
                        Some(i) => (i + 1, true),
                        None => (avail.len(), false),
                    },
                    Err(_) => break PollStop::NoFile,
                };
                reader.consume(used);
                self.offset += used as u64;
                skipped_bytes += used as u64;
                if done {
                    self.skipping = false;
                }
                continue;
            }
            buf.clear();
            let n = match (&mut reader).take(max_line + 1).read_until(b'\n', &mut buf) {
                Ok(n) => n,
                Err(_) => break PollStop::NoFile,
            };
            if n == 0 {
                break PollStop::CaughtUp;
            }
            if buf.last() != Some(&b'\n') {
                if (n as u64) <= max_line {
                    // Still being written: leave it, offset unchanged.
                    break PollStop::PartialLine;
                }
                // Longer than any line we read: skip it, count it.
                self.offset += n as u64;
                self.skipping = true;
                report.examined += 1;
                report.oversized += 1;
                if contains(&buf, ALERT_MARKER) {
                    self.pending.oversized_possible_alerts += 1;
                }
                continue;
            }
            self.offset += n as u64;
            let text = String::from_utf8_lossy(&buf);
            let text = text.trim();
            report.examined += 1;
            if text.is_empty() {
                continue;
            }
            let parsed: Option<Value> = serde_json::from_str(text).ok();
            match classify(parsed.as_ref()) {
                None => {
                    report.admitted += 1;
                    report.alerts_admitted += 1;
                    if let Some(v) = parsed.as_ref() {
                        decide(v);
                    }
                }
                Some(class) => {
                    if is_shed(class, report.level) {
                        self.shed(&mut report, class, true);
                    } else if self.tokens >= class.reserve(self.limits.non_alert_burst) + 1.0 {
                        self.tokens -= 1.0;
                        report.admitted += 1;
                        if let Some(v) = parsed.as_ref() {
                            decide(v);
                        }
                    } else {
                        self.shed(&mut report, class, false);
                    }
                }
            }
        };
        report.stop = Some(stop);
        report.backlog_after = len.saturating_sub(self.offset);

        let p = &mut self.pending;
        p.polls += 1;
        p.admitted += report.admitted;
        p.alerts_admitted += report.alerts_admitted;
        p.examined += report.examined;
        p.shed_rate += report.shed_rate;
        p.shed_backlog += report.shed_backlog;
        p.oversized += report.oversized;
        p.max_backlog = p.max_backlog.max(backlog);
        p.max_level = p.max_level.max(report.level);
        self.cumulative_oversized += report.oversized;
        for (i, n) in report.shed.iter().enumerate() {
            p.shed[i] += n;
            self.cumulative_shed[i] += n;
        }
        if alert_backlog {
            p.alert_backlog_polls += 1;
            p.alert_backlog_max = p.alert_backlog_max.max(backlog);
            p.alert_backlog_alerts_admitted += report.alerts_admitted;
            self.cumulative_alert_backlog_polls += 1;
        }
        report
    }

    fn interval_elapsed(&self, last: Option<Instant>, now: Instant) -> bool {
        match last {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.limits.audit_interval,
        }
    }

    fn quota_block(&self) -> Value {
        json!({
            "non_alert_per_sec": self.limits.non_alert_per_sec,
            "non_alert_burst": self.limits.non_alert_burst,
            "alerts_per_poll": self.limits.alerts_per_poll,
            "examine_per_poll": self.limits.examine_per_poll,
            "poll_work_limit_ms": self.limits.poll_work_limit.as_millis() as u64,
            "max_line_bytes": self.limits.max_line_bytes,
            "backlog_bound_bytes": self.limits.backlog_bound_bytes,
            "alert_backlog_bound_bytes": self.limits.alert_backlog_bound_bytes,
        })
    }

    /// The audit summaries due now: at most one `ingress_shed` and one
    /// `ingress_alert_backlog` per audit interval, each only when there is
    /// something to report. Counts not yet reported carry over to the next.
    pub fn audit_records(&mut self, now: Instant, now_epoch: f64) -> Vec<Value> {
        if self.shutdown_flushed {
            return Vec::new();
        }
        self.summaries(now, now_epoch, false)
    }

    /// The summaries of the last interval, written once when the process
    /// stops (Edge#414 SO-11): whatever is pending is emitted now, without
    /// waiting for the audit interval, in the same shape with `interval_end`
    /// `"shutdown"`. Each kind is emitted only when there is something to
    /// report, as on every interval. A second call, and any later
    /// `audit_records`, returns nothing, so the last interval is never
    /// written twice. It counts and reports only; nothing it does changes
    /// what was read, shed or decided.
    pub fn shutdown_records(&mut self, now: Instant, now_epoch: f64) -> Vec<Value> {
        if self.shutdown_flushed {
            return Vec::new();
        }
        self.shutdown_flushed = true;
        self.summaries(now, now_epoch, true)
    }

    fn summaries(&mut self, now: Instant, now_epoch: f64, at_shutdown: bool) -> Vec<Value> {
        let interval_end = if at_shutdown { "shutdown" } else { "audit_interval" };
        let mut out = Vec::new();
        if self.pending.shed_side_nonzero() && (at_shutdown || self.interval_elapsed(self.last_shed_emit, now)) {
            let mut by_type = serde_json::Map::new();
            let mut cumulative = serde_json::Map::new();
            for c in SHED_CLASSES {
                by_type.insert(c.key().to_string(), json!(self.pending.shed[c.index()]));
                cumulative.insert(c.key().to_string(), json!(self.cumulative_shed[c.index()]));
            }
            let p = &self.pending;
            out.push(json!({
                "source": INGRESS_SOURCE,
                "pipeline": INGRESS_PIPELINE,
                "ingress_shed": {
                    "schema": INGRESS_SHED_SCHEMA,
                    "emitted_epoch": now_epoch,
                    "interval_end": interval_end,
                    "polls": p.polls,
                    "shed_by_type": by_type,
                    "shed_total": p.shed.iter().sum::<u64>(),
                    "shed_by_reason": {"non_alert_rate": p.shed_rate, "backlog": p.shed_backlog},
                    "alerts_shed": 0,
                    "admitted": p.admitted,
                    "alerts_admitted": p.alerts_admitted,
                    "examined": p.examined,
                    "max_backlog_bytes": p.max_backlog,
                    "max_shed_level": p.max_level,
                    "oversized_lines_skipped": p.oversized,
                    "oversized_possible_alerts": p.oversized_possible_alerts,
                    "truncation_resets": p.truncation_resets,
                    "file_replacements": p.file_replacements,
                    "unread_bytes_lost": p.unread_bytes_lost,
                    "cumulative_shed_by_type": cumulative,
                    "cumulative_shed_total": self.cumulative_shed.iter().sum::<u64>(),
                    "cumulative_oversized_lines_skipped": self.cumulative_oversized,
                    "cumulative_resets": self.cumulative_resets,
                    "quota": self.quota_block(),
                },
            }));
            self.last_shed_emit = Some(now);
            let keep = (
                self.pending.alert_backlog_polls,
                self.pending.alert_backlog_max,
                self.pending.alert_backlog_alerts_admitted,
            );
            self.pending = Pending::default();
            self.pending.alert_backlog_polls = keep.0;
            self.pending.alert_backlog_max = keep.1;
            self.pending.alert_backlog_alerts_admitted = keep.2;
        }
        if self.pending.alert_backlog_polls > 0 && (at_shutdown || self.interval_elapsed(self.last_alert_emit, now)) {
            let p = &self.pending;
            out.push(json!({
                "source": INGRESS_SOURCE,
                "pipeline": INGRESS_PIPELINE,
                "ingress_alert_backlog": {
                    "schema": INGRESS_ALERT_BACKLOG_SCHEMA,
                    "emitted_epoch": now_epoch,
                    "interval_end": interval_end,
                    "polls_over_bound": p.alert_backlog_polls,
                    "max_backlog_bytes": p.alert_backlog_max,
                    "alert_backlog_bound_bytes": self.limits.alert_backlog_bound_bytes,
                    "alerts_admitted": p.alert_backlog_alerts_admitted,
                    "alerts_shed": 0,
                    "policy": "alerts are never shed or rate-limited; the backlog stays in the EVE file and is read at the Core's capacity",
                    "cumulative_polls_over_bound": self.cumulative_alert_backlog_polls,
                    "quota": self.quota_block(),
                },
            }));
            self.last_alert_emit = Some(now);
            self.pending.alert_backlog_polls = 0;
            self.pending.alert_backlog_max = 0;
            self.pending.alert_backlog_alerts_admitted = 0;
        }
        out
    }
}

// -- the audit file ----------------------------------------------------------

// O_NOFOLLOW is architecture-specific on Linux, and a wrong value is not an
// error: it silently sets another flag (0o400000 is O_LARGEFILE on arm64) and
// the symlink guard is gone. So every Linux architecture is listed with the
// value from its kernel uapi header, and any other one does not compile.
//
// - arch/arm64/include/uapi/asm/fcntl.h, arch/arm/include/uapi/asm/fcntl.h:
//   O_NOFOLLOW 0100000.
// - x86, riscv and loongarch have no uapi asm/fcntl.h of their own; they use
//   include/uapi/asm-generic/fcntl.h (mandatory-y in asm-generic/Kbuild):
//   O_NOFOLLOW 00400000.
// - Checked against Linux v6.11. mips, powerpc, sparc, alpha and parisc carry
//   their own values and are deliberately not listed.
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "x86", target_arch = "riscv64", target_arch = "loongarch64")
))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))
))]
compile_error!("O_NOFOLLOW is not known for this Linux architecture; add it from the kernel's uapi asm/fcntl.h");
// macOS (xnu bsd/sys/fcntl.h) and FreeBSD (sys/sys/fcntl.h): 0x0100.
#[cfg(not(target_os = "linux"))]
const O_NOFOLLOW: i32 = 0x0100;

/// Open the audit file for append: refused if `path` is a symlink
/// (O_NOFOLLOW), created 0600, and made 0600 if it already existed wider.
fn open_audit_file(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Append one audit record to `path`: never through a symlink (O_NOFOLLOW),
/// created 0600, flushed to disk before returning (at most one or two records
/// a second, so the fsync is affordable), and rotated to `<path>.1` once the
/// file reaches `cap_bytes`, so the audit file cannot fill the disk.
pub fn append_audit_record(path: &Path, record: &Value, cap_bytes: u64) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(io::ErrorKind::Other, "ingress audit path is a symlink"));
        }
        if meta.len() >= cap_bytes {
            let mut rotated = path.as_os_str().to_owned();
            rotated.push(".1");
            fs::rename(path, &rotated)?;
        }
    }
    let mut file = open_audit_file(path)?;
    let mut line = serde_json::to_vec(record).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_path(tag: &str) -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("azazel-ingress-{}-{}-{}.json", tag, std::process::id(), n))
    }

    fn line(event_type: &str, n: u64) -> String {
        if event_type == "alert" {
            format!(
                "{{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.1\",\"alert\":{{\"signature_id\":{},\"severity\":1}}}}\n",
                n
            )
        } else {
            format!("{{\"event_type\":\"{}\",\"n\":{}}}\n", event_type, n)
        }
    }

    fn write_bytes(path: &Path, bytes: &[u8]) {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        f.write_all(bytes).unwrap();
    }

    fn write_lines(path: &Path, lines: &[String]) {
        write_bytes(path, lines.concat().as_bytes());
    }

    /// Generous limits; each test narrows the one it is about.
    fn open_limits() -> IngressLimits {
        IngressLimits {
            non_alert_per_sec: 1_000_000,
            non_alert_burst: 1_000_000,
            alerts_per_poll: 1_000_000,
            examine_per_poll: 1_000_000,
            poll_work_limit: Duration::from_secs(60),
            max_line_bytes: 64 * 1024,
            backlog_bound_bytes: u64::MAX,
            alert_backlog_bound_bytes: u64::MAX,
            audit_interval: Duration::from_secs(1),
            audit_log_cap_bytes: 1024 * 1024,
        }
    }

    fn sig(v: &Value) -> u64 {
        v["alert"]["signature_id"].as_u64().or_else(|| v["n"].as_u64()).unwrap()
    }

    fn alerts_seen(path: &Path, r: &mut IngressReader, polls: u64) -> Vec<u64> {
        let t0 = Instant::now();
        let mut seen = Vec::new();
        for i in 0..polls {
            r.poll(path, t0 + Duration::from_secs(i), |v| {
                if v["event_type"] == "alert" {
                    seen.push(sig(v))
                }
            });
        }
        seen
    }

    #[test]
    fn a_poll_decides_at_most_alerts_per_poll_and_the_rest_follow() {
        let path = temp_path("alertcap");
        write_lines(&path, &(0..250).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.alerts_admitted, 100);
        assert_eq!(rep.stop, Some(PollStop::AlertBudget));
        assert!(rep.budget_exhausted());
        assert!(rep.backlog_after > 0);
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, ..open_limits() });
        assert_eq!(alerts_seen(&path, &mut r, 3), (0..250).collect::<Vec<_>>());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn alerts_are_not_rate_limited_by_the_non_alert_bucket() {
        let path = temp_path("alertrate");
        write_lines(&path, &(0..500).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { non_alert_per_sec: 1, non_alert_burst: 1, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.alerts_admitted, 500);
        assert_eq!(rep.shed_total(), 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lines_are_read_in_order_and_once_across_polls() {
        let path = temp_path("resume");
        write_lines(&path, &(0..250).map(|n| line(if n % 3 == 0 { "dns" } else { "alert" }, n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { examine_per_poll: 70, ..open_limits() });
        let t0 = Instant::now();
        let mut seen = Vec::new();
        for i in 0..5 {
            r.poll(&path, t0 + Duration::from_secs(i), |v| seen.push(sig(v)));
        }
        assert_eq!(seen, (0..250).collect::<Vec<_>>());
        assert_eq!(r.offset, fs::metadata(&path).unwrap().len());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn non_alerts_over_the_rate_are_shed_at_once_and_alerts_keep_flowing() {
        let path = temp_path("rate");
        // 1000 non-alerts and 1000 alerts, interleaved; bucket of 100.
        write_lines(&path, &(0..2000).map(|n| line(if n % 2 == 0 { "http" } else { "alert" }, n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { non_alert_per_sec: 100, non_alert_burst: 100, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.stop, Some(PollStop::CaughtUp), "a low bucket must not stall the reader");
        assert_eq!(rep.alerts_admitted, 1000);
        assert_eq!(rep.admitted - rep.alerts_admitted, 100);
        assert_eq!(rep.shed[ShedClass::Other.index()], 900);
        assert_eq!(rep.shed_rate, 900);
        assert_eq!(rep.shed_backlog, 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_non_alert_rate_holds_across_polls() {
        let path = temp_path("rateholds");
        write_lines(&path, &(0..5000).map(|n| line("http", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { non_alert_per_sec: 1000, non_alert_burst: 500, examine_per_poll: 500, ..open_limits() });
        let t0 = Instant::now();
        let mut admitted = 0;
        for i in 0..10 {
            admitted += r.poll(&path, t0 + Duration::from_millis(100 * i), |_| {}).admitted;
        }
        // The burst, then 100 per 100 ms.
        assert_eq!(admitted, 500 + 9 * 100);
        let _ = fs::remove_file(&path);
    }

    fn over_rate_mix(order: &[&str]) -> PollReport {
        let path = temp_path("prio");
        let mut lines = Vec::new();
        for n in 0..400u64 {
            lines.push(line(order[(n % order.len() as u64) as usize], n));
        }
        write_lines(&path, &lines);
        let mut r = IngressReader::new(0, IngressLimits { non_alert_per_sec: 1, non_alert_burst: 80, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        let _ = fs::remove_file(&path);
        rep
    }

    #[test]
    fn over_the_rate_flow_is_shed_first_then_dns_then_stats() {
        let rep = over_rate_mix(&["flow", "dns", "stats", "http"]);
        let s = |c: ShedClass| rep.shed[c.index()];
        // Burst 80: flow needs 30+1, dns 20+1, stats 10+1, other 1 token.
        assert!(s(ShedClass::Flow) > s(ShedClass::Dns), "{:?}", rep.shed);
        assert!(s(ShedClass::Dns) > s(ShedClass::Stats), "{:?}", rep.shed);
        assert!(s(ShedClass::Stats) > s(ShedClass::Other), "{:?}", rep.shed);
        assert_eq!(rep.admitted, 80);
        assert_eq!(rep.shed_total(), 320);
    }

    #[test]
    fn unparseable_lines_are_shed_last_and_counted_apart() {
        let path = temp_path("unparse");
        let mut body = Vec::new();
        for n in 0..100u64 {
            body.extend_from_slice(line("flow", n).as_bytes());
            body.extend_from_slice(b"{\"event_type\":\"alert\",\"alert\":{\"signature_id\":1\n");
        }
        write_bytes(&path, &body);
        let mut r = IngressReader::new(0, IngressLimits { non_alert_per_sec: 1, non_alert_burst: 80, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        let flow = rep.shed[ShedClass::Flow.index()];
        let bad = rep.shed[ShedClass::Unparseable.index()];
        assert!(flow > bad, "flow {} unparseable {}", flow, bad);
        assert_eq!(rep.shed[ShedClass::Other.index()], 0);
        // Backlog escalation reaches unparseable only at the last level.
        assert!(!is_shed(ShedClass::Unparseable, 3) && is_shed(ShedClass::Unparseable, 4));
        let recs = r.audit_records(Instant::now(), 1.0);
        assert_eq!(recs[0]["ingress_shed"]["shed_by_type"]["unparseable"], bad);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn invalid_utf8_does_not_wedge_the_reader() {
        let path = temp_path("utf8");
        let mut body = b"\xff\xfe not json at all\n".to_vec();
        body.extend_from_slice(b"{\"event_type\":\"alert\",\"note\":\"\xff\",\"alert\":{\"signature_id\":7}}\n");
        body.extend_from_slice(line("alert", 8).as_bytes());
        write_bytes(&path, &body);
        let mut r = IngressReader::new(0, open_limits());
        let seen = alerts_seen(&path, &mut r, 1);
        // The invalid byte inside a string decodes lossily; the alert is decided.
        assert_eq!(seen, vec![7, 8]);
        assert_eq!(r.offset, fs::metadata(&path).unwrap().len());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_oversized_line_is_skipped_counted_and_never_buffered_whole() {
        let path = temp_path("oversize");
        let mut body = line("alert", 1).into_bytes();
        body.extend_from_slice(b"{\"event_type\":\"alert\",\"payload\":\"");
        body.extend(std::iter::repeat(b'a').take(20_000));
        body.extend_from_slice(b"\"}\n");
        body.extend_from_slice(line("alert", 2).as_bytes());
        write_bytes(&path, &body);
        let mut r = IngressReader::new(0, IngressLimits { max_line_bytes: 1000, ..open_limits() });
        let mut seen = Vec::new();
        let rep = r.poll(&path, Instant::now(), |v| seen.push(sig(v)));
        assert_eq!(seen, vec![1, 2]);
        assert_eq!(rep.oversized, 1);
        let recs = r.audit_records(Instant::now(), 1.0);
        assert_eq!(recs[0]["ingress_shed"]["oversized_lines_skipped"], 1);
        assert_eq!(recs[0]["ingress_shed"]["oversized_possible_alerts"], 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_oversized_line_without_its_newline_yet_is_skipped_across_polls() {
        let path = temp_path("oversize2");
        let mut body = b"{\"event_type\":\"flow\",\"x\":\"".to_vec();
        body.extend(std::iter::repeat(b'a').take(5000));
        write_bytes(&path, &body);
        let mut r = IngressReader::new(0, IngressLimits { max_line_bytes: 1000, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.oversized, 1);
        assert_eq!(r.offset, body.len() as u64, "the skipped part is consumed, not buffered");
        write_bytes(&path, b"aaaa\"}\n");
        write_bytes(&path, line("alert", 3).as_bytes());
        let seen = alerts_seen(&path, &mut r, 1);
        assert_eq!(seen, vec![3]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_line_still_being_written_is_left_for_the_next_poll() {
        let path = temp_path("partial");
        write_lines(&path, &[line("alert", 1), "{\"event_type\":\"alert\",\"alert\":{\"signature_id\":2".to_string()]);
        let mut r = IngressReader::new(0, open_limits());
        let mut seen = Vec::new();
        let rep = r.poll(&path, Instant::now(), |v| seen.push(sig(v)));
        assert_eq!(rep.stop, Some(PollStop::PartialLine));
        assert!(!rep.budget_exhausted());
        assert_eq!(seen, vec![1]);
        write_lines(&path, &["}}\n".to_string()]);
        r.poll(&path, Instant::now() + Duration::from_secs(1), |v| seen.push(sig(v)));
        assert_eq!(seen, vec![1, 2]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_work_time_limit_stops_a_poll_after_progress() {
        let path = temp_path("worktime");
        write_lines(&path, &(0..50).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { poll_work_limit: Duration::ZERO, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.examined, 1);
        assert_eq!(rep.stop, Some(PollStop::WorkTime));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_work_time_limit_also_bounds_a_continuing_oversized_skip() {
        let path = temp_path("skiptime");
        let mut body = b"{\"event_type\":\"flow\",\"x\":\"".to_vec();
        body.extend(std::iter::repeat(b'a').take(200_000));
        body.extend_from_slice(b"\"}\n");
        body.extend_from_slice(line("alert", 5).as_bytes());
        write_bytes(&path, &body);
        let mut r = IngressReader::new(0, IngressLimits { max_line_bytes: 1000, poll_work_limit: Duration::ZERO, ..open_limits() });
        let t0 = Instant::now();
        let first = r.poll(&path, t0, |_| {});
        assert_eq!(first.oversized, 1);
        assert_eq!(r.offset, 1001);
        // A poll that starts inside the skip makes some progress, then stops on time.
        let before = r.offset;
        let second = r.poll(&path, t0 + Duration::from_secs(1), |_| {});
        assert_eq!(second.stop, Some(PollStop::WorkTime));
        assert!(second.budget_exhausted());
        assert!(r.offset > before, "a poll inside a skip still makes progress");
        assert!(r.offset - before <= 64 * 1024, "skipped {} bytes in one poll", r.offset - before);
        // The skip still ends and the alert after it is decided.
        let mut seen = Vec::new();
        for i in 2..200 {
            r.poll(&path, t0 + Duration::from_secs(i), |v| seen.push(sig(v)));
            if !seen.is_empty() {
                break;
            }
        }
        assert_eq!(seen, vec![5]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shed_level_rises_one_class_per_multiple_of_the_bound() {
        assert_eq!(shed_level(0, 100), 0);
        assert_eq!(shed_level(100, 100), 0);
        assert_eq!(shed_level(101, 100), 1);
        assert_eq!(shed_level(200, 100), 1);
        assert_eq!(shed_level(201, 100), 2);
        assert_eq!(shed_level(301, 100), 3);
        assert_eq!(shed_level(401, 100), 4);
        assert_eq!(shed_level(10_000, 100), MAX_SHED_LEVEL);
        assert!(is_shed(ShedClass::Flow, 1) && !is_shed(ShedClass::Dns, 1));
        assert!(is_shed(ShedClass::Dns, 2) && !is_shed(ShedClass::Stats, 2));
        assert!(is_shed(ShedClass::Stats, 3) && !is_shed(ShedClass::Other, 3));
        assert!(is_shed(ShedClass::Other, 4) && is_shed(ShedClass::Unparseable, 4));
        assert!(!is_shed(ShedClass::Flow, 0));
    }

    #[test]
    fn classification_is_a_closed_set_and_only_alerts_have_no_class() {
        let v = |s: &str| serde_json::from_str::<Value>(s).unwrap();
        assert_eq!(classify(Some(&v(r#"{"event_type":"alert"}"#))), None);
        assert_eq!(classify(Some(&v(r#"{"event_type":"flow"}"#))), Some(ShedClass::Flow));
        assert_eq!(classify(Some(&v(r#"{"event_type":"netflow"}"#))), Some(ShedClass::Flow));
        assert_eq!(classify(Some(&v(r#"{"event_type":"dns"}"#))), Some(ShedClass::Dns));
        assert_eq!(classify(Some(&v(r#"{"event_type":"stats"}"#))), Some(ShedClass::Stats));
        assert_eq!(classify(Some(&v(r#"{"event_type":"anything-new"}"#))), Some(ShedClass::Other));
        assert_eq!(classify(Some(&v(r#"{"no_type":1}"#))), Some(ShedClass::Other));
        assert_eq!(classify(None), Some(ShedClass::Unparseable));
    }

    fn mixed(n: u64) -> Vec<String> {
        let kinds = ["flow", "dns", "stats", "http", "alert"];
        (0..n).map(|i| line(kinds[(i % 5) as usize], i)).collect()
    }

    fn backlog_poll(multiple: u64) -> (PollReport, Vec<String>) {
        let path = temp_path("shed");
        write_lines(&path, &mixed(500));
        let len = fs::metadata(&path).unwrap().len();
        let bound = (len - 1) / multiple;
        let mut r = IngressReader::new(0, IngressLimits { backlog_bound_bytes: bound, ..open_limits() });
        let mut types = Vec::new();
        let rep = r.poll(&path, Instant::now(), |v| types.push(v["event_type"].as_str().unwrap().to_string()));
        let _ = fs::remove_file(&path);
        (rep, types)
    }

    #[test]
    fn past_the_backlog_bound_classes_are_shed_whatever_the_bucket_holds() {
        let (rep, types) = backlog_poll(1);
        assert_eq!(rep.level, 1);
        assert_eq!(rep.shed[ShedClass::Flow.index()], 100);
        assert_eq!(rep.shed_backlog, 100);
        assert_eq!(rep.shed_rate, 0);
        assert!(!types.iter().any(|t| t == "flow"));
        assert_eq!(types.iter().filter(|t| *t == "dns").count(), 100);

        let (rep, _) = backlog_poll(2);
        assert_eq!(rep.level, 2);
        assert_eq!(rep.shed[ShedClass::Dns.index()], 100);
        assert_eq!(rep.shed[ShedClass::Stats.index()], 0);

        let (rep, _) = backlog_poll(3);
        assert_eq!(rep.level, 3);
        assert_eq!(rep.shed[ShedClass::Stats.index()], 100);
        assert_eq!(rep.shed[ShedClass::Other.index()], 0);

        let (rep, types) = backlog_poll(4);
        assert_eq!(rep.level, 4);
        assert_eq!(rep.shed_total(), 400);
        assert_eq!(types, vec!["alert".to_string(); 100]);
    }

    #[test]
    fn alerts_are_never_shed_at_any_backlog_or_rate() {
        let path = temp_path("alerts");
        write_lines(&path, &mixed(2000));
        let mut r = IngressReader::new(
            0,
            IngressLimits {
                non_alert_per_sec: 1,
                non_alert_burst: 1,
                alerts_per_poll: 50,
                examine_per_poll: 200,
                backlog_bound_bytes: 1,
                alert_backlog_bound_bytes: 1,
                ..open_limits()
            },
        );
        let t0 = Instant::now();
        let mut alerts = Vec::new();
        let mut i = 0;
        while r.offset < fs::metadata(&path).unwrap().len() {
            r.poll(&path, t0 + Duration::from_secs(i), |v| {
                if v["event_type"] == "alert" {
                    alerts.push(sig(v));
                }
            });
            i += 1;
            assert!(i < 1000);
        }
        let expected: Vec<u64> = (0..2000).filter(|n| n % 5 == 4).collect();
        assert_eq!(alerts, expected);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shed_lines_are_bounded_by_examine() {
        let path = temp_path("examine");
        write_lines(&path, &(0..1000).map(|n| line("flow", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { examine_per_poll: 300, backlog_bound_bytes: 1, ..open_limits() });
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.examined, 300);
        assert_eq!(rep.shed[ShedClass::Flow.index()], 300);
        assert_eq!(rep.admitted, 0);
        assert_eq!(rep.stop, Some(PollStop::ExamineBudget));
        assert!(rep.budget_exhausted());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shedding_is_summarised_once_per_interval_with_counts_by_type() {
        let path = temp_path("audit");
        write_lines(&path, &mixed(2000));
        let mut r = IngressReader::new(0, IngressLimits { examine_per_poll: 100, backlog_bound_bytes: 1, ..open_limits() });
        let t0 = Instant::now();
        let mut records = Vec::new();
        let mut shed = 0;
        for i in 0..5 {
            let now = t0 + Duration::from_millis(100 * i);
            shed += r.poll(&path, now, |_| {}).shed_total();
            records.extend(r.audit_records(now, 1.0));
        }
        assert_eq!(records.len(), 1);
        let first = records[0]["ingress_shed"].clone();
        assert_eq!(first["schema"], INGRESS_SHED_SCHEMA);
        assert_eq!(first["alerts_shed"], 0);
        let at_first = first["shed_total"].as_u64().unwrap();
        assert!(at_first > 0);
        assert_eq!(first["shed_by_reason"]["backlog"], at_first);
        assert_eq!(
            first["shed_by_type"].as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
            vec!["dns", "flow", "other", "stats", "unparseable"]
        );
        let later = t0 + Duration::from_millis(1000);
        let more = r.audit_records(later, 2.0);
        assert_eq!(more.len(), 1);
        let second = &more[0]["ingress_shed"];
        assert_eq!(at_first + second["shed_total"].as_u64().unwrap(), shed);
        assert_eq!(second["cumulative_shed_total"].as_u64().unwrap(), shed);
        assert!(r.audit_records(later + Duration::from_secs(5), 3.0).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn no_shedding_no_record() {
        let path = temp_path("quiet");
        write_lines(&path, &mixed(100));
        let mut r = IngressReader::new(0, IngressLimits::DECLARED);
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.shed_total(), 0);
        assert!(r.audit_records(Instant::now(), 1.0).is_empty());
        let _ = fs::remove_file(&path);
    }

    /// The keys every `ingress_shed` summary carries; a shutdown summary has
    /// the same ones.
    fn shed_keys(rec: &Value) -> Vec<String> {
        let mut keys: Vec<String> = rec["ingress_shed"].as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    #[test]
    fn shutdown_writes_the_rest_of_an_interval_once_in_the_same_shape() {
        let path = temp_path("shutdown");
        write_lines(&path, &mixed(2000));
        let mut r = IngressReader::new(0, IngressLimits { examine_per_poll: 100, backlog_bound_bytes: 1, ..open_limits() });
        let t0 = Instant::now();
        let mut shed = r.poll(&path, t0, |_| {}).shed_total();
        let first = r.audit_records(t0, 1.0);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["ingress_shed"]["interval_end"], "audit_interval");
        // More is shed within the same interval: not due yet.
        let mid = t0 + Duration::from_millis(300);
        let rest = r.poll(&path, mid, |_| {}).shed_total();
        assert!(rest > 0);
        shed += rest;
        assert!(r.audit_records(mid, 1.3).is_empty());
        // The process stops 0.4 s into the interval.
        let stop = t0 + Duration::from_millis(400);
        let last = r.shutdown_records(stop, 1.4);
        assert_eq!(last.len(), 1, "one summary for the last interval");
        let rec = &last[0]["ingress_shed"];
        assert_eq!(rec["schema"], INGRESS_SHED_SCHEMA);
        assert_eq!(rec["interval_end"], "shutdown");
        assert_eq!(rec["emitted_epoch"], 1.4);
        assert_eq!(rec["shed_total"].as_u64().unwrap(), rest);
        assert_eq!(rec["cumulative_shed_total"].as_u64().unwrap(), shed);
        assert_eq!(rec["alerts_shed"], 0);
        assert_eq!(rec["quota"], first[0]["ingress_shed"]["quota"]);
        assert_eq!(shed_keys(&last[0]), shed_keys(&first[0]));
        assert_eq!(last[0]["source"], INGRESS_SOURCE);
        assert_eq!(last[0]["pipeline"], INGRESS_PIPELINE);
        // Never twice: not by a second flush, not by a later interval.
        assert!(r.shutdown_records(stop, 1.5).is_empty());
        assert!(r.audit_records(stop + Duration::from_secs(5), 6.4).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shutdown_in_the_first_interval_writes_what_was_never_summarised() {
        let path = temp_path("shutdown-first");
        write_lines(&path, &mixed(500));
        let mut r = IngressReader::new(0, IngressLimits { backlog_bound_bytes: 1, ..open_limits() });
        let t0 = Instant::now();
        let shed = r.poll(&path, t0, |_| {}).shed_total();
        assert!(shed > 0);
        // Stopped before any summary was due.
        let last = r.shutdown_records(t0 + Duration::from_millis(50), 2.0);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0]["ingress_shed"]["shed_total"].as_u64().unwrap(), shed);
        assert_eq!(last[0]["ingress_shed"]["cumulative_shed_total"].as_u64().unwrap(), shed);
        assert_eq!(last[0]["ingress_shed"]["polls"], 1);
        assert!(r.shutdown_records(t0 + Duration::from_millis(60), 2.1).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shutdown_with_nothing_pending_writes_nothing() {
        // Nothing shed at all.
        let path = temp_path("shutdown-quiet");
        write_lines(&path, &mixed(100));
        let mut r = IngressReader::new(0, IngressLimits::DECLARED);
        let t0 = Instant::now();
        assert_eq!(r.poll(&path, t0, |_| {}).shed_total(), 0);
        assert!(r.shutdown_records(t0, 1.0).is_empty());
        let _ = fs::remove_file(&path);
        // Shedding already summarised, and an empty interval since.
        let path = temp_path("shutdown-empty");
        write_lines(&path, &mixed(500));
        let mut r = IngressReader::new(0, IngressLimits { backlog_bound_bytes: 1, ..open_limits() });
        assert!(r.poll(&path, t0, |_| {}).shed_total() > 0);
        assert_eq!(r.audit_records(t0, 1.0).len(), 1);
        r.poll(&path, t0 + Duration::from_millis(200), |_| {});
        assert!(r.shutdown_records(t0 + Duration::from_millis(300), 1.3).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shutdown_also_writes_a_pending_alert_backlog_summary() {
        let path = temp_path("shutdown-alerts");
        write_lines(&path, &(0..300).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, alert_backlog_bound_bytes: 10, ..open_limits() });
        let t0 = Instant::now();
        r.poll(&path, t0, |_| {});
        assert_eq!(r.audit_records(t0, 1.0).len(), 1);
        r.poll(&path, t0 + Duration::from_millis(100), |_| {});
        assert!(r.audit_records(t0 + Duration::from_millis(100), 1.1).is_empty());
        let last = r.shutdown_records(t0 + Duration::from_millis(150), 1.15);
        assert_eq!(last.len(), 1);
        let rec = &last[0]["ingress_alert_backlog"];
        assert_eq!(rec["interval_end"], "shutdown");
        assert_eq!(rec["alerts_admitted"], 100);
        assert_eq!(rec["alerts_shed"], 0);
        assert!(r.shutdown_records(t0 + Duration::from_millis(160), 1.16).is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_alert_backlog_is_recorded_and_alerts_keep_being_read() {
        let path = temp_path("alertbacklog");
        write_lines(&path, &(0..300).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, alert_backlog_bound_bytes: 10, ..open_limits() });
        let t0 = Instant::now();
        let mut seen = 0;
        let rep = r.poll(&path, t0, |_| seen += 1);
        assert_eq!(rep.alerts_admitted, 100);
        let recs = r.audit_records(t0, 1.0);
        assert_eq!(recs.len(), 1);
        let rec = &recs[0]["ingress_alert_backlog"];
        assert_eq!(rec["schema"], INGRESS_ALERT_BACKLOG_SCHEMA);
        assert_eq!(rec["alerts_shed"], 0);
        assert_eq!(rec["alerts_admitted"], 100);
        assert_eq!(rec["polls_over_bound"], 1);
        for i in 1..3 {
            r.poll(&path, t0 + Duration::from_secs(i), |_| seen += 1);
        }
        assert_eq!(seen, 300);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_truncated_file_with_unread_bytes_is_counted() {
        let path = temp_path("trunc");
        write_lines(&path, &(0..300).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, ..open_limits() });
        let t0 = Instant::now();
        r.poll(&path, t0, |_| {});
        let unread = fs::metadata(&path).unwrap().len() - r.offset;
        // Truncate in place (same inode).
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(0).unwrap();
        drop(f);
        write_lines(&path, &[line("alert", 999)]);
        let mut seen = Vec::new();
        r.poll(&path, t0 + Duration::from_secs(1), |v| seen.push(sig(v)));
        assert_eq!(seen, vec![999]);
        let recs = r.audit_records(t0 + Duration::from_secs(1), 1.0);
        assert_eq!(recs[0]["ingress_shed"]["truncation_resets"], 1);
        assert_eq!(recs[0]["ingress_shed"]["file_replacements"], 0);
        assert_eq!(recs[0]["ingress_shed"]["unread_bytes_lost"], unread);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_rotated_file_is_read_from_its_start_and_the_old_unread_bytes_counted() {
        let path = temp_path("rotate");
        write_lines(&path, &(0..300).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, IngressLimits { alerts_per_poll: 100, ..open_limits() });
        let t0 = Instant::now();
        r.poll(&path, t0, |_| {});
        let unread = fs::metadata(&path).unwrap().len() - r.offset;
        // Rotate by rename; the new file is already longer than the old offset.
        let old = path.with_extension("1");
        fs::rename(&path, &old).unwrap();
        write_lines(&path, &(1000..1400).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut seen = Vec::new();
        r.poll(&path, t0 + Duration::from_secs(1), |v| seen.push(sig(v)));
        assert_eq!(seen, (1000..1100).collect::<Vec<_>>());
        let recs = r.audit_records(t0 + Duration::from_secs(1), 1.0);
        assert_eq!(recs[0]["ingress_shed"]["file_replacements"], 1);
        assert_eq!(recs[0]["ingress_shed"]["unread_bytes_lost"], unread);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&old);
    }

    #[test]
    fn the_audit_file_is_private_synced_rotated_and_never_follows_a_symlink() {
        let dir = temp_path("auditdir");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ingress-audit.jsonl");
        let rec = json!({"ingress_shed": {"shed_total": 1}});
        append_audit_record(&path, &rec, 200).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        for _ in 0..10 {
            append_audit_record(&path, &rec, 200).unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() < 200 + 64);
        assert!(dir.join("ingress-audit.jsonl.1").exists());

        let target = dir.join("elsewhere");
        fs::write(&target, b"").unwrap();
        let link = dir.join("linked.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(append_audit_record(&link, &rec, 1 << 20).is_err());
        // O_NOFOLLOW itself refuses, not only the symlink check before it.
        assert!(open_audit_file(&link).is_err());
        assert_eq!(fs::read(&target).unwrap().len(), 0);
        // An existing wider file is narrowed to 0600.
        let wide = dir.join("wide.jsonl");
        fs::write(&wide, b"").unwrap();
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o644)).unwrap();
        append_audit_record(&wide, &rec, 1 << 20).unwrap();
        assert_eq!(fs::metadata(&wide).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_declaration_file_mirrors_the_compiled_limits() {
        let doc: Value = serde_json::from_str(include_str!("../../../config/service_objectives/ingress_quota.json")).unwrap();
        assert_eq!(doc["schema"], "azazel-edge/ingress-quota/v1");
        let quotas = doc["quotas"].as_array().unwrap();
        assert_eq!(quotas.len(), 1);
        let q = &quotas[0];
        let d = IngressLimits::DECLARED;
        assert_eq!(q["ingress"], "core_eve_reader");
        assert_eq!(q["unit"], "eve_non_alert_lines_per_second");
        assert_eq!(q["value"].as_u64(), Some(d.non_alert_per_sec));
        assert_eq!(q["non_alert_burst"].as_u64(), Some(d.non_alert_burst));
        assert_eq!(q["alerts_per_poll"].as_u64(), Some(d.alerts_per_poll));
        assert_eq!(q["examine_per_poll"].as_u64(), Some(d.examine_per_poll));
        assert_eq!(q["poll_work_limit_ms"].as_u64(), Some(d.poll_work_limit.as_millis() as u64));
        assert_eq!(q["max_line_bytes"].as_u64(), Some(d.max_line_bytes));
        assert_eq!(q["backlog_bound_bytes"].as_u64(), Some(d.backlog_bound_bytes));
        assert_eq!(q["alert_backlog_bound_bytes"].as_u64(), Some(d.alert_backlog_bound_bytes));
        assert_eq!(q["audit_interval_ms"].as_u64(), Some(d.audit_interval.as_millis() as u64));
        assert_eq!(q["audit_log_cap_bytes"].as_u64(), Some(d.audit_log_cap_bytes));
        assert_eq!(q["status"], "provisional");
    }
}
