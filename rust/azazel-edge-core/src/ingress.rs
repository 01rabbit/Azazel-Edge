//! The Core's EVE ingress bound (Edge#414 OF-06).
//!
//! Before this module the reader took every new EVE line on each poll and
//! decided it before the release sweep could run, so a flood delayed lease
//! expiry by however long the flood took to read. The owner's decision on
//! Edge#414 (OF-06) is what this implements:
//!
//! * **A bound on work per poll, not data loss.** At most
//!   `admit_per_poll` lines are admitted per poll and at most
//!   `examine_per_poll` are looked at, and admission is also held to the
//!   declared rate `admit_per_sec` by a token bucket. Anything beyond that
//!   stays unread in the EVE file and is read on a later poll: the offset
//!   only moves past lines that were actually handled. A line still being
//!   written (no trailing newline yet) is left for the next poll as well.
//! * **Shedding only past a backlog bound, lowest importance first.** The
//!   backlog is the unread part of the file (`len - offset`). Past
//!   `backlog_bound_bytes`, `flow` records are dropped unread by the decider;
//!   each further multiple of the bound adds the next class (`dns`, then
//!   `stats`, then every other non-alert type).
//! * **Alerts are never shed.** An alert is always admitted when it is
//!   reached. Alerts beyond the rate wait in the file. A backlog past
//!   `alert_backlog_bound_bytes` is recorded as `ingress_alert_backlog` and
//!   the reader keeps going: nothing is dropped. The backlog lives in the EVE
//!   file, not in memory, so letting it grow costs disk Suricata already
//!   wrote, not Core memory. What it does cost is decision latency, which is
//!   exactly what the record makes visible.
//! * **Never silent.** Every shed line is counted by class, and the counts
//!   leave the Core as one `ingress_shed` summary per audit interval (not one
//!   record per line), with cumulative totals so a missing summary shows as a
//!   jump. A truncated EVE file that still held unread bytes is counted in
//!   the same summary.
//!
//! None of this decides anything about enforcement: it only decides which
//! lines reach the decider and when. The limits are compile-time constants;
//! there is no environment variable to raise or disable them.

use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
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
    /// The declared quota: admitted EVE lines per second (token bucket rate).
    pub admit_per_sec: u64,
    /// The token bucket's capacity, and so the most lines one poll admits.
    pub admit_per_poll: u64,
    /// Lines looked at per poll, shed ones included.
    pub examine_per_poll: u64,
    /// Unread bytes past which the lowest class is shed.
    pub backlog_bound_bytes: u64,
    /// Unread bytes past which an alert backlog is recorded (never shed).
    pub alert_backlog_bound_bytes: u64,
    /// At most one summary of each kind per this interval.
    pub audit_interval: Duration,
}

impl IngressLimits {
    pub const DECLARED: IngressLimits = IngressLimits {
        admit_per_sec: 2500,
        admit_per_poll: 1500,
        examine_per_poll: 6000,
        backlog_bound_bytes: 8 * 1024 * 1024,
        alert_backlog_bound_bytes: 256 * 1024 * 1024,
        audit_interval: Duration::from_secs(1),
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

/// The highest shed level: every non-alert class.
pub const MAX_SHED_LEVEL: u8 = 4;

impl ShedClass {
    /// Lower is shed first. Unparseable lines go with "other": the decider
    /// ignores them anyway, they only cost a read.
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

/// How many classes are shed at this backlog: none up to the bound, then one
/// more per further multiple of it.
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
    /// No EVE file, or it could not be opened.
    NoFile,
    /// Everything complete was read.
    CaughtUp,
    /// The last line has no newline yet; it is read once it is complete.
    PartialLine,
    /// The token bucket (declared rate) or the per-poll admit bound ran out.
    AdmitBudget,
    /// The per-poll examine bound ran out.
    ExamineBudget,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PollReport {
    pub admitted: u64,
    pub alerts_admitted: u64,
    pub examined: u64,
    pub shed: [u64; 5],
    pub backlog_before: u64,
    pub backlog_after: u64,
    pub level: u8,
    pub stop: Option<PollStop>,
}

impl PollReport {
    pub fn shed_total(&self) -> u64 {
        self.shed.iter().sum()
    }
}

#[derive(Debug, Clone, Default)]
struct Pending {
    polls: u64,
    shed: [u64; 5],
    admitted: u64,
    alerts_admitted: u64,
    examined: u64,
    max_backlog: u64,
    max_level: u8,
    truncation_resets: u64,
    unread_bytes_at_truncation: u64,
    alert_backlog_polls: u64,
    alert_backlog_max: u64,
    alert_backlog_alerts_admitted: u64,
}

#[derive(Debug)]
pub struct IngressReader {
    pub offset: u64,
    pub limits: IngressLimits,
    last_len: u64,
    tokens: f64,
    last_refill: Option<Instant>,
    pending: Pending,
    last_shed_emit: Option<Instant>,
    last_alert_emit: Option<Instant>,
    cumulative_shed: [u64; 5],
    cumulative_alert_backlog_polls: u64,
    cumulative_truncation_resets: u64,
}

impl IngressReader {
    pub fn new(offset: u64, limits: IngressLimits) -> Self {
        IngressReader {
            offset,
            limits,
            last_len: offset,
            tokens: limits.admit_per_poll as f64,
            last_refill: None,
            pending: Pending::default(),
            last_shed_emit: None,
            last_alert_emit: None,
            cumulative_shed: [0; 5],
            cumulative_alert_backlog_polls: 0,
            cumulative_truncation_resets: 0,
        }
    }

    fn refill(&mut self, now: Instant) {
        let cap = self.limits.admit_per_poll as f64;
        if let Some(last) = self.last_refill {
            let dt = now.saturating_duration_since(last).as_secs_f64();
            self.tokens = (self.tokens + dt * self.limits.admit_per_sec as f64).min(cap);
        } else {
            self.tokens = cap;
        }
        self.last_refill = Some(now);
    }

    /// Read at most one poll's worth of the EVE file at `path`, handing each
    /// admitted, parseable line to `decide`. Returns what was done.
    pub fn poll<F: FnMut(&Value)>(&mut self, path: &Path, now: Instant, mut decide: F) -> PollReport {
        let mut report = PollReport::default();
        self.refill(now);
        let len = match fs::metadata(path) {
            Ok(m) => m.len(),
            Err(_) => {
                report.stop = Some(PollStop::NoFile);
                return report;
            }
        };
        if self.offset > len {
            // The file was truncated or replaced by a shorter one. Whatever was
            // unread in the old one is gone; count it rather than lose it quietly.
            self.pending.truncation_resets += 1;
            self.cumulative_truncation_resets += 1;
            self.pending.unread_bytes_at_truncation += self.last_len.saturating_sub(self.offset);
            self.offset = 0;
        }
        self.last_len = len;
        let backlog = len - self.offset;
        report.backlog_before = backlog;
        report.level = shed_level(backlog, self.limits.backlog_bound_bytes);
        let alert_backlog = backlog > self.limits.alert_backlog_bound_bytes;

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                report.stop = Some(PollStop::NoFile);
                return report;
            }
        };
        let mut reader = BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.offset)).is_err() {
            report.stop = Some(PollStop::NoFile);
            return report;
        }

        let mut line = String::new();
        let stop = loop {
            if report.examined >= self.limits.examine_per_poll {
                break PollStop::ExamineBudget;
            }
            // The bucket holds at most `admit_per_poll` tokens, so this is
            // both the declared rate and the per-poll admit bound.
            if self.tokens < 1.0 {
                break PollStop::AdmitBudget;
            }
            line.clear();
            let n = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => break PollStop::CaughtUp,
            };
            if n == 0 {
                break PollStop::CaughtUp;
            }
            if !line.ends_with('\n') {
                // Still being written: leave it, offset unchanged.
                break PollStop::PartialLine;
            }
            self.offset += n as u64;
            let text = line.trim();
            if text.is_empty() {
                continue;
            }
            report.examined += 1;
            let parsed: Option<Value> = serde_json::from_str(text).ok();
            let class = classify(parsed.as_ref());
            if let Some(c) = class {
                if is_shed(c, report.level) {
                    report.shed[c.index()] += 1;
                    continue;
                }
            }
            report.admitted += 1;
            self.tokens -= 1.0;
            if class.is_none() {
                report.alerts_admitted += 1;
            }
            if let Some(v) = parsed.as_ref() {
                decide(v);
            }
        };
        report.stop = Some(stop);
        report.backlog_after = len.saturating_sub(self.offset);

        let p = &mut self.pending;
        p.polls += 1;
        p.admitted += report.admitted;
        p.alerts_admitted += report.alerts_admitted;
        p.examined += report.examined;
        p.max_backlog = p.max_backlog.max(backlog);
        p.max_level = p.max_level.max(report.level);
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
            "admit_per_sec": self.limits.admit_per_sec,
            "admit_per_poll": self.limits.admit_per_poll,
            "examine_per_poll": self.limits.examine_per_poll,
            "backlog_bound_bytes": self.limits.backlog_bound_bytes,
            "alert_backlog_bound_bytes": self.limits.alert_backlog_bound_bytes,
        })
    }

    /// The audit summaries due now: at most one `ingress_shed` and one
    /// `ingress_alert_backlog` per audit interval, each only when there is
    /// something to report. Counts not yet reported carry over to the next.
    pub fn audit_records(&mut self, now: Instant, now_epoch: f64) -> Vec<Value> {
        let mut out = Vec::new();
        let shed_total: u64 = self.pending.shed.iter().sum();
        let truncated = self.pending.truncation_resets > 0;
        if (shed_total > 0 || truncated) && self.interval_elapsed(self.last_shed_emit, now) {
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
                    "polls": p.polls,
                    "shed_by_type": by_type,
                    "shed_total": shed_total,
                    "alerts_shed": 0,
                    "admitted": p.admitted,
                    "alerts_admitted": p.alerts_admitted,
                    "examined": p.examined,
                    "max_backlog_bytes": p.max_backlog,
                    "max_shed_level": p.max_level,
                    "truncation_resets": p.truncation_resets,
                    "unread_bytes_at_truncation": p.unread_bytes_at_truncation,
                    "cumulative_shed_by_type": cumulative,
                    "cumulative_shed_total": self.cumulative_shed.iter().sum::<u64>(),
                    "cumulative_truncation_resets": self.cumulative_truncation_resets,
                    "quota": self.quota_block(),
                },
            }));
            self.last_shed_emit = Some(now);
            let keep_alert = (
                self.pending.alert_backlog_polls,
                self.pending.alert_backlog_max,
                self.pending.alert_backlog_alerts_admitted,
            );
            self.pending = Pending::default();
            self.pending.alert_backlog_polls = keep_alert.0;
            self.pending.alert_backlog_max = keep_alert.1;
            self.pending.alert_backlog_alerts_admitted = keep_alert.2;
        }
        if self.pending.alert_backlog_polls > 0 && self.interval_elapsed(self.last_alert_emit, now) {
            let p = &self.pending;
            out.push(json!({
                "source": INGRESS_SOURCE,
                "pipeline": INGRESS_PIPELINE,
                "ingress_alert_backlog": {
                    "schema": INGRESS_ALERT_BACKLOG_SCHEMA,
                    "emitted_epoch": now_epoch,
                    "polls_over_bound": p.alert_backlog_polls,
                    "max_backlog_bytes": p.alert_backlog_max,
                    "alert_backlog_bound_bytes": self.limits.alert_backlog_bound_bytes,
                    "alerts_admitted": p.alert_backlog_alerts_admitted,
                    "alerts_shed": 0,
                    "policy": "alerts are never shed; the backlog stays in the EVE file and is read at the declared rate",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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

    fn write_lines(path: &Path, lines: &[String]) {
        let mut f = fs::OpenOptions::new().create(true).append(true).open(path).unwrap();
        for l in lines {
            f.write_all(l.as_bytes()).unwrap();
        }
    }

    fn limits(admit: u64, examine: u64, rate: u64, backlog: u64, alert_backlog: u64) -> IngressLimits {
        IngressLimits {
            admit_per_sec: rate,
            admit_per_poll: admit,
            examine_per_poll: examine,
            backlog_bound_bytes: backlog,
            alert_backlog_bound_bytes: alert_backlog,
            audit_interval: Duration::from_secs(1),
        }
    }

    fn sig(v: &Value) -> u64 {
        v["alert"]["signature_id"].as_u64().or_else(|| v["n"].as_u64()).unwrap()
    }

    #[test]
    fn a_poll_admits_at_most_the_per_poll_bound() {
        let path = temp_path("bound");
        write_lines(&path, &(0..250).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, limits(100, 400, 1_000_000, u64::MAX, u64::MAX));
        let mut seen = 0;
        let rep = r.poll(&path, Instant::now(), |_| seen += 1);
        assert_eq!(rep.admitted, 100);
        assert_eq!(seen, 100);
        assert_eq!(rep.stop, Some(PollStop::AdmitBudget));
        assert!(rep.backlog_after > 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lines_beyond_the_bound_are_read_on_later_polls_in_order_and_once() {
        let path = temp_path("resume");
        write_lines(&path, &(0..250).map(|n| line(if n % 3 == 0 { "dns" } else { "alert" }, n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, limits(100, 400, 1_000_000, u64::MAX, u64::MAX));
        let start = Instant::now();
        let mut seen = Vec::new();
        for i in 0..5 {
            r.poll(&path, start + Duration::from_secs(i), |v| seen.push(sig(v)));
        }
        assert_eq!(seen, (0..250).collect::<Vec<_>>());
        assert_eq!(r.offset, fs::metadata(&path).unwrap().len());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn the_declared_rate_holds_across_polls() {
        let path = temp_path("rate");
        write_lines(&path, &(0..5000).map(|n| line("alert", n)).collect::<Vec<_>>());
        // 1000/s, 500 per poll: ten polls 100 ms apart may admit 500 + 9*100.
        let mut r = IngressReader::new(0, limits(500, 2000, 1000, u64::MAX, u64::MAX));
        let start = Instant::now();
        let mut admitted = 0;
        for i in 0..10 {
            admitted += r.poll(&path, start + Duration::from_millis(100 * i), |_| {}).admitted;
        }
        assert_eq!(admitted, 500 + 9 * 100);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_line_still_being_written_is_left_for_the_next_poll() {
        let path = temp_path("partial");
        write_lines(&path, &[line("alert", 1), "{\"event_type\":\"alert\",\"alert\":{\"signature_id\":2".to_string()]);
        let mut r = IngressReader::new(0, limits(100, 400, 1_000_000, u64::MAX, u64::MAX));
        let mut seen = Vec::new();
        let rep = r.poll(&path, Instant::now(), |v| seen.push(sig(v)));
        assert_eq!(rep.stop, Some(PollStop::PartialLine));
        assert_eq!(seen, vec![1]);
        write_lines(&path, &["}}\n".to_string()]);
        r.poll(&path, Instant::now() + Duration::from_secs(1), |v| seen.push(sig(v)));
        assert_eq!(seen, vec![1, 2]);
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

    fn backlog_poll(level_bytes_multiple: u64) -> (PollReport, Vec<String>) {
        let path = temp_path("shed");
        let lines = mixed(500);
        write_lines(&path, &lines);
        let len = fs::metadata(&path).unwrap().len();
        // Pick the bound so the backlog sits just past `multiple` bounds.
        let bound = (len - 1) / level_bytes_multiple;
        let mut r = IngressReader::new(0, limits(10_000, 10_000, 1_000_000, bound, u64::MAX));
        let mut types = Vec::new();
        let rep = r.poll(&path, Instant::now(), |v| types.push(v["event_type"].as_str().unwrap().to_string()));
        let _ = fs::remove_file(&path);
        (rep, types)
    }

    #[test]
    fn past_the_backlog_bound_the_lowest_importance_class_is_shed_first() {
        let (rep, types) = backlog_poll(1);
        assert_eq!(rep.level, 1);
        assert_eq!(rep.shed[ShedClass::Flow.index()], 100);
        assert_eq!(rep.shed_total(), 100);
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
    fn alerts_are_never_shed_at_any_backlog() {
        let path = temp_path("alerts");
        let lines = mixed(2000);
        write_lines(&path, &lines);
        // Every bound tiny: maximum shed level and an alert backlog.
        let mut r = IngressReader::new(0, limits(50, 200, 1_000_000, 1, 1));
        let start = Instant::now();
        let mut alerts = Vec::new();
        let mut i = 0;
        while r.offset < fs::metadata(&path).unwrap().len() {
            let rep = r.poll(&path, start + Duration::from_secs(i), |v| {
                if v["event_type"] == "alert" {
                    alerts.push(sig(v));
                }
            });
            assert!(rep.level == MAX_SHED_LEVEL || rep.backlog_before <= 1 || rep.backlog_before == 0);
            i += 1;
            assert!(i < 1000);
        }
        let expected: Vec<u64> = (0..2000).filter(|n| n % 5 == 4).collect();
        assert_eq!(alerts, expected);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shed_lines_do_not_use_the_admit_budget_but_are_bounded_by_examine() {
        let path = temp_path("examine");
        write_lines(&path, &(0..1000).map(|n| line("flow", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, limits(10, 300, 1_000_000, 1, u64::MAX));
        let rep = r.poll(&path, Instant::now(), |_| {});
        assert_eq!(rep.examined, 300);
        assert_eq!(rep.shed[ShedClass::Flow.index()], 300);
        assert_eq!(rep.admitted, 0);
        assert_eq!(rep.stop, Some(PollStop::ExamineBudget));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn shedding_is_summarised_once_per_interval_with_counts_by_type() {
        let path = temp_path("audit");
        write_lines(&path, &mixed(2000));
        let mut r = IngressReader::new(0, limits(100, 100, 1_000_000, 1, u64::MAX));
        let t0 = Instant::now();
        // Five polls inside one interval: the first emits, the next four carry over.
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
        assert_eq!(
            first["shed_by_type"].as_object().unwrap().keys().cloned().collect::<Vec<_>>(),
            vec!["dns", "flow", "other", "stats", "unparseable"]
        );
        // The next interval reports exactly what the first one did not.
        let later = t0 + Duration::from_millis(1000);
        let more = r.audit_records(later, 2.0);
        assert_eq!(more.len(), 1);
        let second = &more[0]["ingress_shed"];
        assert_eq!(at_first + second["shed_total"].as_u64().unwrap(), shed);
        assert_eq!(second["cumulative_shed_total"].as_u64().unwrap(), shed);
        // Nothing new: nothing emitted.
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

    #[test]
    fn an_alert_backlog_is_recorded_and_alerts_keep_being_read() {
        let path = temp_path("alertbacklog");
        write_lines(&path, &(0..300).map(|n| line("alert", n)).collect::<Vec<_>>());
        let mut r = IngressReader::new(0, limits(100, 400, 1_000_000, u64::MAX, 10));
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
        let mut r = IngressReader::new(0, limits(100, 400, 1_000_000, u64::MAX, u64::MAX));
        let t0 = Instant::now();
        r.poll(&path, t0, |_| {});
        let unread = fs::metadata(&path).unwrap().len() - r.offset;
        fs::write(&path, line("alert", 999)).unwrap();
        let mut seen = Vec::new();
        r.poll(&path, t0 + Duration::from_secs(1), |v| seen.push(sig(v)));
        assert_eq!(seen, vec![999]);
        let recs = r.audit_records(t0 + Duration::from_secs(1), 1.0);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["ingress_shed"]["truncation_resets"], 1);
        assert_eq!(recs[0]["ingress_shed"]["unread_bytes_at_truncation"], unread);
        let _ = fs::remove_file(&path);
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
        assert_eq!(q["unit"], "eve_lines_per_second");
        assert_eq!(q["value"].as_u64(), Some(d.admit_per_sec));
        assert_eq!(q["admit_per_poll"].as_u64(), Some(d.admit_per_poll));
        assert_eq!(q["examine_per_poll"].as_u64(), Some(d.examine_per_poll));
        assert_eq!(q["backlog_bound_bytes"].as_u64(), Some(d.backlog_bound_bytes));
        assert_eq!(q["alert_backlog_bound_bytes"].as_u64(), Some(d.alert_backlog_bound_bytes));
        assert_eq!(q["audit_interval_ms"].as_u64(), Some(d.audit_interval.as_millis() as u64));
        assert_eq!(q["status"], "provisional");
    }
}
