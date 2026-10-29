mod audit_chain;
mod ingress;
mod release;
mod safety;

use ingress::{append_audit_record, IngressLimits, IngressReader, PollReport};
use release::{
    abandon_release_task, activate_release_task, admit_release_task, build_flow_throttle_task, build_release_task,
    nft_comment_arg, nft_family, owned_state_matches_plan, process_due_releases, Admission, FlowScope, LeaseNow,
    ReleaseTask, THROTTLE_CHAIN,
};
#[cfg(test)]
use release::prepare_release_task;
use safety::{ProtectedMatch, ProtectedSet};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Config {
    eve_path: String,
    ai_socket_path: String,
    normalized_log_path: String,
    from_start: bool,
    poll_ms: u64,
    forward_ai: bool,
    forward_log: bool,
    event_stdout: StdoutMode,
    defense_enforce: bool,
    defense_dry_run: bool,
    defense_enforce_level: String,
    defense_action_ttl_sec: u64,
    /// How the TTL was obtained (`safety::bounded_ttl`).
    defense_ttl_source: String,
    defense_release_ledger_path: String,
    /// The protected communications set (management, expert contact,
    /// mission), read once at start from `AZAZEL_PROTECTED_FLOWS_PATH`.
    protected_flows_path: String,
    protected: ProtectedSet,
    defense_allow_high_impact_auto: bool,
    defense_iface: String,
    defense_honeypot_port: u16,
    redirect_policy_path: String,
    redirect_policy: Option<RedirectPolicyConfig>,
    redirect_policy_source: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NormalizedEvent {
    ts: String,
    src_ip: String,
    dst_ip: String,
    attack_type: String,
    severity: u8,
    target_port: u16,
    protocol: String,
    sid: u64,
    category: String,
    event_type: String,
    action: String,
    confidence: u8,
    risk_score: u8,
    ingest_epoch: f64,
    /// MITRE ATT&CK technique ids the rule itself declares, for consumers that
    /// look up cited context. Never inferred, and never an input to a decision.
    technique_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DefensiveDecision {
    action: String,
    reason: String,
    policy_reason: String,
    delay_ms: u32,
    target: String,
}

#[derive(Debug, Clone, Serialize)]
struct EnforcementPlan {
    action: String,
    target: String,
    apply_commands: Vec<String>,
    rollback_commands: Vec<String>,
    /// The argv actually executed for each entry of `apply_commands`, in the
    /// same order. `apply_commands` is the rendering kept in records (with the
    /// bare owner token after `comment`); it is never split back into argv,
    /// because the executed nft comment is an nft quoted string.
    #[serde(skip)]
    apply_argv: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
struct EnforcementStatus {
    enforce_enabled: bool,
    enforce_level: String,
    dry_run: bool,
    high_impact_auto: bool,
    allowed_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EnforcementOutcome {
    mode: String,
    trace_id: String,
    selected_action: String,
    target: String,
    policy_reason: String,
    command_plan: Vec<String>,
    rollback_plan: Vec<String>,
    executed_count: u32,
    failed_count: u32,
    errors: Vec<String>,
    rollback_hint: String,
    result: String,
    metadata: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct RedirectPolicyRoot {
    redirect_policy: Option<RedirectPolicyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct RedirectPolicyConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    prepared_ports: HashMap<u16, u16>,
    #[serde(default = "default_notify")]
    unsupported_port_action: String,
    #[serde(default = "default_isolate")]
    high_risk_unsupported_port_action: String,
    #[serde(default = "default_throttle")]
    scan_burst_action: String,
    /// Where the deployment writes the decoy separation evidence
    /// (`safety::check_decoy_evidence`). Without it no redirect is executed.
    #[serde(default)]
    decoy_separation_evidence_path: String,
    #[serde(default = "default_evidence_age")]
    decoy_evidence_max_age_sec: u64,
}

fn default_evidence_age() -> u64 {
    600
}

fn default_notify() -> String {
    "notify".to_string()
}

/// The high-risk unsupported-port fallback defaults to notify: the
/// automatic path never chooses isolate (ADR, scoped temporary actions).
fn default_isolate() -> String {
    "notify".to_string()
}

fn default_throttle() -> String {
    "throttle".to_string()
}

/// A fallback the redirect policy may name. `isolate` (and `redirect`,
/// which would loop) are not automatic fallbacks: they become `notify`
/// whatever the file says.
fn normalize_safe_action(raw: &str, default_action: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "observe" | "notify" | "throttle" => raw.to_ascii_lowercase(),
        "isolate" | "redirect" => "notify".to_string(),
        _ => default_action.to_string(),
    }
}

fn load_redirect_policy(path: &str) -> Result<Option<RedirectPolicyConfig>, String> {
    let source = Path::new(path);
    if !source.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(source).map_err(|e| format!("redirect_policy_read_failed:{}", e))?;
    let parsed: RedirectPolicyRoot = serde_yaml::from_str(&raw).map_err(|e| format!("redirect_policy_parse_failed:{}", e))?;
    Ok(parsed.redirect_policy)
}

fn now_epoch() -> f64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(_) => 0.0,
    }
}

/// What each processed event prints to stdout, which a service manager usually
/// keeps in its journal. `Full` is the historical behaviour. `Summary` keeps the
/// decision and the posture but no address, target or command plan, for a
/// deployment whose journal leaves the host. `Off` prints nothing per event.
/// None of them changes a decision, the socket forward or the JSONL record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StdoutMode {
    Full,
    Summary,
    Off,
}

fn stdout_mode(value: Option<String>) -> StdoutMode {
    match value.as_deref().map(str::trim) {
        None | Some("") | Some("full") => StdoutMode::Full,
        Some("summary") => StdoutMode::Summary,
        Some("off") => StdoutMode::Off,
        Some(other) => {
            eprintln!("AZAZEL_EVENT_STDOUT={:?} is not full|summary|off; using full", other);
            StdoutMode::Full
        }
    }
}

/// The event as `Summary` prints it: the decision, Edge's posture and the
/// enforcement outcome, without addresses, target or planned commands.
fn summary_line(event: &Value) -> Value {
    let pick = |path: &[&str]| -> Value {
        let mut node = event;
        for key in path {
            match node.get(*key) {
                Some(next) => node = next,
                None => return Value::Null,
            }
        }
        node.clone()
    };
    json!({
        "summary": true,
        "source": pick(&["source"]),
        "pipeline": pick(&["pipeline"]),
        "severity": pick(&["normalized", "severity"]),
        "sid": pick(&["normalized", "sid"]),
        "technique_ids": pick(&["normalized", "technique_ids"]),
        "defense": {
            "action": pick(&["defense", "action"]),
            "policy_reason": pick(&["defense", "policy_reason"]),
        },
        "enforcement": {
            "mode": pick(&["enforcement", "mode"]),
            "result": pick(&["enforcement", "result"]),
            "trace_id": pick(&["enforcement", "trace_id"]),
        },
        "enforcement_status": pick(&["enforcement_status"]),
    })
}

fn print_event(mode: StdoutMode, event: &Value) {
    match mode {
        StdoutMode::Full => println!("{}", event),
        StdoutMode::Summary => println!("{}", summary_line(event)),
        StdoutMode::Off => {}
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

fn load_config() -> Config {
    let args: Vec<String> = env::args().collect();
    let mut from_start = env_bool("AZAZEL_EVE_FROM_START", false);
    for arg in &args {
        if arg == "--from-start" {
            from_start = true;
        }
    }

    let redirect_policy_path = env::var("AZAZEL_REDIRECT_POLICY_PATH").unwrap_or_else(|_| "config/redirect_policy.yaml".to_string());
    let (redirect_policy, redirect_policy_source) = match load_redirect_policy(&redirect_policy_path) {
        Ok(Some(policy)) => (Some(policy), format!("file:{}", redirect_policy_path)),
        Ok(None) => (None, "env_honeypot_fallback".to_string()),
        Err(e) => {
            eprintln!("redirect policy load failed, using fail-safe notify fallback: {}", e);
            (None, format!("invalid_file_notify_fallback:{}", redirect_policy_path))
        }
    };

    // The TTL is bounded by Edge constants; the environment can shorten it,
    // never lengthen it past MAX_LEASE_TTL_SEC.
    let ttl_raw = env::var("AZAZEL_DEFENSE_ACTION_TTL_SEC").ok();
    let (ttl, ttl_source) = safety::bounded_ttl(ttl_raw.as_deref());
    let protected_flows_path = env::var("AZAZEL_PROTECTED_FLOWS_PATH")
        .unwrap_or_else(|_| "/etc/azazel-edge/protected-flows.yaml".to_string());

    Config {
        eve_path: env::var("AZAZEL_EVE_PATH").unwrap_or_else(|_| "/var/log/suricata/eve.json".to_string()),
        ai_socket_path: env::var("AZAZEL_AI_SOCKET").unwrap_or_else(|_| "/run/azazel-edge-ai/ai-bridge.sock".to_string()),
        normalized_log_path: env::var("AZAZEL_NORMALIZED_EVENT_LOG")
            .unwrap_or_else(|_| "/var/log/azazel-edge/normalized-events.jsonl".to_string()),
        from_start,
        poll_ms: env::var("AZAZEL_EVE_POLL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(200),
        forward_ai: env_bool("AZAZEL_FORWARD_AI", true),
        forward_log: env_bool("AZAZEL_FORWARD_LOG", true),
        event_stdout: stdout_mode(env::var("AZAZEL_EVENT_STDOUT").ok()),
        defense_enforce: env_bool("AZAZEL_DEFENSE_ENFORCE", false),
        defense_dry_run: env_bool("AZAZEL_DEFENSE_DRY_RUN", true),
        defense_enforce_level: env::var("AZAZEL_DEFENSE_ENFORCE_LEVEL").unwrap_or_else(|_| "advisory".to_string()),
        defense_action_ttl_sec: ttl,
        defense_ttl_source: ttl_source.to_string(),
        protected_flows_path: protected_flows_path.clone(),
        protected: ProtectedSet::load(&protected_flows_path),
        defense_release_ledger_path: env::var("AZAZEL_DEFENSE_RELEASE_LEDGER")
            .unwrap_or_else(|_| "/var/lib/azazel-edge/release-ledger.json".to_string()),
        defense_allow_high_impact_auto: env_bool("AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO", false),
        defense_iface: env::var("AZAZEL_DEFENSE_IFACE").unwrap_or_else(|_| "br0".to_string()),
        defense_honeypot_port: env::var("AZAZEL_DEFENSE_HONEYPOT_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(2222),
        redirect_policy_path,
        redirect_policy,
        redirect_policy_source,
    }
}

fn build_normalized_event(v: &Value) -> Option<NormalizedEvent> {
    let event_type = v.get("event_type")?.as_str()?.to_string();
    if event_type != "alert" {
        return None;
    }

    let alert = v.get("alert").and_then(|x| x.as_object())?;
    let severity = alert.get("severity").and_then(|x| x.as_u64()).unwrap_or(3).min(10) as u8;
    // Standard Suricata EVE uses "signature_id"; accept legacy/custom "sid" as fallback.
    let sid = alert
        .get("signature_id")
        .or_else(|| alert.get("sid"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    let attack_type = alert.get("signature").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
    let category = alert.get("category").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();

    let dst_port = v.get("dest_port").and_then(|x| x.as_u64()).unwrap_or(0).min(u16::MAX as u64) as u16;

    let protocol = v.get("proto").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();

    let action = alert.get("action").and_then(|x| x.as_str()).unwrap_or("allowed").to_string();

    let risk_score = ((11_u16.saturating_sub(severity as u16)) * 9).min(100) as u8;
    let confidence = if sid > 0 { 90 } else { 50 };

    Some(NormalizedEvent {
        ts: v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        src_ip: v.get("src_ip").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        dst_ip: v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        attack_type,
        severity,
        target_port: dst_port,
        protocol,
        sid,
        category,
        event_type,
        action,
        confidence,
        risk_score,
        ingest_epoch: now_epoch(),
        technique_ids: rule_technique_ids(alert),
    })
}

const MAX_TECHNIQUE_IDS: usize = 8;

/// `T1234` or `T1234.567`, the only shapes a technique id takes.
fn is_technique_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    let digits = |range: &[u8]| range.iter().all(|b| b.is_ascii_digit());
    match bytes.len() {
        5 => bytes[0] == b'T' && digits(&bytes[1..5]),
        9 => bytes[0] == b'T' && digits(&bytes[1..5]) && bytes[5] == b'.' && digits(&bytes[6..9]),
        _ => false,
    }
}

/// The technique ids in the rule's own `metadata.mitre_technique_id`.
///
/// Suricata writes rule metadata as arrays of strings. Anything that is not a
/// well-formed id is dropped rather than repaired, duplicates are removed, and
/// at most `MAX_TECHNIQUE_IDS` are carried.
fn rule_technique_ids(alert: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let values = alert
        .get("metadata")
        .and_then(|m| m.get("mitre_technique_id"))
        .and_then(|v| v.as_array());
    for value in values.into_iter().flatten() {
        if let Some(id) = value.as_str() {
            if is_technique_id(id) && !ids.iter().any(|seen| seen == id) {
                ids.push(id.to_string());
                if ids.len() == MAX_TECHNIQUE_IDS {
                    break;
                }
            }
        }
    }
    ids
}

fn decide_defense(ev: &NormalizedEvent) -> DefensiveDecision {
    // Critical: the strict flow-scoped temporary restriction. The automatic
    // path never isolates (ADR, scoped temporary actions).
    if ev.severity <= 1 {
        return DefensiveDecision {
            action: "throttle".to_string(),
            reason: format!("critical severity sid={}", ev.sid),
            policy_reason: "severity_critical_strict_flow_restriction".to_string(),
            delay_ms: 0,
            target: ev.src_ip.clone(),
        };
    }
    if ev.severity <= 2 {
        return DefensiveDecision {
            action: "redirect".to_string(),
            reason: format!("high severity sid={}", ev.sid),
            policy_reason: "severity_high_redirect_to_decoy".to_string(),
            delay_ms: 800,
            target: format!("{}:{}", ev.src_ip, ev.target_port),
        };
    }
    if ev.severity == 3 {
        return DefensiveDecision {
            action: "throttle".to_string(),
            reason: format!("elevated severity sid={}", ev.sid),
            policy_reason: "severity_elevated_throttle_reversible".to_string(),
            delay_ms: 1000,
            target: ev.src_ip.clone(),
        };
    }
    if ev.severity == 4 {
        return DefensiveDecision {
            action: "notify".to_string(),
            reason: format!("moderate severity sid={}", ev.sid),
            policy_reason: "severity_moderate_operator_notification".to_string(),
            delay_ms: 0,
            target: ev.src_ip.clone(),
        };
    }
    DefensiveDecision {
        action: "observe".to_string(),
        reason: "normal baseline telemetry".to_string(),
        policy_reason: "baseline_observe_only".to_string(),
        delay_ms: 0,
        target: ev.src_ip.clone(),
    }
}

fn shell_quote(raw: &str) -> String {
    if raw.is_empty() {
        "''".to_string()
    } else if raw.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '/')) {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

fn command_to_string(argv: &[String]) -> String {
    argv.iter().map(|part| shell_quote(part)).collect::<Vec<String>>().join(" ")
}

#[cfg(test)]
fn build_enforcement_plan(ev: &NormalizedEvent, decision: &DefensiveDecision, iface: &str, honeypot_port: u16) -> EnforcementPlan {
    build_enforcement_plan_owned(ev, decision, iface, honeypot_port, None)
}

/// The flow an alert names: its source and destination of one address
/// family and, for TCP/UDP with a port, the destination port. `None` when it
/// cannot be scoped to a flow; then nothing is restricted.
fn flow_scope(ev: &NormalizedEvent) -> Option<FlowScope> {
    let family = nft_family(&ev.src_ip)?;
    if nft_family(&ev.dst_ip) != Some(family) {
        return None;
    }
    let protocol = match ev.protocol.to_ascii_lowercase().as_str() {
        "tcp" if ev.target_port > 0 => "tcp",
        "udp" if ev.target_port > 0 => "udp",
        _ => "",
    };
    Some(FlowScope {
        source_ip: ev.src_ip.clone(),
        destination_ip: ev.dst_ip.clone(),
        protocol: protocol.to_string(),
        destination_port: if protocol.is_empty() { 0 } else { ev.target_port },
    })
}

/// The restriction strength for an alert: strict for critical severity.
fn strength_for(ev: &NormalizedEvent) -> (&'static str, u32, u32) {
    if ev.severity <= 1 {
        safety::STRENGTH_STRICT
    } else {
        safety::STRENGTH_STANDARD
    }
}

/// The nft argv of a flow-scoped rate limit in the owned `throttle` chain:
/// only this flow's packets above the rate are dropped. No qdisc is
/// created, replaced or deleted, so the interface's own shaping stays.
fn flow_limit_argv(verb: &str, flow: &FlowScope, rate: u32, burst: u32) -> Vec<String> {
    let family = nft_family(&flow.source_ip).unwrap_or("ip");
    let mut argv = vec![
        "nft".to_string(), verb.to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
        THROTTLE_CHAIN.to_string(), family.to_string(), "saddr".to_string(), flow.source_ip.clone(),
        family.to_string(), "daddr".to_string(), flow.destination_ip.clone(),
    ];
    if !flow.protocol.is_empty() {
        argv.extend([flow.protocol.clone(), "dport".to_string(), flow.destination_port.to_string()]);
    }
    argv.extend([
        "limit".to_string(), "rate".to_string(), "over".to_string(), rate.to_string(), "kbytes/second".to_string(),
        "burst".to_string(), burst.to_string(), "kbytes".to_string(), "drop".to_string(),
    ]);
    argv
}

/// The apply and rollback plan. Only `throttle` (flow-scoped nft limit) and
/// `redirect` produce commands; `isolate` produces none, so the automatic
/// path cannot reach a source-wide drop even if a decision named it.
fn build_enforcement_plan_owned(
    ev: &NormalizedEvent,
    decision: &DefensiveDecision,
    _iface: &str,
    honeypot_port: u16,
    release_task: Option<&ReleaseTask>,
) -> EnforcementPlan {
    let mut apply: Vec<Vec<String>> = Vec::new();
    let mut rollback: Vec<Vec<String>> = Vec::new();
    // An owned nft rule carries its owner token as an nft quoted string. A
    // token that cannot be one gives no owned plan (admission rejects that
    // task before anything is executed).
    let owned_nft = release_task
        .and_then(|task| nft_comment_arg(&task.owner_token).ok().map(|comment| (task, comment)));

    if decision.action == "throttle" {
        if let Some(flow) = flow_scope(ev) {
            let (_, rate, burst) = strength_for(ev);
            let mut command = flow_limit_argv("insert", &flow, rate, burst);
            if let Some((task, comment)) = &owned_nft {
                command.push("comment".to_string());
                command.push(comment.clone());
                rollback.push(vec![
                    "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
                    THROTTLE_CHAIN.to_string(), "handle".to_string(), format!("<owned:{}>", task.owner_token),
                ]);
            } else {
                rollback.push(flow_limit_argv("delete", &flow, rate, burst));
            }
            apply.push(command);
        }
    }

    if decision.action == "redirect" {
        let mut command = vec![
            "nft".to_string(), "insert".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "prerouting".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "tcp".to_string(),
            "dport".to_string(), ev.target_port.to_string(), "redirect".to_string(), "to".to_string(), honeypot_port.to_string(),
        ];
        if let Some((task, comment)) = &owned_nft {
            command.push("comment".to_string());
            command.push(comment.clone());
            rollback.push(vec![
                "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
                "prerouting".to_string(), "handle".to_string(), format!("<owned:{}>", task.owner_token),
            ]);
        } else {
            rollback.push(vec![
                "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
                "prerouting".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "tcp".to_string(),
                "dport".to_string(), ev.target_port.to_string(), "redirect".to_string(), "to".to_string(), honeypot_port.to_string(),
            ]);
        }
        apply.push(command);
    }

    EnforcementPlan {
        action: decision.action.clone(),
        target: decision.target.clone(),
        // The recorded plan keeps the bare owner token after `comment` (the
        // record format parsed by outcome/ownership.py); only the executed
        // argv carries the nft quoted string.
        apply_commands: apply
            .iter()
            .map(|argv| {
                let shown = argv
                    .iter()
                    .map(|part| match &owned_nft {
                        Some((task, comment)) if part == comment => task.owner_token.clone(),
                        _ => part.clone(),
                    })
                    .collect::<Vec<String>>();
                command_to_string(&shown)
            })
            .collect::<Vec<String>>(),
        rollback_commands: rollback.iter().map(|argv| command_to_string(argv)).collect::<Vec<String>>(),
        apply_argv: apply,
    }
}

/// Run one apply command, killed and failed past
/// `safety::APPLY_COMMAND_TIMEOUT`. nft is started by absolute path from the
/// trusted directories, with the environment cleared and a fixed PATH
/// (Edge#477).
fn run_command(argv: &[String]) -> Result<(), String> {
    run_command_with_timeout(argv, safety::APPLY_COMMAND_TIMEOUT)
}

fn run_command_with_timeout(argv: &[String], timeout: Duration) -> Result<(), String> {
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    match release::run_bounded(argv, timeout) {
        Ok(result) if result.returncode == 0 => Ok(()),
        Ok(result) => Err(format!("command failed (exit={}): {}", result.returncode, command_to_string(argv))),
        Err(e) if e == "command timeout" => Err(format!("command timeout after {:?}: {}", timeout, command_to_string(argv))),
        Err(e) => Err(format!("command exec error: {} ({})", e, command_to_string(argv))),
    }
}

/// What each level may execute automatically. `isolate` is in none of
/// them, whatever the high-impact flag says: the automatic path is limited
/// to notification, flow-scoped temporary restriction and decoy redirect.
fn action_allowlist(level: &str, high_impact_auto: bool) -> Vec<String> {
    match level {
        "full-auto" => vec!["observe", "notify", "throttle", "redirect"].iter().map(|s| s.to_string()).collect(),
        "semi-auto" => {
            let mut base = vec!["observe", "notify", "throttle"].iter().map(|s| s.to_string()).collect::<Vec<String>>();
            if high_impact_auto {
                base.push("redirect".to_string());
            }
            base
        }
        _ => vec!["observe".to_string(), "notify".to_string()],
    }
}

fn enforcement_status(cfg: &Config) -> EnforcementStatus {
    let level = cfg.defense_enforce_level.to_ascii_lowercase();
    EnforcementStatus {
        enforce_enabled: cfg.defense_enforce,
        enforce_level: level.clone(),
        dry_run: cfg.defense_dry_run,
        high_impact_auto: cfg.defense_allow_high_impact_auto,
        allowed_actions: action_allowlist(&level, cfg.defense_allow_high_impact_auto),
    }
}

fn calc_trace_id(ev: &NormalizedEvent, decision: &DefensiveDecision) -> String {
    let mut hasher = DefaultHasher::new();
    ev.ts.hash(&mut hasher);
    ev.src_ip.hash(&mut hasher);
    ev.dst_ip.hash(&mut hasher);
    ev.sid.hash(&mut hasher);
    decision.action.hash(&mut hasher);
    format!("trace-{:#x}", hasher.finish())
}

fn should_execute_action(action: &str, cfg: &Config) -> (bool, String) {
    if !cfg.defense_enforce {
        return (false, "enforce_disabled".to_string());
    }
    let level = cfg.defense_enforce_level.to_ascii_lowercase();
    if level == "advisory" {
        return (false, "advisory_mode".to_string());
    }
    let allowed = action_allowlist(&level, cfg.defense_allow_high_impact_auto);
    if allowed.iter().any(|x| x == action) {
        (true, "policy_permitted".to_string())
    } else {
        (false, "approval_required_for_high_impact_action".to_string())
    }
}

fn add_release_metadata(metadata: &mut Value, task: Option<&ReleaseTask>, state: &str) {
    if let Some(task) = task {
        metadata["release_task_id"] = json!(task.task_id);
        metadata["release_due_epoch"] = json!(task.due_epoch);
        metadata["release_resource_key"] = json!(task.resource_key);
        metadata["release_owner_token"] = json!(task.owner_token);
        metadata["release_tc_handle"] = json!(task.tc_handle);
        metadata["release_ledger_state"] = json!(state);
    } else {
        metadata["release_task_id"] = Value::Null;
        metadata["release_due_epoch"] = Value::Null;
        metadata["release_resource_key"] = Value::Null;
        metadata["release_owner_token"] = Value::Null;
        metadata["release_tc_handle"] = Value::Null;
        metadata["release_ledger_state"] = json!(state);
    }
}

/// How an admitted plan is applied and read back. The daemon uses
/// [`SystemApplier`]; tests substitute failures, hangs and mismatches.
trait Applier {
    /// Run one apply argv; bounded in time by the implementation.
    fn apply(&self, argv: &[String]) -> Result<(), String>;
    /// Whether the task's owned state reads back exactly as planned.
    fn readback(&self, task: &ReleaseTask) -> Result<bool, String>;
}

struct SystemApplier;

impl Applier for SystemApplier {
    fn apply(&self, argv: &[String]) -> Result<(), String> {
        run_command(argv)
    }
    fn readback(&self, task: &ReleaseTask) -> Result<bool, String> {
        owned_state_matches_plan(task)
    }
}

fn maybe_enforce(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config) -> EnforcementOutcome {
    maybe_enforce_with(ev, decision, cfg, &SystemApplier)
}

/// Why a restriction may not target this alert, by rules that need no
/// command and no clock: never isolate, a scopable target, and never a flow
/// of the protected communications set. Evaluated in every mode, so a dry
/// run shows what would really happen.
fn static_safety_refusal(ev: &NormalizedEvent, action: &str, cfg: &Config) -> (Option<String>, Option<ProtectedMatch>) {
    match action {
        "isolate" => return (Some("isolate_not_automatic".to_string()), None),
        "throttle" if flow_scope(ev).is_none() => return (Some("target_not_a_flow".to_string()), None),
        "redirect" => {
            if !ev.protocol.eq_ignore_ascii_case("tcp") || ev.target_port == 0 {
                return (Some("redirect_target_ineligible:not_tcp".to_string()), None);
            }
            if nft_family(&ev.src_ip) != Some("ip") {
                return (Some("redirect_target_ineligible:not_ipv4_source".to_string()), None);
            }
        }
        "throttle" => {}
        _ => return (None, None),
    }
    let Ok(source) = ev.src_ip.parse::<std::net::IpAddr>() else {
        return (Some("target_source_invalid".to_string()), None);
    };
    let destination = ev.dst_ip.parse::<std::net::IpAddr>().ok();
    match cfg.protected.matches(&source, destination.as_ref(), ev.target_port) {
        Some(found) => (Some(format!("protected_flow:{}", found.role)), Some(found)),
        None => (None, None),
    }
}

/// Rules checked only when a restriction is about to be executed: the
/// protected set is declared, the alert is recent, and for a redirect the
/// decoy is separated (this boot's evidence) and reachable.
fn execution_safety_refusal(ev: &NormalizedEvent, action: &str, decoy_port: u16, cfg: &Config, now: &LeaseNow) -> Result<f64, String> {
    cfg.protected.ready_for_execution()?;
    let event_epoch = safety::alert_freshness(&ev.ts, now.wall_epoch)?;
    if action == "redirect" {
        let (path, max_age) = match &cfg.redirect_policy {
            Some(policy) => (policy.decoy_separation_evidence_path.as_str(), policy.decoy_evidence_max_age_sec),
            None => ("", 0),
        };
        safety::check_decoy_evidence(path, max_age, decoy_port, now.wall_epoch, now.boot_id.as_deref().unwrap_or(""))?;
        if !safety::decoy_reachable(decoy_port) {
            return Err("decoy_unreachable".to_string());
        }
    }
    Ok(event_epoch)
}

fn maybe_enforce_with<A: Applier>(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config, applier: &A) -> EnforcementOutcome {
    let trace_id = calc_trace_id(ev, decision);
    let (mut effective_decision, mut redirect_meta) = resolve_redirect_decision(ev, decision, cfg);
    let requested_action = effective_decision.action.clone();
    let strength = if requested_action == "throttle" { strength_for(ev).0 } else { "" };
    let scope = match requested_action.as_str() {
        "throttle" => flow_scope(ev).map(|f| format!("flow:{}", f.key())).unwrap_or_else(|| "unscoped".to_string()),
        "redirect" => format!("source_and_port:{}:{}", ev.src_ip, ev.target_port),
        _ => "none".to_string(),
    };
    let (static_refusal, protected_match) = static_safety_refusal(ev, &requested_action, cfg);
    if let Some(reason) = &static_refusal {
        effective_decision.action = "notify".to_string();
        effective_decision.policy_reason = format!("{}:safety_refused:{}", effective_decision.policy_reason, reason);
        effective_decision.reason = format!("{}; {} not executed ({}), fallback=notify", effective_decision.reason, requested_action, reason);
    }
    let protected_status = cfg.protected.status();
    let safety_meta = |gate: &str, decoy: &str| {
        safety::safety_block(
            &protected_status,
            protected_match.as_ref(),
            &scope,
            gate,
            cfg.defense_action_ttl_sec,
            &cfg.defense_ttl_source,
            strength,
            decoy,
        )
    };
    let selected_decoy_port = redirect_meta
        .get("selected_decoy_port")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)
        .unwrap_or(cfg.defense_honeypot_port);
    let now = LeaseNow::read(now_epoch());
    let release_task = match effective_decision.action.as_str() {
        "throttle" => flow_scope(ev).and_then(|flow| {
            let (_, rate, burst) = strength_for(ev);
            build_flow_throttle_task(&trace_id, &flow, rate, burst, cfg.defense_action_ttl_sec, &now)
        }),
        "redirect" => build_release_task(
            &trace_id,
            "redirect",
            &cfg.defense_iface,
            &ev.src_ip,
            ev.target_port,
            selected_decoy_port,
            effective_decision.delay_ms,
            cfg.defense_action_ttl_sec,
            &now,
        ),
        _ => None,
    };
    let plan = build_enforcement_plan_owned(
        ev,
        &effective_decision,
        &cfg.defense_iface,
        selected_decoy_port,
        release_task.as_ref(),
    );

    if plan.apply_commands.is_empty() {
        add_release_metadata(&mut redirect_meta, None, "not_applicable");
        let gate = static_refusal.as_ref().map(|r| format!("refused:{}", r)).unwrap_or_else(|| "not_applicable".to_string());
        redirect_meta["safety"] = safety_meta(&gate, "not_applicable");
        return EnforcementOutcome {
            mode: "disabled".to_string(),
            trace_id,
            selected_action: effective_decision.action.clone(),
            target: effective_decision.target.clone(),
            policy_reason: effective_decision.policy_reason.clone(),
            command_plan: plan.apply_commands.clone(),
            rollback_plan: plan.rollback_commands.clone(),
            executed_count: 0,
            failed_count: 0,
            errors: Vec::new(),
            rollback_hint: "no_runtime_change".to_string(),
            result: "no_disruptive_action".to_string(),
            metadata: redirect_meta,
        };
    }

    let (allowed_by_policy, policy_gate_reason) = should_execute_action(&effective_decision.action, cfg);
    if cfg.defense_dry_run || !allowed_by_policy {
        add_release_metadata(&mut redirect_meta, release_task.as_ref(), "planned_only");
        redirect_meta["safety"] = safety_meta("not_evaluated:not_executing", "not_evaluated");
        return EnforcementOutcome {
            mode: if cfg.defense_dry_run { "dry_run".to_string() } else { "policy_gated".to_string() },
            trace_id,
            selected_action: effective_decision.action.clone(),
            target: effective_decision.target.clone(),
            policy_reason: format!("{}:{}", effective_decision.policy_reason, policy_gate_reason),
            command_plan: plan.apply_commands.clone(),
            rollback_plan: plan.rollback_commands.clone(),
            executed_count: 0,
            failed_count: 0,
            errors: Vec::new(),
            rollback_hint: "set AZAZEL_DEFENSE_ENFORCE_LEVEL=full-auto or explicit high-impact approval policy".to_string(),
            result: "planned_not_applied".to_string(),
            metadata: redirect_meta,
        };
    }

    let decoy_state = |ok: bool| if effective_decision.action == "redirect" { if ok { "met" } else { "unmet" } } else { "not_applicable" };
    let event_epoch = match execution_safety_refusal(ev, &effective_decision.action, selected_decoy_port, cfg, &now) {
        Ok(at) => at,
        Err(reason) => {
            add_release_metadata(&mut redirect_meta, release_task.as_ref(), "planned_only");
            let decoy = if reason.starts_with("decoy") { "unmet" } else { "not_evaluated" };
            redirect_meta["safety"] = safety_meta(&format!("refused:{}", reason), decoy);
            return EnforcementOutcome {
                mode: "policy_gated".to_string(),
                trace_id,
                selected_action: effective_decision.action.clone(),
                target: effective_decision.target.clone(),
                policy_reason: format!("{}:safety_gate:{}", effective_decision.policy_reason, reason),
                command_plan: plan.apply_commands.clone(),
                rollback_plan: plan.rollback_commands.clone(),
                executed_count: 0,
                failed_count: 0,
                errors: Vec::new(),
                rollback_hint: format!("not applied: {}; operator notified", reason),
                result: "planned_not_applied".to_string(),
                metadata: redirect_meta,
            };
        }
    };

    let mut task = match release_task {
        Some(task) => task,
        None => {
            add_release_metadata(&mut redirect_meta, None, "ownership_unavailable");
            redirect_meta["safety"] = safety_meta("refused:ownership_unavailable", decoy_state(true));
            return EnforcementOutcome {
                mode: "release_guard_failed".to_string(),
                trace_id,
                selected_action: effective_decision.action.clone(),
                target: effective_decision.target.clone(),
                policy_reason: effective_decision.policy_reason.clone(),
                command_plan: plan.apply_commands,
                rollback_plan: plan.rollback_commands,
                executed_count: 0,
                failed_count: 0,
                errors: vec!["disruptive action has no releasable ownership contract".to_string()],
                rollback_hint: "disruptive action blocked before execution".to_string(),
                result: "planned_not_applied".to_string(),
                metadata: redirect_meta,
            };
        }
    };
    task.event_epoch = Some(event_epoch);

    let admitted = match admit_release_task(&cfg.defense_release_ledger_path, &task, cfg.defense_action_ttl_sec, &now) {
        Ok(Admission::Prepared(admitted)) => admitted,
        Ok(Admission::Extended { task_id, due_epoch, extensions }) => {
            add_release_metadata(&mut redirect_meta, Some(&task), "merged");
            redirect_meta["release_extended_task_id"] = json!(task_id);
            redirect_meta["release_due_epoch"] = json!(due_epoch);
            redirect_meta["release_extensions"] = json!(extensions);
            redirect_meta["safety"] = safety_meta("passed:extended", decoy_state(true));
            return EnforcementOutcome {
                mode: "enforced".to_string(),
                trace_id,
                selected_action: effective_decision.action.clone(),
                target: effective_decision.target.clone(),
                policy_reason: effective_decision.policy_reason.clone(),
                command_plan: Vec::new(),
                rollback_plan: plan.rollback_commands,
                executed_count: 0,
                failed_count: 0,
                errors: Vec::new(),
                rollback_hint: format!("held lease {} extended ({} of {}); release due at {:.0}", task_id, extensions, release::MAX_LEASE_EXTENSIONS, due_epoch),
                result: "extended".to_string(),
                metadata: redirect_meta,
            };
        }
        Ok(Admission::AlreadyHeld { task_id, due_epoch }) => {
            add_release_metadata(&mut redirect_meta, Some(&task), "merged");
            redirect_meta["release_extended_task_id"] = json!(task_id);
            redirect_meta["release_due_epoch"] = json!(due_epoch);
            redirect_meta["safety"] = safety_meta("passed:already_held", decoy_state(true));
            return EnforcementOutcome {
                mode: "enforced".to_string(),
                trace_id,
                selected_action: effective_decision.action.clone(),
                target: effective_decision.target.clone(),
                policy_reason: effective_decision.policy_reason.clone(),
                command_plan: Vec::new(),
                rollback_plan: plan.rollback_commands,
                executed_count: 0,
                failed_count: 0,
                errors: Vec::new(),
                rollback_hint: format!("held lease {} already lasts until {:.0}; unchanged", task_id, due_epoch),
                result: "already_held".to_string(),
                metadata: redirect_meta,
            };
        }
        Err(error) => {
            add_release_metadata(&mut redirect_meta, Some(&task), "prepare_failed");
            redirect_meta["safety"] = safety_meta(&format!("refused:admission:{}", error), decoy_state(true));
            return EnforcementOutcome {
                mode: "release_guard_failed".to_string(),
                trace_id,
                selected_action: effective_decision.action.clone(),
                target: effective_decision.target.clone(),
                policy_reason: effective_decision.policy_reason.clone(),
                command_plan: plan.apply_commands,
                rollback_plan: plan.rollback_commands,
                executed_count: 0,
                failed_count: 0,
                errors: vec![format!("release_schedule_prepare_failed:{}", error)],
                rollback_hint: "disruptive action blocked because durable release intent could not be admitted".to_string(),
                result: "planned_not_applied".to_string(),
                metadata: redirect_meta,
            };
        }
    };

    // Apply, each command time-bounded; stop at the first failure.
    let mut executed_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut errors: Vec<String> = Vec::new();
    for argv in &plan.apply_argv {
        match applier.apply(argv) {
            Ok(_) => executed_count += 1,
            Err(e) => {
                failed_count += 1;
                errors.push(e);
                break;
            }
        }
    }
    // Applied only when the owned state reads back exactly as planned.
    let confirmed = if failed_count == 0 && executed_count > 0 {
        match applier.readback(&admitted) {
            Ok(true) => true,
            Ok(false) => {
                failed_count += 1;
                errors.push("owned_state_readback_mismatch".to_string());
                false
            }
            Err(e) => {
                failed_count += 1;
                errors.push(format!("owned_state_readback_failed:{}", e));
                false
            }
        }
    } else {
        false
    };
    let ledger_state = if confirmed {
        match activate_release_task(&cfg.defense_release_ledger_path, &admitted.task_id, now_epoch()) {
            Ok(_) => "active",
            Err(error) => {
                errors.push(format!("release_schedule_activation_failed:{}", error));
                "prepared"
            }
        }
    } else {
        // Not confirmed: release at once (the sweep deletes whatever owned
        // state exists and verifies absence), never left to its TTL.
        match abandon_release_task(&cfg.defense_release_ledger_path, &admitted.task_id, "apply_unconfirmed", &LeaseNow::read(now_epoch())) {
            Ok(_) => "uncertain_release_scheduled",
            Err(error) => {
                errors.push(format!("release_schedule_abandon_failed:{}", error));
                "prepared"
            }
        }
    };
    add_release_metadata(&mut redirect_meta, Some(&admitted), ledger_state);
    redirect_meta["safety"] = safety_meta("passed", decoy_state(true));

    EnforcementOutcome {
        mode: "enforced".to_string(),
        trace_id,
        selected_action: effective_decision.action.clone(),
        target: effective_decision.target.clone(),
        policy_reason: effective_decision.policy_reason.clone(),
        command_plan: plan.apply_commands,
        rollback_plan: plan.rollback_commands,
        executed_count,
        failed_count,
        errors,
        rollback_hint: if confirmed {
            format!(
                "durable automatic release due at {:.0} (ttl {}s, Edge maximum {}s); release is verified by owned-state absence readback",
                admitted.due_epoch,
                cfg.defense_action_ttl_sec,
                release::MAX_LEASE_TTL_SEC
            )
        } else {
            "apply not confirmed; immediate release scheduled".to_string()
        },
        result: if confirmed {
            "applied".to_string()
        } else if executed_count > 0 {
            "partial_failure".to_string()
        } else {
            "failed".to_string()
        },
        metadata: redirect_meta,
    }
}

fn resolve_redirect_decision(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config) -> (DefensiveDecision, Value) {
    let mut metadata = json!({
        "original_dst_port": ev.target_port,
        "selected_decoy_port": Value::Null,
        "redirect_policy_source": cfg.redirect_policy_source,
        "redirect_mapping_matched": false,
        "unsupported_port_fallback": "",
        "fallback_reason": "",
    });
    if decision.action != "redirect" {
        return (decision.clone(), metadata);
    }

    match &cfg.redirect_policy {
        Some(policy) => {
            if !policy.enabled {
                metadata["unsupported_port_fallback"] = json!("notify");
                metadata["fallback_reason"] = json!("policy_disabled");
                let mut adjusted = decision.clone();
                adjusted.action = "notify".to_string();
                adjusted.policy_reason = format!("{}:policy_disabled", decision.policy_reason);
                adjusted.reason = format!("{}; redirect policy disabled, fallback=notify", decision.reason);
                return (adjusted, metadata);
            }
            if let Some(mapped) = policy.prepared_ports.get(&ev.target_port) {
                metadata["selected_decoy_port"] = json!(mapped);
                metadata["redirect_mapping_matched"] = json!(true);
                metadata["fallback_reason"] = json!("prepared_mapping");
                return (decision.clone(), metadata);
            }

            let high_risk = ev.risk_score >= 80 || ev.severity >= 4;
            // Never isolate, never redirect again: normalize_safe_action
            // turns either into notify, whatever the policy file names.
            let fallback = if high_risk {
                normalize_safe_action(&policy.high_risk_unsupported_port_action, "notify")
            } else {
                normalize_safe_action(&policy.unsupported_port_action, "notify")
            };
            metadata["unsupported_port_fallback"] = json!(fallback.clone());
            metadata["fallback_reason"] = json!(if high_risk {
                "unsupported_port_high_risk"
            } else {
                "unsupported_port_default"
            });
            let mut adjusted = decision.clone();
            adjusted.action = fallback.clone();
            adjusted.policy_reason = format!("{}:{}", decision.policy_reason, metadata["fallback_reason"].as_str().unwrap_or("unsupported_port"));
            adjusted.reason = format!("{}; unsupported port={} fallback={}", decision.reason, ev.target_port, fallback);
            return (adjusted, metadata);
        }
        None => {
            if cfg.redirect_policy_source.starts_with("env_honeypot_fallback") {
                metadata["selected_decoy_port"] = json!(cfg.defense_honeypot_port);
                metadata["redirect_mapping_matched"] = json!(true);
                metadata["fallback_reason"] = json!("no_redirect_policy_file_env_honeypot_fallback");
                return (decision.clone(), metadata);
            }
            metadata["unsupported_port_fallback"] = json!("notify");
            metadata["fallback_reason"] = json!("invalid_redirect_policy");
            let mut adjusted = decision.clone();
            adjusted.action = "notify".to_string();
            adjusted.policy_reason = format!("{}:invalid_redirect_policy", decision.policy_reason);
            adjusted.reason = format!("{}; redirect policy invalid, fallback=notify", decision.reason);
            (adjusted, metadata)
        }
    }
}

/// The decision loop and the release sweep thread both append to the
/// normalized log; each line is one write under this lock.
static LOG_LOCK: Mutex<()> = Mutex::new(());

fn append_json_line(path: &str, value: &Value) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let line = format!("{}\n", value);
    let _guard = LOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Events waiting for the forwarder. Bounded: a receiver that stops reading
/// costs at most this many queued lines, never the detection loop.
const AI_FORWARD_QUEUE: usize = 1024;
/// A connected receiver that stops reading costs the forwarder this long per
/// line, not forever.
const AI_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

static AI_FORWARDER: OnceLock<SyncSender<Forward>> = OnceLock::new();
static AI_FORWARD_DROPPED: AtomicU64 = AtomicU64::new(0);
/// Lines the forwarder took off the queue but could not deliver (no
/// listener, refused, or the write timed out). Counted apart from queue drops
/// so a receiver that is absent reads differently from one that is slow.
static AI_FORWARD_FAILED: AtomicU64 = AtomicU64::new(0);
/// Event lines written to the receiver. A completed write is not proof the
/// receiver kept the line; that is the receiver's own count.
static AI_FORWARD_SENT: AtomicU64 = AtomicU64::new(0);

/// The forward counts are reported to the same receiver as one closed-shape
/// line, because stderr (the only other report) is rate limited by the
/// journal under exactly the load that drops lines (#432).
const FORWARD_STATS_SCHEMA: &str = "azazel-edge/forward-stats/v1";
/// How often the loop considers a report; one is queued only when the counts
/// differ from the last delivered report.
const FORWARD_STATS_INTERVAL: Duration = Duration::from_secs(10);
/// Unchanged counts are still reported this often, so a receiver that
/// restarted learns them again and an old report can be told apart.
const FORWARD_STATS_HEARTBEAT: Duration = Duration::from_secs(300);
/// One report waits in the queue at a time; the forwarder clears this when it
/// takes it.
static FORWARD_STATS_QUEUED: AtomicBool = AtomicBool::new(false);
/// The counts carried by the last report the receiver took.
static FORWARD_STATS_DELIVERED: Mutex<Option<ForwardCounts>> = Mutex::new(None);
/// This process's start, in epoch seconds: counts are cumulative since then.
static PROCESS_START: OnceLock<u64> = OnceLock::new();

/// What the forwarding thread carries.
enum Forward {
    /// One event, already serialised with its newline.
    Line(String),
    /// Report the forward counts. They are read when the forwarder reaches
    /// this marker, so the report includes every line queued before it.
    Stats,
    /// Answered when the forwarder reaches it: every line queued before it
    /// has been delivered or counted as failed. Used once, at shutdown.
    Drained(SyncSender<()>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForwardCounts {
    dropped: u64,
    failed: u64,
    sent: u64,
}

fn forward_counts() -> ForwardCounts {
    ForwardCounts {
        dropped: AI_FORWARD_DROPPED.load(Ordering::Relaxed),
        failed: AI_FORWARD_FAILED.load(Ordering::Relaxed),
        sent: AI_FORWARD_SENT.load(Ordering::Relaxed),
    }
}

fn process_start() -> u64 {
    *PROCESS_START.get_or_init(|| now_epoch() as u64)
}

fn forward_stats_line(counts: ForwardCounts, since: u64) -> String {
    format!(
        "{}\n",
        json!({
            "schema": FORWARD_STATS_SCHEMA,
            "dropped": counts.dropped,
            "failed": counts.failed,
            "sent": counts.sent,
            "since": since,
        })
    )
}

fn delivered_counts() -> Option<ForwardCounts> {
    *FORWARD_STATS_DELIVERED.lock().unwrap_or_else(|e| e.into_inner())
}

/// A report is due when the receiver has not taken these counts yet, or took
/// them longer than a heartbeat ago (judged by when the last one was queued).
fn forward_report_due(
    current: ForwardCounts,
    delivered: Option<ForwardCounts>,
    since_queued: Option<Duration>,
) -> bool {
    delivered != Some(current) || since_queued.map_or(true, |d| d >= FORWARD_STATS_HEARTBEAT)
}

/// Paces the reports from the detection loop. Never waits: considering a
/// report is a few atomic loads, and queueing one is a `try_send`.
struct ForwardReporter {
    last_check: Option<Instant>,
    last_queued: Option<Instant>,
}

impl ForwardReporter {
    fn new() -> Self {
        ForwardReporter { last_check: None, last_queued: None }
    }

    /// `queue` queues one report and says whether it did.
    fn tick(&mut self, now: Instant, queue: impl FnOnce() -> bool) {
        if self.last_check.map_or(false, |c| now.duration_since(c) < FORWARD_STATS_INTERVAL) {
            return;
        }
        self.last_check = Some(now);
        let due = forward_report_due(
            forward_counts(),
            delivered_counts(),
            self.last_queued.map(|q| now.duration_since(q)),
        );
        if due && queue() {
            self.last_queued = Some(now);
        }
    }
}

/// Queue one report unless one is already waiting. A full queue costs this
/// report only, and is not counted: it is not an event, and the next report
/// carries the same cumulative counts.
fn queue_forward_stats(socket_path: &str) -> bool {
    if FORWARD_STATS_QUEUED.swap(true, Ordering::AcqRel) {
        return false;
    }
    match ai_forwarder(socket_path).try_send(Forward::Stats) {
        Ok(()) => true,
        Err(_) => {
            FORWARD_STATS_QUEUED.store(false, Ordering::Release);
            false
        }
    }
}

fn ai_forwarder(socket_path: &str) -> &'static SyncSender<Forward> {
    AI_FORWARDER.get_or_init(|| start_ai_forwarder(socket_path.to_string()))
}

/// Hand an event to the forwarder thread; never wait for the receiver.
///
/// The receiver (for example a Nexus intake) is another process. A blocking
/// `connect` to a listener that stopped accepting -- stopped, frozen, wedged --
/// would otherwise stall detection itself once its backlog filled. Here the
/// loop only enqueues: when the queue is full the event is dropped and
/// counted, and decisions, the JSONL record and stdout are unaffected.
fn send_to_ai_socket(socket_path: &str, value: &Value) {
    match ai_forwarder(socket_path).try_send(Forward::Line(format!("{}\n", value))) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            let dropped = AI_FORWARD_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped == 1 || dropped % 1000 == 0 {
                eprintln!("ai socket forward queue full; {} event(s) dropped so far", dropped);
            }
        }
    }
}

fn start_ai_forwarder(socket_path: String) -> SyncSender<Forward> {
    let (sender, receiver) = sync_channel::<Forward>(AI_FORWARD_QUEUE);
    thread::spawn(move || forward_ai_lines(&socket_path, receiver));
    sender
}

fn deliver(socket_path: &str, line: &str) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_write_timeout(Some(AI_WRITE_TIMEOUT))?;
    stream.write_all(line.as_bytes())
}

/// One connection per line, as before; only this thread ever waits on it.
fn forward_ai_lines(socket_path: &str, receiver: Receiver<Forward>) {
    for item in receiver {
        match item {
            Forward::Line(line) => {
                if deliver(socket_path, &line).is_ok() {
                    AI_FORWARD_SENT.fetch_add(1, Ordering::Relaxed);
                } else {
                    let failed = AI_FORWARD_FAILED.fetch_add(1, Ordering::Relaxed) + 1;
                    if failed == 1 || failed % 1000 == 0 {
                        eprintln!("ai socket forward failed; {} event(s) not delivered so far", failed);
                    }
                }
            }
            Forward::Drained(ack) => {
                let _ = ack.try_send(());
            }
            Forward::Stats => {
                FORWARD_STATS_QUEUED.store(false, Ordering::Release);
                let counts = forward_counts();
                // A report that does not arrive is not counted; the next one
                // is due because the delivered counts stay behind.
                if deliver(socket_path, &forward_stats_line(counts, process_start())).is_ok() {
                    *FORWARD_STATS_DELIVERED.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(counts);
                }
            }
        }
    }
}

/// The decision event the core writes to the normalized log and forwards to
/// the AI socket. The AI agent (py/azazel_edge_ai/agent.py) records P0
/// decisions from it for the P0 alert queue (Edge#414 SO-03), so its shape is
/// pinned by tests/fixtures/rust_core_event_v1.json on both sides.
fn core_event(normalized: &NormalizedEvent, decision: &DefensiveDecision, enforcement: &EnforcementOutcome, cfg: &Config) -> Value {
    json!({
        "normalized": normalized,
        "defense": decision,
        "enforcement": enforcement,
        "enforcement_status": enforcement_status(cfg),
        "source": "suricata_eve",
        "pipeline": "rust_event_engine_v1",
    })
}

/// Decide one EVE record the ingress reader admitted.
fn process_value(cfg: &Config, parsed: &Value) {
    let normalized = match build_normalized_event(parsed) {
        Some(ev) => ev,
        None => return,
    };

    let decision = decide_defense(&normalized);
    let enforcement = maybe_enforce(&normalized, &decision, cfg);
    let event = core_event(&normalized, &decision, &enforcement, cfg);
    if enforcement_evidence_due(&enforcement) {
        spool_enforcement_evidence(cfg, &event);
    }

    if cfg.forward_log {
        append_json_line(&cfg.normalized_log_path, &event);
    }
    if cfg.forward_ai {
        send_to_ai_socket(&cfg.ai_socket_path, &event);
    }

    print_event(cfg.event_stdout, &event);
}

fn process_release_events(cfg: &Config) {
    match process_due_releases(&cfg.defense_release_ledger_path, &LeaseNow::read(now_epoch())) {
        Ok(outcomes) => {
            for outcome in outcomes {
                let event = json!({
                    "release": outcome,
                    "enforcement_status": enforcement_status(cfg),
                    "source": "release_ledger",
                    "pipeline": "rust_release_engine_v1",
                });
                spool_enforcement_evidence(cfg, &event);
                if cfg.forward_log {
                    append_json_line(&cfg.normalized_log_path, &event);
                }
                // G1b release records have a different schema from normalized alert events.
                // Do not forward them to the AI socket until that receiver explicitly supports
                // this contract. Release evidence is available through the canonical JSONL.
                match cfg.event_stdout {
                    StdoutMode::Full => println!("{}", event),
                    // A release names its target; the summary keeps only that
                    // one happened and Edge's posture.
                    StdoutMode::Summary => println!("{}", json!({
                        "summary": true,
                        "source": "release_ledger",
                        "pipeline": "rust_release_engine_v1",
                        "enforcement_status": enforcement_status(cfg),
                    })),
                    StdoutMode::Off => {}
                }
            }
        }
        Err(error) => eprintln!("release ledger processing failed: {}", error),
    }
}

/// The Edge-owned enforcement evidence spool, beside the release ledger:
/// every decision that reached the execution path (applied, extended,
/// failed, refused by an execution-time safety rule or by admission) and
/// every release outcome, fsynced, size-capped with one rotation. It is
/// written whatever `AZAZEL_FORWARD_LOG` says and whether or not the intake
/// socket is up, so what the Edge did to the network can be reconstructed
/// after an intake outage. Dry-run and policy-gated "would" decisions are not
/// spooled: they changed nothing, and spooling every alert would put an
/// fsync per alert on the decision path.
fn enforcement_evidence_path(cfg: &Config) -> std::path::PathBuf {
    Path::new(&cfg.defense_release_ledger_path).with_file_name("enforcement-evidence.jsonl")
}

const ENFORCEMENT_EVIDENCE_CAP_BYTES: u64 = 8 * 1024 * 1024;
static EVIDENCE_SEQ: AtomicU64 = AtomicU64::new(0);

fn enforcement_evidence_due(outcome: &EnforcementOutcome) -> bool {
    matches!(outcome.mode.as_str(), "enforced" | "release_guard_failed")
        || outcome.policy_reason.contains(":safety_gate:")
}

fn spool_enforcement_evidence(cfg: &Config, event: &Value) {
    let mut record = event.clone();
    // A per-run sequence: a gap, or a first number above 1 after a rotation,
    // shows what the cap dropped.
    record["evidence_spool"] = json!({
        "seq": EVIDENCE_SEQ.fetch_add(1, Ordering::Relaxed) + 1,
        "since": process_start(),
        "cap_bytes": ENFORCEMENT_EVIDENCE_CAP_BYTES,
    });
    let path = enforcement_evidence_path(cfg);
    if let Err(error) = append_audit_record(&path, &record, ENFORCEMENT_EVIDENCE_CAP_BYTES) {
        eprintln!("enforcement evidence spool write failed ({}): {}", path.display(), error);
    }
}

/// Where the ingress audit summaries go: next to the normalized event log,
/// in their own file, so readers of that log never meet a record of another
/// shape. No setting of its own: it follows `AZAZEL_NORMALIZED_EVENT_LOG`.
fn ingress_audit_log_path(cfg: &Config) -> String {
    match Path::new(&cfg.normalized_log_path).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("ingress-audit.jsonl").to_string_lossy().into_owned(),
        _ => "ingress-audit.jsonl".to_string(),
    }
}

/// An ingress summary is written whatever the log and stdout settings are:
/// shedding is never silent. It carries counts and bounds only, no address.
/// The file copy is the audit record (0600, no symlink, fsync, size-capped);
/// the console copy goes to stdout, or to stderr under
/// `AZAZEL_EVENT_STDOUT=off` because that setting silences per-event output,
/// not audit. If the file cannot be written the failure and the record both
/// go to stderr. With the AI forward on, the `ingress_shed` part is also
/// queued for the AI socket (see [`ingress_forward_line`]).
fn emit_ingress_record(cfg: &Config, record: &Value) {
    write_ingress_record(cfg, record);
    if cfg.forward_ai {
        if let Some(line) = ingress_forward_line(record) {
            queue_ai_line(&cfg.ai_socket_path, line);
        }
    }
}

/// What the AI socket receives of an ingress summary (Edge#414 SO-11): the
/// `ingress_shed` object as written to the audit file, on one line. Its
/// `schema` (`azazel-edge/ingress-shed/v1`) lets the agent keep it as a
/// read-only metric beside the forward counts; it holds counts, the interval
/// end and the compiled quota, no address or other identifier. An
/// `ingress_alert_backlog` summary is not forwarded.
fn ingress_forward_line(record: &Value) -> Option<String> {
    match record.get("ingress_shed") {
        Some(inner) if inner.is_object() => Some(format!("{}\n", inner)),
        _ => None,
    }
}

/// The longest the main loop sleeps between looks at the stop flag. The
/// poll interval (`AZAZEL_EVE_POLL_MS`, unbounded) is kept as it is; it is
/// only slept in slices, so a stop waits at most about one slice for the
/// sleep, however long the interval.
const STOP_CHECK_SLICE: Duration = Duration::from_millis(50);

/// Sleep `total` in slices of at most `slice`, returning early once
/// `stopped` says so. Returns whether it stopped early. A signal does not
/// interrupt `thread::sleep`, so this is how a stop is noticed in time.
fn sleep_unless_stopped(total: Duration, slice: Duration, stopped: &dyn Fn() -> bool) -> bool {
    let end = Instant::now() + total;
    loop {
        if stopped() {
            return true;
        }
        let now = Instant::now();
        if now >= end {
            return false;
        }
        thread::sleep((end - now).min(slice));
    }
}

/// How long shutdown waits for the forwarder to hand over the last summary.
/// A receiver that is absent or wedged costs the stop this long, not more.
const SHUTDOWN_FORWARD_WAIT: Duration = Duration::from_secs(2);

/// Queue one already-serialised line for the AI socket; a full queue drops
/// and counts it, as for events.
fn queue_ai_line(socket_path: &str, line: String) {
    match ai_forwarder(socket_path).try_send(Forward::Line(line)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            AI_FORWARD_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Wait, at most `wait`, until the forwarder has taken every line queued so
/// far. Says whether it did.
///
/// A full queue (the receiver is slow or absent and 1024 lines wait) is
/// refused at once and returns false without waiting: the stop is not held
/// up. The shutdown summary is then not delivered to the AI socket -- if it
/// could not be queued it was counted in `AI_FORWARD_DROPPED`, otherwise it
/// may still be in the queue when the process exits -- but it is always in
/// `ingress-audit.jsonl` and on the console, which are written first.
fn drain_ai_forward(sender: &SyncSender<Forward>, wait: Duration) -> bool {
    let (ack, done) = sync_channel::<()>(1);
    if sender.try_send(Forward::Drained(ack)).is_err() {
        return false;
    }
    done.recv_timeout(wait).is_ok()
}

/// The process is stopping (SIGTERM from systemd, or SIGINT): write the
/// ingress summaries of the last interval, which is shorter than the audit
/// interval and would otherwise be lost (Edge#414 SO-11). They go to the same
/// audit file and console as every other summary, once: the reader refuses a
/// second flush. `forward` receives each one for the AI socket. Returns how
/// many were written. Nothing here reads, sheds or decides.
fn shutdown_ingress(cfg: &Config, ingress: &mut IngressReader, forward: &mut dyn FnMut(&Value)) -> usize {
    let records = ingress.shutdown_records(Instant::now(), now_epoch());
    for record in &records {
        write_ingress_record(cfg, record);
        forward(record);
    }
    records.len()
}

fn write_ingress_record(cfg: &Config, record: &Value) {
    let path = ingress_audit_log_path(cfg);
    if let Err(error) = append_audit_record(Path::new(&path), record, IngressLimits::DECLARED.audit_log_cap_bytes) {
        eprintln!("ingress audit write failed ({}): {}: {}", path, error, record);
    }
    match cfg.event_stdout {
        StdoutMode::Full | StdoutMode::Summary => println!("{}", record),
        StdoutMode::Off => eprintln!("{}", record),
    }
}

/// One iteration of the main loop: one bounded read of the EVE file and its
/// audit summaries. The release sweep is not here: it runs on its own
/// thread (`spawn_release_sweeper`), so neither an alert backlog nor an
/// apply command waiting on its time bound holds a release back.
fn poll_iteration(cfg: &Config, ingress: &mut IngressReader) -> PollReport {
    let report = ingress.poll(Path::new(&cfg.eve_path), Instant::now(), |v| process_value(cfg, v));
    for record in ingress.audit_records(Instant::now(), now_epoch()) {
        emit_ingress_record(cfg, &record);
    }
    report
}

/// The longest the release sweeper waits between sweeps.
const SWEEP_INTERVAL_MAX: Duration = Duration::from_millis(1000);
/// How often the sweeper reports a ledger that is not `ok`.
const CAPACITY_NOTICE_INTERVAL: Duration = Duration::from_secs(600);

/// The release sweep on its own thread: due leases are released every
/// interval whatever the decision loop is doing (an apply waiting for its
/// time bound, a flood of alerts). It runs whether enforcement is on or
/// not, so a restart or a configuration change never strands old state.
fn spawn_release_sweeper(cfg: Config, stopped: fn() -> bool) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let interval = Duration::from_millis(cfg.poll_ms.max(50)).min(SWEEP_INTERVAL_MAX);
        let mut last_state = String::from("ok");
        let mut last_notice: Option<Instant> = None;
        while !stopped() {
            process_release_events(&cfg);
            capacity_notice(&cfg, &mut last_state, &mut last_notice);
            sleep_unless_stopped(interval, STOP_CHECK_SLICE, &stopped);
        }
    })
}

/// The capacity notice: when the release ledger leaves `ok` (or stays out of
/// it), a record goes to the normalized log and stderr before new
/// restrictions are refused, naming the maintenance entry.
fn capacity_notice(cfg: &Config, last_state: &mut String, last_notice: &mut Option<Instant>) {
    let Ok(capacity) = release::ledger_capacity(&cfg.defense_release_ledger_path) else {
        return;
    };
    let state = capacity["state"].as_str().unwrap_or("ok").to_string();
    let due = state != "ok" && (state != *last_state || last_notice.map_or(true, |at| at.elapsed() >= CAPACITY_NOTICE_INTERVAL));
    if due {
        let event = json!({
            "release_ledger_capacity": capacity,
            "maintenance": "azazel-edge-core --release-ledger-compact (generation migration; keeps the replay watermark and every held lease)",
            "source": "release_ledger",
            "pipeline": "rust_release_engine_v1",
        });
        if cfg.forward_log {
            append_json_line(&cfg.normalized_log_path, &event);
        }
        eprintln!("release ledger capacity {}: {}", state, event);
        *last_notice = Some(Instant::now());
    }
    *last_state = state;
}


// -- the health and version contract Nexus consumes (Edge#424) -------------
//
// `docs/nexus-core-package.md` is the contract. Two rules shape the code
// below and both are about *not* being mistaken for healthy.
//
// **A one-shot check establishes the binary, never the daemon.** `--health`
// proves this executable is present, is this version, and can evaluate its
// own posture. It does not prove anything is running. Nexus determines that
// separately, which is why accepting a package never on its own produces
// `edge-baseline-ready`.
//
// **Anything unevaluated is unhealthy.** A check that cannot be run reports
// `ok: false` with the reason. There is no path that omits a check and still
// reports `healthy`, because a reader counting green checks would not notice
// one missing.
//
// The exit status and the `status` field agree, and Nexus is required to
// insist on both plus the contract string: a truncated or garbled stdout then
// cannot read as healthy.

const HEALTH_CONTRACT: &str = "azazel-edge-core/health/v1";
const CORE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct HealthCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// Evaluate the posture. Observe-only is the only posture this package ships.
fn health_checks(cfg: &Config) -> Vec<HealthCheck> {
    let mut checks = Vec::new();

    checks.push(HealthCheck {
        name: "enforcement_disabled",
        ok: !cfg.defense_enforce,
        detail: format!("AZAZEL_DEFENSE_ENFORCE={}", cfg.defense_enforce),
    });
    checks.push(HealthCheck {
        name: "dry_run",
        ok: cfg.defense_dry_run,
        detail: format!("AZAZEL_DEFENSE_DRY_RUN={}", cfg.defense_dry_run),
    });
    checks.push(HealthCheck {
        name: "advisory_level",
        ok: cfg.defense_enforce_level == "advisory",
        detail: format!("AZAZEL_DEFENSE_ENFORCE_LEVEL={}", cfg.defense_enforce_level),
    });
    checks.push(HealthCheck {
        name: "high_impact_auto_disabled",
        ok: !cfg.defense_allow_high_impact_auto,
        detail: format!(
            "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO={}",
            cfg.defense_allow_high_impact_auto
        ),
    });
    checks.push(HealthCheck {
        name: "redirect_policy_not_enforcing",
        ok: !cfg.defense_enforce,
        detail: format!("redirect_policy_source={}", cfg.redirect_policy_source),
    });

    checks
}

fn observe_only(checks: &[HealthCheck]) -> bool {
    checks.iter().all(|c| c.ok)
}

fn health_report(cfg: &Config) -> Value {
    let checks = health_checks(cfg);
    let healthy = observe_only(&checks);
    json!({
        "contract": HEALTH_CONTRACT,
        "status": if healthy { "healthy" } else { "unhealthy" },
        "version": CORE_VERSION,
        "observe_only": healthy,
        "checks": checks
            .iter()
            .map(|c| json!({"name": c.name, "ok": c.ok, "detail": c.detail}))
            .collect::<Vec<Value>>(),
    })
}

fn main() {
    let cfg = load_config();

    // The contract subcommands return before anything else happens. They read
    // no file, write no file, open no socket and start no loop -- a health
    // check that changed the node would be a health check nobody could run.
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("{}", CORE_VERSION);
        return;
    }
    if args.iter().any(|a| a == "--health") {
        let report = health_report(&cfg);
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
        if report["status"] != "healthy" {
            std::process::exit(1);
        }
        return;
    }
    // Maintenance of the release ledger: report its capacity, or run one
    // generation migration under the admission rules. Neither applies,
    // releases or forgets a held lease, and both keep the replay checkpoint.
    if args.iter().any(|a| a == "--release-ledger-status") {
        match release::ledger_capacity(&cfg.defense_release_ledger_path) {
            Ok(value) => println!("{}", value),
            Err(error) => {
                eprintln!("release ledger status failed: {}", error);
                std::process::exit(1);
            }
        }
        return;
    }
    if args.iter().any(|a| a == "--release-ledger-compact") {
        match release::compact_release_ledger(&cfg.defense_release_ledger_path, now_epoch()) {
            Ok(value) => println!("{}", value),
            Err(error) => {
                eprintln!("release ledger compaction failed: {}", error);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(parent) = Path::new(&cfg.normalized_log_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let offset = if cfg.from_start { 0 } else { fs::metadata(&cfg.eve_path).map(|m| m.len()).unwrap_or(0) };

    eprintln!(
        "azazel-edge-core started: eve_path={}, ai_socket={}, from_start={}, poll_ms={}, defense_enforce={}, defense_dry_run={}, defense_enforce_level={}, high_impact_auto={}, defense_iface={}, honeypot_port={}, release_ledger={}, ingress_non_alert_per_sec={}, ingress_alerts_per_poll={}",
        cfg.eve_path,
        cfg.ai_socket_path,
        cfg.from_start,
        cfg.poll_ms,
        cfg.defense_enforce,
        cfg.defense_dry_run,
        cfg.defense_enforce_level,
        cfg.defense_allow_high_impact_auto,
        cfg.defense_iface,
        cfg.defense_honeypot_port,
        cfg.defense_release_ledger_path,
        IngressLimits::DECLARED.non_alert_per_sec,
        IngressLimits::DECLARED.alerts_per_poll
    );

    eprintln!(
        "azazel-edge-core safety: protected_flows={} ({}), lease_ttl_sec={} ({}, Edge max {}), max_extensions={}, max_cumulative_sec={}, max_held_leases={}, isolate_automatic=false",
        cfg.protected.status(),
        cfg.protected_flows_path,
        cfg.defense_action_ttl_sec,
        cfg.defense_ttl_source,
        release::MAX_LEASE_TTL_SEC,
        release::MAX_LEASE_EXTENSIONS,
        release::MAX_CUMULATIVE_LEASE_SEC,
        release::MAX_ACTIVE_LEASES,
    );

    // A restart grants nothing: a lease still `prepared` was being applied
    // when the previous process stopped and was never confirmed, so it is
    // released now, before any alert is read. Then due release work is
    // reconciled; both run even when enforcement is disabled, so a restart
    // or a configuration change cannot strand old temporary state.
    match release::recover_unconfirmed_on_start(&cfg.defense_release_ledger_path, &LeaseNow::read(now_epoch())) {
        Ok(0) => {}
        Ok(n) => eprintln!("release ledger: {} unconfirmed lease(s) from the previous run scheduled for immediate release", n),
        Err(error) => eprintln!("release ledger recovery failed: {}", error),
    }
    process_release_events(&cfg);
    process_start();
    let mut reporter = ForwardReporter::new();
    let mut ingress = IngressReader::new(offset, IngressLimits::DECLARED);
    stop_signal::install();
    let sweeper = spawn_release_sweeper(cfg.clone(), stop_signal::requested);
    while !stop_signal::requested() {
        let report = poll_iteration(&cfg, &mut ingress);
        if cfg.forward_ai {
            reporter.tick(Instant::now(), || queue_forward_stats(&cfg.ai_socket_path));
        }
        // A poll that stopped on a per-poll budget left work in the file: the
        // next one follows at once, so alerts are read at the Core's capacity
        // and still with a release sweep between every bounded poll.
        if !report.budget_exhausted() {
            sleep_unless_stopped(Duration::from_millis(cfg.poll_ms), STOP_CHECK_SLICE, &stop_signal::requested);
        }
    }
    let written = shutdown_ingress(&cfg, &mut ingress, &mut |record| {
        if cfg.forward_ai {
            if let Some(line) = ingress_forward_line(record) {
                queue_ai_line(&cfg.ai_socket_path, line);
            }
        }
    });
    if cfg.forward_ai && written > 0 && !drain_ai_forward(ai_forwarder(&cfg.ai_socket_path), SHUTDOWN_FORWARD_WAIT) {
        eprintln!("ingress summary at shutdown: the AI socket forward did not finish within {:?}", SHUTDOWN_FORWARD_WAIT);
    }
    let _ = sweeper.join();
    eprintln!("azazel-edge-core stopping: {} ingress summary record(s) written for the last interval", written);
}

/// SIGTERM (systemd's stop) and SIGINT end the main loop after the current
/// iteration, so the last interval's ingress summaries are written
/// (Edge#414 SO-11). The handler only sets a flag. There is no other way to
/// stop or skip anything: the flag is set by these signals alone.
mod stop_signal {
    use std::os::raw::c_int;
    use std::sync::atomic::{AtomicBool, Ordering};

    static STOP: AtomicBool = AtomicBool::new(false);

    // The same on every Linux architecture this crate builds for and on macOS.
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;

    extern "C" {
        fn signal(signum: c_int, handler: extern "C" fn(c_int)) -> usize;
    }

    extern "C" fn on_stop(_signum: c_int) {
        // An atomic store is async-signal-safe.
        STOP.store(true, Ordering::SeqCst);
    }

    pub fn install() {
        unsafe {
            signal(SIGTERM, on_stop);
            signal(SIGINT, on_stop);
        }
    }

    pub fn requested() -> bool {
        STOP.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Edge#477: the apply path no longer looks argv[0] up on the inherited
    // PATH; only nft and tc from the trusted directories are started.
    #[test]
    fn run_command_refuses_a_binary_outside_the_trusted_set_without_running_it() {
        let marker = std::env::temp_dir().join(format!("azazel-apply-ran-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        for argv in [
            vec!["touch".to_string(), marker.display().to_string()],
            vec!["/usr/bin/touch".to_string(), marker.display().to_string()],
            vec!["./nft".to_string(), "list".to_string(), "ruleset".to_string()],
        ] {
            let err = run_command(&argv).expect_err("must be refused");
            assert!(err.starts_with("command exec error: "), "{err}");
        }
        assert!(!marker.exists());
        assert_eq!(run_command(&[]), Err("empty command".to_string()));
    }

    #[test]
    fn every_planned_apply_command_names_a_trusted_binary() {
        let ev = sample_event();
        for action in ["throttle", "redirect"] {
            let decision = DefensiveDecision {
                action: action.to_string(),
                reason: "test".to_string(),
                policy_reason: "test".to_string(),
                delay_ms: 100,
                target: ev.src_ip.clone(),
            };
            let plan = build_enforcement_plan(&ev, &decision, "eth0", 2222);
            assert!(!plan.apply_argv.is_empty(), "{action}");
            for argv in &plan.apply_argv {
                assert!(matches!(argv[0].as_str(), "nft" | "tc"), "{argv:?}");
            }
        }
        // isolate has no apply plan at all: no automatic path can execute it.
        let isolate = DefensiveDecision { action: "isolate".to_string(), reason: "t".to_string(), policy_reason: "t".to_string(), delay_ms: 0, target: ev.src_ip.clone() };
        assert!(build_enforcement_plan(&ev, &isolate, "eth0", 2222).apply_argv.is_empty());
    }

    fn sample_event() -> NormalizedEvent {
        NormalizedEvent {
            ts: "2026-01-01T00:00:00Z".to_string(),
            src_ip: "10.0.0.8".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            attack_type: "test".to_string(),
            severity: 1,
            target_port: 443,
            protocol: "TCP".to_string(),
            sid: 9999,
            category: "test".to_string(),
            event_type: "alert".to_string(),
            action: "allowed".to_string(),
            confidence: 90,
            risk_score: 90,
            ingest_epoch: 0.0,
            technique_ids: Vec::new(),
        }
    }

    #[test]
    fn a_wedged_receiver_never_blocks_the_caller() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;
        let dir = std::env::temp_dir().join(format!("az-edge-fwd-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("wedged.sock");
        let _ = fs::remove_file(&path);
        // A listener that never accepts: its backlog fills and connect blocks.
        let _listener = UnixListener::bind(&path).expect("bind");
        let socket = path.to_string_lossy().to_string();
        let started = Instant::now();
        for n in 0..(AI_FORWARD_QUEUE + 4096) {
            send_to_ai_socket(&socket, &json!({"n": n}));
        }
        assert!(started.elapsed() < Duration::from_secs(5), "the caller waited on the receiver");
        assert!(AI_FORWARD_DROPPED.load(Ordering::Relaxed) > 0, "nothing was dropped and counted");
        let _ = fs::remove_file(&path);
    }

    /// The decision path never waits on the receiver of its events (the AI
    /// agent, where the P0 alert path is attached): with a receiver that
    /// never reads, every decision is still taken and logged at once.
    #[test]
    fn decisions_are_taken_and_logged_while_the_receiver_is_wedged() {
        use std::os::unix::net::UnixListener;
        use std::time::Instant;
        let dir = std::env::temp_dir().join(format!("az-edge-decide-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("wedged.sock");
        let log = dir.join("normalized-events.jsonl");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&log);
        let _listener = UnixListener::bind(&path).expect("bind");
        let mut cfg = sample_cfg();
        cfg.forward_ai = true;
        cfg.forward_log = true;
        cfg.event_stdout = StdoutMode::Off;
        cfg.ai_socket_path = path.to_string_lossy().to_string();
        cfg.normalized_log_path = log.to_string_lossy().to_string();
        // More than the queue plus the listener's backlog (the kernel caps it
        // at net.core.somaxconn, 4096 by default): the receiver is wedged.
        let n = AI_FORWARD_QUEUE + 8192;
        let started = Instant::now();
        for i in 0..n {
            process_value(&cfg, &json!({
                "event_type": "alert",
                "timestamp": format!("2026-01-01T00:00:00.{:06}+0000", i),
                "src_ip": "192.0.2.7",
                "dest_ip": "192.0.2.1",
                "dest_port": 22,
                "proto": "TCP",
                "alert": {"signature_id": 9_300_000 + i as u64, "signature": "wedged", "category": "test", "severity": 1 + (i % 3) as u64},
            }));
        }
        assert!(started.elapsed() < Duration::from_secs(10), "deciding waited on the receiver");
        let text = fs::read_to_string(&log).expect("normalized log");
        let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).expect("json")).collect();
        assert_eq!(lines.len(), n);
        assert!(lines.iter().all(|v| v["enforcement"]["mode"] == "dry_run"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&log);
    }

    fn shape(value: &Value) -> Value {
        match value {
            Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (k.clone(), shape(v))).collect()),
            Value::Array(_) => json!("array"),
            Value::String(_) => json!("string"),
            Value::Number(_) => json!("number"),
            Value::Bool(_) => json!("bool"),
            Value::Null => json!("null"),
        }
    }

    /// The event the AI agent records P0 decisions from has the shape the
    /// Python side is tested against (tests/fixtures/rust_core_event_v1.json).
    #[test]
    fn the_core_event_has_the_shape_the_agent_is_tested_against() {
        let fixture: Value = serde_json::from_str(include_str!("../../../tests/fixtures/rust_core_event_v1.json")).expect("fixture");
        let mut cfg = sample_cfg();
        cfg.redirect_policy = load_redirect_policy(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/redirect_policy.yaml")).expect("policy");
        cfg.redirect_policy_source = "file:config/redirect_policy.yaml".to_string();
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 22;
        ev.technique_ids = vec!["T1046".to_string()];
        let decision = decide_defense(&ev);
        let enforcement = maybe_enforce(&ev, &decision, &cfg);
        let event = core_event(&ev, &decision, &enforcement, &cfg);
        assert_eq!(shape(&event), shape(&fixture));
        assert_eq!(event["source"], fixture["source"]);
        assert_eq!(event["pipeline"], fixture["pipeline"]);
        assert_eq!(event["defense"]["action"], fixture["defense"]["action"]);
        assert_eq!(event["enforcement"]["mode"], fixture["enforcement"]["mode"]);
    }

    #[test]
    fn undeliverable_lines_are_counted_not_silently_dropped() {
        let path = std::env::temp_dir()
            .join(format!("az-edge-absent-{}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        let before = AI_FORWARD_FAILED.load(Ordering::Relaxed);
        let (sender, receiver) = sync_channel::<Forward>(4);
        for n in 0..3 {
            sender.send(Forward::Line(format!("{{\"n\":{}}}\n", n))).expect("queue");
        }
        drop(sender);
        forward_ai_lines(&path.to_string_lossy(), receiver);
        assert!(AI_FORWARD_FAILED.load(Ordering::Relaxed) >= before + 3);
    }

    /// Tests that read or set the forward-report state hold this.
    static FORWARD_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn forward_test_lock() -> std::sync::MutexGuard<'static, ()> {
        FORWARD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn forward_stats_line_is_one_closed_shape_line() {
        let counts = ForwardCounts { dropped: 460, failed: 7, sent: u64::MAX };
        let line = forward_stats_line(counts, 1_790_000_000);
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        let value: Value = serde_json::from_str(line.trim_end()).expect("json");
        let object = value.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["dropped", "failed", "schema", "sent", "since"]);
        assert_eq!(value["schema"], "azazel-edge/forward-stats/v1");
        assert_eq!(value["dropped"], 460);
        assert_eq!(value["failed"], 7);
        assert_eq!(value["sent"], u64::MAX);
        assert_eq!(value["since"], 1_790_000_000u64);
        // Nothing an event carries: no address, decision or plan.
        assert!(!line.contains("normalized") && !line.contains("defense"));
    }

    #[test]
    fn a_report_is_due_until_the_receiver_took_the_current_counts() {
        let now = ForwardCounts { dropped: 1, failed: 2, sent: 3 };
        let recent = Some(Duration::from_secs(10));
        // Nothing delivered yet: report, including all-zero counts at start.
        assert!(forward_report_due(ForwardCounts { dropped: 0, failed: 0, sent: 0 }, None, None));
        assert!(forward_report_due(now, None, recent));
        // Delivered and unchanged: quiet until the heartbeat.
        assert!(!forward_report_due(now, Some(now), recent));
        assert!(!forward_report_due(now, Some(now), Some(FORWARD_STATS_HEARTBEAT - Duration::from_secs(1))));
        assert!(forward_report_due(now, Some(now), Some(FORWARD_STATS_HEARTBEAT)));
        // Any count moved since the last delivered report: report.
        for moved in [
            ForwardCounts { dropped: 2, ..now },
            ForwardCounts { failed: 3, ..now },
            ForwardCounts { sent: 4, ..now },
        ] {
            assert!(forward_report_due(moved, Some(now), recent));
        }
    }

    #[test]
    fn reports_are_considered_at_most_once_per_interval() {
        let _guard = forward_test_lock();
        *FORWARD_STATS_DELIVERED.lock().unwrap() = None;
        let start = Instant::now();
        let mut reporter = ForwardReporter::new();
        let mut queued = 0;
        reporter.tick(start, || { queued += 1; true });
        reporter.tick(start + Duration::from_secs(1), || { queued += 1; true });
        reporter.tick(start + FORWARD_STATS_INTERVAL - Duration::from_millis(1), || { queued += 1; true });
        assert_eq!(queued, 1);
        // Still not delivered: the next interval tries again.
        reporter.tick(start + FORWARD_STATS_INTERVAL, || { queued += 1; true });
        assert_eq!(queued, 2);
        // A report the queue refused is retried on the next interval too.
        reporter.tick(start + FORWARD_STATS_INTERVAL * 2, || { queued += 1; false });
        assert_eq!(queued, 3);
        assert_eq!(reporter.last_queued, Some(start + FORWARD_STATS_INTERVAL));
    }

    #[test]
    fn only_one_report_waits_in_the_queue() {
        let _guard = forward_test_lock();
        FORWARD_STATS_QUEUED.store(true, Ordering::Release);
        // Returns before touching the forwarder: nothing more is queued.
        assert!(!queue_forward_stats("/nonexistent/never-used.sock"));
        assert!(FORWARD_STATS_QUEUED.load(Ordering::Acquire));
        FORWARD_STATS_QUEUED.store(false, Ordering::Release);
    }

    #[test]
    fn the_report_follows_the_lines_queued_before_it_on_the_same_socket() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        let _guard = forward_test_lock();
        let dir = std::env::temp_dir().join(format!("az-edge-stats-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("intake.sock");
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let reader = thread::spawn(move || {
            let mut lines = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut line = String::new();
                stream.read_to_string(&mut line).expect("read");
                lines.push(line);
            }
            lines
        });
        let before = forward_counts();
        *FORWARD_STATS_DELIVERED.lock().unwrap() = None;
        FORWARD_STATS_QUEUED.store(true, Ordering::Release);
        let (sender, receiver) = sync_channel::<Forward>(4);
        sender.send(Forward::Line("{\"n\":1}\n".to_string())).expect("queue");
        sender.send(Forward::Line("{\"n\":2}\n".to_string())).expect("queue");
        sender.send(Forward::Stats).expect("queue");
        drop(sender);
        forward_ai_lines(&path.to_string_lossy(), receiver);
        let lines = reader.join().expect("reader");
        assert_eq!(&lines[..2], ["{\"n\":1}\n", "{\"n\":2}\n"]);
        let report: Value = serde_json::from_str(lines[2].trim_end()).expect("report");
        assert_eq!(report["schema"], FORWARD_STATS_SCHEMA);
        // Read when the marker was reached: both lines before it are in it.
        assert!(report["sent"].as_u64().unwrap() >= before.sent + 2);
        assert_eq!(report["since"].as_u64().unwrap(), process_start());
        let delivered = delivered_counts().expect("delivered");
        assert_eq!(delivered.sent, report["sent"].as_u64().unwrap());
        assert!(!FORWARD_STATS_QUEUED.load(Ordering::Acquire), "marker not cleared");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn an_undelivered_report_leaves_the_next_one_due() {
        let _guard = forward_test_lock();
        let path = std::env::temp_dir()
            .join(format!("az-edge-stats-absent-{}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        *FORWARD_STATS_DELIVERED.lock().unwrap() = None;
        let (sender, receiver) = sync_channel::<Forward>(1);
        sender.send(Forward::Stats).expect("queue");
        drop(sender);
        forward_ai_lines(&path.to_string_lossy(), receiver);
        assert_eq!(delivered_counts(), None);
        assert!(forward_report_due(forward_counts(), delivered_counts(), Some(Duration::ZERO)));
    }

    #[test]
    fn stdout_mode_defaults_to_full_and_rejects_unknown_values() {
        assert_eq!(stdout_mode(None), StdoutMode::Full);
        assert_eq!(stdout_mode(Some("".into())), StdoutMode::Full);
        assert_eq!(stdout_mode(Some("summary".into())), StdoutMode::Summary);
        assert_eq!(stdout_mode(Some(" off ".into())), StdoutMode::Off);
        assert_eq!(stdout_mode(Some("SUMMARY".into())), StdoutMode::Full);
    }

    #[test]
    fn summary_line_keeps_the_decision_and_drops_addresses_and_plans() {
        let eve = json!({
            "event_type": "alert", "src_ip": "203.0.113.7", "dest_ip": "192.0.2.10",
            "dest_port": 22, "proto": "TCP",
            "alert": {"signature_id": 2001219, "severity": 1,
                      "metadata": {"mitre_technique_id": ["T1110"]}}
        });
        let ev = build_normalized_event(&eve).expect("alert normalises");
        let decision = decide_defense(&ev);
        let cfg = sample_cfg();
        let enforcement = maybe_enforce(&ev, &decision, &cfg);
        let event = json!({
            "normalized": ev, "defense": decision, "enforcement": enforcement,
            "enforcement_status": enforcement_status(&cfg),
            "source": "suricata_eve", "pipeline": "rust_event_engine_v1",
        });
        let line = summary_line(&event).to_string();
        for leaked in ["203.0.113.7", "192.0.2.10", "command_plan", "target", "nft"] {
            assert!(!line.contains(leaked), "summary leaked {leaked}: {line}");
        }
        let summary = summary_line(&event);
        assert_eq!(summary["defense"]["action"], event["defense"]["action"]);
        assert_eq!(summary["enforcement_status"], event["enforcement_status"]);
        assert_eq!(summary["technique_ids"], json!(["T1110"]));
        assert_eq!(summary["severity"], json!(1));
    }

    #[test]
    fn technique_ids_come_only_from_rule_metadata() {
        let eve = json!({
            "event_type": "alert",
            "alert": {
                "signature_id": 2001219,
                "severity": 2,
                "metadata": {"mitre_technique_id": [
                    "T1110", "T1110.001", "T1110", "t1110", "T11100", "T1110.1",
                    "T1046", "T1021", "T1078", "T1059", "T1071", "T1190", "T1133"
                ]}
            }
        });
        let ev = build_normalized_event(&eve).expect("alert normalises");
        assert_eq!(
            ev.technique_ids,
            vec!["T1110", "T1110.001", "T1046", "T1021", "T1078", "T1059", "T1071", "T1190"]
        );
    }

    #[test]
    fn technique_ids_are_empty_without_metadata_and_do_not_change_decisions() {
        let eve = json!({"event_type": "alert", "alert": {"signature_id": 1, "severity": 2}});
        let ev = build_normalized_event(&eve).expect("alert normalises");
        assert!(ev.technique_ids.is_empty());
        let tagged_eve = json!({"event_type": "alert", "alert": {
            "signature_id": 1, "severity": 2,
            "metadata": {"mitre_technique_id": ["T1110"]}}});
        let tagged = build_normalized_event(&tagged_eve).expect("alert normalises");
        assert_eq!(tagged.technique_ids, vec!["T1110"]);
        assert_eq!(decide_defense(&ev).action, decide_defense(&tagged).action);
        assert_eq!(decide_defense(&ev).policy_reason, decide_defense(&tagged).policy_reason);
    }

    #[test]
    fn an_ingress_backlog_is_read_in_bounded_polls() {
        let dir = std::env::temp_dir().join(format!("azazel-bounded-polls-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let eve = dir.join("eve.json");
        let limits = IngressLimits::DECLARED;
        let total = limits.alerts_per_poll * 5;
        let mut body = String::new();
        for n in 0..total {
            body.push_str(&format!(
                "{{\"event_type\":\"alert\",\"src_ip\":\"203.0.113.1\",\"dest_ip\":\"192.0.2.10\",\"dest_port\":22,\"alert\":{{\"signature_id\":{},\"severity\":3}}}}\n",
                n
            ));
            body.push_str(&format!("{{\"event_type\":\"flow\",\"n\":{}}}\n", n));
        }
        fs::write(&eve, &body).unwrap();
        let len = body.len() as u64;
        let mut cfg = sample_cfg();
        cfg.eve_path = eve.to_string_lossy().into_owned();
        cfg.normalized_log_path = dir.join("normalized-events.jsonl").to_string_lossy().into_owned();
        cfg.event_stdout = StdoutMode::Off;
        let mut ingress = IngressReader::new(0, limits);
        let mut iterations = 0;
        while ingress.offset < len {
            let report = poll_iteration(&cfg, &mut ingress);
            iterations += 1;
            assert!(report.alerts_admitted <= limits.alerts_per_poll);
            assert!(report.examined <= limits.examine_per_poll);
            assert!(iterations < 1000);
        }
        assert!(iterations >= 5, "the backlog took several iterations: {}", iterations);
        let _ = fs::remove_dir_all(&dir);
    }

    /// The release sweep runs on its own thread: while an apply command is
    /// held (here for 1.5 s, as a wedged nft would be until its bound), a
    /// due lease is still released and verified absent.
    #[test]
    fn a_held_apply_never_holds_the_release_sweep_back() {
        use release::{process_due_releases_with_runner, CommandResult, ReleaseCommandRunner};
        struct AbsentRunner;
        impl ReleaseCommandRunner for AbsentRunner {
            fn run(&self, _argv: &[String]) -> Result<CommandResult, String> {
                Ok(CommandResult { returncode: 0, stdout: json!({"nftables": []}).to_string(), stderr: String::new() })
            }
        }
        struct HeldApplier;
        impl Applier for HeldApplier {
            fn apply(&self, _argv: &[String]) -> Result<(), String> {
                thread::sleep(Duration::from_millis(1500));
                Err("command timeout".to_string())
            }
            fn readback(&self, _task: &ReleaseTask) -> Result<bool, String> {
                Ok(false)
            }
        }
        let dir = std::env::temp_dir().join(format!("azazel-held-apply-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let ledger = dir.join("ledger.json").to_string_lossy().into_owned();
        // A lease that is due now (created 400 s ago with a 300 s TTL).
        let now = now_epoch();
        let mut due = release::build_release_task("trace-due", "redirect", "br0", "198.51.100.9", 22, 12222, 0, 300, &LeaseNow::wall_only(now - 400.0)).unwrap();
        due.status = "active".to_string();
        prepare_release_task(&ledger, &due).unwrap();
        let mut cfg = executing_cfg(&dir);
        cfg.defense_release_ledger_path = ledger.clone();
        let ev = fresh_event(3, "203.0.113.50");
        let decision = decide_defense(&ev);
        let applying = {
            let cfg = cfg.clone();
            thread::spawn(move || maybe_enforce_with(&ev, &decision, &cfg, &HeldApplier))
        };
        thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        let outcomes = process_due_releases_with_runner(&ledger, &LeaseNow::wall_only(now_epoch()), &AbsentRunner).unwrap();
        let took = started.elapsed();
        assert!(!applying.is_finished(), "the apply was meant to still be held");
        assert!(took < Duration::from_millis(800), "the sweep waited on the apply: {:?}", took);
        assert!(outcomes.iter().any(|o| o.release_task_id == due.task_id && o.status == "released"), "{outcomes:?}");
        let outcome = applying.join().unwrap();
        assert_eq!(outcome.result, "failed", "{outcome:?}");
        assert_eq!(outcome.metadata["release_ledger_state"], "uncertain_release_scheduled");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ingress_audit_log_sits_beside_the_normalized_log() {
        let mut cfg = sample_cfg();
        cfg.normalized_log_path = "/var/log/azazel-edge/normalized-events.jsonl".to_string();
        assert_eq!(ingress_audit_log_path(&cfg), "/var/log/azazel-edge/ingress-audit.jsonl");
    }

    fn shed_flood(dir: &std::path::Path) -> (Config, IngressReader) {
        let _ = fs::create_dir_all(dir);
        let eve = dir.join("eve.json");
        let mut body = String::new();
        for n in 0..400 {
            body.push_str(&format!("{{\"event_type\":\"flow\",\"n\":{}}}\n", n));
        }
        fs::write(&eve, &body).unwrap();
        let mut cfg = sample_cfg();
        cfg.eve_path = eve.to_string_lossy().into_owned();
        cfg.normalized_log_path = dir.join("normalized-events.jsonl").to_string_lossy().into_owned();
        cfg.event_stdout = StdoutMode::Off;
        let limits = IngressLimits { non_alert_burst: 10, non_alert_per_sec: 1, ..IngressLimits::DECLARED };
        (cfg, IngressReader::new(0, limits))
    }

    fn audit_lines(cfg: &Config) -> Vec<Value> {
        fs::read_to_string(ingress_audit_log_path(cfg))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn shutdown_writes_the_last_interval_to_the_audit_file_once() {
        let dir = std::env::temp_dir().join(format!("azazel-shutdown-flush-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (cfg, mut ingress) = shed_flood(&dir);
        // The first iteration sheds and writes its summary at once.
        poll_iteration(&cfg, &mut ingress);
        assert_eq!(audit_lines(&cfg).len(), 1);
        // More arrives and is shed within the same interval: not written yet.
        let mut more = String::new();
        for n in 0..50 {
            more.push_str(&format!("{{\"event_type\":\"flow\",\"n\":{}}}\n", 1000 + n));
        }
        OpenOptions::new().append(true).open(&cfg.eve_path).unwrap().write_all(more.as_bytes()).unwrap();
        poll_iteration(&cfg, &mut ingress);
        assert_eq!(audit_lines(&cfg).len(), 1);
        let mut forwarded = Vec::new();
        let written = shutdown_ingress(&cfg, &mut ingress, &mut |r| forwarded.push(r.clone()));
        assert_eq!(written, 1);
        let lines = audit_lines(&cfg);
        assert_eq!(lines.len(), 2);
        let last = &lines[1]["ingress_shed"];
        assert_eq!(last["interval_end"], "shutdown");
        assert_eq!(last["shed_total"], 50);
        assert_eq!(last["cumulative_shed_total"].as_u64().unwrap(), lines[0]["ingress_shed"]["shed_total"].as_u64().unwrap() + 50);
        // Compare the forwarded record with the line as written, not with a
        // re-parse of it: serde_json does not round-trip every f64 exactly
        // (no float_roundtrip), so `emitted_epoch` can differ in the last digit.
        let raw = fs::read_to_string(ingress_audit_log_path(&cfg)).unwrap();
        let written_line = raw.lines().nth(1).unwrap();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(serde_json::to_string(&forwarded[0]).unwrap(), written_line);
        // A second stop writes nothing.
        assert_eq!(shutdown_ingress(&cfg, &mut ingress, &mut |_| panic!("forwarded twice")), 0);
        assert_eq!(audit_lines(&cfg).len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn shutdown_with_an_empty_last_interval_writes_nothing() {
        let dir = std::env::temp_dir().join(format!("azazel-shutdown-empty-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (cfg, mut ingress) = shed_flood(&dir);
        poll_iteration(&cfg, &mut ingress);
        poll_iteration(&cfg, &mut ingress);
        assert_eq!(audit_lines(&cfg).len(), 1);
        assert_eq!(shutdown_ingress(&cfg, &mut ingress, &mut |_| panic!("nothing to forward")), 0);
        assert_eq!(audit_lines(&cfg).len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ai_socket_gets_the_ingress_shed_object_and_counts_only() {
        let record = json!({
            "source": "core_ingress",
            "pipeline": "rust_ingress_v1",
            "ingress_shed": {"schema": ingress::INGRESS_SHED_SCHEMA, "shed_total": 3, "interval_end": "shutdown"},
        });
        let line = ingress_forward_line(&record).expect("forwarded");
        assert!(line.ends_with('\n') && !line.trim_end().contains('\n'));
        let sent: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(sent, record["ingress_shed"]);
        // An alert backlog summary is not forwarded.
        assert_eq!(ingress_forward_line(&json!({"ingress_alert_backlog": {"alerts_shed": 0}})), None);
        // A real summary names no address, MAC or id: counts, bounds, epoch.
        let dir = std::env::temp_dir().join(format!("azazel-shed-fields-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (cfg, mut ingress) = shed_flood(&dir);
        poll_iteration(&cfg, &mut ingress);
        let lines = audit_lines(&cfg);
        let inner = ingress_forward_line(&lines[0]).unwrap();
        for word in ["ip", "mac", "addr", "host", "trace", "uuid", "_id\""] {
            assert!(!inner.to_lowercase().contains(&format!("\"{}", word)), "{} in {}", word, inner);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_shutdown_drain_answers_after_the_lines_queued_before_it() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        let _guard = forward_test_lock();
        let dir = std::env::temp_dir().join(format!("az-edge-drain-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("intake.sock");
        let _ = fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let (sender, receiver) = sync_channel::<Forward>(4);
        let socket = path.to_string_lossy().to_string();
        let forwarder = thread::spawn(move || forward_ai_lines(&socket, receiver));
        sender.send(Forward::Line("{\"schema\":\"azazel-edge/ingress-shed/v1\"}\n".to_string())).unwrap();
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            stream.read_to_string(&mut line).expect("read");
            line
        });
        assert!(drain_ai_forward(&sender, Duration::from_secs(10)));
        assert_eq!(reader.join().unwrap(), "{\"schema\":\"azazel-edge/ingress-shed/v1\"}\n");
        drop(sender);
        forwarder.join().unwrap();
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_long_poll_interval_is_slept_in_slices_and_a_stop_ends_it_within_one() {
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        // A 60 s poll interval: the stop must not wait for it.
        let stopped = sleep_unless_stopped(Duration::from_secs(60), STOP_CHECK_SLICE, &|| stop.load(Ordering::SeqCst));
        let took = started.elapsed();
        setter.join().unwrap();
        assert!(stopped);
        assert!(took >= Duration::from_millis(100), "returned before the stop: {:?}", took);
        assert!(took < Duration::from_millis(100) + STOP_CHECK_SLICE * 6, "the stop waited {:?}", took);
    }

    #[test]
    fn without_a_stop_the_poll_interval_is_slept_whole() {
        let started = Instant::now();
        assert!(!sleep_unless_stopped(Duration::from_millis(230), STOP_CHECK_SLICE, &|| false));
        assert!(started.elapsed() >= Duration::from_millis(230));
        // A stop already requested sleeps not at all.
        let started = Instant::now();
        assert!(sleep_unless_stopped(Duration::from_secs(60), STOP_CHECK_SLICE, &|| true));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn the_shutdown_drain_is_bounded_when_the_forwarder_never_answers() {
        // Nothing takes from this queue: the drain gives up after its wait.
        let (sender, _receiver) = sync_channel::<Forward>(1);
        let started = Instant::now();
        assert!(!drain_ai_forward(&sender, Duration::from_millis(200)));
        assert!(started.elapsed() < Duration::from_secs(5));
        // A full queue is refused at once.
        let (full, _r) = sync_channel::<Forward>(0);
        assert!(!drain_ai_forward(&full, Duration::from_secs(60)));
    }

    fn sample_cfg() -> Config {
        Config {
            eve_path: "".to_string(),
            ai_socket_path: "".to_string(),
            normalized_log_path: "".to_string(),
            from_start: false,
            poll_ms: 100,
            forward_ai: false,
            forward_log: false,
            event_stdout: StdoutMode::Full,
            defense_enforce: false,
            defense_dry_run: true,
            defense_enforce_level: "advisory".to_string(),
            defense_action_ttl_sec: 300,
            defense_ttl_source: "default".to_string(),
            defense_release_ledger_path: "/tmp/azazel-edge-test-release-ledger.json".to_string(),
            protected_flows_path: "".to_string(),
            protected: ProtectedSet::NotConfigured,
        defense_allow_high_impact_auto: false,
        defense_iface: "br0".to_string(),
        defense_honeypot_port: 2222,
        redirect_policy_path: "config/redirect_policy.yaml".to_string(),
        redirect_policy: None,
        redirect_policy_source: "env_honeypot_fallback".to_string(),
    }
}

    #[test]
    fn build_enforcement_plan_for_critical_event() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let plan = build_enforcement_plan(&ev, &decision, "br0", 2222);
        assert!(!plan.apply_commands.is_empty());
        let flat = plan.apply_commands.join("\n");
        assert!(flat.contains("nft"));
    }

    fn owned_flow_task(ev: &NormalizedEvent) -> ReleaseTask {
        let (_, rate, burst) = strength_for(ev);
        build_flow_throttle_task("trace-test", &flow_scope(ev).unwrap(), rate, burst, 300, &LeaseNow::wall_only(100.0)).unwrap()
    }

    #[test]
    fn owned_flow_throttle_plan_quotes_the_comment_and_scopes_one_flow() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        assert_eq!(decision.action, "throttle");
        let task = owned_flow_task(&ev);
        let plan = build_enforcement_plan_owned(&ev, &decision, "br0", 2222, Some(&task));
        // nft joins its argv and parses it: the comment must be one argv
        // element holding an nft quoted string, not the bare token (`:` is a
        // syntax error there, Edge#464).
        let quoted = format!("\"{}\"", task.owner_token);
        assert_eq!(plan.apply_argv.len(), 1);
        let argv = &plan.apply_argv[0];
        assert_eq!(&argv[argv.len() - 2..], &["comment".to_string(), quoted.clone()]);
        assert!(!argv.contains(&task.owner_token));
        assert_eq!(
            plan.apply_commands[0],
            format!("nft insert rule inet azazel_edge throttle ip saddr 10.0.0.8 ip daddr 10.0.0.1 tcp dport 443 limit rate over 16 kbytes/second burst 16 kbytes drop comment {}", task.owner_token)
        );
        assert_eq!(
            plan.rollback_commands,
            vec![format!("nft delete rule inet azazel_edge throttle handle '<owned:{}>'", task.owner_token)]
        );
        // Never a qdisc, never a source-wide match.
        assert!(!plan.apply_commands[0].contains("qdisc") && !plan.apply_commands[0].contains(" input "));
    }

    #[test]
    fn owned_redirect_plan_quotes_the_nft_comment() {
        let mut ev = sample_event();
        ev.severity = 2;
        let decision = decide_defense(&ev);
        assert_eq!(decision.action, "redirect");
        let task = build_release_task(
            "trace-test", "redirect", "br0", &ev.src_ip, ev.target_port, 2222, decision.delay_ms, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let plan = build_enforcement_plan_owned(&ev, &decision, "br0", 2222, Some(&task));
        assert_eq!(plan.apply_argv.len(), 1);
        let argv = &plan.apply_argv[0];
        assert_eq!(argv[5], "prerouting");
        assert_eq!(&argv[argv.len() - 2..], &["comment".to_string(), format!("\"{}\"", task.owner_token)]);
        assert!(plan.apply_commands[0].ends_with(&format!(" redirect to 2222 comment {}", task.owner_token)));
        assert!(plan.rollback_commands[0].contains(&format!("handle '<owned:{}>'", task.owner_token)));
    }

    #[test]
    fn apply_argv_is_what_the_recorded_plan_shows_except_the_quoted_comment() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let unowned = build_enforcement_plan(&ev, &decision, "br0", 2222);
        assert_eq!(unowned.apply_commands, unowned.apply_argv.iter().map(|a| command_to_string(a)).collect::<Vec<_>>());
        assert!(unowned.apply_argv.iter().flatten().all(|part| part != "comment"));
    }

    #[test]
    fn owned_nft_plan_refuses_an_owner_token_that_cannot_be_an_nft_string() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let mut task = owned_flow_task(&ev);
        for bad in [
            "azazel-edge:release-ab\"; flush ruleset; \"",
            "azazel-edge:release-a b",
            "azazel-edge:release-a#b",
            "azazel-edge:release-a\nb",
            "other:release-ab",
        ] {
            task.owner_token = bad.to_string();
            let plan = build_enforcement_plan_owned(&ev, &decision, "br0", 2222, Some(&task));
            // No owned (commented) rule is planned for such a token, and
            // admission refuses the task before any apply.
            assert!(plan.apply_argv.iter().flatten().all(|part| part != "comment"), "{bad:?}");
            assert!(prepare_release_task("/nonexistent/azazel-edge-test-ledger.json", &task).is_err());
        }
    }

    #[test]
    fn throttle_strength_is_strict_for_critical_and_standard_otherwise() {
        let mut ev = sample_event();
        assert_eq!(strength_for(&ev), safety::STRENGTH_STRICT);
        ev.severity = 3;
        assert_eq!(strength_for(&ev), safety::STRENGTH_STANDARD);
        let plan = build_enforcement_plan(&ev, &decide_defense(&ev), "br0", 2222);
        assert!(plan.apply_commands[0].contains("limit rate over 32 kbytes/second burst 32 kbytes drop"));
        // A flow without TCP/UDP port is scoped to source and destination.
        ev.protocol = "ICMP".to_string();
        let plan = build_enforcement_plan(&ev, &decide_defense(&ev), "br0", 2222);
        assert!(!plan.apply_commands[0].contains("dport"));
        // Mixed families cannot be one flow: nothing is planned.
        ev.dst_ip = "2001:db8::1".to_string();
        assert!(build_enforcement_plan(&ev, &decide_defense(&ev), "br0", 2222).apply_argv.is_empty());
    }

    #[test]
    fn maybe_enforce_is_dry_run_when_enforce_is_false() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let mut cfg = sample_cfg();
        cfg.defense_enforce = false;
        cfg.defense_dry_run = true;
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.mode, "dry_run");
        assert_eq!(outcome.executed_count, 0);
        assert_eq!(outcome.failed_count, 0);
        assert!(!outcome.command_plan.is_empty());
        assert_eq!(
            outcome.metadata.get("release_ledger_state").and_then(Value::as_str),
            Some("planned_only")
        );
    }

    #[test]
    fn advisory_level_never_applies_disruptive_commands() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let mut cfg = sample_cfg();
        cfg.defense_enforce = true;
        cfg.defense_dry_run = false;
        cfg.defense_enforce_level = "advisory".to_string();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.mode, "policy_gated");
        assert_eq!(outcome.executed_count, 0);
    }

    #[test]
    fn semi_auto_blocks_high_impact_without_approval() {
        let allowed = action_allowlist("semi-auto", false);
        assert!(allowed.contains(&"throttle".to_string()));
        assert!(!allowed.contains(&"isolate".to_string()));
        assert!(!allowed.contains(&"redirect".to_string()));
    }

    #[test]
    fn no_level_and_no_flag_allows_isolate() {
        for level in ["advisory", "semi-auto", "full-auto", "anything"] {
            for flag in [false, true] {
                assert!(!action_allowlist(level, flag).contains(&"isolate".to_string()), "{level} {flag}");
            }
        }
        let allowed = action_allowlist("full-auto", false);
        assert!(allowed.contains(&"throttle".to_string()));
        assert!(allowed.contains(&"redirect".to_string()));
    }

    fn cfg_with_redirect_policy() -> Config {
        let mut cfg = sample_cfg();
        cfg.redirect_policy = Some(RedirectPolicyConfig {
            enabled: true,
            prepared_ports: HashMap::from([(22_u16, 12222_u16), (80_u16, 18080_u16), (8080_u16, 18080_u16)]),
            unsupported_port_action: "notify".to_string(),
            high_risk_unsupported_port_action: "isolate".to_string(),
            scan_burst_action: "throttle".to_string(),
            decoy_separation_evidence_path: String::new(),
            decoy_evidence_max_age_sec: 600,
        });
        cfg.redirect_policy_source = "file:config/redirect_policy.yaml".to_string();
        cfg
    }

    #[test]
    fn mapped_ssh_redirect_uses_prepared_port() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 22;
        let decision = decide_defense(&ev);
        assert_eq!(decision.action, "redirect");
        let cfg = cfg_with_redirect_policy();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "redirect");
        assert!(outcome.command_plan.join("\n").contains("to 12222"));
        assert_eq!(outcome.metadata.get("redirect_mapping_matched").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn mapped_http_redirect_uses_prepared_port() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 80;
        let decision = decide_defense(&ev);
        let cfg = cfg_with_redirect_policy();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "redirect");
        assert!(outcome.command_plan.join("\n").contains("to 18080"));
    }

    #[test]
    fn unsupported_port_falls_back_to_notify() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 5432;
        ev.risk_score = 40;
        let decision = decide_defense(&ev);
        let cfg = cfg_with_redirect_policy();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "notify");
        assert!(outcome.command_plan.is_empty());
        assert_eq!(outcome.metadata.get("unsupported_port_fallback").and_then(|v| v.as_str()), Some("notify"));
    }

    #[test]
    fn unsupported_high_risk_port_falls_back_to_notify_even_if_the_policy_names_isolate() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 5432;
        ev.risk_score = 95;
        let decision = decide_defense(&ev);
        let cfg = cfg_with_redirect_policy();
        assert_eq!(cfg.redirect_policy.as_ref().unwrap().high_risk_unsupported_port_action, "isolate");
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "notify");
        assert!(outcome.command_plan.is_empty());
        assert_eq!(outcome.metadata.get("unsupported_port_fallback").and_then(|v| v.as_str()), Some("notify"));
    }

    #[test]
    fn invalid_redirect_policy_is_rejected() {
        let parsed = serde_yaml::from_str::<RedirectPolicyRoot>("redirect_policy: [invalid");
        assert!(parsed.is_err());
    }

    #[test]
    fn invalid_redirect_policy_falls_back_to_notify() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 2222;
        let decision = decide_defense(&ev);
        let mut cfg = sample_cfg();
        cfg.redirect_policy = None;
        cfg.redirect_policy_source = "invalid_file_notify_fallback:config/redirect_policy.yaml".to_string();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "notify");
        assert!(outcome.command_plan.is_empty());
        assert_eq!(outcome.metadata.get("fallback_reason").and_then(|v| v.as_str()), Some("invalid_redirect_policy"));
    }

    #[test]
    fn missing_redirect_policy_falls_back_to_honeypot_env() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 2222;
        let decision = decide_defense(&ev);
        let mut cfg = sample_cfg();
        cfg.redirect_policy = None;
        cfg.redirect_policy_source = "env_honeypot_fallback".to_string();
        cfg.defense_honeypot_port = 2222;
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "redirect");
        assert!(outcome.command_plan.join("\n").contains("to 2222"));
    }

    #[test]
    fn disabled_redirect_policy_falls_back_to_notify() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 22;
        let decision = decide_defense(&ev);
        let mut cfg = cfg_with_redirect_policy();
        if let Some(policy) = cfg.redirect_policy.as_mut() {
            policy.enabled = false;
        }
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "notify");
        assert!(outcome.command_plan.is_empty());
        assert_eq!(outcome.metadata.get("fallback_reason").and_then(|v| v.as_str()), Some("policy_disabled"));
    }

    #[test]
    fn enforcement_gate_still_blocks_high_impact_redirect() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 22;
        let decision = decide_defense(&ev);
        let mut cfg = cfg_with_redirect_policy();
        cfg.defense_enforce = true;
        cfg.defense_dry_run = false;
        cfg.defense_enforce_level = "semi-auto".to_string();
        cfg.defense_allow_high_impact_auto = false;
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.mode, "policy_gated");
        assert_eq!(outcome.executed_count, 0);
    }

    // -- scoped temporary actions (ADR: docs/architecture/scoped-temporary-actions.md)

    /// An EVE timestamp for `epoch` (UTC).
    fn eve_ts(epoch: f64) -> String {
        let secs = epoch.floor() as i64;
        let micros = ((epoch - secs as f64) * 1e6) as i64;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        // civil_from_days (Howard Hinnant).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+0000", y, m, d, rem / 3600, rem % 3600 / 60, rem % 60, micros)
    }

    #[test]
    fn eve_ts_helper_round_trips_through_the_core_parser() {
        let now = now_epoch();
        let parsed = safety::parse_eve_epoch(&eve_ts(now)).unwrap();
        assert!((parsed - now).abs() < 1e-3, "{} {}", parsed, now);
    }

    fn fresh_event(severity: u8, src: &str) -> NormalizedEvent {
        let mut ev = sample_event();
        ev.ts = eve_ts(now_epoch());
        ev.severity = severity;
        ev.src_ip = src.to_string();
        ev.dst_ip = "10.20.0.5".to_string();
        ev.target_port = 22;
        ev.risk_score = ((11_u16.saturating_sub(severity as u16)) * 9).min(100) as u8;
        ev
    }

    const PROTECTED: &str = "protected_flows:\n  version: 1\n  entries:\n    - {name: mgmt, role: management, network: 192.0.2.0/28}\n    - {name: expert, role: expert_contact, network: 198.51.100.7, ports: [443]}\n";

    /// Enforcement on, dry run off, full-auto, a ledger in `dir`, the
    /// protected set above, the prepared-port redirect policy with its decoy
    /// evidence path in `dir` (not written: tests that need it write it).
    fn executing_cfg(dir: &Path) -> Config {
        let mut cfg = cfg_with_redirect_policy();
        cfg.defense_enforce = true;
        cfg.defense_dry_run = false;
        cfg.defense_enforce_level = "full-auto".to_string();
        cfg.defense_release_ledger_path = dir.join("ledger.json").to_string_lossy().into_owned();
        cfg.protected = ProtectedSet::parse(PROTECTED);
        if let Some(policy) = cfg.redirect_policy.as_mut() {
            policy.decoy_separation_evidence_path = dir.join("decoy.json").to_string_lossy().into_owned();
            policy.decoy_evidence_max_age_sec = 600;
        }
        cfg
    }

    fn test_dir(tag: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("az-scoped-{}-{}-{}", tag, std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Records what it was asked to apply; applies and reads back as told.
    struct FakeApplier {
        applied: Mutex<Vec<Vec<String>>>,
        apply_result: Result<(), String>,
        readback: Result<bool, String>,
    }

    impl FakeApplier {
        fn ok() -> Self {
            FakeApplier { applied: Mutex::new(Vec::new()), apply_result: Ok(()), readback: Ok(true) }
        }
        fn applied(&self) -> Vec<Vec<String>> {
            self.applied.lock().unwrap().clone()
        }
    }

    impl Applier for FakeApplier {
        fn apply(&self, argv: &[String]) -> Result<(), String> {
            self.applied.lock().unwrap().push(argv.to_vec());
            self.apply_result.clone()
        }
        fn readback(&self, _task: &ReleaseTask) -> Result<bool, String> {
            self.readback.clone()
        }
    }

    fn ledger_tasks(cfg: &Config) -> Vec<Value> {
        fs::read_to_string(&cfg.defense_release_ledger_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v["tasks"].as_array().cloned())
            .unwrap_or_default()
    }

    #[test]
    fn no_automatic_path_reaches_isolate_whatever_the_level_flag_policy_or_port() {
        let dir = test_dir("noiso");
        let policies: Vec<(Option<RedirectPolicyConfig>, &str)> = vec![
            (None, "env_honeypot_fallback"),
            (None, "invalid_file_notify_fallback:x"),
            (cfg_with_redirect_policy().redirect_policy, "file:x"),
            (
                Some(RedirectPolicyConfig {
                    enabled: true,
                    prepared_ports: HashMap::new(),
                    unsupported_port_action: "isolate".to_string(),
                    high_risk_unsupported_port_action: "ISOLATE".to_string(),
                    scan_burst_action: "isolate".to_string(),
                    decoy_separation_evidence_path: String::new(),
                    decoy_evidence_max_age_sec: 600,
                }),
                "file:x",
            ),
        ];
        let mut cases = 0;
        for (policy, source) in &policies {
            for level in ["advisory", "semi-auto", "full-auto"] {
                for high_impact in [false, true] {
                    for dry_run in [false, true] {
                        for severity in 0..=10_u8 {
                            for port in [0_u16, 22, 80, 443, 5432] {
                                let mut cfg = executing_cfg(&dir);
                                cfg.redirect_policy = policy.clone();
                                cfg.redirect_policy_source = source.to_string();
                                cfg.defense_enforce_level = level.to_string();
                                cfg.defense_allow_high_impact_auto = high_impact;
                                cfg.defense_dry_run = dry_run;
                                cfg.defense_release_ledger_path = dir.join(format!("l-{}.json", cases)).to_string_lossy().into_owned();
                                let mut ev = fresh_event(severity, "203.0.113.77");
                                ev.target_port = port;
                                let decision = decide_defense(&ev);
                                assert_ne!(decision.action, "isolate");
                                let applier = FakeApplier::ok();
                                let outcome = maybe_enforce_with(&ev, &decision, &cfg, &applier);
                                assert_ne!(outcome.selected_action, "isolate", "{level} {high_impact} {severity} {port} {source}");
                                for argv in applier.applied() {
                                    let line = argv.join(" ");
                                    assert!(!line.contains(" input ") && !line.contains("qdisc"), "{line}");
                                    assert!(!line.ends_with(" drop") || line.contains(" limit rate over "), "{line}");
                                }
                                for command in &outcome.command_plan {
                                    assert!(!command.contains(" input "), "{command}");
                                }
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        assert!(cases > 1000);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_protected_flow_is_never_restricted_and_the_refusal_is_recorded() {
        let dir = test_dir("prot");
        let cfg = executing_cfg(&dir);
        // The management network as the source (any port), and the expert's
        // contact port as the destination.
        let mgmt_src = fresh_event(1, "192.0.2.5");
        let mut expert_dst = fresh_event(3, "203.0.113.9");
        expert_dst.dst_ip = "198.51.100.7".to_string();
        expert_dst.target_port = 443;
        for (ev, role) in [(mgmt_src, "management"), (expert_dst, "expert_contact")] {
            for dry_run in [true, false] {
                let mut cfg = cfg.clone();
                cfg.defense_dry_run = dry_run;
                let applier = FakeApplier::ok();
                let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier);
                assert!(applier.applied().is_empty());
                assert_eq!(outcome.selected_action, "notify");
                assert!(outcome.command_plan.is_empty());
                assert_eq!(outcome.metadata["safety"]["gate"], format!("refused:protected_flow:{}", role));
                assert_eq!(outcome.metadata["safety"]["protected_match"]["role"], role);
                assert!(outcome.policy_reason.contains("safety_refused:protected_flow"));
            }
        }
        // The same alert from an unprotected source, or to the expert on
        // another port, is restricted, and only that flow.
        let mut other_port = fresh_event(3, "203.0.113.9");
        other_port.dst_ip = "198.51.100.7".to_string();
        other_port.target_port = 8443;
        let applier = FakeApplier::ok();
        let outcome = maybe_enforce_with(&other_port, &decide_defense(&other_port), &cfg, &applier);
        assert_eq!(outcome.result, "applied", "{outcome:?}");
        assert_eq!(applier.applied().len(), 1);
        assert!(applier.applied()[0].join(" ").contains("ip saddr 203.0.113.9 ip daddr 198.51.100.7 tcp dport 8443 limit rate over"));
        assert_eq!(outcome.metadata["release_ledger_state"], "active");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn execution_is_refused_without_a_declared_protected_set_or_with_no_management_entry() {
        let dir = test_dir("noset");
        for set in [
            ProtectedSet::NotConfigured,
            ProtectedSet::Invalid("parse".to_string()),
            ProtectedSet::parse("protected_flows: {version: 1, entries: [{name: r, role: mission, network: 10.9.0.0/16}]}"),
        ] {
            let mut cfg = executing_cfg(&dir);
            cfg.protected = set.clone();
            let ev = fresh_event(3, "203.0.113.10");
            let applier = FakeApplier::ok();
            let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier);
            assert!(applier.applied().is_empty(), "{set:?}");
            assert_eq!(outcome.mode, "policy_gated");
            assert_eq!(outcome.result, "planned_not_applied");
            assert!(outcome.metadata["safety"]["gate"].as_str().unwrap().starts_with("refused:protected_set_"), "{outcome:?}");
            assert!(ledger_tasks(&cfg).is_empty());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_or_undated_alert_does_not_start_a_restriction() {
        let dir = test_dir("stale");
        let cfg = executing_cfg(&dir);
        for ts in [eve_ts(now_epoch() - 1000.0), "garbage".to_string(), eve_ts(now_epoch() + 600.0)] {
            let mut ev = fresh_event(3, "203.0.113.11");
            ev.ts = ts;
            let applier = FakeApplier::ok();
            let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier);
            assert!(applier.applied().is_empty());
            assert_eq!(outcome.mode, "policy_gated");
            assert!(outcome.metadata["safety"]["gate"].as_str().unwrap().starts_with("refused:alert_"));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_apply_failure_timeout_or_readback_mismatch_is_never_applied_and_is_released_at_once() {
        let dir = test_dir("fail");
        let cases: Vec<(Result<(), String>, Result<bool, String>, &str, &str)> = vec![
            (Err("command timeout after 3s: nft ...".to_string()), Ok(true), "failed", "command timeout"),
            (Err("command failed (exit=1): nft ...".to_string()), Ok(true), "failed", "command failed"),
            (Ok(()), Ok(false), "partial_failure", "owned_state_readback_mismatch"),
            (Ok(()), Err("nft readback failed".to_string()), "partial_failure", "owned_state_readback_failed"),
        ];
        for (n, (apply, readback, result, error)) in cases.into_iter().enumerate() {
            let cfg = executing_cfg(&dir);
            let mut cfg = cfg;
            cfg.defense_release_ledger_path = dir.join(format!("l{}.json", n)).to_string_lossy().into_owned();
            let ev = fresh_event(3, "203.0.113.12");
            let applier = FakeApplier { applied: Mutex::new(Vec::new()), apply_result: apply, readback };
            let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier);
            assert_eq!(outcome.result, result);
            assert!(outcome.errors.iter().any(|e| e.contains(error)), "{:?}", outcome.errors);
            assert_eq!(outcome.metadata["release_ledger_state"], "uncertain_release_scheduled");
            let tasks = ledger_tasks(&cfg);
            assert_eq!(tasks.len(), 1);
            assert_eq!(tasks[0]["status"], "uncertain");
            // Due now, not after its TTL: the next sweep releases it.
            assert!(tasks[0]["due_epoch"].as_f64().unwrap() <= now_epoch());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_alert_for_a_held_flow_extends_its_lease_within_the_edge_bounds() {
        let dir = test_dir("ext");
        let cfg = executing_cfg(&dir);
        let first = fresh_event(3, "203.0.113.13");
        let applier = FakeApplier::ok();
        let outcome = maybe_enforce_with(&first, &decide_defense(&first), &cfg, &applier);
        assert_eq!(outcome.result, "applied");
        // An immediate re-alert asks for nothing longer: already held.
        let mut again = fresh_event(3, "203.0.113.13");
        again.sid = 49_999;
        let outcome = maybe_enforce_with(&again, &decide_defense(&again), &cfg, &FakeApplier::ok());
        assert_eq!(outcome.result, "already_held", "{outcome:?}");
        let mut results = Vec::new();
        for n in 0..(release::MAX_LEASE_EXTENSIONS + 2) {
            // The held lease is near its end when the next alert comes.
            shorten_held_lease(&cfg, 20.0);
            let mut ev = fresh_event(3, "203.0.113.13");
            ev.sid = 50_000 + n as u64; // another alert of the same flow
            let applier = FakeApplier::ok();
            let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier);
            assert!(applier.applied().is_empty(), "an extension applies nothing");
            results.push(outcome.result.clone());
        }
        let extended = results.iter().filter(|r| *r == "extended").count();
        assert_eq!(extended as u32, release::MAX_LEASE_EXTENSIONS, "{results:?}");
        assert_eq!(results.last().unwrap(), "planned_not_applied");
        let tasks = ledger_tasks(&cfg);
        let held: Vec<&Value> = tasks.iter().filter(|t| t["status"] == "active").collect();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0]["extensions"], release::MAX_LEASE_EXTENSIONS);
        let created = held[0]["created_epoch"].as_f64().unwrap();
        assert!(held[0]["due_epoch"].as_f64().unwrap() <= created + release::MAX_CUMULATIVE_LEASE_SEC as f64);
        // Replaying an alert that was merged is refused, not extended again.
        let _ = fs::remove_dir_all(&dir);
    }

    /// Move the active lease's expiry to `left` seconds from now (both
    /// clocks), as if it had been held for most of its TTL.
    fn shorten_held_lease(cfg: &Config, left: f64) {
        let raw = fs::read_to_string(&cfg.defense_release_ledger_path).unwrap();
        let mut ledger: Value = serde_json::from_str(&raw).unwrap();
        let now = LeaseNow::read(now_epoch());
        for task in ledger["tasks"].as_array_mut().unwrap() {
            if task["status"] == "active" {
                let due = task["due_epoch"].as_f64().unwrap();
                let target = now.wall_epoch + left;
                let delta = due - target;
                task["due_epoch"] = json!(target);
                task["next_attempt_epoch"] = json!(target);
                if let Some(mono) = task["due_boottime_ns"].as_u64() {
                    task["due_boottime_ns"] = json!(mono - (delta * 1e9) as u64);
                }
                task["created_epoch"] = json!(task["created_epoch"].as_f64().unwrap().min(target));
            }
        }
        fs::write(&cfg.defense_release_ledger_path, ledger.to_string()).unwrap();
    }

    #[test]
    fn a_replayed_alert_is_refused_and_never_applied_twice() {
        let dir = test_dir("replay");
        let cfg = executing_cfg(&dir);
        let ev = fresh_event(3, "203.0.113.14");
        let applier = FakeApplier::ok();
        assert_eq!(maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &applier).result, "applied");
        let again = FakeApplier::ok();
        let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &again);
        assert!(again.applied().is_empty());
        assert_eq!(outcome.mode, "release_guard_failed");
        assert!(outcome.errors[0].contains("replayed disruptive apply blocked"), "{:?}", outcome.errors);
        let _ = fs::remove_dir_all(&dir);
    }

    fn write_decoy_evidence(cfg: &Config, ports: &[u16], boot: &str) {
        use std::os::unix::fs::PermissionsExt;
        let path = cfg.redirect_policy.as_ref().unwrap().decoy_separation_evidence_path.clone();
        let body = json!({"schema": safety::DECOY_EVIDENCE_SCHEMA, "boot_id": boot, "observed_epoch": now_epoch(), "separation": "network_namespace", "decoy_ports": ports});
        fs::write(&path, body.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn a_redirect_runs_only_with_this_boots_separation_evidence_and_a_reachable_decoy() {
        let dir = test_dir("decoy");
        let mut cfg = executing_cfg(&dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        cfg.redirect_policy.as_mut().unwrap().prepared_ports = HashMap::from([(22_u16, port)]);
        let ev = fresh_event(2, "203.0.113.15");
        let decision = decide_defense(&ev);
        assert_eq!(decision.action, "redirect");
        let boot = LeaseNow::read(now_epoch()).boot_id.unwrap_or_default();

        // No evidence: notified with the reason, nothing applied.
        let applier = FakeApplier::ok();
        let outcome = maybe_enforce_with(&ev, &decision, &cfg, &applier);
        assert!(applier.applied().is_empty());
        assert_eq!(outcome.mode, "policy_gated");
        assert_eq!(outcome.metadata["safety"]["decoy_preconditions"], "unmet");
        assert_eq!(outcome.metadata["safety"]["gate"], "refused:decoy_separation_evidence_missing");

        // Another boot's evidence.
        write_decoy_evidence(&cfg, &[port], "other-boot");
        let outcome = maybe_enforce_with(&ev, &decision, &cfg, &FakeApplier::ok());
        assert_eq!(outcome.metadata["safety"]["gate"], "refused:decoy_separation_evidence_other_boot");

        if boot.is_empty() {
            // No boot id on this platform: a redirect can never be proven.
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        // This boot's evidence, but the decoy is not listening.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        cfg.redirect_policy.as_mut().unwrap().prepared_ports = HashMap::from([(22_u16, closed)]);
        write_decoy_evidence(&cfg, &[closed], &boot);
        let outcome = maybe_enforce_with(&ev, &decision, &cfg, &FakeApplier::ok());
        assert_eq!(outcome.metadata["safety"]["gate"], "refused:decoy_unreachable");

        // Everything holds: applied.
        cfg.redirect_policy.as_mut().unwrap().prepared_ports = HashMap::from([(22_u16, port)]);
        write_decoy_evidence(&cfg, &[port], &boot);
        let applier = FakeApplier::ok();
        let outcome = maybe_enforce_with(&ev, &decision, &cfg, &applier);
        assert_eq!(outcome.result, "applied", "{outcome:?}");
        assert_eq!(outcome.metadata["safety"]["decoy_preconditions"], "met");
        assert!(applier.applied()[0].join(" ").contains(&format!("redirect to {}", port)));
        drop(listener);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_held_lease_count_is_capped() {
        let dir = test_dir("cap");
        let cfg = executing_cfg(&dir);
        let mut applied = 0;
        let mut refused = 0;
        for n in 0..(release::MAX_ACTIVE_LEASES + 3) {
            let ev = fresh_event(3, &format!("203.0.{}.{}", 100 + n / 200, 1 + n % 200));
            let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &FakeApplier::ok());
            match outcome.result.as_str() {
                "applied" => applied += 1,
                _ => {
                    assert!(outcome.errors[0].contains("active lease limit reached"), "{:?}", outcome.errors);
                    refused += 1
                }
            }
        }
        assert_eq!(applied, release::MAX_ACTIVE_LEASES);
        assert_eq!(refused, 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn executed_and_refused_actions_and_releases_are_spooled_whatever_forward_log_says() {
        let dir = test_dir("spool");
        let mut cfg = executing_cfg(&dir);
        cfg.forward_log = false;
        cfg.forward_ai = false;
        cfg.event_stdout = StdoutMode::Off;
        let ev = fresh_event(3, "203.0.113.60");
        let outcome = maybe_enforce_with(&ev, &decide_defense(&ev), &cfg, &FakeApplier::ok());
        assert!(enforcement_evidence_due(&outcome));
        let mut dry = cfg.clone();
        dry.defense_dry_run = true;
        assert!(!enforcement_evidence_due(&maybe_enforce(&fresh_event(3, "203.0.113.61"), &decide_defense(&ev), &dry)));
        let mut stale = fresh_event(3, "203.0.113.62");
        stale.ts = "2020-01-01T00:00:00Z".to_string();
        assert!(enforcement_evidence_due(&maybe_enforce_with(&stale, &decide_defense(&stale), &cfg, &FakeApplier::ok())));
        let event = core_event(&ev, &decide_defense(&ev), &outcome, &cfg);
        spool_enforcement_evidence(&cfg, &event);
        let raw = fs::read_to_string(enforcement_evidence_path(&cfg)).unwrap();
        let line: Value = serde_json::from_str(raw.lines().last().unwrap()).unwrap();
        assert_eq!(line["enforcement"]["result"], "applied");
        assert!(line["evidence_spool"]["seq"].as_u64().unwrap() >= 1);
        assert!(!fs::metadata(&cfg.normalized_log_path).map(|m| m.len() > 0).unwrap_or(false));
        let _ = fs::remove_dir_all(&dir);
    }
}
