mod audit_chain;
mod ingress;
mod release;

use ingress::{IngressLimits, IngressReader, PollReport};
use release::{
    activate_release_task, build_release_task, cancel_release_task, mark_release_task_uncertain,
    prepare_release_task, process_due_releases, LeaseNow, ReleaseTask,
};
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
use std::process::Command;
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
    defense_release_ledger_path: String,
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
}

fn default_notify() -> String {
    "notify".to_string()
}

fn default_isolate() -> String {
    "isolate".to_string()
}

fn default_throttle() -> String {
    "throttle".to_string()
}

fn normalize_safe_action(raw: &str, default_action: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "observe" | "notify" | "throttle" | "redirect" | "isolate" => raw.to_ascii_lowercase(),
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

    Config {
        eve_path: env::var("AZAZEL_EVE_PATH").unwrap_or_else(|_| "/var/log/suricata/eve.json".to_string()),
        ai_socket_path: env::var("AZAZEL_AI_SOCKET").unwrap_or_else(|_| "/run/azazel-edge/ai-bridge.sock".to_string()),
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
        defense_action_ttl_sec: env::var("AZAZEL_DEFENSE_ACTION_TTL_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300),
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
    if ev.severity <= 1 {
        return DefensiveDecision {
            action: "isolate".to_string(),
            reason: format!("critical severity sid={}", ev.sid),
            policy_reason: "severity_critical_contains_immediately".to_string(),
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

fn parse_shell_words(line: &str) -> Vec<String> {
    line.split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>()
}

fn build_enforcement_plan(ev: &NormalizedEvent, decision: &DefensiveDecision, iface: &str, honeypot_port: u16) -> EnforcementPlan {
    build_enforcement_plan_owned(ev, decision, iface, honeypot_port, None)
}

fn build_enforcement_plan_owned(
    ev: &NormalizedEvent,
    decision: &DefensiveDecision,
    iface: &str,
    honeypot_port: u16,
    release_task: Option<&ReleaseTask>,
) -> EnforcementPlan {
    let mut apply: Vec<Vec<String>> = Vec::new();
    let mut rollback: Vec<Vec<String>> = Vec::new();

    if decision.action == "isolate" {
        let mut command = vec![
            "nft".to_string(), "insert".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "input".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "drop".to_string(),
        ];
        if let Some(task) = release_task {
            command.push("comment".to_string());
            command.push(task.owner_token.clone());
            rollback.push(vec![
                "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
                "input".to_string(), "handle".to_string(), format!("<owned:{}>", task.owner_token),
            ]);
        } else {
            rollback.push(vec![
                "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
                "input".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "drop".to_string(),
            ]);
        }
        apply.push(command);
    }

    if decision.action == "throttle" {
        let mut command = vec![
            "tc".to_string(), "qdisc".to_string(), "replace".to_string(), "dev".to_string(), iface.to_string(), "root".to_string(),
        ];
        if let Some(task) = release_task {
            command.push("handle".to_string());
            command.push(task.tc_handle.clone());
        }
        command.extend(vec![
            "tbf".to_string(), "rate".to_string(), "256kbit".to_string(), "burst".to_string(), "32kbit".to_string(),
            "latency".to_string(), format!("{}ms", decision.delay_ms.max(100)),
        ]);
        apply.push(command);

        let mut rollback_command = vec![
            "tc".to_string(), "qdisc".to_string(), "del".to_string(), "dev".to_string(), iface.to_string(), "root".to_string(),
        ];
        if let Some(task) = release_task {
            rollback_command.push("handle".to_string());
            rollback_command.push(task.tc_handle.clone());
        }
        rollback.push(rollback_command);
    }

    if decision.action == "redirect" {
        let mut command = vec![
            "nft".to_string(), "insert".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "prerouting".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "tcp".to_string(),
            "dport".to_string(), ev.target_port.to_string(), "redirect".to_string(), "to".to_string(), honeypot_port.to_string(),
        ];
        if let Some(task) = release_task {
            command.push("comment".to_string());
            command.push(task.owner_token.clone());
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
        apply_commands: apply.iter().map(|argv| command_to_string(argv)).collect::<Vec<String>>(),
        rollback_commands: rollback.iter().map(|argv| command_to_string(argv)).collect::<Vec<String>>(),
    }
}

fn run_command(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() {
        return Err("empty command".to_string());
    }
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    match cmd.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!(
            "command failed (exit={}): {}",
            status.code().map(|v| v.to_string()).unwrap_or_else(|| "signal".to_string()),
            command_to_string(argv)
        )),
        Err(e) => Err(format!("command exec error: {} ({})", e, command_to_string(argv))),
    }
}

fn action_allowlist(level: &str, high_impact_auto: bool) -> Vec<String> {
    match level {
        "full-auto" => vec!["observe", "notify", "throttle", "redirect", "isolate"].iter().map(|s| s.to_string()).collect(),
        "semi-auto" => {
            let mut base = vec!["observe", "notify", "throttle"].iter().map(|s| s.to_string()).collect::<Vec<String>>();
            if high_impact_auto {
                base.push("redirect".to_string());
                base.push("isolate".to_string());
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

fn maybe_enforce(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config) -> EnforcementOutcome {
    let trace_id = calc_trace_id(ev, decision);
    let (effective_decision, mut redirect_meta) = resolve_redirect_decision(ev, decision, cfg);
    let selected_decoy_port = redirect_meta
        .get("selected_decoy_port")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)
        .unwrap_or(cfg.defense_honeypot_port);
    let release_task = build_release_task(
        &trace_id,
        &effective_decision.action,
        &cfg.defense_iface,
        &ev.src_ip,
        ev.target_port,
        selected_decoy_port,
        effective_decision.delay_ms,
        cfg.defense_action_ttl_sec,
        &LeaseNow::read(now_epoch()),
    );
    let plan = build_enforcement_plan_owned(
        ev,
        &effective_decision,
        &cfg.defense_iface,
        selected_decoy_port,
        release_task.as_ref(),
    );

    if plan.apply_commands.is_empty() {
        add_release_metadata(&mut redirect_meta, None, "not_applicable");
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

    let task = match release_task.as_ref() {
        Some(task) => task,
        None => {
            add_release_metadata(&mut redirect_meta, None, "ownership_unavailable");
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

    if let Err(error) = prepare_release_task(&cfg.defense_release_ledger_path, task) {
        add_release_metadata(&mut redirect_meta, Some(task), "prepare_failed");
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
            rollback_hint: "disruptive action blocked because durable release intent could not be persisted".to_string(),
            result: "planned_not_applied".to_string(),
            metadata: redirect_meta,
        };
    }

    let mut executed_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut errors: Vec<String> = Vec::new();
    for cmd in &plan.apply_commands {
        let argv = parse_shell_words(cmd);
        match run_command(&argv) {
            Ok(_) => executed_count += 1,
            Err(e) => {
                failed_count += 1;
                errors.push(e);
            }
        }
    }

    let ledger_state = if failed_count == 0 && executed_count > 0 {
        match activate_release_task(&cfg.defense_release_ledger_path, &task.task_id, now_epoch()) {
            Ok(_) => "active",
            Err(error) => {
                errors.push(format!("release_schedule_activation_failed:{}", error));
                "prepared"
            }
        }
    } else if executed_count > 0 {
        match mark_release_task_uncertain(
            &cfg.defense_release_ledger_path,
            &task.task_id,
            "provider_partial_apply",
            now_epoch(),
        ) {
            Ok(_) => "uncertain",
            Err(error) => {
                errors.push(format!("release_schedule_uncertain_persist_failed:{}", error));
                "prepared"
            }
        }
    } else {
        match cancel_release_task(
            &cfg.defense_release_ledger_path,
            &task.task_id,
            "provider_apply_failed",
            now_epoch(),
        ) {
            Ok(_) => "cancelled",
            Err(error) => {
                errors.push(format!("release_schedule_cancel_failed:{}", error));
                "prepared"
            }
        }
    };
    add_release_metadata(&mut redirect_meta, Some(task), ledger_state);

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
        rollback_hint: format!(
            "durable automatic release due after {}s; release remains unverified until owned-state absence readback",
            cfg.defense_action_ttl_sec
        ),
        result: if failed_count > 0 { "partial_failure".to_string() } else { "applied".to_string() },
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
            let fallback = if high_risk {
                normalize_safe_action(&policy.high_risk_unsupported_port_action, "isolate")
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

fn append_json_line(path: &str, value: &Value) {
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{}", value);
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

/// Decide one EVE record the ingress reader admitted.
fn process_value(cfg: &Config, parsed: &Value) {
    let normalized = match build_normalized_event(parsed) {
        Some(ev) => ev,
        None => return,
    };

    let decision = decide_defense(&normalized);
    let enforcement = maybe_enforce(&normalized, &decision, cfg);

    let event = json!({
        "normalized": normalized,
        "defense": decision,
        "enforcement": enforcement,
        "enforcement_status": enforcement_status(cfg),
        "source": "suricata_eve",
        "pipeline": "rust_event_engine_v1",
    });

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
fn emit_ingress_record(cfg: &Config, record: &Value) {
    append_json_line(&ingress_audit_log_path(cfg), record);
    match cfg.event_stdout {
        StdoutMode::Full | StdoutMode::Summary => println!("{}", record),
        StdoutMode::Off => eprintln!("{}", record),
    }
}

/// One iteration of the main loop: one bounded read of the EVE file, its
/// audit summaries, then the release sweep. The read is bounded
/// (`IngressLimits`), so the sweep runs on every iteration however much is
/// waiting in the EVE file; whatever the read left is read next time.
fn poll_iteration(cfg: &Config, ingress: &mut IngressReader, sweep: &mut dyn FnMut(&Config, &IngressReader)) -> PollReport {
    let report = ingress.poll(Path::new(&cfg.eve_path), Instant::now(), |v| process_value(cfg, v));
    for record in ingress.audit_records(Instant::now(), now_epoch()) {
        emit_ingress_record(cfg, &record);
    }
    sweep(cfg, ingress);
    report
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

    if let Some(parent) = Path::new(&cfg.normalized_log_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let offset = if cfg.from_start { 0 } else { fs::metadata(&cfg.eve_path).map(|m| m.len()).unwrap_or(0) };

    eprintln!(
        "azazel-edge-core started: eve_path={}, ai_socket={}, from_start={}, poll_ms={}, defense_enforce={}, defense_dry_run={}, defense_enforce_level={}, high_impact_auto={}, defense_iface={}, honeypot_port={}, release_ledger={}, ingress_admit_per_sec={}, ingress_admit_per_poll={}",
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
        IngressLimits::DECLARED.admit_per_sec,
        IngressLimits::DECLARED.admit_per_poll
    );

    // Reconcile due release work before reading new alerts. This runs even when new
    // enforcement is disabled so a restart/config change cannot strand old temporary state.
    process_release_events(&cfg);
    process_start();
    let mut reporter = ForwardReporter::new();
    let mut ingress = IngressReader::new(offset, IngressLimits::DECLARED);
    loop {
        poll_iteration(&cfg, &mut ingress, &mut |c, _| process_release_events(c));
        if cfg.forward_ai {
            reporter.tick(Instant::now(), || queue_forward_stats(&cfg.ai_socket_path));
        }
        thread::sleep(Duration::from_millis(cfg.poll_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> NormalizedEvent {
        NormalizedEvent {
            ts: "2026-01-01T00:00:00Z".to_string(),
            src_ip: "10.0.0.8".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            attack_type: "test".to_string(),
            severity: 1,
            target_port: 443,
            protocol: "tcp".to_string(),
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
    fn the_release_sweep_runs_every_iteration_while_an_ingress_backlog_remains() {
        let dir = std::env::temp_dir().join(format!("azazel-sweep-under-load-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let eve = dir.join("eve.json");
        let limits = IngressLimits::DECLARED;
        // Five polls' worth of alerts plus the same number of flow records,
        // all present before the first poll: a flood the old reader would have
        // read to the end before the sweep.
        let total = limits.admit_per_poll * 5;
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
        let mut sweeps: Vec<u64> = Vec::new();
        let mut iterations = 0;
        while ingress.offset < len {
            let report = poll_iteration(&cfg, &mut ingress, &mut |_, r| sweeps.push(r.offset));
            iterations += 1;
            assert!(report.admitted <= limits.admit_per_poll);
            assert!(report.examined <= limits.examine_per_poll);
            assert_eq!(sweeps.len(), iterations, "one sweep per iteration");
            assert!(iterations < 1000);
            // The declared rate refills the bucket between real polls; do not
            // wait for it here, the bound per poll is what is under test.
            ingress.limits.admit_per_sec = u64::MAX / 4;
        }
        assert!(iterations >= 5, "the backlog took several iterations: {}", iterations);
        // The first sweep ran with most of the flood still unread.
        assert!(sweeps[0] < len / 2, "first sweep at offset {} of {}", sweeps[0], len);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_ingress_audit_log_sits_beside_the_normalized_log() {
        let mut cfg = sample_cfg();
        cfg.normalized_log_path = "/var/log/azazel-edge/normalized-events.jsonl".to_string();
        assert_eq!(ingress_audit_log_path(&cfg), "/var/log/azazel-edge/ingress-audit.jsonl");
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
            defense_release_ledger_path: "/tmp/azazel-edge-test-release-ledger.json".to_string(),
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

    #[test]
    fn owned_isolation_plan_has_release_comment_and_handle_template() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let task = build_release_task(
            "trace-test", "isolate", "br0", &ev.src_ip, ev.target_port, 2222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let plan = build_enforcement_plan_owned(&ev, &decision, "br0", 2222, Some(&task));
        assert!(plan.apply_commands.join("\n").contains(&task.owner_token));
        assert!(plan.rollback_commands.join("\n").contains("handle"));
    }

    #[test]
    fn owned_throttle_plan_has_unique_tc_handle() {
        let mut ev = sample_event();
        ev.severity = 3;
        let decision = decide_defense(&ev);
        let task = build_release_task(
            "trace-test", "throttle", "br0", &ev.src_ip, ev.target_port, 2222, decision.delay_ms, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let plan = build_enforcement_plan_owned(&ev, &decision, "br0", 2222, Some(&task));
        let flat = plan.apply_commands.join("\n");
        assert!(flat.contains("root handle"));
        assert!(flat.contains(&task.tc_handle));
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
    fn full_auto_allows_high_impact() {
        let allowed = action_allowlist("full-auto", false);
        assert!(allowed.contains(&"throttle".to_string()));
        assert!(allowed.contains(&"redirect".to_string()));
        assert!(allowed.contains(&"isolate".to_string()));
    }

    fn cfg_with_redirect_policy() -> Config {
        let mut cfg = sample_cfg();
        cfg.redirect_policy = Some(RedirectPolicyConfig {
            enabled: true,
            prepared_ports: HashMap::from([(22_u16, 12222_u16), (80_u16, 18080_u16), (8080_u16, 18080_u16)]),
            unsupported_port_action: "notify".to_string(),
            high_risk_unsupported_port_action: "isolate".to_string(),
            scan_burst_action: "throttle".to_string(),
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
    fn unsupported_high_risk_port_can_fallback_to_isolate() {
        let mut ev = sample_event();
        ev.severity = 2;
        ev.target_port = 5432;
        ev.risk_score = 95;
        let decision = decide_defense(&ev);
        let cfg = cfg_with_redirect_policy();
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.selected_action, "isolate");
        assert!(outcome.command_plan.join("\n").contains("input"));
        assert_eq!(outcome.metadata.get("unsupported_port_fallback").and_then(|v| v.as_str()), Some("isolate"));
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
}
