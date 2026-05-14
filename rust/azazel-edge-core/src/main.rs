use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Config {
    eve_path: String,
    ai_socket_path: String,
    normalized_log_path: String,
    from_start: bool,
    poll_ms: u64,
    forward_ai: bool,
    forward_log: bool,
    defense_enforce: bool,
    defense_dry_run: bool,
    defense_enforce_level: String,
    defense_action_ttl_sec: u64,
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
            eprintln!("redirect policy load failed, using honeypot fallback: {}", e);
            (None, format!("invalid_file_env_fallback:{}", redirect_policy_path))
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
        defense_enforce: env_bool("AZAZEL_DEFENSE_ENFORCE", false),
        defense_dry_run: env_bool("AZAZEL_DEFENSE_DRY_RUN", true),
        defense_enforce_level: env::var("AZAZEL_DEFENSE_ENFORCE_LEVEL").unwrap_or_else(|_| "advisory".to_string()),
        defense_action_ttl_sec: env::var("AZAZEL_DEFENSE_ACTION_TTL_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300),
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
    let sid = alert.get("sid").and_then(|x| x.as_u64()).unwrap_or(0);
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
    })
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
    let mut apply: Vec<Vec<String>> = Vec::new();
    let mut rollback: Vec<Vec<String>> = Vec::new();

    if decision.action == "isolate" {
        apply.push(vec![
            "nft".to_string(), "insert".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "input".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "drop".to_string(),
        ]);
        rollback.push(vec![
            "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "input".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "drop".to_string(),
        ]);
    }

    if decision.action == "throttle" {
        apply.push(vec![
            "tc".to_string(), "qdisc".to_string(), "replace".to_string(), "dev".to_string(), iface.to_string(), "root".to_string(),
            "tbf".to_string(), "rate".to_string(), "256kbit".to_string(), "burst".to_string(), "32kbit".to_string(),
            "latency".to_string(), format!("{}ms", decision.delay_ms.max(100)),
        ]);
        rollback.push(vec![
            "tc".to_string(), "qdisc".to_string(), "del".to_string(), "dev".to_string(), iface.to_string(), "root".to_string(),
        ]);
    }

    if decision.action == "redirect" {
        apply.push(vec![
            "nft".to_string(), "insert".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "prerouting".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "tcp".to_string(),
            "dport".to_string(), ev.target_port.to_string(), "redirect".to_string(), "to".to_string(), honeypot_port.to_string(),
        ]);
        rollback.push(vec![
            "nft".to_string(), "delete".to_string(), "rule".to_string(), "inet".to_string(), "azazel_edge".to_string(),
            "prerouting".to_string(), "ip".to_string(), "saddr".to_string(), ev.src_ip.clone(), "tcp".to_string(),
            "dport".to_string(), ev.target_port.to_string(), "redirect".to_string(), "to".to_string(), honeypot_port.to_string(),
        ]);
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

fn maybe_enforce(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config) -> EnforcementOutcome {
    let trace_id = calc_trace_id(ev, decision);
    let (effective_decision, redirect_meta) = resolve_redirect_decision(ev, decision, cfg);
    let selected_decoy_port = redirect_meta
        .get("selected_decoy_port")
        .and_then(|v| v.as_u64())
        .map(|v| v as u16)
        .unwrap_or(cfg.defense_honeypot_port);
    let plan = build_enforcement_plan(ev, &effective_decision, &cfg.defense_iface, selected_decoy_port);

    if plan.apply_commands.is_empty() {
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
        rollback_hint: format!("temporary action ttl={}s; execute rollback_plan when control is no longer needed", cfg.defense_action_ttl_sec),
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
                metadata["selected_decoy_port"] = json!(cfg.defense_honeypot_port);
                metadata["redirect_mapping_matched"] = json!(true);
                metadata["fallback_reason"] = json!("policy_disabled_env_honeypot_fallback");
                return (decision.clone(), metadata);
            }
            if let Some(mapped) = policy.prepared_ports.get(&ev.target_port) {
                metadata["selected_decoy_port"] = json!(mapped);
                metadata["redirect_mapping_matched"] = json!(true);
                metadata["fallback_reason"] = json!("prepared_mapping");
                return (decision.clone(), metadata);
            }

            let high_risk = ev.risk_score >= 80 || ev.severity <= 2;
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
            metadata["selected_decoy_port"] = json!(cfg.defense_honeypot_port);
            metadata["redirect_mapping_matched"] = json!(true);
            metadata["fallback_reason"] = json!("no_redirect_policy_file_env_honeypot_fallback");
            (decision.clone(), metadata)
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

fn send_to_ai_socket(socket_path: &str, value: &Value) {
    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        let line = format!("{}\n", value);
        let _ = stream.write_all(line.as_bytes());
    }
}

fn process_line(cfg: &Config, line: &str) {
    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return,
    };

    let normalized = match build_normalized_event(&parsed) {
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

    println!("{}", event);
}

fn read_new_lines(cfg: &Config, offset: &mut u64) {
    let path = Path::new(&cfg.eve_path);
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let len = metadata.len();
    if *offset > len {
        *offset = 0;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut reader = BufReader::new(file);
    if reader.seek(SeekFrom::Start(*offset)).is_err() {
        return;
    }

    let mut line = String::new();
    loop {
        line.clear();
        let n = match reader.read_line(&mut line) {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        process_line(cfg, line.trim_end());
    }

    if let Ok(pos) = reader.stream_position() {
        *offset = pos;
    }
}

fn main() {
    let cfg = load_config();

    if let Some(parent) = Path::new(&cfg.normalized_log_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let mut offset = if cfg.from_start { 0 } else { fs::metadata(&cfg.eve_path).map(|m| m.len()).unwrap_or(0) };

    eprintln!(
        "azazel-edge-core started: eve_path={}, ai_socket={}, from_start={}, poll_ms={}, defense_enforce={}, defense_dry_run={}, defense_enforce_level={}, high_impact_auto={}, defense_iface={}, honeypot_port={}",
        cfg.eve_path,
        cfg.ai_socket_path,
        cfg.from_start,
        cfg.poll_ms,
        cfg.defense_enforce,
        cfg.defense_dry_run,
        cfg.defense_enforce_level,
        cfg.defense_allow_high_impact_auto,
        cfg.defense_iface,
        cfg.defense_honeypot_port
    );

    loop {
        read_new_lines(&cfg, &mut offset);
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
        }
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
            defense_enforce: false,
            defense_dry_run: true,
            defense_enforce_level: "advisory".to_string(),
            defense_action_ttl_sec: 300,
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
