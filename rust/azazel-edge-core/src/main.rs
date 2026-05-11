use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, File, OpenOptions};
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
    defense_iface: String,
    defense_honeypot_port: u16,
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
    decision: String,
    reason: String,
    delay_ms: u32,
    should_block: bool,
    should_honeypot: bool,
}

#[derive(Debug, Clone, Serialize)]
struct EnforcementOutcome {
    mode: String,
    commands: Vec<String>,
    executed_count: u32,
    failed_count: u32,
    errors: Vec<String>,
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
        defense_iface: env::var("AZAZEL_DEFENSE_IFACE").unwrap_or_else(|_| "br0".to_string()),
        defense_honeypot_port: env::var("AZAZEL_DEFENSE_HONEYPOT_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(2222),
    }
}

fn build_normalized_event(v: &Value) -> Option<NormalizedEvent> {
    let event_type = v.get("event_type")?.as_str()?.to_string();
    if event_type != "alert" {
        return None;
    }

    let alert = v.get("alert").and_then(|x| x.as_object())?;
    let severity = alert
        .get("severity")
        .and_then(|x| x.as_u64())
        .unwrap_or(3)
        .min(10) as u8;
    let sid = alert.get("sid").and_then(|x| x.as_u64()).unwrap_or(0);
    let attack_type = alert
        .get("signature")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let category = alert
        .get("category")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();

    let dst_port = v
        .get("dest_port")
        .and_then(|x| x.as_u64())
        .unwrap_or(0)
        .min(u16::MAX as u64) as u16;

    let protocol = v
        .get("proto")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();

    let action = alert
        .get("action")
        .and_then(|x| x.as_str())
        .unwrap_or("allowed")
        .to_string();

    let risk_score = ((11_u16.saturating_sub(severity as u16)) * 9).min(100) as u8;
    let confidence = if sid > 0 { 90 } else { 50 };

    Some(NormalizedEvent {
        ts: v
            .get("timestamp")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        src_ip: v
            .get("src_ip")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
        dst_ip: v
            .get("dest_ip")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
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
            decision: "block_and_honeypot".to_string(),
            reason: format!("critical severity sid={}", ev.sid),
            delay_ms: 0,
            should_block: true,
            should_honeypot: true,
        };
    }

    if ev.severity <= 2 {
        return DefensiveDecision {
            decision: "delay_and_observe".to_string(),
            reason: format!("high severity sid={}", ev.sid),
            delay_ms: 800,
            should_block: false,
            should_honeypot: true,
        };
    }

    DefensiveDecision {
        decision: "observe".to_string(),
        reason: "normal baseline telemetry".to_string(),
        delay_ms: 0,
        should_block: false,
        should_honeypot: false,
    }
}

fn shell_quote(raw: &str) -> String {
    if raw.is_empty() {
        "''".to_string()
    } else if raw
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-' | '/'))
    {
        raw.to_string()
    } else {
        format!("'{}'", raw.replace('\'', "'\\''"))
    }
}

fn command_to_string(argv: &[String]) -> String {
    argv.iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<String>>()
        .join(" ")
}

fn build_enforcement_commands(
    ev: &NormalizedEvent,
    decision: &DefensiveDecision,
    iface: &str,
    honeypot_port: u16,
) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();

    if decision.should_block {
        out.push(vec![
            "nft".to_string(),
            "insert".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            "azazel_edge".to_string(),
            "input".to_string(),
            "ip".to_string(),
            "saddr".to_string(),
            ev.src_ip.clone(),
            "drop".to_string(),
        ]);
    }

    if decision.delay_ms > 0 {
        out.push(vec![
            "tc".to_string(),
            "qdisc".to_string(),
            "replace".to_string(),
            "dev".to_string(),
            iface.to_string(),
            "root".to_string(),
            "tbf".to_string(),
            "rate".to_string(),
            "256kbit".to_string(),
            "burst".to_string(),
            "32kbit".to_string(),
            "latency".to_string(),
            format!("{}ms", decision.delay_ms.max(100)),
        ]);
    }

    if decision.should_honeypot {
        out.push(vec![
            "nft".to_string(),
            "insert".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            "azazel_edge".to_string(),
            "prerouting".to_string(),
            "ip".to_string(),
            "saddr".to_string(),
            ev.src_ip.clone(),
            "tcp".to_string(),
            "dport".to_string(),
            ev.target_port.to_string(),
            "redirect".to_string(),
            "to".to_string(),
            honeypot_port.to_string(),
        ]);
    }

    out
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

fn maybe_enforce(ev: &NormalizedEvent, decision: &DefensiveDecision, cfg: &Config) -> EnforcementOutcome {
    let commands = build_enforcement_commands(ev, decision, &cfg.defense_iface, cfg.defense_honeypot_port);
    let rendered = commands
        .iter()
        .map(|argv| command_to_string(argv))
        .collect::<Vec<String>>();

    if commands.is_empty() {
        return EnforcementOutcome {
            mode: "disabled".to_string(),
            commands: rendered,
            executed_count: 0,
            failed_count: 0,
            errors: Vec::new(),
        };
    }

    if !cfg.defense_enforce || cfg.defense_dry_run {
        return EnforcementOutcome {
            mode: "dry_run".to_string(),
            commands: rendered,
            executed_count: 0,
            failed_count: 0,
            errors: Vec::new(),
        };
    }

    let mut executed_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut errors: Vec<String> = Vec::new();
    for cmd in &commands {
        match run_command(cmd) {
            Ok(_) => executed_count += 1,
            Err(e) => {
                failed_count += 1;
                errors.push(e);
            }
        }
    }

    EnforcementOutcome {
        mode: "enforced".to_string(),
        commands: rendered,
        executed_count,
        failed_count,
        errors,
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

    let mut offset = if cfg.from_start {
        0
    } else {
        fs::metadata(&cfg.eve_path).map(|m| m.len()).unwrap_or(0)
    };

    eprintln!(
        "azazel-edge-core started: eve_path={}, ai_socket={}, from_start={}, poll_ms={}, defense_enforce={}, defense_dry_run={}, defense_iface={}, honeypot_port={}",
        cfg.eve_path,
        cfg.ai_socket_path,
        cfg.from_start,
        cfg.poll_ms,
        cfg.defense_enforce,
        cfg.defense_dry_run,
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

    #[test]
    fn build_enforcement_commands_for_critical_event() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let commands = build_enforcement_commands(&ev, &decision, "br0", 2222);
        assert!(!commands.is_empty());
        let flat = commands
            .iter()
            .map(|c| c.join(" "))
            .collect::<Vec<String>>()
            .join("\n");
        assert!(flat.contains("nft"));
        assert!(flat.contains("redirect"));
    }

    #[test]
    fn maybe_enforce_is_dry_run_when_enforce_is_false() {
        let ev = sample_event();
        let decision = decide_defense(&ev);
        let cfg = Config {
            eve_path: "".to_string(),
            ai_socket_path: "".to_string(),
            normalized_log_path: "".to_string(),
            from_start: false,
            poll_ms: 100,
            forward_ai: false,
            forward_log: false,
            defense_enforce: false,
            defense_dry_run: true,
            defense_iface: "br0".to_string(),
            defense_honeypot_port: 2222,
        };
        let outcome = maybe_enforce(&ev, &decision, &cfg);
        assert_eq!(outcome.mode, "dry_run");
        assert_eq!(outcome.executed_count, 0);
        assert_eq!(outcome.failed_count, 0);
        assert!(!outcome.commands.is_empty());
    }
}
