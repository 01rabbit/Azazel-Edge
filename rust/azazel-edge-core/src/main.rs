use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
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

fn maybe_enforce(_ev: &NormalizedEvent, _decision: &DefensiveDecision, enforce: bool) {
    if !enforce {
        return;
    }
    // Enforcement is intentionally disabled by default.
    // In enforce mode, wire this path to nftables/tc commands.
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
    maybe_enforce(&normalized, &decision, cfg.defense_enforce);

    let event = json!({
        "normalized": normalized,
        "defense": decision,
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
        "azazel-edge-core started: eve_path={}, ai_socket={}, from_start={}, poll_ms={}",
        cfg.eve_path, cfg.ai_socket_path, cfg.from_start, cfg.poll_ms
    );

    loop {
        read_new_lines(&cfg, &mut offset);
        thread::sleep(Duration::from_millis(cfg.poll_ms));
    }
}
