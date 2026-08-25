use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const LEDGER_SCHEMA_VERSION: &str = "azazel-release-ledger/v1";
const MAX_LEDGER_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LEDGER_TASKS: usize = 4096;
const MAX_TERMINAL_TASKS: usize = 512;
const MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const TRUSTED_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseTask {
    pub task_id: String,
    pub trace_id: String,
    pub action: String,
    pub resource_key: String,
    pub owner_token: String,
    pub iface: String,
    pub tc_handle: String,
    pub source_ip: String,
    pub destination_port: u16,
    pub redirect_port: u16,
    pub expected_rate_bps: u64,
    pub expected_burst_bytes: u64,
    pub expected_latency_us: u64,
    pub due_epoch: f64,
    pub next_attempt_epoch: f64,
    pub created_epoch: f64,
    pub updated_epoch: f64,
    pub status: String,
    pub attempts: u32,
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReleaseLedger {
    schema_version: String,
    tasks: Vec<ReleaseTask>,
}

impl Default for ReleaseLedger {
    fn default() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            tasks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseOutcome {
    pub release_task_id: String,
    pub trace_id: String,
    pub action: String,
    pub resource_key: String,
    pub owner_token: String,
    pub tc_handle: String,
    pub due_epoch: f64,
    pub attempted_at_epoch: f64,
    pub status: String,
    pub result: String,
    pub command_count: u32,
    pub failed_count: u32,
    pub errors: Vec<String>,
    pub postcondition: Value,
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait ReleaseCommandRunner {
    fn run(&self, argv: &[String]) -> Result<CommandResult, String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemReleaseCommandRunner;

impl ReleaseCommandRunner for SystemReleaseCommandRunner {
    fn run(&self, argv: &[String]) -> Result<CommandResult, String> {
        if !allowed_release_command(argv) {
            return Err(format!("release command rejected by allowlist: {:?}", argv));
        }
        let binary = resolve_trusted_binary(&argv[0])?;
        let mut command = Command::new(binary);
        command
            .args(&argv[1..])
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("PATH", TRUSTED_DIRS.join(":"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|e| format!("release command spawn failed: {e}"))?;
        let stdout = child.stdout.take().ok_or_else(|| "release stdout pipe unavailable".to_string())?;
        let stderr = child.stderr.take().ok_or_else(|| "release stderr pipe unavailable".to_string())?;
        let out_reader = thread::spawn(move || drain_capture(stdout, MAX_STDOUT_BYTES));
        let err_reader = thread::spawn(move || drain_capture(stderr, MAX_STDERR_BYTES));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < COMMAND_TIMEOUT => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_reader.join();
                    let _ = err_reader.join();
                    return Err("release command timeout".to_string());
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = out_reader.join();
                    let _ = err_reader.join();
                    return Err(format!("release command wait failed: {e}"));
                }
            }
        };
        let (stdout, stdout_exceeded) = out_reader.join().map_err(|_| "release stdout reader panicked".to_string())??;
        let (stderr, stderr_exceeded) = err_reader.join().map_err(|_| "release stderr reader panicked".to_string())??;
        if stdout_exceeded || stderr_exceeded {
            return Err("release command output exceeded safety bound".to_string());
        }
        Ok(CommandResult {
            returncode: status.code().unwrap_or(-1),
            stdout,
            stderr,
        })
    }
}

fn drain_capture<R: Read>(mut reader: R, limit: usize) -> Result<(String, bool), String> {
    let mut retained = Vec::new();
    let mut total = 0_usize;
    let mut buf = [0_u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("release output read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if retained.len() < limit {
            let remaining = limit - retained.len();
            retained.extend_from_slice(&buf[..n.min(remaining)]);
        }
    }
    Ok((String::from_utf8_lossy(&retained).into_owned(), total > limit))
}

pub fn build_release_task(
    trace_id: &str,
    action: &str,
    iface: &str,
    source_ip: &str,
    destination_port: u16,
    redirect_port: u16,
    delay_ms: u32,
    ttl_sec: u64,
    now_epoch: f64,
) -> Option<ReleaseTask> {
    let resource_key = match action {
        "throttle" => format!("tc:root:{iface}"),
        "isolate" => format!("nft:inet:azazel_edge:input:{source_ip}"),
        "redirect" => format!("nft:inet:azazel_edge:prerouting:{source_ip}:tcp:{destination_port}"),
        _ => return None,
    };
    let seed = format!("{trace_id}|{action}|{resource_key}");
    let task_id = format!("release-{:016x}", fnv1a64(seed.as_bytes()));
    let owner_token = format!("azazel-edge:{task_id}");
    let handle_major = ((fnv1a64(owner_token.as_bytes()) % 0xfffe) + 1) as u16;
    let tc_handle = if action == "throttle" {
        format!("{handle_major:x}:")
    } else {
        String::new()
    };
    let due_epoch = now_epoch + ttl_sec as f64;
    Some(ReleaseTask {
        task_id,
        trace_id: trace_id.to_string(),
        action: action.to_string(),
        resource_key,
        owner_token,
        iface: iface.to_string(),
        tc_handle,
        source_ip: source_ip.to_string(),
        destination_port,
        redirect_port,
        expected_rate_bps: if action == "throttle" { 256_000 } else { 0 },
        expected_burst_bytes: if action == "throttle" { 4096 } else { 0 },
        expected_latency_us: if action == "throttle" { delay_ms.max(100) as u64 * 1000 } else { 0 },
        due_epoch,
        next_attempt_epoch: due_epoch,
        created_epoch: now_epoch,
        updated_epoch: now_epoch,
        status: "prepared".to_string(),
        attempts: 0,
        last_error: String::new(),
    })
}

pub fn prepare_release_task(path: &str, task: &ReleaseTask) -> Result<(), String> {
    validate_task(task)?;
    let mut ledger = load_ledger(path)?;
    if let Some(existing) = ledger.tasks.iter().find(|item| item.task_id == task.task_id) {
        if existing.trace_id == task.trace_id
            && existing.action == task.action
            && existing.resource_key == task.resource_key
            && existing.owner_token == task.owner_token
        {
            return Ok(());
        }
        return Err("release task id collision".to_string());
    }
    if ledger.tasks.len() >= MAX_LEDGER_TASKS {
        compact_ledger(&mut ledger);
    }
    if ledger.tasks.len() >= MAX_LEDGER_TASKS {
        return Err("release ledger task limit reached".to_string());
    }
    ledger.tasks.push(task.clone());
    save_ledger(path, &mut ledger)
}

pub fn activate_release_task(path: &str, task_id: &str, now_epoch: f64) -> Result<(), String> {
    let mut ledger = load_ledger(path)?;
    let resource_key = ledger
        .tasks
        .iter()
        .find(|item| item.task_id == task_id)
        .map(|item| item.resource_key.clone())
        .ok_or_else(|| "release task missing during activation".to_string())?;
    for item in &mut ledger.tasks {
        if item.task_id != task_id && item.resource_key == resource_key && eligible_status(&item.status) {
            item.status = "superseded".to_string();
            item.updated_epoch = now_epoch;
            item.last_error = format!("superseded_by:{task_id}");
        }
    }
    let task = ledger
        .tasks
        .iter_mut()
        .find(|item| item.task_id == task_id)
        .ok_or_else(|| "release task missing during activation".to_string())?;
    task.status = "active".to_string();
    task.updated_epoch = now_epoch;
    task.last_error.clear();
    save_ledger(path, &mut ledger)
}

pub fn mark_release_task_uncertain(path: &str, task_id: &str, reason: &str, now_epoch: f64) -> Result<(), String> {
    update_task_status(path, task_id, "uncertain", reason, now_epoch)
}

pub fn cancel_release_task(path: &str, task_id: &str, reason: &str, now_epoch: f64) -> Result<(), String> {
    update_task_status(path, task_id, "cancelled", reason, now_epoch)
}

fn update_task_status(path: &str, task_id: &str, status: &str, reason: &str, now_epoch: f64) -> Result<(), String> {
    let mut ledger = load_ledger(path)?;
    let task = ledger
        .tasks
        .iter_mut()
        .find(|item| item.task_id == task_id)
        .ok_or_else(|| "release task missing".to_string())?;
    task.status = status.to_string();
    task.updated_epoch = now_epoch;
    task.last_error = reason.to_string();
    save_ledger(path, &mut ledger)
}

pub fn process_due_releases(path: &str, now_epoch: f64) -> Result<Vec<ReleaseOutcome>, String> {
    let runner = SystemReleaseCommandRunner;
    process_due_releases_with_runner(path, now_epoch, &runner)
}

pub fn process_due_releases_with_runner<R: ReleaseCommandRunner>(
    path: &str,
    now_epoch: f64,
    runner: &R,
) -> Result<Vec<ReleaseOutcome>, String> {
    let mut ledger = load_ledger(path)?;
    let mut outcomes = Vec::new();
    let candidates: Vec<String> = ledger
        .tasks
        .iter()
        .filter(|task| eligible_status(&task.status) && task.next_attempt_epoch <= now_epoch)
        .map(|task| task.task_id.clone())
        .collect();

    for task_id in candidates {
        let current = match ledger.tasks.iter().find(|task| task.task_id == task_id) {
            Some(task) if eligible_status(&task.status) => task.clone(),
            _ => continue,
        };
        if let Some(newer) = ledger.tasks.iter().find(|other| {
            other.task_id != current.task_id
                && other.resource_key == current.resource_key
                && eligible_status(&other.status)
                && other.created_epoch > current.created_epoch
        }) {
            if let Some(task) = ledger.tasks.iter_mut().find(|task| task.task_id == current.task_id) {
                task.status = "superseded".to_string();
                task.updated_epoch = now_epoch;
                task.last_error = format!("superseded_by:{}", newer.task_id);
            }
            outcomes.push(outcome_for(
                &current,
                now_epoch,
                "superseded",
                "superseded_by_newer_task",
                0,
                0,
                Vec::new(),
                json!({"verified": false, "reason": "newer_release_owner_exists"}),
            ));
            continue;
        }

        let result = release_owned_state(&current, runner, now_epoch);
        if let Some(task) = ledger.tasks.iter_mut().find(|task| task.task_id == current.task_id) {
            task.updated_epoch = now_epoch;
            task.attempts = task.attempts.saturating_add(1);
            match &result {
                Ok(outcome) if outcome.status == "released" => {
                    task.status = "released".to_string();
                    task.last_error.clear();
                    task.next_attempt_epoch = f64::INFINITY;
                }
                Ok(outcome) => {
                    task.last_error = outcome.errors.join("; ");
                    task.next_attempt_epoch = now_epoch + retry_delay_seconds(task.attempts);
                }
                Err(error) => {
                    task.last_error = error.clone();
                    task.next_attempt_epoch = now_epoch + retry_delay_seconds(task.attempts);
                }
            }
        }
        match result {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => outcomes.push(outcome_for(
                &current,
                now_epoch,
                "retry_pending",
                "release_attempt_failed",
                0,
                1,
                vec![error],
                json!({"verified": false}),
            )),
        }
    }
    save_ledger(path, &mut ledger)?;
    Ok(outcomes)
}

fn release_owned_state<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    runner: &R,
    now_epoch: f64,
) -> Result<ReleaseOutcome, String> {
    match task.action.as_str() {
        "throttle" => release_throttle(task, runner, now_epoch),
        "isolate" | "redirect" => release_nft_rule(task, runner, now_epoch),
        _ => Err("unsupported release action".to_string()),
    }
}

fn release_throttle<R: ReleaseCommandRunner>(task: &ReleaseTask, runner: &R, now_epoch: f64) -> Result<ReleaseOutcome, String> {
    let before = tc_owned_state_present(task, runner)?;
    if !before {
        return Ok(outcome_for(
            task,
            now_epoch,
            "released",
            "owned_state_already_absent",
            0,
            0,
            Vec::new(),
            json!({"verified": true, "owned_state_present": false}),
        ));
    }
    let argv = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "del".to_string(),
        "dev".to_string(),
        task.iface.clone(),
        "root".to_string(),
        "handle".to_string(),
        task.tc_handle.clone(),
    ];
    let result = runner.run(&argv)?;
    if result.returncode != 0 {
        return Ok(outcome_for(
            task,
            now_epoch,
            "retry_pending",
            "rollback_command_failed",
            1,
            1,
            vec![bounded_error(&result.stderr)],
            json!({"verified": false, "owned_state_present_before": true}),
        ));
    }
    let still_present = tc_owned_state_present(task, runner)?;
    if still_present {
        return Ok(outcome_for(
            task,
            now_epoch,
            "retry_pending",
            "release_postcondition_failed",
            1,
            1,
            vec!["owned tc handle remains after delete".to_string()],
            json!({"verified": false, "owned_state_present": true}),
        ));
    }
    Ok(outcome_for(
        task,
        now_epoch,
        "released",
        "rollback_applied_and_absence_verified",
        1,
        0,
        Vec::new(),
        json!({"verified": true, "owned_state_present": false}),
    ))
}

fn tc_owned_state_present<R: ReleaseCommandRunner>(task: &ReleaseTask, runner: &R) -> Result<bool, String> {
    let argv = vec![
        "tc".to_string(),
        "-j".to_string(),
        "qdisc".to_string(),
        "show".to_string(),
        "dev".to_string(),
        task.iface.clone(),
    ];
    let result = runner.run(&argv)?;
    if result.returncode != 0 {
        return Err(format!("tc readback failed: {}", bounded_error(&result.stderr)));
    }
    let payload: Value = serde_json::from_str(&result.stdout).map_err(|e| format!("tc readback parse failed: {e}"))?;
    let items = payload.as_array().ok_or_else(|| "tc readback was not an array".to_string())?;
    for item in items {
        if item.get("root").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if item.get("handle").and_then(Value::as_str) != Some(task.tc_handle.as_str()) {
            continue;
        }
        if item.get("kind").and_then(Value::as_str) != Some("tbf") {
            return Err("tc ownership handle exists with unexpected qdisc kind".to_string());
        }
        if !tbf_parameters_match(task, item) {
            return Err("tc ownership handle exists with unexpected TBF parameters".to_string());
        }
        return Ok(true);
    }
    Ok(false)
}

fn release_nft_rule<R: ReleaseCommandRunner>(task: &ReleaseTask, runner: &R, now_epoch: f64) -> Result<ReleaseOutcome, String> {
    let chain = if task.action == "isolate" { "input" } else { "prerouting" };
    let handles = nft_owned_handles(task, chain, runner)?;
    if handles.is_empty() {
        return Ok(outcome_for(
            task,
            now_epoch,
            "released",
            "owned_state_already_absent",
            0,
            0,
            Vec::new(),
            json!({"verified": true, "owned_rule_count": 0}),
        ));
    }
    let mut command_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut errors = Vec::new();
    for handle in handles {
        let argv = vec![
            "nft".to_string(),
            "delete".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            "azazel_edge".to_string(),
            chain.to_string(),
            "handle".to_string(),
            handle.to_string(),
        ];
        command_count += 1;
        match runner.run(&argv) {
            Ok(result) if result.returncode == 0 => {}
            Ok(result) => {
                failed_count += 1;
                errors.push(bounded_error(&result.stderr));
            }
            Err(error) => {
                failed_count += 1;
                errors.push(error);
            }
        }
    }
    if failed_count > 0 {
        return Ok(outcome_for(
            task,
            now_epoch,
            "retry_pending",
            "rollback_command_failed",
            command_count,
            failed_count,
            errors,
            json!({"verified": false}),
        ));
    }
    let remaining = nft_owned_handles(task, chain, runner)?;
    if !remaining.is_empty() {
        return Ok(outcome_for(
            task,
            now_epoch,
            "retry_pending",
            "release_postcondition_failed",
            command_count,
            1,
            vec!["owned nft rule remains after delete".to_string()],
            json!({"verified": false, "owned_rule_count": remaining.len()}),
        ));
    }
    Ok(outcome_for(
        task,
        now_epoch,
        "released",
        "rollback_applied_and_absence_verified",
        command_count,
        0,
        Vec::new(),
        json!({"verified": true, "owned_rule_count": 0}),
    ))
}

fn nft_owned_handles<R: ReleaseCommandRunner>(task: &ReleaseTask, chain: &str, runner: &R) -> Result<Vec<u64>, String> {
    let argv = vec![
        "nft".to_string(),
        "-a".to_string(),
        "-j".to_string(),
        "list".to_string(),
        "chain".to_string(),
        "inet".to_string(),
        "azazel_edge".to_string(),
        chain.to_string(),
    ];
    let result = runner.run(&argv)?;
    if result.returncode != 0 {
        return Err(format!("nft readback failed: {}", bounded_error(&result.stderr)));
    }
    let payload: Value = serde_json::from_str(&result.stdout).map_err(|e| format!("nft readback parse failed: {e}"))?;
    let entries = payload
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft readback missing nftables array".to_string())?;
    let mut handles = Vec::new();
    for entry in entries {
        let rule = match entry.get("rule") {
            Some(rule) => rule,
            None => continue,
        };
        if rule.get("chain").and_then(Value::as_str) != Some(chain) {
            continue;
        }
        if rule.get("comment").and_then(Value::as_str) != Some(task.owner_token.as_str()) {
            continue;
        }
        if !nft_rule_semantics_match(task, rule) {
            return Err("nft ownership tag exists on semantically different rule".to_string());
        }
        let handle = rule
            .get("handle")
            .and_then(Value::as_u64)
            .ok_or_else(|| "owned nft rule missing numeric handle".to_string())?;
        handles.push(handle);
    }
    Ok(handles)
}

fn nft_rule_semantics_match(task: &ReleaseTask, rule: &Value) -> bool {
    let exprs = match rule.get("expr").and_then(Value::as_array) {
        Some(exprs) => exprs,
        None => return false,
    };
    if match_value(exprs, "ip", "saddr").and_then(Value::as_str) != Some(task.source_ip.as_str()) {
        return false;
    }
    if task.action == "isolate" {
        return exprs.iter().any(|expr| expr.get("drop").is_some());
    }
    if task.action == "redirect" {
        if match_value(exprs, "tcp", "dport").and_then(value_u16) != Some(task.destination_port) {
            return false;
        }
        return exprs.iter().any(|expr| {
            expr.get("redirect")
                .and_then(|redirect| redirect.get("port"))
                .and_then(value_u16)
                == Some(task.redirect_port)
        });
    }
    false
}

fn match_value<'a>(exprs: &'a [Value], protocol: &str, field: &str) -> Option<&'a Value> {
    for expr in exprs {
        let matched = expr.get("match")?;
        if matched.get("op").and_then(Value::as_str) != Some("==") {
            continue;
        }
        let payload = matched.get("left")?.get("payload")?;
        if payload.get("protocol").and_then(Value::as_str) == Some(protocol)
            && payload.get("field").and_then(Value::as_str) == Some(field)
        {
            return matched.get("right");
        }
    }
    None
}

fn value_u16(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|v| u16::try_from(v).ok())
        .or_else(|| value.as_str().and_then(|v| v.parse::<u16>().ok()))
}

fn tbf_parameters_match(task: &ReleaseTask, item: &Value) -> bool {
    let rate = item.get("rate").and_then(parse_readback_rate_bps);
    let burst = item.get("burst").and_then(parse_readback_size_bytes);
    let latency = item.get("lat").and_then(parse_readback_time_us);
    match (rate, burst, latency) {
        (Some(rate), Some(burst), Some(latency)) => {
            within_relative(task.expected_rate_bps, rate, 0.01)
                && within_relative(task.expected_burst_bytes, burst, 0.02)
                && abs_diff(task.expected_latency_us, latency) <= 1000.max(task.expected_latency_us / 50)
        }
        _ => false,
    }
}

fn parse_readback_rate_bps(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return raw.checked_mul(8);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(&raw, &[("gbit", 1_000_000_000), ("mbit", 1_000_000), ("kbit", 1_000), ("bit", 1)])
}

fn parse_readback_size_bytes(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return Some(raw);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(
        &raw,
        &[("gbit", 1024 * 1024 * 1024 / 8), ("mbit", 1024 * 1024 / 8), ("kbit", 1024 / 8), ("gb", 1024 * 1024 * 1024), ("mb", 1024 * 1024), ("kb", 1024), ("b", 1)],
    )
}

fn parse_readback_time_us(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return Some(raw);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(&raw, &[("msec", 1000), ("usec", 1), ("ms", 1000), ("us", 1), ("sec", 1_000_000), ("s", 1_000_000)])
}

fn parse_scaled(raw: &str, suffixes: &[(&str, u64)]) -> Option<u64> {
    for (suffix, factor) in suffixes {
        if let Some(number) = raw.strip_suffix(suffix) {
            let parsed = number.parse::<f64>().ok()?;
            if !parsed.is_finite() || parsed < 0.0 {
                return None;
            }
            return Some((parsed * *factor as f64).round() as u64);
        }
    }
    raw.parse::<u64>().ok()
}

fn within_relative(expected: u64, observed: u64, tolerance: f64) -> bool {
    if expected == 0 {
        return observed == 0;
    }
    abs_diff(expected, observed) <= ((expected as f64 * tolerance).round() as u64).max(1)
}

fn abs_diff(left: u64, right: u64) -> u64 {
    left.max(right) - left.min(right)
}

fn outcome_for(
    task: &ReleaseTask,
    now_epoch: f64,
    status: &str,
    result: &str,
    command_count: u32,
    failed_count: u32,
    errors: Vec<String>,
    postcondition: Value,
) -> ReleaseOutcome {
    ReleaseOutcome {
        release_task_id: task.task_id.clone(),
        trace_id: task.trace_id.clone(),
        action: task.action.clone(),
        resource_key: task.resource_key.clone(),
        owner_token: task.owner_token.clone(),
        tc_handle: task.tc_handle.clone(),
        due_epoch: task.due_epoch,
        attempted_at_epoch: now_epoch,
        status: status.to_string(),
        result: result.to_string(),
        command_count,
        failed_count,
        errors,
        postcondition,
    }
}

fn retry_delay_seconds(attempts: u32) -> f64 {
    let power = attempts.min(8);
    (2_u64.pow(power) as f64).min(300.0)
}

fn eligible_status(status: &str) -> bool {
    matches!(status, "prepared" | "active" | "uncertain")
}

fn terminal_status(status: &str) -> bool {
    matches!(status, "released" | "cancelled" | "superseded")
}

fn load_ledger(path: &str) -> Result<ReleaseLedger, String> {
    let source = Path::new(path);
    if !source.exists() {
        return Ok(ReleaseLedger::default());
    }
    let metadata = fs::symlink_metadata(source).map_err(|e| format!("release ledger metadata failed: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("release ledger must be a regular non-symlink file".to_string());
    }
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err("release ledger exceeds safety size bound".to_string());
    }
    let raw = fs::read_to_string(source).map_err(|e| format!("release ledger read failed: {e}"))?;
    let ledger: ReleaseLedger = serde_json::from_str(&raw).map_err(|e| format!("release ledger parse failed: {e}"))?;
    if ledger.schema_version != LEDGER_SCHEMA_VERSION {
        return Err("unsupported release ledger schema".to_string());
    }
    if ledger.tasks.len() > MAX_LEDGER_TASKS {
        return Err("release ledger task count exceeds safety bound".to_string());
    }
    for task in &ledger.tasks {
        validate_task(task)?;
    }
    Ok(ledger)
}

fn save_ledger(path: &str, ledger: &mut ReleaseLedger) -> Result<(), String> {
    compact_ledger(ledger);
    let destination = Path::new(path);
    let parent = destination.parent().ok_or_else(|| "release ledger path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("release ledger mkdir failed: {e}"))?;
    if destination.exists() {
        let metadata = fs::symlink_metadata(destination).map_err(|e| format!("release ledger metadata failed: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("release ledger destination is not a regular file".to_string());
        }
    }
    let encoded = serde_json::to_vec(ledger).map_err(|e| format!("release ledger serialize failed: {e}"))?;
    if encoded.len() as u64 > MAX_LEDGER_BYTES {
        return Err("release ledger encoded size exceeds safety bound".to_string());
    }
    let temp = temp_path(destination);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| format!("release ledger temp create failed: {e}"))?;
    if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(format!("release ledger durable write failed: {error}"));
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(format!("release ledger atomic rename failed: {error}"));
    }
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn compact_ledger(ledger: &mut ReleaseLedger) {
    if ledger.tasks.len() <= MAX_TERMINAL_TASKS {
        return;
    }
    let mut terminal: Vec<ReleaseTask> = ledger.tasks.iter().filter(|task| terminal_status(&task.status)).cloned().collect();
    terminal.sort_by(|a, b| b.updated_epoch.partial_cmp(&a.updated_epoch).unwrap_or(std::cmp::Ordering::Equal));
    terminal.truncate(MAX_TERMINAL_TASKS);
    let mut retained: Vec<ReleaseTask> = ledger.tasks.iter().filter(|task| !terminal_status(&task.status)).cloned().collect();
    retained.extend(terminal);
    ledger.tasks = retained;
}

fn validate_task(task: &ReleaseTask) -> Result<(), String> {
    if task.task_id.is_empty() || task.trace_id.is_empty() || task.resource_key.is_empty() || task.owner_token.is_empty() {
        return Err("release task missing identity fields".to_string());
    }
    if !matches!(task.action.as_str(), "throttle" | "isolate" | "redirect") {
        return Err("release task has unsupported action".to_string());
    }
    if !task.due_epoch.is_finite() || !task.next_attempt_epoch.is_finite() || !task.created_epoch.is_finite() || !task.updated_epoch.is_finite() {
        return Err("release task contains non-finite time".to_string());
    }
    if task.action == "throttle" && (!valid_interface(&task.iface) || !valid_tc_handle(&task.tc_handle)) {
        return Err("release task has invalid tc ownership".to_string());
    }
    Ok(())
}

fn temp_path(destination: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let name = destination.file_name().and_then(|value| value.to_str()).unwrap_or("release-ledger");
    destination.with_file_name(format!(".{name}.tmp.{}.{}", std::process::id(), stamp))
}

fn resolve_trusted_binary(name: &str) -> Result<PathBuf, String> {
    if !matches!(name, "tc" | "nft") {
        return Err("unsupported release binary".to_string());
    }
    for directory in TRUSTED_DIRS {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("release binary not found in trusted directories: {name}"))
}

fn allowed_release_command(argv: &[String]) -> bool {
    if argv.len() == 6
        && argv[0] == "tc"
        && argv[1] == "-j"
        && argv[2] == "qdisc"
        && argv[3] == "show"
        && argv[4] == "dev"
    {
        return valid_interface(&argv[5]);
    }
    if argv.len() == 8
        && argv[0] == "tc"
        && argv[1] == "qdisc"
        && argv[2] == "del"
        && argv[3] == "dev"
        && argv[5] == "root"
        && argv[6] == "handle"
    {
        return valid_interface(&argv[4]) && valid_tc_handle(&argv[7]);
    }
    if argv.len() == 8
        && argv[0] == "nft"
        && argv[1] == "-a"
        && argv[2] == "-j"
        && argv[3] == "list"
        && argv[4] == "chain"
        && argv[5] == "inet"
        && argv[6] == "azazel_edge"
    {
        return matches!(argv[7].as_str(), "input" | "prerouting");
    }
    if argv.len() == 8
        && argv[0] == "nft"
        && argv[1] == "delete"
        && argv[2] == "rule"
        && argv[3] == "inet"
        && argv[4] == "azazel_edge"
        && argv[6] == "handle"
    {
        return matches!(argv[5].as_str(), "input" | "prerouting") && argv[7].parse::<u64>().is_ok();
    }
    false
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
}

fn valid_tc_handle(value: &str) -> bool {
    let Some(raw) = value.strip_suffix(':') else {
        return false;
    };
    !raw.is_empty() && raw.len() <= 4 && u16::from_str_radix(raw, 16).map(|v| v > 0).unwrap_or(false)
}

fn bounded_error(value: &str) -> String {
    value.chars().take(512).collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FakeRunner {
        results: Mutex<VecDeque<Result<CommandResult, String>>>,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl FakeRunner {
        fn new(results: Vec<Result<CommandResult, String>>) -> Self {
            Self {
                results: Mutex::new(results.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ReleaseCommandRunner for FakeRunner {
        fn run(&self, argv: &[String]) -> Result<CommandResult, String> {
            self.calls.lock().unwrap().push(argv.to_vec());
            self.results.lock().unwrap().pop_front().unwrap_or_else(|| Err("missing fake result".to_string()))
        }
    }

    fn ok_json(value: Value) -> Result<CommandResult, String> {
        Ok(CommandResult {
            returncode: 0,
            stdout: value.to_string(),
            stderr: String::new(),
        })
    }

    fn test_path(name: &str) -> String {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("azazel-release-test-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name).to_string_lossy().to_string()
    }

    #[test]
    fn task_identity_is_stable_and_owned() {
        let one = build_release_task("trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, 100.0).unwrap();
        let two = build_release_task("trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, 100.0).unwrap();
        assert_eq!(one.task_id, two.task_id);
        assert_eq!(one.owner_token, two.owner_token);
        assert!(valid_tc_handle(&one.tc_handle));
        assert_eq!(one.expected_burst_bytes, 4096);
    }

    #[test]
    fn prepare_is_idempotent_and_activation_supersedes_older_resource_owner() {
        let path = test_path("ledger.json");
        let first = build_release_task("trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, 100.0).unwrap();
        let second = build_release_task("trace-b", "throttle", "br0", "10.0.0.9", 22, 12222, 1000, 300, 110.0).unwrap();
        prepare_release_task(&path, &first).unwrap();
        prepare_release_task(&path, &first).unwrap();
        activate_release_task(&path, &first.task_id, 101.0).unwrap();
        prepare_release_task(&path, &second).unwrap();
        activate_release_task(&path, &second.task_id, 111.0).unwrap();
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks.len(), 2);
        assert_eq!(ledger.tasks.iter().find(|v| v.task_id == first.task_id).unwrap().status, "superseded");
        assert_eq!(ledger.tasks.iter().find(|v| v.task_id == second.task_id).unwrap().status, "active");
    }

    #[test]
    fn prepared_task_survives_restart_and_absent_owned_state_closes_release() {
        let path = test_path("ledger.json");
        let mut task = build_release_task("trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, 100.0).unwrap();
        task.next_attempt_epoch = 101.0;
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, 102.0, &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].result, "owned_state_already_absent");
        assert_eq!(load_ledger(&path).unwrap().tasks[0].status, "released");
    }

    #[test]
    fn nft_release_deletes_only_owned_handle_and_verifies_absence() {
        let path = test_path("ledger.json");
        let mut task = build_release_task("trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, 100.0).unwrap();
        task.status = "active".to_string();
        task.next_attempt_epoch = 101.0;
        prepare_release_task(&path, &task).unwrap();
        let owned = json!({
            "nftables": [{"rule": {
                "chain": "input",
                "handle": 42,
                "comment": task.owner_token,
                "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.8"}},
                    {"drop": null}
                ]
            }}]
        });
        let runner = FakeRunner::new(vec![
            ok_json(owned),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: String::new() }),
            ok_json(json!({"nftables": []})),
        ]);
        let outcomes = process_due_releases_with_runner(&path, 102.0, &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| call == &vec!["nft", "delete", "rule", "inet", "azazel_edge", "input", "handle", "42"].iter().map(|v| v.to_string()).collect::<Vec<_>>()));
    }

    #[test]
    fn ownership_tag_semantic_mismatch_never_deletes_rule() {
        let path = test_path("ledger.json");
        let mut task = build_release_task("trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, 100.0).unwrap();
        task.status = "active".to_string();
        task.next_attempt_epoch = 101.0;
        prepare_release_task(&path, &task).unwrap();
        let poisoned = json!({
            "nftables": [{"rule": {
                "chain": "input",
                "handle": 42,
                "comment": task.owner_token,
                "expr": [
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.99"}},
                    {"drop": null}
                ]
            }}]
        });
        let runner = FakeRunner::new(vec![ok_json(poisoned)]);
        let outcomes = process_due_releases_with_runner(&path, 102.0, &runner).unwrap();
        assert_eq!(outcomes[0].status, "retry_pending");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn tc_release_never_deletes_different_owner_handle() {
        let path = test_path("ledger.json");
        let mut task = build_release_task("trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 1, 100.0).unwrap();
        task.status = "active".to_string();
        task.next_attempt_epoch = 101.0;
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!([{
            "kind": "tbf",
            "root": true,
            "handle": "ffff:",
            "rate": 32000,
            "burst": 4096,
            "lat": 1_000_000
        }]))]);
        let outcomes = process_due_releases_with_runner(&path, 102.0, &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].result, "owned_state_already_absent");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn release_command_allowlist_rejects_arbitrary_mutation() {
        assert!(!allowed_release_command(&vec!["nft", "flush", "ruleset"].iter().map(|v| v.to_string()).collect::<Vec<_>>()));
        assert!(!allowed_release_command(&vec!["tc", "qdisc", "del", "dev", "br0;id", "root", "handle", "1:"].iter().map(|v| v.to_string()).collect::<Vec<_>>()));
    }
}
