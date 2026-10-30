use crate::audit_chain;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The ledger this core writes. v2 adds the replay checkpoint (generation
/// migration) and the lease fields of the flow-scoped throttle; a v1 ledger
/// (an older core, or the SO-04 harness) is read and rewritten as v2. An older
/// core refuses a v2 ledger instead of ignoring its checkpoint.
const LEDGER_SCHEMA_VERSION: &str = "azazel-release-ledger/v2";
const LEDGER_SCHEMA_V1: &str = "azazel-release-ledger/v1";
const MAX_LEDGER_BYTES: u64 = 2 * 1024 * 1024;
const MAX_LEDGER_TASKS: usize = 4096;
/// New leases are admitted only while the ledger is below these marks; what
/// lies above them is kept for the release path (status and error updates of
/// leases already granted), so releasing never fails on capacity.
const ADMIT_MAX_TASKS: usize = MAX_LEDGER_TASKS * 7 / 8;
const ADMIT_MAX_BYTES: u64 = MAX_LEDGER_BYTES * 3 / 4;
/// At or above these marks admission first compacts the ledger (generation
/// migration) and the capacity report says `warning`.
const COMPACT_AT_TASKS: usize = MAX_LEDGER_TASKS * 3 / 4;
const COMPACT_AT_BYTES: u64 = MAX_LEDGER_BYTES / 2;
const MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// The owned nft chain of the flow-scoped temporary restriction.
pub const THROTTLE_CHAIN: &str = "throttle";
/// `ReleaseTask::mechanism` of a flow-scoped nft rate limit. An empty
/// mechanism is a lease written before it existed: a throttle is then the
/// legacy root TBF qdisc, which is still released but never applied.
pub const MECHANISM_NFT_FLOW_LIMIT: &str = "nft_flow_limit";
/// `ReleaseTask::mechanism` of a flow-scoped decoy redirect: ingress
/// interface, source, destination and TCP port. An empty mechanism on a
/// redirect is a legacy lease (source and port only), released only.
pub const MECHANISM_NFT_FLOW_REDIRECT: &str = "nft_flow_redirect";
/// Protocols a flow-scoped lease may name. TCP/UDP always with a port;
/// ICMP/ICMPv6 never with one, matched by `meta l4proto`.
pub const FLOW_PROTOCOLS: [&str; 4] = ["tcp", "udp", "icmp", "ipv6-icmp"];

pub fn protocol_has_port(protocol: &str) -> bool {
    matches!(protocol, "tcp" | "udp")
}
const TRUSTED_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];
/// The audit-chain kind stating that rollback of a lease has begun (SO-04).
pub const ROLLBACK_STARTED_KIND: &str = "rollback_started";
/// The payload shape of a `rollback_started` record. The chain format itself
/// is `P0AuditLogger`'s and is unchanged.
pub const ROLLBACK_STARTED_SCHEMA: &str = "azazel-edge/rollback-started/v1";
const ROLLBACK_AUDIT_SOURCE: &str = "azazel-edge-core/release_engine";
/// When both deadlines have passed, the wall deadline is named as the one
/// that fired only if it passed this much earlier than the monotonic one.
/// Below it the two are the same instant read twice (read skew); above it the
/// wall clock was stepped forward. It only names the clock in the records;
/// whether the lease expires never depends on it.
pub const WALL_ATTRIBUTION_TOLERANCE_NS: i128 = 50_000_000;
const MAX_BOOT_ID_LEN: usize = 64;

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
    /// The lease's expiry on `CLOCK_BOOTTIME`, beside the wall-clock
    /// `due_epoch`; the lease expires at whichever passes first. Absent on a
    /// lease written before this field existed, or created when the clock or
    /// the boot identity could not be read: such a lease keeps wall-clock-only
    /// expiry and none is invented for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_boottime_ns: Option<u64>,
    /// The boot (`/proc/sys/kernel/random/boot_id`) `due_boottime_ns` belongs
    /// to. In any other boot, or when it cannot be compared, the monotonic
    /// deadline counts as already passed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub due_boot_id: String,
    /// When the next retry is due on `CLOCK_BOOTTIME`, beside the wall-clock
    /// `next_attempt_epoch`; a retry is due when either says so. Set only for
    /// a lease with a monotonic deadline, and only when the clock and the
    /// boot id could be read when the retry was scheduled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_boottime_ns: Option<u64>,
    /// The boot `next_attempt_boottime_ns` belongs to.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_attempt_boot_id: String,
    /// How the restriction is held (`MECHANISM_NFT_FLOW_LIMIT`); empty for
    /// isolate/redirect rules and for a legacy throttle.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mechanism: String,
    /// The flow's destination (flow-scoped throttle only).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination_ip: String,
    /// `tcp`, `udp`, or empty when the restriction matches no port.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    /// nft `limit rate over <n> kbytes/second burst <m> kbytes`.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub limit_rate_kbytes: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub limit_burst_kbytes: u32,
    /// The alert's own time (EVE timestamp), the replay checkpoint's basis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_epoch: Option<f64>,
    /// When the first lease of this resource in the current family began:
    /// a family is bounded to `MAX_CUMULATIVE_LEASE_SEC` in total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_started_epoch: Option<f64>,
    /// How many times this lease's expiry has been extended.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub extensions: u32,
    /// The alert's own identity (time, addresses, port, protocol, sid),
    /// independent of the action and of how it is held: the replay guard
    /// that survives a change of mechanism or of the decided action.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub event_key: String,
    /// Set on the lease that brought its family to the cumulative bound:
    /// from that bound until this time the flow is in cooldown and is not
    /// restricted again (notify only). Kept in the ledger, so it holds
    /// across restarts; the task outlives it there (`COMPACT_MIN_AGE_SEC`
    /// is longer than `FLOW_COOLDOWN_SEC`), so a generation migration cannot
    /// drop it early.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_until_epoch: Option<f64>,
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// Edge-fixed lease bounds. They are compiled in: no environment variable or
/// file raises them.
pub const MIN_LEASE_TTL_SEC: u64 = 30;
pub const MAX_LEASE_TTL_SEC: u64 = 900;
pub const MAX_LEASE_EXTENSIONS: u32 = 3;
pub const MAX_CUMULATIVE_LEASE_SEC: u64 = 3600;
/// Leases restricting traffic at once; above it a new restriction is refused
/// (notify) rather than widening the restricted set.
pub const MAX_ACTIVE_LEASES: usize = 64;
/// A terminal task leaves the ledger (into the checkpoint) only this long
/// after its last change. It is longer than a lease family can last and than
/// an alert may be old and still acted on, so a compacted task's alert is
/// already refused as stale on a correct clock; the checkpoint watermark
/// keeps refusing it when the wall clock is stepped back.
pub const COMPACT_MIN_AGE_SEC: f64 = (MAX_CUMULATIVE_LEASE_SEC + 600) as f64;
/// After a flow's lease family reaches `MAX_CUMULATIVE_LEASE_SEC`, the flow
/// is not restricted again for this long (owner decision 2026-10-30): its
/// alerts are notified only. Compiled in; nothing in the environment or a
/// file changes it. It never makes a restriction longer or permanent.
pub const FLOW_COOLDOWN_SEC: u64 = 900;
// A cooldown must outlive neither the task that carries it nor a compaction.
const _: () = assert!((FLOW_COOLDOWN_SEC as f64) < COMPACT_MIN_AGE_SEC);

/// The clocks a lease is created and expired against, read together.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseNow {
    pub wall_epoch: f64,
    /// `CLOCK_BOOTTIME`; `None` when it cannot be read.
    pub boottime_ns: Option<u64>,
    /// This boot's id; `None` when it cannot be read.
    pub boot_id: Option<String>,
}

impl LeaseNow {
    /// The node's clocks now, with `wall_epoch` as the wall reading.
    pub fn read(wall_epoch: f64) -> Self {
        let boot_id = audit_chain::boot_id();
        Self {
            wall_epoch,
            boottime_ns: audit_chain::boottime_ns(),
            boot_id: if boot_id.is_empty() { None } else { Some(boot_id) },
        }
    }

    /// Only a wall reading: a lease created from it has no monotonic
    /// deadline, and a lease that has one counts as `boot_unknown`. Tests
    /// only; the daemon always reads the node's clocks.
    #[cfg(test)]
    pub fn wall_only(wall_epoch: f64) -> Self {
        Self {
            wall_epoch,
            boottime_ns: None,
            boot_id: None,
        }
    }
}

/// Which deadline expired a lease (program plan section 4.3: the earlier of
/// the wall and monotonic deadlines wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryClock {
    /// The wall deadline passed and the monotonic one had not (or passed
    /// materially later): the wall clock was stepped forward.
    Wall,
    /// The monotonic deadline passed on this boot.
    Monotonic,
    /// The monotonic deadline belongs to another boot: counted as passed.
    BootChanged,
    /// The boot id or `CLOCK_BOOTTIME` cannot be read now, or the lease names
    /// no boot: the monotonic deadline cannot be checked, counted as passed.
    BootUnknown,
    /// The lease's own boot id or monotonic deadline is malformed (not as
    /// the core writes them): it cannot be checked, counted as passed. Only
    /// this lease is affected; the ledger is still read.
    BootInvalid,
    /// The lease has no monotonic deadline; its wall deadline passed.
    Legacy,
}

impl ExpiryClock {
    pub fn as_str(self) -> &'static str {
        match self {
            ExpiryClock::Wall => "wall",
            ExpiryClock::Monotonic => "monotonic",
            ExpiryClock::BootChanged => "boot_changed",
            ExpiryClock::BootUnknown => "boot_unknown",
            ExpiryClock::BootInvalid => "boot_invalid",
            ExpiryClock::Legacy => "legacy",
        }
    }
}

/// Whether the lease has expired at `now`, and on which clock; `None` while
/// it has not. A monotonic deadline can only make a lease expire earlier than
/// its wall deadline would, never later: a wall clock stepped backward no
/// longer extends a lease, and one stepped forward still expires it early.
pub fn lease_expiry(task: &ReleaseTask, now: &LeaseNow) -> Option<ExpiryClock> {
    let wall_passed = task.due_epoch <= now.wall_epoch;
    let Some(due_boottime_ns) = task.due_boottime_ns else {
        return wall_passed.then_some(ExpiryClock::Legacy);
    };
    if due_boottime_ns > i64::MAX as u64 || (!task.due_boot_id.is_empty() && !valid_boot_id(&task.due_boot_id)) {
        return Some(ExpiryClock::BootInvalid);
    }
    let (Some(boot_id), Some(boottime_ns)) = (now.boot_id.as_deref(), now.boottime_ns) else {
        return Some(ExpiryClock::BootUnknown);
    };
    if task.due_boot_id.is_empty() {
        return Some(ExpiryClock::BootUnknown);
    }
    if task.due_boot_id != boot_id {
        return Some(ExpiryClock::BootChanged);
    }
    let monotonic_overshoot = i128::from(boottime_ns) - i128::from(due_boottime_ns);
    match (wall_passed, monotonic_overshoot >= 0) {
        (false, false) => None,
        (true, false) => Some(ExpiryClock::Wall),
        (false, true) => Some(ExpiryClock::Monotonic),
        (true, true) => {
            let wall_overshoot = ((now.wall_epoch - task.due_epoch) * 1e9) as i128;
            if wall_overshoot > monotonic_overshoot + WALL_ATTRIBUTION_TOLERANCE_NS {
                Some(ExpiryClock::Wall)
            } else {
                Some(ExpiryClock::Monotonic)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReleaseLedger {
    schema_version: String,
    tasks: Vec<ReleaseTask>,
    #[serde(default)]
    checkpoint: LedgerCheckpoint,
}

/// What a generation migration leaves of the terminal tasks it removes. The
/// replay guard is the task id while a task is in the ledger and, once it is
/// compacted, the watermark: no task whose alert (or, without an alert time,
/// whose creation) is at or before it is admitted again.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LedgerCheckpoint {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub replay_watermark_epoch: f64,
    #[serde(default)]
    pub compacted_total: u64,
    #[serde(default)]
    pub last_compacted_epoch: f64,
}

impl Default for ReleaseLedger {
    fn default() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION.to_string(),
            tasks: Vec::new(),
            checkpoint: LedgerCheckpoint::default(),
        }
    }
}

/// One process-wide lock for every read-modify-write of a ledger, plus an
/// advisory `flock` on a lock file beside it for the maintenance subcommand
/// (another process). The apply path holds it only around ledger updates,
/// never while an apply command runs; the release sweep holds it for a
/// sweep, whose commands are each time-bounded.
static LEDGER_LOCK: Mutex<()> = Mutex::new(());

struct LedgerGuard {
    _process: MutexGuard<'static, ()>,
    _file: Option<File>,
}

extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}
const LOCK_EX: std::os::raw::c_int = 2;

fn lock_ledger(path: &str) -> Result<LedgerGuard, String> {
    let process = LEDGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let destination = Path::new(path);
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty());
    let file = match parent {
        Some(dir) if dir.is_dir() => {
            let name = destination
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("release-ledger");
            let lock_path = destination.with_file_name(format!(".{name}.lock"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(O_NOFOLLOW)
                .open(&lock_path)
                .map_err(|e| format!("release ledger lock open failed: {e}"))?;
            use std::os::unix::io::AsRawFd;
            // SAFETY: flock on a descriptor this function owns.
            if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
                return Err("release ledger lock failed".to_string());
            }
            Some(file)
        }
        // No directory, so no ledger: nothing on disk to serialise.
        _ => None,
    };
    Ok(LedgerGuard { _process: process, _file: file })
}

/// Leases whose apply is running in this process. The sweep never releases
/// one of them: it would verify absence before the apply lands and leave a
/// rule with no lease. `activate_release_task` or `abandon_release_task`
/// takes the lease out again; after a crash, `recover_unconfirmed_on_start`
/// releases what was still in flight.
static IN_FLIGHT: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn set_in_flight(task_id: &str, on: bool) {
    let mut set = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    set.retain(|id| id != task_id);
    if on {
        set.push(task_id.to_string());
    }
}

fn in_flight(task_id: &str) -> bool {
    IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|id| id == task_id)
}

#[cfg(target_os = "linux")]
pub(crate) const O_NOFOLLOW: i32 = 0o400000;
#[cfg(not(target_os = "linux"))]
pub(crate) const O_NOFOLLOW: i32 = 0x0100;

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
    /// Whether this attempt's `rollback_started` audit record was written:
    /// `recorded`, `failed:<reason>`, or `not_applicable` when no rollback
    /// command was issued (superseded or deferred). A failure never holds
    /// the rollback back; this field is how it is seen besides stderr.
    #[serde(default)]
    pub rollback_start_audit: String,
    /// Which deadline expired the lease (`ExpiryClock::as_str`).
    #[serde(default)]
    pub expiry_clock: String,
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
            return Err(format!("release command rejected by allowlist: {argv:?}"));
        }
        run_bounded(argv, COMMAND_TIMEOUT)
    }
}

/// Run a trusted `nft`/`tc` argv with its output bounded and its run time
/// bounded by `timeout`: past it the child is killed and the call fails
/// (`command timeout`). Both the apply path and the release path use it, so
/// neither can wait on a wedged command for ever.
pub(crate) fn run_bounded(argv: &[String], timeout: Duration) -> Result<CommandResult, String> {
    {
        if argv.is_empty() {
            return Err("empty command".to_string());
        }
        let binary = resolve_trusted_binary(&argv[0])?;
        let mut command = trusted_command(&binary);
        command
            .args(&argv[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .map_err(|e| format!("release command spawn failed: {e}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "release stdout pipe unavailable".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "release stderr pipe unavailable".to_string())?;
        let out_reader = thread::spawn(move || drain_capture(stdout, MAX_STDOUT_BYTES));
        let err_reader = thread::spawn(move || drain_capture(stderr, MAX_STDERR_BYTES));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => {
                    thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    // A grandchild could keep the pipes open; the readers are
                    // not joined, so the timeout holds regardless.
                    return Err("command timeout".to_string());
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

        let (stdout, stdout_exceeded) = out_reader
            .join()
            .map_err(|_| "release stdout reader panicked".to_string())??;
        let (stderr, stderr_exceeded) = err_reader
            .join()
            .map_err(|_| "release stderr reader panicked".to_string())??;
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
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("release output read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if retained.len() < limit {
            let remaining = limit - retained.len();
            retained.extend_from_slice(&buf[..n.min(remaining)]);
        }
    }
    Ok((
        String::from_utf8_lossy(&retained).into_owned(),
        total > limit,
    ))
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
    now: &LeaseNow,
) -> Option<ReleaseTask> {
    let now_epoch = now.wall_epoch;
    if !now_epoch.is_finite() || now_epoch < 0.0 {
        return None;
    }
    let resource_key = match action {
        "throttle" => format!("tc:root:{iface}"),
        "isolate" => format!("nft:inet:azazel_edge:input:{source_ip}"),
        "redirect" => {
            format!("nft:inet:azazel_edge:prerouting:{source_ip}:tcp:{destination_port}")
        }
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
    if !due_epoch.is_finite() {
        return None;
    }
    // Both deadlines, or only the wall one: a monotonic deadline is kept only
    // with the boot it belongs to.
    let (due_boottime_ns, due_boot_id) = match (now.boottime_ns, now.boot_id.as_deref()) {
        (Some(boottime), Some(boot_id)) if valid_boot_id(boot_id) => {
            let due = ttl_sec
                .checked_mul(1_000_000_000)
                .and_then(|ttl| boottime.checked_add(ttl))
                .filter(|due| *due <= i64::MAX as u64)?;
            (Some(due), boot_id.to_string())
        }
        _ => (None, String::new()),
    };
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
        expected_latency_us: if action == "throttle" {
            delay_ms.max(100) as u64 * 1000
        } else {
            0
        },
        due_epoch,
        next_attempt_epoch: due_epoch,
        created_epoch: now_epoch,
        updated_epoch: now_epoch,
        status: "prepared".to_string(),
        attempts: 0,
        last_error: String::new(),
        due_boottime_ns,
        due_boot_id,
        next_attempt_boottime_ns: None,
        next_attempt_boot_id: String::new(),
        mechanism: String::new(),
        destination_ip: String::new(),
        protocol: String::new(),
        limit_rate_kbytes: 0,
        limit_burst_kbytes: 0,
        event_epoch: None,
        family_started_epoch: None,
        extensions: 0,
        event_key: String::new(),
        cooldown_until_epoch: None,
    })
}

/// The flow a temporary restriction is scoped to: the source, the
/// destination and, when the protocol carries one, the destination port.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowScope {
    pub source_ip: String,
    pub destination_ip: String,
    /// `tcp`, `udp`, or empty (then no port is matched).
    pub protocol: String,
    pub destination_port: u16,
}

impl FlowScope {
    pub fn key(&self) -> String {
        format!(
            "{}>{}:{}:{}",
            self.source_ip,
            self.destination_ip,
            if self.protocol.is_empty() { "any" } else { &self.protocol },
            self.destination_port
        )
    }
}

/// A flow-scoped temporary restriction: an nft rate limit in the owned
/// `throttle` chain that drops this flow's packets above the given rate.
/// It changes no qdisc and touches no other flow.
pub fn build_flow_throttle_task(
    trace_id: &str,
    flow: &FlowScope,
    rate_kbytes: u32,
    burst_kbytes: u32,
    ttl_sec: u64,
    now: &LeaseNow,
) -> Option<ReleaseTask> {
    if rate_kbytes == 0 || burst_kbytes == 0 || !FLOW_PROTOCOLS.contains(&flow.protocol.as_str()) {
        return None;
    }
    if protocol_has_port(&flow.protocol) != (flow.destination_port != 0) {
        return None;
    }
    let mut task = build_release_task(trace_id, "redirect", "", &flow.source_ip, flow.destination_port.max(1), 1, 0, ttl_sec, now)?;
    let resource_key = format!("nft:inet:azazel_edge:{THROTTLE_CHAIN}:{}", flow.key());
    let seed = format!("{trace_id}|throttle|{resource_key}");
    task.task_id = format!("release-{:016x}", fnv1a64(seed.as_bytes()));
    task.owner_token = format!("azazel-edge:{}", task.task_id);
    task.action = "throttle".to_string();
    task.resource_key = resource_key;
    task.iface = String::new();
    task.tc_handle = String::new();
    task.destination_port = flow.destination_port;
    task.redirect_port = 0;
    task.mechanism = MECHANISM_NFT_FLOW_LIMIT.to_string();
    task.destination_ip = flow.destination_ip.clone();
    task.protocol = flow.protocol.clone();
    task.limit_rate_kbytes = rate_kbytes;
    task.limit_burst_kbytes = burst_kbytes;
    Some(task)
}

/// A flow-scoped decoy redirect: on `iface` (the ingress interface the
/// decoy evidence names), this source to this destination and TCP port is
/// redirected to the local decoy port. Other destinations of the source,
/// and other sources, are untouched.
pub fn build_flow_redirect_task(
    trace_id: &str,
    flow: &FlowScope,
    iface: &str,
    redirect_port: u16,
    ttl_sec: u64,
    now: &LeaseNow,
) -> Option<ReleaseTask> {
    if flow.protocol != "tcp" || flow.destination_port == 0 || redirect_port == 0 || !valid_interface(iface) {
        return None;
    }
    let mut task = build_release_task(trace_id, "redirect", iface, &flow.source_ip, flow.destination_port, redirect_port, 0, ttl_sec, now)?;
    let resource_key = format!("nft:inet:azazel_edge:prerouting:{iface}:{}", flow.key());
    let seed = format!("{trace_id}|redirect|{resource_key}");
    task.task_id = format!("release-{:016x}", fnv1a64(seed.as_bytes()));
    task.owner_token = format!("azazel-edge:{}", task.task_id);
    task.resource_key = resource_key;
    task.mechanism = MECHANISM_NFT_FLOW_REDIRECT.to_string();
    task.destination_ip = flow.destination_ip.clone();
    task.protocol = "tcp".to_string();
    Some(task)
}

/// Whether this throttle lease is the legacy root TBF qdisc.
pub fn is_legacy_tc_throttle(task: &ReleaseTask) -> bool {
    task.action == "throttle" && task.mechanism.is_empty()
}

/// The owned nft chain a task's rule lives in, for an nft-held task.
pub fn owned_nft_chain(task: &ReleaseTask) -> Option<&'static str> {
    match task.action.as_str() {
        "isolate" => Some("input"),
        "redirect" => Some("prerouting"),
        "throttle" if task.mechanism == MECHANISM_NFT_FLOW_LIMIT => Some(THROTTLE_CHAIN),
        _ => None,
    }
}

/// An owner token is `azazel-edge:release-` followed by ASCII alphanumerics,
/// `:` and `-` only (what `build_release_task` generates: a hex task id). It
/// can never hold `"`, whitespace, `;`, `#` or a newline, so it fits inside
/// one nft quoted string unescaped.
pub fn valid_owner_token(token: &str) -> bool {
    token.starts_with("azazel-edge:release-")
        && token.len() <= 96
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, ':' | '-'))
}

/// The single argv element passed after `comment` to `nft`. nft joins its
/// argv with spaces and parses the result, so a bare `azazel-edge:release-...`
/// is a syntax error at the `:`; the token must reach the parser as an nft
/// quoted string. `nft -j` reports the comment without the quotes, so the
/// readback in `nft_owned_handles` still compares against the bare token.
/// A token outside `valid_owner_token` is refused rather than escaped.
pub fn nft_comment_arg(owner_token: &str) -> Result<String, String> {
    if !valid_owner_token(owner_token) {
        return Err("owner token is not a valid nft comment".to_string());
    }
    Ok(format!("\"{owner_token}\""))
}

/// Admission without the lease-family rules (tests and the SO-04 shape);
/// the daemon uses `admit_release_task`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn prepare_release_task(path: &str, task: &ReleaseTask) -> Result<(), String> {
    validate_task(task)?;
    let _guard = lock_ledger(path)?;
    let mut ledger = load_ledger(path)?;
    admit_new_task(&mut ledger, task, task.created_epoch)?;
    ledger.tasks.push(task.clone());
    save_ledger(path, &mut ledger)
}

/// Replay guard, generation migration and capacity, for a task not yet in
/// the ledger. Never forgets a terminal identity outside a checkpoint: an old
/// provider event must not become executable again.
fn admit_new_task(ledger: &mut ReleaseLedger, task: &ReleaseTask, now_epoch: f64) -> Result<(), String> {
    if let Some(existing) = ledger.tasks.iter().find(|item| item.task_id == task.task_id) {
        if same_task_identity(existing, task) {
            return Err(format!(
                "release task already exists; replayed disruptive apply blocked (status={})",
                existing.status
            ));
        }
        return Err("release task id collision".to_string());
    }
    if !task.event_key.is_empty() && ledger.tasks.iter().any(|item| item.event_key == task.event_key) {
        return Err("this alert already led to a lease; replayed disruptive apply blocked".to_string());
    }
    if ledger.checkpoint.generation > 0
        && task.event_epoch.unwrap_or(task.created_epoch) <= ledger.checkpoint.replay_watermark_epoch
    {
        return Err("release task is at or before the ledger replay checkpoint; replayed disruptive apply blocked".to_string());
    }
    if ledger.tasks.len() >= COMPACT_AT_TASKS || encoded_len(ledger) >= COMPACT_AT_BYTES {
        compact_ledger(ledger, now_epoch);
    }
    if ledger.tasks.len() >= ADMIT_MAX_TASKS || encoded_len(ledger) >= ADMIT_MAX_BYTES {
        return Err("release ledger capacity reached; disruptive apply blocked (release continues)".to_string());
    }
    Ok(())
}

fn encoded_len(ledger: &ReleaseLedger) -> u64 {
    serde_json::to_vec(ledger).map(|v| v.len() as u64).unwrap_or(u64::MAX)
}

/// Generation migration: terminal tasks unchanged for `COMPACT_MIN_AGE_SEC`
/// leave the ledger; the checkpoint watermark rises to the latest of their
/// alert/creation times, so a replay of any of them is still refused.
/// Eligible tasks (prepared, active, uncertain) are never removed. Returns
/// how many tasks were compacted.
fn compact_ledger(ledger: &mut ReleaseLedger, now_epoch: f64) -> usize {
    let cutoff = now_epoch - COMPACT_MIN_AGE_SEC;
    let mut watermark = ledger.checkpoint.replay_watermark_epoch;
    let before = ledger.tasks.len();
    ledger.tasks.retain(|task| {
        let compactable = terminal_status(&task.status) && task.updated_epoch <= cutoff;
        if compactable {
            let basis = task.event_epoch.unwrap_or(task.created_epoch).max(task.created_epoch);
            if basis > watermark {
                watermark = basis;
            }
        }
        !compactable
    });
    let removed = before - ledger.tasks.len();
    if removed > 0 {
        ledger.checkpoint.generation = ledger.checkpoint.generation.saturating_add(1);
        ledger.checkpoint.replay_watermark_epoch = watermark;
        ledger.checkpoint.compacted_total = ledger.checkpoint.compacted_total.saturating_add(removed as u64);
        ledger.checkpoint.last_compacted_epoch = now_epoch;
    }
    removed
}

/// What admission did with a new restriction.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// A new lease was written as `prepared`; apply it, then activate or
    /// abandon it.
    Prepared(ReleaseTask),
    /// An active lease of the same resource was extended; nothing is
    /// applied. The new task's identity is kept as a `merged` tombstone so a
    /// replay of the same alert is refused.
    Extended { task_id: String, due_epoch: f64, extensions: u32 },
    /// An active lease of the same resource already lasts at least as long
    /// as this alert would ask; nothing changes but the tombstone.
    AlreadyHeld { task_id: String, due_epoch: f64 },
    /// The flow used up its lease family and is in cooldown until
    /// `until_epoch`: nothing is applied and nothing is written (the alert
    /// executed nothing, so there is nothing a replay could repeat).
    Cooldown { until_epoch: f64 },
}

/// Admit a restriction under the Edge-fixed bounds (production path):
/// replay guard and checkpoint, capacity, at most `MAX_ACTIVE_LEASES` held
/// at once, one lease per resource (a new alert for a held resource extends
/// it at most `MAX_LEASE_EXTENSIONS` times), and a family of leases of one
/// resource bounded to `MAX_CUMULATIVE_LEASE_SEC` from its first lease.
pub fn admit_release_task(path: &str, task: &ReleaseTask, ttl_sec: u64, now: &LeaseNow) -> Result<Admission, String> {
    validate_task(task)?;
    validate_now(now.wall_epoch)?;
    let now_epoch = now.wall_epoch;
    let _guard = lock_ledger(path)?;
    let mut ledger = load_ledger(path)?;
    admit_new_task(&mut ledger, task, now_epoch)?;
    let ttl = ttl_sec.clamp(MIN_LEASE_TTL_SEC, MAX_LEASE_TTL_SEC) as f64;

    // Cooldown: from the end of a used-up family until its recorded time.
    let cooldown = ledger
        .tasks
        .iter()
        .filter(|item| item.resource_key == task.resource_key)
        .filter_map(|item| {
            let until = item.cooldown_until_epoch?;
            let from = item.family_started_epoch.unwrap_or(item.created_epoch) + MAX_CUMULATIVE_LEASE_SEC as f64;
            (now_epoch >= from - 1.0 && now_epoch < until).then_some(until)
        })
        .fold(None, |acc: Option<f64>, until| Some(acc.map_or(until, |a| a.max(until))));
    if let Some(until_epoch) = cooldown {
        return Ok(Admission::Cooldown { until_epoch });
    }

    if let Some(index) = ledger
        .tasks
        .iter()
        .position(|item| item.resource_key == task.resource_key && eligible_status(&item.status))
    {
        let held = ledger.tasks[index].clone();
        if held.status != "active" {
            return Err(format!("resource has an unconfirmed lease (status={}); not extended", held.status));
        }
        let family = held.family_started_epoch.unwrap_or(held.created_epoch);
        let cap = family + MAX_CUMULATIVE_LEASE_SEC as f64;
        let new_due = (now_epoch + ttl).min(cap);
        let mut tombstone = task.clone();
        tombstone.status = "merged".to_string();
        tombstone.last_error = format!("merged_into:{}", held.task_id);
        tombstone.updated_epoch = now_epoch;
        if new_due <= held.due_epoch + 1.0 {
            if held.due_epoch + 1.0 >= cap {
                return Err("lease cumulative limit reached".to_string());
            }
            // Held long enough already: record the alert, change nothing.
            ledger.tasks.push(tombstone);
            save_ledger(path, &mut ledger)?;
            return Ok(Admission::AlreadyHeld { task_id: held.task_id, due_epoch: held.due_epoch });
        }
        if held.extensions >= MAX_LEASE_EXTENSIONS {
            return Err("lease extension limit reached".to_string());
        }
        // The monotonic deadline moves by the same amount, on the lease's own
        // boot only; in another boot or unreadable, it is not extended.
        let added_ns = ((new_due - held.due_epoch) * 1e9) as u64;
        let due_boottime_ns = match (held.due_boottime_ns, now.boot_id.as_deref()) {
            (Some(due), Some(boot)) if boot == held.due_boot_id => Some(due.saturating_add(added_ns).min(i64::MAX as u64)),
            (None, _) => None,
            _ => return Err("lease belongs to another boot; not extended".to_string()),
        };
        ledger.tasks.push(tombstone);
        let item = &mut ledger.tasks[index];
        item.due_epoch = new_due;
        item.next_attempt_epoch = new_due;
        item.due_boottime_ns = due_boottime_ns;
        item.extensions += 1;
        if new_due >= cap {
            item.cooldown_until_epoch = Some(cap + FLOW_COOLDOWN_SEC as f64);
        }
        item.updated_epoch = now_epoch;
        let extensions = item.extensions;
        let task_id = item.task_id.clone();
        save_ledger(path, &mut ledger)?;
        return Ok(Admission::Extended { task_id, due_epoch: new_due, extensions });
    }

    let held = ledger.tasks.iter().filter(|item| eligible_status(&item.status)).count();
    if held >= MAX_ACTIVE_LEASES {
        return Err("active lease limit reached; restriction not widened".to_string());
    }

    // A family continues while its first lease began less than the
    // cumulative bound ago; the new lease ends no later than the bound.
    let family = ledger
        .tasks
        .iter()
        .filter(|item| item.resource_key == task.resource_key && item.status != "merged")
        .filter_map(|item| item.family_started_epoch.or(Some(item.created_epoch)))
        .filter(|start| now_epoch - start < MAX_CUMULATIVE_LEASE_SEC as f64)
        .fold(None, |acc: Option<f64>, start| Some(acc.map_or(start, |a| a.min(start))));
    let family_start = family.unwrap_or(now_epoch);
    let cap = family_start + MAX_CUMULATIVE_LEASE_SEC as f64;
    let mut admitted = task.clone();
    admitted.family_started_epoch = Some(family_start);
    if admitted.due_epoch >= cap {
        if cap - now_epoch < MIN_LEASE_TTL_SEC as f64 {
            // The family is used up: record its cooldown on its latest lease
            // (nothing is applied) so it holds across restarts.
            let until = cap + FLOW_COOLDOWN_SEC as f64;
            if let Some(last) = ledger
                .tasks
                .iter_mut()
                .filter(|item| item.resource_key == task.resource_key && item.status != "merged")
                .filter(|item| item.family_started_epoch.unwrap_or(item.created_epoch) == family_start)
                .max_by(|a, b| a.created_epoch.total_cmp(&b.created_epoch))
            {
                last.cooldown_until_epoch = Some(until);
                save_ledger(path, &mut ledger)?;
            }
            return Err("lease cumulative limit reached".to_string());
        }
        admitted.cooldown_until_epoch = Some(cap + FLOW_COOLDOWN_SEC as f64);
        let shortened = admitted.due_epoch - cap;
        admitted.due_epoch = cap;
        admitted.next_attempt_epoch = cap;
        if let Some(due) = admitted.due_boottime_ns {
            admitted.due_boottime_ns = Some(due.saturating_sub((shortened * 1e9) as u64));
        }
    }
    admitted.status = "prepared".to_string();
    ledger.tasks.push(admitted.clone());
    set_in_flight(&admitted.task_id, true);
    if let Err(error) = save_ledger(path, &mut ledger) {
        set_in_flight(&admitted.task_id, false);
        return Err(error);
    }
    Ok(Admission::Prepared(admitted))
}

/// A lease whose apply did not end confirmed (failed, timed out, or its
/// owned state did not read back as planned) is released at once: it
/// becomes `uncertain` and due now, so the next sweep deletes whatever owned
/// state exists and verifies its absence. It is never left to its TTL.
pub fn abandon_release_task(path: &str, task_id: &str, reason: &str, now: &LeaseNow) -> Result<(), String> {
    validate_now(now.wall_epoch)?;
    let _guard = lock_ledger(path)?;
    set_in_flight(task_id, false);
    let mut ledger = load_ledger(path)?;
    let task = ledger
        .tasks
        .iter_mut()
        .find(|item| item.task_id == task_id)
        .ok_or_else(|| "release task missing".to_string())?;
    if task.status != "prepared" {
        return Err(format!("invalid release lifecycle transition {} -> uncertain", task.status));
    }
    make_due_now(task, now);
    task.status = "uncertain".to_string();
    task.last_error = bounded_error(reason);
    save_ledger(path, &mut ledger)
}

fn make_due_now(task: &mut ReleaseTask, now: &LeaseNow) {
    let now_epoch = now.wall_epoch.max(task.created_epoch);
    task.due_epoch = now_epoch;
    task.next_attempt_epoch = now_epoch;
    task.updated_epoch = now.wall_epoch;
    if task.due_boottime_ns.is_some() {
        match (now.boottime_ns, now.boot_id.as_deref()) {
            (Some(boottime), Some(boot)) if boot == task.due_boot_id => task.due_boottime_ns = Some(boottime),
            // Another boot or unreadable: the monotonic deadline already
            // counts as passed (lease_expiry).
            _ => {}
        }
    }
}

/// At start, before any alert is read: a lease still `prepared` was being
/// applied when the previous process stopped, and its outcome was never
/// confirmed. It is released at once (as `abandon_release_task`), never
/// activated, so a restart grants nothing the previous run did not confirm.
pub fn recover_unconfirmed_on_start(path: &str, now: &LeaseNow) -> Result<usize, String> {
    validate_now(now.wall_epoch)?;
    let _guard = lock_ledger(path)?;
    if !Path::new(path).exists() {
        return Ok(0);
    }
    let mut ledger = load_ledger(path)?;
    let mut count = 0;
    for task in ledger.tasks.iter_mut().filter(|t| t.status == "prepared") {
        make_due_now(task, now);
        task.status = "uncertain".to_string();
        task.last_error = "apply_unconfirmed_at_restart".to_string();
        count += 1;
    }
    if count > 0 {
        save_ledger(path, &mut ledger)?;
    }
    Ok(count)
}

/// The ledger's fill, for the capacity notice and the maintenance
/// subcommand. `state`: `ok`, `warning` (compaction will run on the next
/// admission), or `full` (new restrictions are refused; release continues).
pub fn ledger_capacity(path: &str) -> Result<Value, String> {
    let _guard = lock_ledger(path)?;
    let ledger = load_ledger(path)?;
    Ok(capacity_value(&ledger))
}

fn capacity_value(ledger: &ReleaseLedger) -> Value {
    let bytes = encoded_len(ledger);
    let tasks = ledger.tasks.len();
    let held = ledger.tasks.iter().filter(|t| eligible_status(&t.status)).count();
    let state = if tasks >= ADMIT_MAX_TASKS || bytes >= ADMIT_MAX_BYTES {
        "full"
    } else if tasks >= COMPACT_AT_TASKS || bytes >= COMPACT_AT_BYTES {
        "warning"
    } else {
        "ok"
    };
    json!({
        "state": state,
        "tasks": tasks,
        "held_leases": held,
        "admit_max_tasks": ADMIT_MAX_TASKS,
        "max_tasks": MAX_LEDGER_TASKS,
        "bytes": bytes,
        "admit_max_bytes": ADMIT_MAX_BYTES,
        "max_bytes": MAX_LEDGER_BYTES,
        "checkpoint": {
            "generation": ledger.checkpoint.generation,
            "replay_watermark_epoch": ledger.checkpoint.replay_watermark_epoch,
            "compacted_total": ledger.checkpoint.compacted_total,
        },
    })
}

/// The maintenance entry (`--release-ledger-compact`): one generation
/// migration under the same rules as admission. It removes only terminal
/// tasks older than `COMPACT_MIN_AGE_SEC` and keeps the replay watermark;
/// it never removes a held lease, so nothing that must be released is lost.
pub fn compact_release_ledger(path: &str, now_epoch: f64) -> Result<Value, String> {
    validate_now(now_epoch)?;
    let _guard = lock_ledger(path)?;
    if !Path::new(path).exists() {
        return Ok(json!({"compacted": 0, "capacity": capacity_value(&ReleaseLedger::default())}));
    }
    let mut ledger = load_ledger(path)?;
    let removed = compact_ledger(&mut ledger, now_epoch);
    if removed > 0 || ledger.schema_version != LEDGER_SCHEMA_VERSION {
        save_ledger(path, &mut ledger)?;
    }
    Ok(json!({"compacted": removed, "capacity": capacity_value(&ledger)}))
}

/// Read back the owned state of a just-applied lease: present exactly once
/// with the planned semantics. Only then is the lease `active`.
pub fn owned_state_matches_plan(task: &ReleaseTask) -> Result<bool, String> {
    owned_state_matches_plan_with_runner(task, &SystemReleaseCommandRunner)
}

pub fn owned_state_matches_plan_with_runner<R: ReleaseCommandRunner>(task: &ReleaseTask, runner: &R) -> Result<bool, String> {
    match owned_nft_chain(task) {
        Some(chain) => {
            let rules = nft_owned_rules(task, chain, runner)?;
            Ok(rules.len() == 1 && rules[0].1)
        }
        None => Err("no readback for this lease mechanism".to_string()),
    }
}

fn same_task_identity(left: &ReleaseTask, right: &ReleaseTask) -> bool {
    left.trace_id == right.trace_id
        && left.action == right.action
        && left.resource_key == right.resource_key
        && left.owner_token == right.owner_token
        && left.iface == right.iface
        && left.tc_handle == right.tc_handle
        && left.source_ip == right.source_ip
        && left.destination_port == right.destination_port
        && left.redirect_port == right.redirect_port
        && left.expected_rate_bps == right.expected_rate_bps
        && left.expected_burst_bytes == right.expected_burst_bytes
        && left.expected_latency_us == right.expected_latency_us
        && left.mechanism == right.mechanism
        && left.destination_ip == right.destination_ip
        && left.protocol == right.protocol
        && left.limit_rate_kbytes == right.limit_rate_kbytes
        && left.limit_burst_kbytes == right.limit_burst_kbytes
        && left.event_key == right.event_key
}

pub fn activate_release_task(path: &str, task_id: &str, now_epoch: f64) -> Result<(), String> {
    validate_now(now_epoch)?;
    let _guard = lock_ledger(path)?;
    set_in_flight(task_id, false);
    let mut ledger = load_ledger(path)?;
    let snapshot = ledger
        .tasks
        .iter()
        .find(|item| item.task_id == task_id)
        .cloned()
        .ok_or_else(|| "release task missing during activation".to_string())?;
    if snapshot.status != "prepared" {
        return Err(format!(
            "release task cannot activate from status={}",
            snapshot.status
        ));
    }

    // Only a legacy root-qdisc throttle shares one resource per interface;
    // a flow-scoped lease is never superseded (one lease per flow).
    if is_legacy_tc_throttle(&snapshot) {
        for item in &mut ledger.tasks {
            if item.task_id != task_id
                && is_legacy_tc_throttle(item)
                && item.resource_key == snapshot.resource_key
                && eligible_status(&item.status)
            {
                item.status = "superseded".to_string();
                item.updated_epoch = now_epoch;
                item.last_error = format!("superseded_by:{task_id}");
            }
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

#[cfg_attr(not(test), allow(dead_code))]
pub fn cancel_release_task(
    path: &str,
    task_id: &str,
    reason: &str,
    now_epoch: f64,
) -> Result<(), String> {
    transition_task(path, task_id, &["prepared"], "cancelled", reason, now_epoch)
}

#[cfg_attr(not(test), allow(dead_code))]
fn transition_task(
    path: &str,
    task_id: &str,
    allowed_from: &[&str],
    status: &str,
    reason: &str,
    now_epoch: f64,
) -> Result<(), String> {
    validate_now(now_epoch)?;
    if !valid_status(status) {
        return Err("invalid release task status".to_string());
    }
    let _guard = lock_ledger(path)?;
    let mut ledger = load_ledger(path)?;
    let task = ledger
        .tasks
        .iter_mut()
        .find(|item| item.task_id == task_id)
        .ok_or_else(|| "release task missing".to_string())?;
    if !allowed_from.iter().any(|value| *value == task.status) {
        return Err(format!(
            "invalid release lifecycle transition {} -> {status}",
            task.status
        ));
    }
    task.status = status.to_string();
    task.updated_epoch = now_epoch;
    task.last_error = bounded_error(reason);
    save_ledger(path, &mut ledger)
}

pub fn process_due_releases(path: &str, now: &LeaseNow) -> Result<Vec<ReleaseOutcome>, String> {
    let runner = SystemReleaseCommandRunner;
    process_due_releases_with_runner(path, now, &runner)
}

pub fn process_due_releases_with_runner<R: ReleaseCommandRunner>(
    path: &str,
    now: &LeaseNow,
    runner: &R,
) -> Result<Vec<ReleaseOutcome>, String> {
    let now_epoch = now.wall_epoch;
    validate_now(now_epoch)?;
    let _guard = lock_ledger(path)?;
    if !Path::new(path).exists() {
        return Ok(Vec::new());
    }
    let mut ledger = load_ledger(path)?;
    // The first attempt waits only for expiry. A lease with a monotonic
    // deadline can expire before its wall deadline, and its
    // next_attempt_epoch (equal to due_epoch until an attempt) would then
    // hold the first attempt back on the wall clock. A retry is due when its
    // wall or its monotonic retry time says so (retry_due_on_boottime); a
    // legacy lease keeps exactly its old rule.
    let candidates: Vec<(String, ExpiryClock)> = ledger
        .tasks
        .iter()
        .filter(|task| eligible_status(&task.status) && !in_flight(&task.task_id))
        .filter_map(|task| {
            let clock = lease_expiry(task, now)?;
            let attempt_due = task.next_attempt_epoch <= now_epoch
                || (task.attempts == 0 && clock != ExpiryClock::Legacy)
                || retry_due_on_boottime(task, now);
            attempt_due.then(|| (task.task_id.clone(), clock))
        })
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let mut outcomes = Vec::new();
    for (task_id, expiry_clock) in candidates {
        let current = match ledger.tasks.iter().find(|task| task.task_id == task_id) {
            Some(task) if eligible_status(&task.status) => task.clone(),
            _ => continue,
        };

        if is_legacy_tc_throttle(&current) {
            let newer = ledger.tasks.iter().find(|other| {
                other.task_id != current.task_id
                    && is_legacy_tc_throttle(other)
                    && other.resource_key == current.resource_key
                    && eligible_status(&other.status)
                    && other.created_epoch > current.created_epoch
            });
            if let Some(newer) = newer {
                let newer_id = newer.task_id.clone();
                let newer_status = newer.status.clone();
                let same_handle = newer.tc_handle == current.tc_handle;
                if newer_status == "active" {
                    if let Some(task) = ledger
                        .tasks
                        .iter_mut()
                        .find(|task| task.task_id == current.task_id)
                    {
                        task.status = "superseded".to_string();
                        task.updated_epoch = now_epoch;
                        task.last_error = format!("superseded_by:{newer_id}");
                    }
                    let mut outcome = outcome_for(
                        &current,
                        now_epoch,
                        "superseded",
                        "superseded_by_newer_throttle",
                        0,
                        0,
                        Vec::new(),
                        json!({"verified": false, "reason": "newer_throttle_owner_exists"}),
                    );
                    outcome.expiry_clock = expiry_clock.as_str().to_string();
                    outcomes.push(outcome);
                    continue;
                }
                if same_handle && matches!(newer_status.as_str(), "prepared" | "uncertain") {
                    if let Some(task) = ledger
                        .tasks
                        .iter_mut()
                        .find(|task| task.task_id == current.task_id)
                    {
                        task.updated_epoch = now_epoch;
                        task.attempts = task.attempts.saturating_add(1);
                        task.last_error = format!("ambiguous_newer_owner:{newer_id}:{newer_status}");
                        schedule_retry(task, now);
                    }
                    let mut outcome = outcome_for(
                        &current,
                        now_epoch,
                        "retry_pending",
                        "ambiguous_newer_throttle_owner",
                        0,
                        0,
                        Vec::new(),
                        json!({
                            "verified": false,
                            "reason": "same_tc_handle_owned_by_newer_unreconciled_task",
                            "newer_task_id": newer_id,
                            "newer_status": newer_status,
                        }),
                    );
                    outcome.expiry_clock = expiry_clock.as_str().to_string();
                    outcomes.push(outcome);
                    continue;
                }
            }
        }

        // The record stating that rollback has begun is durable before the
        // first rollback command runs. A failure to write it is reported but
        // never holds the rollback back: releasing the lease is the safe
        // direction, and a missing record is what the SO-04 harness detects.
        let start_audit = match record_rollback_start(path, &current, expiry_clock) {
            Ok(()) => "recorded".to_string(),
            Err(error) => {
                eprintln!(
                    "rollback start audit record failed: release_task_id={} error={}",
                    current.task_id, error
                );
                bounded_error(&format!("failed:{error}"))
            }
        };
        let result = release_owned_state(&current, runner, now_epoch);
        if let Some(task) = ledger
            .tasks
            .iter_mut()
            .find(|task| task.task_id == current.task_id)
        {
            task.updated_epoch = now_epoch;
            task.attempts = task.attempts.saturating_add(1);
            match &result {
                Ok(outcome) if outcome.status == "released" => {
                    task.status = "released".to_string();
                    task.last_error.clear();
                    task.next_attempt_epoch = now_epoch;
                    task.next_attempt_boottime_ns = None;
                    task.next_attempt_boot_id.clear();
                }
                Ok(outcome) => {
                    task.last_error = bounded_error(&outcome.errors.join("; "));
                    schedule_retry(task, now);
                }
                Err(error) => {
                    task.last_error = bounded_error(error);
                    schedule_retry(task, now);
                }
            }
        }
        let mut outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => outcome_for(
                &current,
                now_epoch,
                "retry_pending",
                "release_attempt_failed",
                0,
                1,
                vec![bounded_error(&error)],
                json!({"verified": false}),
            ),
        };
        outcome.rollback_start_audit = start_audit;
        outcome.expiry_clock = expiry_clock.as_str().to_string();
        outcomes.push(outcome);
    }
    // Release never fails on capacity: if the updated ledger would exceed
    // its size bound, compact (generation migration) and save again.
    if let Err(error) = save_ledger(path, &mut ledger) {
        if compact_ledger(&mut ledger, now_epoch) == 0 {
            return Err(error);
        }
        save_ledger(path, &mut ledger)?;
    }
    Ok(outcomes)
}

/// The audit chain the release engine writes, beside the ledger it serves:
/// `<dir>/<ledger stem>.rollback-audit.jsonl`. The core is its only writer.
pub fn rollback_audit_path(ledger_path: &str) -> PathBuf {
    let ledger = Path::new(ledger_path);
    let stem = ledger
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("release-ledger");
    ledger.with_file_name(format!("{stem}.rollback-audit.jsonl"))
}

/// Append and fsync the `rollback_started` record naming this lease
/// (`release_task_id`) and the decision it came from (`trace_id`).
///
/// Instants are integer nanoseconds: `lease_due_epoch_ns` and
/// `lease_due_boottime_ns` are the lease's own declared deadlines on the wall
/// clock and `CLOCK_BOOTTIME` (null when the lease has none), and
/// `started_monotonic_ns` / `started_boottime_ns` / `started_wall_epoch_ns`
/// are read together just before the record is written. `expiry_clock` names
/// the deadline that expired the lease.
fn record_rollback_start(ledger_path: &str, task: &ReleaseTask, expiry_clock: ExpiryClock) -> Result<(), String> {
    let monotonic = audit_chain::monotonic_ns();
    let boottime = audit_chain::boottime_ns();
    let wall = audit_chain::wall_epoch_ns();
    let due_ns = task.due_epoch * 1e9;
    let lease_due_epoch_ns = if due_ns.is_finite() && due_ns >= 0.0 && due_ns < i64::MAX as f64 {
        Value::from(due_ns.round() as i64)
    } else {
        Value::Null
    };
    let mut fields = Map::new();
    fields.insert("ts".into(), json!(audit_chain::iso_utc_millis(wall.unwrap_or(0))));
    fields.insert("kind".into(), json!(ROLLBACK_STARTED_KIND));
    fields.insert("trace_id".into(), json!(task.trace_id));
    fields.insert("source".into(), json!(ROLLBACK_AUDIT_SOURCE));
    fields.insert("record_schema".into(), json!(ROLLBACK_STARTED_SCHEMA));
    fields.insert("release_task_id".into(), json!(task.task_id));
    fields.insert("action".into(), json!(task.action));
    fields.insert("resource_key".into(), json!(task.resource_key));
    fields.insert("owner_token".into(), json!(task.owner_token));
    fields.insert("trigger".into(), json!("lease_expired"));
    fields.insert("attempt".into(), json!(u64::from(task.attempts) + 1));
    fields.insert("lease_due_epoch_ns".into(), lease_due_epoch_ns);
    fields.insert(
        "lease_clock".into(),
        json!(if task.due_boottime_ns.is_some() { "earlier_of_wall_clock_and_boottime" } else { "wall_clock" }),
    );
    fields.insert("lease_due_boottime_ns".into(), task.due_boottime_ns.map(Value::from).unwrap_or(Value::Null));
    // A malformed boot id is not copied into the chain (it is bounded only by
    // the ledger size); the record says it was malformed instead.
    let lease_boot_id = if task.due_boot_id.is_empty() || valid_boot_id(&task.due_boot_id) {
        task.due_boot_id.as_str()
    } else {
        "invalid"
    };
    fields.insert("lease_boot_id".into(), json!(lease_boot_id));
    fields.insert("expiry_clock".into(), json!(expiry_clock.as_str()));
    fields.insert("started_monotonic_ns".into(), monotonic.map(Value::from).unwrap_or(Value::Null));
    fields.insert("started_boottime_ns".into(), boottime.map(Value::from).unwrap_or(Value::Null));
    fields.insert("boottime_clock".into(), json!("CLOCK_BOOTTIME"));
    fields.insert("started_wall_epoch_ns".into(), wall.map(Value::from).unwrap_or(Value::Null));
    fields.insert("monotonic_clock".into(), json!("CLOCK_MONOTONIC"));
    fields.insert("boot_id".into(), json!(audit_chain::boot_id()));
    audit_chain::append(&rollback_audit_path(ledger_path), fields).map(|_| ())
}

fn release_owned_state<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    runner: &R,
    now_epoch: f64,
) -> Result<ReleaseOutcome, String> {
    if is_legacy_tc_throttle(task) {
        return release_throttle(task, runner, now_epoch);
    }
    match owned_nft_chain(task) {
        Some(chain) => release_nft_rule(task, chain, runner, now_epoch),
        None => Err("unsupported release action".to_string()),
    }
}

fn release_throttle<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    runner: &R,
    now_epoch: f64,
) -> Result<ReleaseOutcome, String> {
    if !tc_owned_state_present(task, runner)? {
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
    let argv = strings(&[
        "tc",
        "qdisc",
        "del",
        "dev",
        &task.iface,
        "root",
        "handle",
        &task.tc_handle,
    ]);
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
    if tc_owned_state_present(task, runner)? {
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

fn tc_owned_state_present<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    runner: &R,
) -> Result<bool, String> {
    let argv = strings(&["tc", "-j", "qdisc", "show", "dev", &task.iface]);
    let result = runner.run(&argv)?;
    if result.returncode != 0 {
        return Err(format!(
            "tc readback failed: {}",
            bounded_error(&result.stderr)
        ));
    }
    let payload: Value = serde_json::from_str(&result.stdout)
        .map_err(|e| format!("tc readback parse failed: {e}"))?;
    let items = payload
        .as_array()
        .ok_or_else(|| "tc readback was not an array".to_string())?;
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

fn release_nft_rule<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    chain: &str,
    runner: &R,
    now_epoch: f64,
) -> Result<ReleaseOutcome, String> {
    let owned = nft_owned_rules(task, chain, runner)?;
    let handles: Vec<u64> = owned.iter().map(|(handle, _)| *handle).collect();
    let deviating = owned.iter().filter(|(_, planned)| !planned).count();
    if handles.is_empty() {
        let connections = clear_redirect_connections(task, runner);
        return Ok(outcome_for(
            task,
            now_epoch,
            "released",
            "owned_state_already_absent",
            0,
            0,
            Vec::new(),
            json!({"verified": true, "owned_rule_count": 0, "existing_connections": connections}),
        ));
    }

    let mut command_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut errors = Vec::new();
    for handle in handles {
        let handle_string = handle.to_string();
        let argv = strings(&[
            "nft",
            "delete",
            "rule",
            "inet",
            "azazel_edge",
            chain,
            "handle",
            &handle_string,
        ]);
        command_count += 1;
        match runner.run(&argv) {
            Ok(result) if result.returncode == 0 => {}
            Ok(result) => {
                failed_count += 1;
                errors.push(bounded_error(&result.stderr));
            }
            Err(error) => {
                failed_count += 1;
                errors.push(bounded_error(&error));
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
    let remaining = nft_owned_rules(task, chain, runner)?;
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
    // The rule is gone (verified above); connections it already redirected
    // live on in connection tracking. That is separate evidence.
    let connections = clear_redirect_connections(task, runner);
    Ok(outcome_for(
        task,
        now_epoch,
        "released",
        "rollback_applied_and_absence_verified",
        command_count,
        0,
        Vec::new(),
        json!({
            "verified": true,
            "owned_rule_count": 0,
            "deleted_deviating_rules": deviating,
            "existing_connections": connections,
        }),
    ))
}

/// After a redirect's rule is gone, connections it already redirected keep
/// their NAT binding in connection tracking and stay on the decoy. Delete
/// the tracking entries of the owned flow only (original tuple: this
/// source, destination when the lease has one, TCP port); the next packet
/// of such a connection is no longer translated and the connection ends,
/// new connections go to the real destination. Not a redirect:
/// `not_applicable`. Reported apart from the rule's absence:
/// `cleared`, `none_found`, `conntrack_unavailable` (no `conntrack` tool;
/// redirected connections may persist until they close), `failed:<why>`.
fn clear_redirect_connections<R: ReleaseCommandRunner>(task: &ReleaseTask, runner: &R) -> String {
    if task.action != "redirect" {
        return "not_applicable".to_string();
    }
    let port = task.destination_port.to_string();
    let argv = if task.destination_ip.is_empty() {
        strings(&["conntrack", "-D", "-p", "tcp", "--orig-src", &task.source_ip, "--dport", &port])
    } else {
        strings(&["conntrack", "-D", "-p", "tcp", "--orig-src", &task.source_ip, "--orig-dst", &task.destination_ip, "--dport", &port])
    };
    match runner.run(&argv) {
        Ok(result) if result.returncode == 0 => "cleared".to_string(),
        // conntrack exits 1 when no entry matched ("0 flow entries").
        Ok(result) if result.returncode == 1 && result.stderr.contains(" 0 flow entries") => "none_found".to_string(),
        Ok(result) => bounded_error(&format!("failed:exit={}:{}", result.returncode, result.stderr.trim())),
        Err(error) if error.contains("not found in trusted directories") => "conntrack_unavailable".to_string(),
        Err(error) => bounded_error(&format!("failed:{error}")),
    }
}

/// The rules carrying this lease's owner token in `chain`, with whether
/// each reads back exactly as planned. Two checks, kept apart:
///
/// * applied (`owned_state_matches_plan`): exactly one rule, as planned;
/// * removable (release): the owner token *and* the lease's own flow
///   identity (source, and the destination when the lease has one). A rule
///   that is ours by both but deviates otherwise (another rate, a missing
///   match) is still deleted -- leaving it would keep a restriction no
///   lease accounts for. A rule with our token on another flow is not ours
///   to delete: that is an error and nothing is deleted.
fn nft_owned_rules<R: ReleaseCommandRunner>(
    task: &ReleaseTask,
    chain: &str,
    runner: &R,
) -> Result<Vec<(u64, bool)>, String> {
    let argv = strings(&["nft", "-a", "-j", "list", "chain", "inet", "azazel_edge", chain]);
    let result = runner.run(&argv)?;
    if result.returncode != 0 {
        return Err(format!("nft readback failed: {}", bounded_error(&result.stderr)));
    }
    let payload: Value = serde_json::from_str(&result.stdout)
        .map_err(|e| format!("nft readback parse failed: {e}"))?;
    let entries = payload
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "nft readback missing nftables array".to_string())?;
    let mut rules = Vec::new();
    for entry in entries {
        let Some(rule) = entry.get("rule") else {
            continue;
        };
        if rule.get("chain").and_then(Value::as_str) != Some(chain) {
            continue;
        }
        if rule.get("comment").and_then(Value::as_str) != Some(task.owner_token.as_str()) {
            continue;
        }
        if !nft_rule_identity_match(task, rule) {
            return Err("nft ownership tag exists on a rule for another flow".to_string());
        }
        let handle = rule
            .get("handle")
            .and_then(Value::as_u64)
            .ok_or_else(|| "owned nft rule missing numeric handle".to_string())?;
        if handle == 0 {
            return Err("owned nft rule has invalid zero handle".to_string());
        }
        rules.push((handle, nft_rule_semantics_match(task, rule)));
    }
    Ok(rules)
}

/// The flow identity of an owned rule: its source, and its destination when
/// the lease names one.
fn nft_rule_identity_match(task: &ReleaseTask, rule: &Value) -> bool {
    let Some(exprs) = rule.get("expr").and_then(Value::as_array) else {
        return false;
    };
    let Some(family) = nft_family(&task.source_ip) else {
        return false;
    };
    if !ip_matches(match_value(exprs, family, "saddr"), &task.source_ip) {
        return false;
    }
    task.destination_ip.is_empty() || ip_matches(match_value(exprs, family, "daddr"), &task.destination_ip)
}

fn nft_rule_semantics_match(task: &ReleaseTask, rule: &Value) -> bool {
    let exprs = match rule.get("expr").and_then(Value::as_array) {
        Some(exprs) => exprs,
        None => return false,
    };
    if task.mechanism == MECHANISM_NFT_FLOW_LIMIT {
        return flow_limit_semantics_match(task, exprs);
    }
    if task.mechanism == MECHANISM_NFT_FLOW_REDIRECT {
        return meta_value(exprs, "iifname").and_then(Value::as_str) == Some(task.iface.as_str())
            && ip_matches(match_value(exprs, "ip", "saddr"), &task.source_ip)
            && ip_matches(match_value(exprs, "ip", "daddr"), &task.destination_ip)
            && match_value(exprs, "tcp", "dport").and_then(value_u16) == Some(task.destination_port)
            && exprs.iter().any(|expr| {
                expr.get("redirect").and_then(|r| r.get("port")).and_then(value_u16) == Some(task.redirect_port)
            });
    }
    if match_value(exprs, "ip", "saddr").and_then(Value::as_str)
        != Some(task.source_ip.as_str())
    {
        return false;
    }
    if task.action == "isolate" {
        return exprs.iter().any(|expr| expr.get("drop").is_some());
    }
    if task.action == "redirect" {
        if match_value(exprs, "tcp", "dport").and_then(value_u16)
            != Some(task.destination_port)
        {
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

/// nft family keyword of an address: `ip` or `ip6`.
pub fn nft_family(address: &str) -> Option<&'static str> {
    match address.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => Some("ip"),
        IpAddr::V6(_) => Some("ip6"),
    }
}

/// The flow-limit rule reads back as planned: this source, this
/// destination, this port (when one is scoped), an inverted (`over`) limit
/// of exactly the planned rate and burst per second, and `drop`.
fn flow_limit_semantics_match(task: &ReleaseTask, exprs: &[Value]) -> bool {
    let Some(family) = nft_family(&task.source_ip) else {
        return false;
    };
    if nft_family(&task.destination_ip) != Some(family) {
        return false;
    }
    if !ip_matches(match_value(exprs, family, "saddr"), &task.source_ip)
        || !ip_matches(match_value(exprs, family, "daddr"), &task.destination_ip)
    {
        return false;
    }
    if protocol_has_port(&task.protocol) {
        if match_value(exprs, &task.protocol, "dport").and_then(value_u16) != Some(task.destination_port) {
            return false;
        }
    } else if meta_value(exprs, "l4proto").and_then(Value::as_str) != Some(task.protocol.as_str())
        || exprs.iter().any(|expr| {
        expr.get("match")
            .and_then(|m| m.get("left"))
            .and_then(|l| l.get("payload"))
            .and_then(|p| p.get("field"))
            .and_then(Value::as_str)
            == Some("dport")
    }) {
        return false;
    }
    let limit_ok = exprs.iter().any(|expr| {
        let Some(limit) = expr.get("limit") else {
            return false;
        };
        limit.get("inv").and_then(Value::as_bool) == Some(true)
            && limit.get("per").and_then(Value::as_str) == Some("second")
            && limit.get("rate").and_then(Value::as_u64) == Some(u64::from(task.limit_rate_kbytes))
            && limit.get("rate_unit").and_then(Value::as_str) == Some("kbytes")
            && limit.get("burst").and_then(Value::as_u64) == Some(u64::from(task.limit_burst_kbytes))
            && limit.get("burst_unit").and_then(Value::as_str) == Some("kbytes")
    });
    limit_ok && exprs.iter().any(|expr| expr.get("drop").is_some())
}

/// The right side of an `==` match on `meta <key>`.
fn meta_value<'a>(exprs: &'a [Value], key: &str) -> Option<&'a Value> {
    exprs.iter().find_map(|expr| {
        let matched = expr.get("match")?;
        if matched.get("op").and_then(Value::as_str) != Some("==") {
            return None;
        }
        (matched.get("left")?.get("meta")?.get("key")?.as_str()? == key).then(|| matched.get("right")).flatten()
    })
}

fn ip_matches(value: Option<&Value>, expected: &str) -> bool {
    let (Some(observed), Ok(expected)) = (value.and_then(Value::as_str), expected.parse::<IpAddr>()) else {
        return false;
    };
    observed.parse::<IpAddr>().map(|o| o == expected).unwrap_or(false)
}

fn match_value<'a>(exprs: &'a [Value], protocol: &str, field: &str) -> Option<&'a Value> {
    for expr in exprs {
        let Some(matched) = expr.get("match") else {
            continue;
        };
        if matched.get("op").and_then(Value::as_str) != Some("==") {
            continue;
        }
        let Some(left) = matched.get("left") else {
            continue;
        };
        let Some(payload) = left.get("payload") else {
            continue;
        };
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

/// Locate the TBF readback fields (`rate`, `burst`, `lat`) in one `tc -j qdisc show`
/// item. iproute2 with TBF JSON support (observed: 5.5, 6.1, 6.15) nests them under
/// `options`; a flat top-level shape is accepted for compatibility. This is part of a
/// safety check, so anything ambiguous fails closed (returns `None`): a non-object
/// `options`, fields split across both locations, a field missing from the location
/// that carries the others, or the same field present in both with different values.
fn tbf_readback_fields(item: &Value) -> Option<[&Value; 3]> {
    const KEYS: [&str; 3] = ["rate", "burst", "lat"];
    let options = match item.get("options") {
        None => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => return None,
    };
    let nested_any = options.is_some_and(|map| KEYS.iter().any(|key| map.contains_key(*key)));
    let mut fields = [&Value::Null; 3];
    for (slot, key) in fields.iter_mut().zip(KEYS) {
        let top = item.get(key);
        let nested = options.and_then(|map| map.get(key));
        *slot = if nested_any {
            let nested = nested?;
            if top.is_some_and(|top| top != nested) {
                return None;
            }
            nested
        } else {
            top?
        };
    }
    Some(fields)
}

fn tbf_parameters_match(task: &ReleaseTask, item: &Value) -> bool {
    let Some([rate, burst, latency]) = tbf_readback_fields(item) else {
        return false;
    };
    let rate = parse_readback_rate_bps(rate);
    let burst = parse_readback_size_bytes(burst);
    let latency = parse_readback_time_us(latency);
    match (rate, burst, latency) {
        (Some(rate), Some(burst), Some(latency)) => {
            within_relative(task.expected_rate_bps, rate, 0.01)
                && within_relative(task.expected_burst_bytes, burst, 0.02)
                && abs_diff(task.expected_latency_us, latency)
                    <= 1000.max(task.expected_latency_us / 50)
        }
        _ => false,
    }
}

fn parse_readback_rate_bps(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return raw.checked_mul(8);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(
        &raw,
        &[
            ("gbit", 1_000_000_000),
            ("mbit", 1_000_000),
            ("kbit", 1_000),
            ("bit", 1),
        ],
    )
}

fn parse_readback_size_bytes(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return Some(raw);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(
        &raw,
        &[
            ("gbit", 1024 * 1024 * 1024 / 8),
            ("mbit", 1024 * 1024 / 8),
            ("kbit", 1024 / 8),
            ("gb", 1024 * 1024 * 1024),
            ("mb", 1024 * 1024),
            ("kb", 1024),
            ("b", 1),
        ],
    )
}

fn parse_readback_time_us(value: &Value) -> Option<u64> {
    if let Some(raw) = value.as_u64() {
        return Some(raw);
    }
    let raw = value.as_str()?.trim().to_ascii_lowercase();
    parse_scaled(
        &raw,
        &[
            ("msec", 1000),
            ("usec", 1),
            ("ms", 1000),
            ("us", 1),
            ("sec", 1_000_000),
            ("s", 1_000_000),
        ],
    )
}

fn parse_scaled(raw: &str, suffixes: &[(&str, u64)]) -> Option<u64> {
    for (suffix, factor) in suffixes {
        if let Some(number) = raw.strip_suffix(suffix) {
            let parsed = number.parse::<f64>().ok()?;
            if !parsed.is_finite() || parsed < 0.0 {
                return None;
            }
            let scaled = parsed * *factor as f64;
            if !scaled.is_finite() || scaled > u64::MAX as f64 {
                return None;
            }
            return Some(scaled.round() as u64);
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
        rollback_start_audit: "not_applicable".to_string(),
        expiry_clock: String::new(),
    }
}

/// Schedule the next retry after the backoff for `task.attempts` (at least
/// 2 s), on the wall clock and, for a lease with a monotonic deadline, on
/// `CLOCK_BOOTTIME` with the boot it belongs to. Either clock can make the
/// retry due, so a wall clock stepped back cannot hold it past its backoff.
/// The wall retry time may then lie before the task's creation, which
/// `validate_task` allows once an attempt has been made.
fn schedule_retry(task: &mut ReleaseTask, now: &LeaseNow) {
    let delay = retry_delay_seconds(task.attempts);
    task.next_attempt_epoch = now.wall_epoch + delay;
    let monotonic = match (task.due_boottime_ns, now.boottime_ns, now.boot_id.as_deref()) {
        (Some(_), Some(boottime), Some(boot_id)) if valid_boot_id(boot_id) => boottime
            .checked_add(delay as u64 * 1_000_000_000)
            .filter(|at| *at <= i64::MAX as u64)
            .map(|at| (at, boot_id.to_string())),
        _ => None,
    };
    match monotonic {
        Some((at, boot_id)) => {
            task.next_attempt_boottime_ns = Some(at);
            task.next_attempt_boot_id = boot_id;
        }
        None => {
            task.next_attempt_boottime_ns = None;
            task.next_attempt_boot_id.clear();
        }
    }
}

/// Whether a retry is due on `CLOCK_BOOTTIME`. In the boot it was scheduled
/// in, it is due once its time has passed; in another boot it is due at once
/// (the attempt then schedules the next retry in this boot, so this fires
/// once per boot, never every sweep). With no monotonic retry time, or when
/// the boot id or the clock cannot be read now, only the wall retry time
/// counts: making it due at once would retry on every sweep.
fn retry_due_on_boottime(task: &ReleaseTask, now: &LeaseNow) -> bool {
    let Some(at) = task.next_attempt_boottime_ns else {
        return false;
    };
    let (Some(boot_id), Some(boottime)) = (now.boot_id.as_deref(), now.boottime_ns) else {
        return false;
    };
    if task.next_attempt_boot_id != boot_id {
        return true;
    }
    boottime >= at
}

fn retry_delay_seconds(attempts: u32) -> f64 {
    let power = attempts.min(8);
    (2_u64.pow(power) as f64).min(300.0)
}

fn eligible_status(status: &str) -> bool {
    matches!(status, "prepared" | "active" | "uncertain")
}

/// `merged`: a restriction admitted as an extension of a held lease; kept as
/// the replay guard of its alert, never applied or released itself.
fn terminal_status(status: &str) -> bool {
    matches!(status, "released" | "cancelled" | "superseded" | "merged")
}

fn valid_status(status: &str) -> bool {
    eligible_status(status) || terminal_status(status)
}

fn validate_now(value: f64) -> Result<(), String> {
    if value.is_finite() && value >= 0.0 {
        Ok(())
    } else {
        Err("release clock must be finite and non-negative".to_string())
    }
}

fn load_ledger(path: &str) -> Result<ReleaseLedger, String> {
    let source = Path::new(path);
    if !source.exists() {
        return Ok(ReleaseLedger::default());
    }
    let metadata = fs::symlink_metadata(source)
        .map_err(|e| format!("release ledger metadata failed: {e}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("release ledger must be a regular non-symlink file".to_string());
    }
    if metadata.len() > MAX_LEDGER_BYTES {
        return Err("release ledger exceeds safety size bound".to_string());
    }
    let raw = fs::read_to_string(source)
        .map_err(|e| format!("release ledger read failed: {e}"))?;
    let mut ledger: ReleaseLedger = serde_json::from_str(&raw)
        .map_err(|e| format!("release ledger parse failed: {e}"))?;
    if ledger.schema_version == LEDGER_SCHEMA_V1 {
        // A v1 ledger has no checkpoint and its tasks have no event key; a
        // v1 task id (built from the old mechanism and action) does not
        // match what this core builds for the same alert. Migration boundary:
        // every alert at or before the v1 file's last write is refused as a
        // possible replay. The boundary is the file's own mtime, so reading
        // the same v1 file again gives the same boundary; it is kept in the
        // checkpoint when the ledger is saved as v2.
        if !ledger.tasks.is_empty() {
            let written = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs_f64())
                .unwrap_or(f64::MAX);
            let boundary = if written.is_finite() { written } else { f64::MAX / 2.0 };
            ledger.checkpoint.replay_watermark_epoch = ledger.checkpoint.replay_watermark_epoch.max(boundary);
            ledger.checkpoint.generation = ledger.checkpoint.generation.max(1);
        }
        ledger.schema_version = LEDGER_SCHEMA_VERSION.to_string();
    }
    if ledger.schema_version != LEDGER_SCHEMA_VERSION {
        return Err("unsupported release ledger schema".to_string());
    }
    let mark = ledger.checkpoint.replay_watermark_epoch;
    if !mark.is_finite() || mark < 0.0 {
        return Err("release ledger checkpoint is invalid".to_string());
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
    let destination = Path::new(path);
    let parent = destination
        .parent()
        .ok_or_else(|| "release ledger path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("release ledger mkdir failed: {e}"))?;
    if destination.exists() {
        let metadata = fs::symlink_metadata(destination)
            .map_err(|e| format!("release ledger metadata failed: {e}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("release ledger destination is not a regular file".to_string());
        }
    }
    let encoded = serde_json::to_vec(ledger)
        .map_err(|e| format!("release ledger serialize failed: {e}"))?;
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

fn validate_task(task: &ReleaseTask) -> Result<(), String> {
    if task.task_id.is_empty()
        || task.trace_id.is_empty()
        || task.resource_key.is_empty()
        || task.owner_token.is_empty()
    {
        return Err("release task missing identity fields".to_string());
    }
    if !matches!(task.action.as_str(), "throttle" | "isolate" | "redirect") {
        return Err("release task has unsupported action".to_string());
    }
    if !valid_status(&task.status) {
        return Err("release task has invalid lifecycle status".to_string());
    }
    for value in [
        task.due_epoch,
        task.next_attempt_epoch,
        task.created_epoch,
        task.updated_epoch,
    ]
    .into_iter()
    .chain(task.event_epoch)
    .chain(task.family_started_epoch)
    .chain(task.cooldown_until_epoch)
    {
        validate_now(value)?;
    }
    // Before any attempt the next attempt is the expiry itself. After one, it
    // is the wall clock at that attempt plus the backoff, and the wall clock
    // may have been stepped back past the task's creation by then.
    if task.due_epoch < task.created_epoch
        || (task.attempts == 0 && task.next_attempt_epoch < task.created_epoch)
    {
        return Err("release task has impossible time ordering".to_string());
    }
    // A malformed boot id or monotonic deadline does not reject the ledger
    // (that would hold every lease back); lease_expiry counts that lease's
    // monotonic deadline as passed (`boot_invalid`).
    if task.source_ip.parse::<IpAddr>().is_err() {
        return Err("release task has invalid source IP".to_string());
    }
    if !valid_owner_token(&task.owner_token) {
        return Err("release task has invalid owner token".to_string());
    }
    if task.action == "throttle" && task.mechanism == MECHANISM_NFT_FLOW_LIMIT {
        if !task.tc_handle.is_empty()
            || nft_family(&task.source_ip).is_none()
            || nft_family(&task.destination_ip) != nft_family(&task.source_ip)
            || !FLOW_PROTOCOLS.contains(&task.protocol.as_str())
            || protocol_has_port(&task.protocol) != (task.destination_port != 0)
            || task.limit_rate_kbytes == 0
            || task.limit_burst_kbytes == 0
        {
            return Err("release task has invalid flow-limit semantics".to_string());
        }
    } else if task.action == "redirect" && task.mechanism == MECHANISM_NFT_FLOW_REDIRECT {
        if task.protocol != "tcp"
            || !valid_interface(&task.iface)
            || nft_family(&task.source_ip) != Some("ip")
            || nft_family(&task.destination_ip) != Some("ip")
        {
            return Err("release task has invalid flow-redirect semantics".to_string());
        }
    } else if !task.mechanism.is_empty() {
        return Err("release task has unsupported mechanism".to_string());
    } else if task.action == "throttle" {
        if !valid_interface(&task.iface) || !valid_tc_handle(&task.tc_handle) {
            return Err("release task has invalid tc ownership".to_string());
        }
        if task.expected_rate_bps == 0
            || task.expected_burst_bytes == 0
            || task.expected_latency_us == 0
        {
            return Err("release task has invalid TBF semantics".to_string());
        }
    }
    if task.action == "redirect" && (task.destination_port == 0 || task.redirect_port == 0) {
        return Err("release task has invalid redirect ports".to_string());
    }
    Ok(())
}

fn valid_boot_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BOOT_ID_LEN
        && value.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
}

fn temp_path(destination: &Path) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("release-ledger");
    destination.with_file_name(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        stamp
    ))
}

/// A `Command` for a binary found by `resolve_trusted_binary`, with nothing
/// inherited from the core's environment: only `LC_ALL`/`LANG` (C, so the
/// output and messages do not depend on the locale) and a fixed `PATH` of the
/// trusted directories. The apply path (main.rs `run_command`) and the release
/// path both start nft and tc through it (Edge#477).
pub(crate) fn trusted_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PATH", TRUSTED_DIRS.join(":"));
    command
}

/// The absolute path of `nft` or `tc` in the first trusted directory that
/// has it; any other name is refused. `PATH` is never consulted.
pub(crate) fn resolve_trusted_binary(name: &str) -> Result<PathBuf, String> {
    if !matches!(name, "tc" | "nft" | "conntrack") {
        return Err("unsupported release binary".to_string());
    }
    for directory in TRUSTED_DIRS {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "release binary not found in trusted directories: {name}"
    ))
}

fn allowed_release_command(argv: &[String]) -> bool {
    // `conntrack -D -p tcp --orig-src S --orig-dst D --dport P` (or without
    // the destination for a legacy redirect): only the owned flow's
    // connection-tracking entries.
    if argv.first().map(String::as_str) == Some("conntrack") {
        let ip_ok = |value: &String| value.parse::<IpAddr>().is_ok();
        let port_ok = |value: &String| value.parse::<u16>().map(|p| p > 0).unwrap_or(false);
        return match argv.len() {
            10 => argv[1] == "-D" && argv[2] == "-p" && argv[3] == "tcp" && argv[4] == "--orig-src" && ip_ok(&argv[5])
                && argv[6] == "--orig-dst" && ip_ok(&argv[7]) && argv[8] == "--dport" && port_ok(&argv[9]),
            8 => argv[1] == "-D" && argv[2] == "-p" && argv[3] == "tcp" && argv[4] == "--orig-src" && ip_ok(&argv[5])
                && argv[6] == "--dport" && port_ok(&argv[7]),
            _ => false,
        };
    }
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
        return matches!(argv[7].as_str(), "input" | "prerouting" | THROTTLE_CHAIN);
    }
    if argv.len() == 8
        && argv[0] == "nft"
        && argv[1] == "delete"
        && argv[2] == "rule"
        && argv[3] == "inet"
        && argv[4] == "azazel_edge"
        && argv[6] == "handle"
    {
        return matches!(argv[5].as_str(), "input" | "prerouting" | THROTTLE_CHAIN)
            && argv[7].parse::<u64>().map(|v| v > 0).unwrap_or(false);
    }
    false
}

fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':'))
}

fn valid_tc_handle(value: &str) -> bool {
    let Some(raw) = value.strip_suffix(':') else {
        return false;
    };
    !raw.is_empty()
        && raw.len() <= 4
        && u16::from_str_radix(raw, 16)
            .map(|value| value > 0)
            .unwrap_or(false)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
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

    // Edge#477: nft/tc (apply and release) start with nothing inherited.
    #[test]
    fn trusted_command_sets_only_a_c_locale_and_a_fixed_path() {
        let command = trusted_command(Path::new("/usr/bin/env"));
        let mut envs: Vec<(String, Option<String>)> = command
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        envs.sort();
        assert_eq!(
            envs,
            vec![
                ("LANG".to_string(), Some("C".to_string())),
                ("LC_ALL".to_string(), Some("C".to_string())),
                (
                    "PATH".to_string(),
                    Some("/usr/sbin:/usr/bin:/sbin:/bin".to_string())
                ),
            ]
        );
        assert_eq!(command.get_program(), Path::new("/usr/bin/env").as_os_str());
    }

    #[test]
    fn trusted_command_clears_the_inherited_environment() {
        // The test process always has more than these three variables (HOME,
        // CARGO_*, ...); the child sees exactly the three it is given.
        let env_bin = ["/usr/bin/env", "/bin/env"]
            .iter()
            .map(Path::new)
            .find(|p| p.is_file())
            .expect("env(1) in /usr/bin or /bin");
        assert!(std::env::vars_os().any(|(k, _)| k != "LC_ALL" && k != "LANG" && k != "PATH"));
        let out = trusted_command(env_bin).output().expect("run env");
        assert!(out.status.success());
        let mut lines: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        assert_eq!(
            lines,
            vec![
                "LANG=C".to_string(),
                "LC_ALL=C".to_string(),
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            ]
        );
    }

    #[test]
    fn resolve_trusted_binary_refuses_other_names_and_paths() {
        for name in ["sh", "true", "/tmp/nft", "./nft", "../sbin/nft", "nft ", ""] {
            assert!(resolve_trusted_binary(name).is_err(), "{name:?}");
        }
        for name in ["nft", "tc"] {
            if let Ok(path) = resolve_trusted_binary(name) {
                assert!(path.is_absolute());
                assert!(TRUSTED_DIRS.contains(&path.parent().unwrap().to_str().unwrap()));
                assert_eq!(path.file_name().unwrap(), name);
            }
        }
    }

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
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err("missing fake result".to_string()))
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
        // Tests run in parallel; two calls in the same clock tick would share
        // a directory and each other's ledger, so a counter keeps them apart.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "azazel-release-test-{}-{stamp}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.join(name).to_string_lossy().to_string()
    }

    #[test]
    fn generated_owner_tokens_are_valid_nft_comment_strings() {
        for (trace, action) in [("t1", "isolate"), ("t2", "redirect"), ("t3", "throttle")] {
            let task = build_release_task(
                trace, action, "br0", "10.0.0.8", 443, 2222, 0, 300, &LeaseNow::wall_only(100.0),
            )
            .unwrap();
            assert!(valid_owner_token(&task.owner_token));
            assert_eq!(nft_comment_arg(&task.owner_token).unwrap(), format!("\"{}\"", task.owner_token));
        }
        for bad in ["", "azazel-edge:release-\"x", "azazel-edge:release- x", "azazel-edge:release-x;y", "release-x"] {
            assert!(nft_comment_arg(bad).is_err(), "{bad:?}");
        }
        assert!(nft_comment_arg(&format!("azazel-edge:release-{}", "a".repeat(80))).is_err());
    }

    #[test]
    fn task_identity_is_stable_and_burst_uses_iproute2_size_semantics() {
        let one = build_release_task(
            "trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let two = build_release_task(
            "trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        assert_eq!(one.task_id, two.task_id);
        assert_eq!(one.owner_token, two.owner_token);
        assert!(valid_tc_handle(&one.tc_handle));
        assert_eq!(one.expected_burst_bytes, 4096);
    }

    #[test]
    fn duplicate_prepare_blocks_replayed_apply_and_does_not_extend_ttl() {
        let path = test_path("ledger.json");
        let first = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let replay = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(200.0),
        )
        .unwrap();
        prepare_release_task(&path, &first).unwrap();
        let error = prepare_release_task(&path, &replay).unwrap_err();
        assert!(error.contains("replayed disruptive apply blocked"));
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks.len(), 1);
        assert_eq!(ledger.tasks[0].due_epoch, 400.0);
    }

    #[test]
    fn terminal_identity_is_retained_for_replay_guard() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-retained", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        cancel_release_task(&path, &task.task_id, "test", 100.5).unwrap();
        let replay = build_release_task(
            "trace-retained", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(200.0),
        )
        .unwrap();
        assert!(prepare_release_task(&path, &replay).is_err());
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks.len(), 1);
        assert_eq!(ledger.tasks[0].status, "cancelled");
    }

    #[test]
    fn terminal_task_cannot_be_reactivated() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        cancel_release_task(&path, &task.task_id, "test", 100.5).unwrap();
        assert!(activate_release_task(&path, &task.task_id, 101.0).is_err());
    }

    #[test]
    fn throttle_activation_supersedes_only_older_throttle_owner() {
        let path = test_path("ledger.json");
        let first = build_release_task(
            "trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let second = build_release_task(
            "trace-b", "throttle", "br0", "10.0.0.9", 22, 12222, 1000, 300, &LeaseNow::wall_only(110.0),
        )
        .unwrap();
        prepare_release_task(&path, &first).unwrap();
        activate_release_task(&path, &first.task_id, 101.0).unwrap();
        prepare_release_task(&path, &second).unwrap();
        activate_release_task(&path, &second.task_id, 111.0).unwrap();
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(
            ledger
                .tasks
                .iter()
                .find(|task| task.task_id == first.task_id)
                .unwrap()
                .status,
            "superseded"
        );
        assert_eq!(
            ledger
                .tasks
                .iter()
                .find(|task| task.task_id == second.task_id)
                .unwrap()
                .status,
            "active"
        );
    }

    #[test]
    fn ambiguous_same_handle_newer_prepared_task_defers_old_throttle_release() {
        let path = test_path("ledger.json");
        let old = build_release_task(
            "trace-old", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 10, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let mut newer = build_release_task(
            "trace-new", "throttle", "br0", "10.0.0.9", 22, 12222, 1000, 100, &LeaseNow::wall_only(105.0),
        )
        .unwrap();
        newer.tc_handle = old.tc_handle.clone();
        prepare_release_task(&path, &old).unwrap();
        activate_release_task(&path, &old.task_id, 101.0).unwrap();
        prepare_release_task(&path, &newer).unwrap();
        let runner = FakeRunner::new(Vec::new());
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(111.0), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "retry_pending");
        assert_eq!(outcomes[0].result, "ambiguous_newer_throttle_owner");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn nft_tasks_with_same_scope_remain_independently_releasable() {
        let path = test_path("ledger.json");
        let first = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let second = build_release_task(
            "trace-b", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(110.0),
        )
        .unwrap();
        prepare_release_task(&path, &first).unwrap();
        activate_release_task(&path, &first.task_id, 101.0).unwrap();
        prepare_release_task(&path, &second).unwrap();
        activate_release_task(&path, &second.task_id, 111.0).unwrap();
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(
            ledger
                .tasks
                .iter()
                .filter(|task| task.status == "active")
                .count(),
            2
        );
    }

    #[test]
    fn prepared_task_survives_restart_and_absent_owned_state_closes_release() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].result, "owned_state_already_absent");
        assert_eq!(load_ledger(&path).unwrap().tasks[0].status, "released");
    }

    #[test]
    fn no_due_task_performs_no_runner_call_and_no_lifecycle_change() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(Vec::new());
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(101.0), &runner).unwrap();
        assert!(outcomes.is_empty());
        assert!(runner.calls.lock().unwrap().is_empty());
        assert_eq!(load_ledger(&path).unwrap().tasks[0].status, "prepared");
    }

    #[test]
    fn nft_release_deletes_only_owned_handle_and_verifies_absence_with_noise_expr() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let owned = json!({"nftables": [{"rule": {
            "chain": "input",
            "handle": 42,
            "comment": task.owner_token,
            "expr": [
                {"counter": {"packets": 1, "bytes": 64}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.8"}},
                {"drop": null}
            ]
        }}]});
        let runner = FakeRunner::new(vec![
            ok_json(owned),
            Ok(CommandResult {
                returncode: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
            ok_json(json!({"nftables": []})),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        let calls = runner.calls.lock().unwrap();
        assert!(calls.iter().any(|call| {
            call == &strings(&[
                "nft", "delete", "rule", "inet", "azazel_edge", "input", "handle", "42",
            ])
        }));
    }

    #[test]
    fn ownership_tag_semantic_mismatch_never_deletes_rule() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let poisoned = json!({"nftables": [{"rule": {
            "chain": "input",
            "handle": 42,
            "comment": task.owner_token,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.0.0.99"}},
                {"drop": null}
            ]
        }}]});
        let runner = FakeRunner::new(vec![ok_json(poisoned)]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "retry_pending");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn tc_release_never_deletes_different_owner_handle() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!([{
            "kind": "tbf", "root": true, "handle": "ffff:", "rate": 32000,
            "burst": 4096, "lat": 1_000_000
        }]))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].result, "owned_state_already_absent");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    // Captured verbatim from `tc -j qdisc show dev d0` after
    // `tc qdisc replace dev d0 root handle 1a: tbf rate 256kbit burst 32kbit latency 1000ms`
    // in a NET_ADMIN container. iproute2 5.5 (ss200127) emits the same shape.
    const TC_JSON_IPROUTE2_6_15: &str = r#"[{"kind":"tbf","handle":"1a:","root":true,"refcnt":2,"options":{"rate":32000,"burst":4096,"lat":999999}}]"#;
    const TC_JSON_IPROUTE2_6_1: &str = r#"[{"kind":"tbf","handle":"1a:","root":true,"refcnt":2,"options":{"rate":32000,"burst":4096,"lat":999999}}]"#;
    // iproute2 4.15 (ss180129) has no TBF JSON printer and emits text inside `options`,
    // which is not valid JSON.
    const TC_JSON_IPROUTE2_4_15: &str = "[{\n        \"kind\": \"tbf\",\n        \"handle\": \"1a:\",\n        \"root\": true,\n        \"refcnt\": 2,\n        \"options\": {rate 256Kbit burst 4Kb lat 1000.0ms }\n    }\n]";

    fn tbf_task() -> ReleaseTask {
        build_release_task(
            "trace-a",
            "throttle",
            "br0",
            "10.0.0.8",
            22,
            12222,
            1000,
            1,
            &LeaseNow::wall_only(100.0),
        )
        .unwrap()
    }

    fn captured_item(capture: &str, task: &ReleaseTask) -> Value {
        let payload: Value =
            serde_json::from_str(&capture.replace("\"1a:\"", &format!("\"{}\"", task.tc_handle)))
                .unwrap();
        payload.as_array().unwrap()[0].clone()
    }

    #[test]
    fn tbf_parameters_are_read_from_options_in_captured_iproute2_json() {
        let task = tbf_task();
        assert!(tbf_parameters_match(
            &task,
            &captured_item(TC_JSON_IPROUTE2_6_15, &task)
        ));
        assert!(tbf_parameters_match(
            &task,
            &captured_item(TC_JSON_IPROUTE2_6_1, &task)
        ));
    }

    #[test]
    fn tbf_parameters_flat_top_level_shape_is_still_accepted() {
        let task = tbf_task();
        let flat = json!({"kind": "tbf", "root": true, "handle": task.tc_handle,
            "rate": 32000, "burst": 4096, "lat": 999999});
        assert!(tbf_parameters_match(&task, &flat));
        let both_equal = json!({"kind": "tbf", "root": true, "handle": task.tc_handle,
            "rate": 32000, "burst": 4096, "lat": 999999,
            "options": {"rate": 32000, "burst": 4096, "lat": 999999}});
        assert!(tbf_parameters_match(&task, &both_equal));
    }

    #[test]
    fn tbf_parameters_options_values_are_compared_not_just_located() {
        let task = tbf_task();
        for (key, value) in [
            ("rate", json!(64000)),
            ("burst", json!(8192)),
            ("lat", json!(50000)),
        ] {
            let mut item = captured_item(TC_JSON_IPROUTE2_6_15, &task);
            item["options"][key] = value;
            assert!(!tbf_parameters_match(&task, &item), "{key}");
        }
    }

    #[test]
    fn tbf_parameters_ambiguous_missing_or_mistyped_readback_fails_closed() {
        let task = tbf_task();
        let h = task.tc_handle.clone();
        let refused = [
            // same field in both places with different values
            json!({"kind": "tbf", "root": true, "handle": h, "rate": 64000,
                "options": {"rate": 32000, "burst": 4096, "lat": 999999}}),
            json!({"kind": "tbf", "root": true, "handle": h, "lat": "1s",
                "options": {"rate": 32000, "burst": 4096, "lat": 999999}}),
            // a field missing from options
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": {"rate": 32000, "burst": 4096}}),
            // fields split across options and the top level
            json!({"kind": "tbf", "root": true, "handle": h, "lat": 999999,
                "options": {"rate": 32000, "burst": 4096}}),
            // nothing at all
            json!({"kind": "tbf", "root": true, "handle": h}),
            json!({"kind": "tbf", "root": true, "handle": h, "options": {}}),
            // options of an unexpected type
            json!({"kind": "tbf", "root": true, "handle": h, "options": null,
                "rate": 32000, "burst": 4096, "lat": 999999}),
            json!({"kind": "tbf", "root": true, "handle": h, "options": "rate 256Kbit",
                "rate": 32000, "burst": 4096, "lat": 999999}),
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": [{"rate": 32000, "burst": 4096, "lat": 999999}]}),
            // fields of an unexpected type
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": {"rate": 32000.0, "burst": 4096, "lat": 999999}}),
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": {"rate": true, "burst": 4096, "lat": 999999}}),
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": {"rate": {"value": 32000}, "burst": 4096, "lat": 999999}}),
            json!({"kind": "tbf", "root": true, "handle": h,
                "options": {"rate": 32000, "burst": null, "lat": 999999}}),
        ];
        for item in refused {
            assert!(!tbf_parameters_match(&task, &item), "{item}");
        }
    }

    fn due_throttle(path: &str) -> ReleaseTask {
        let task = tbf_task();
        prepare_release_task(path, &task).unwrap();
        activate_release_task(path, &task.task_id, 100.5).unwrap();
        task
    }

    fn ok_raw(stdout: &str) -> Result<CommandResult, String> {
        Ok(CommandResult {
            returncode: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        })
    }

    #[test]
    fn tc_release_deletes_owned_tbf_reported_under_options_and_verifies_absence() {
        for capture in [TC_JSON_IPROUTE2_6_15, TC_JSON_IPROUTE2_6_1] {
            let path = test_path("ledger.json");
            let task = due_throttle(&path);
            let owned = capture.replace("\"1a:\"", &format!("\"{}\"", task.tc_handle));
            let runner = FakeRunner::new(vec![
                ok_raw(&owned),
                ok_raw(""),
                ok_raw(r#"[{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,"options":{}}]"#),
            ]);
            let outcomes =
                process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner)
                    .unwrap();
            assert_eq!(outcomes[0].status, "released");
            assert_eq!(outcomes[0].result, "rollback_applied_and_absence_verified");
            let calls = runner.calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            assert_eq!(
                calls[1],
                strings(&[
                    "tc",
                    "qdisc",
                    "del",
                    "dev",
                    "br0",
                    "root",
                    "handle",
                    &task.tc_handle
                ])
            );
        }
    }

    #[test]
    fn tc_release_never_deletes_when_options_readback_is_ambiguous_or_unparseable() {
        let conflicting = |task: &ReleaseTask| {
            json!([{"kind": "tbf", "root": true, "handle": task.tc_handle, "rate": 64000,
                "options": {"rate": 32000, "burst": 4096, "lat": 999999}}])
            .to_string()
        };
        let incomplete = |task: &ReleaseTask| {
            json!([{"kind": "tbf", "root": true, "handle": task.tc_handle,
                "options": {"rate": 32000, "burst": 4096}}])
            .to_string()
        };
        let legacy_text = |task: &ReleaseTask| {
            TC_JSON_IPROUTE2_4_15.replace("\"1a:\"", &format!("\"{}\"", task.tc_handle))
        };
        let cases: [&dyn Fn(&ReleaseTask) -> String; 3] = [&conflicting, &incomplete, &legacy_text];
        for build in cases {
            let path = test_path("ledger.json");
            let task = due_throttle(&path);
            let runner = FakeRunner::new(vec![ok_raw(&build(&task))]);
            let outcomes =
                process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner)
                    .unwrap();
            assert_eq!(outcomes[0].status, "retry_pending");
            let calls = runner.calls.lock().unwrap();
            assert_eq!(
                calls.len(),
                1,
                "no tc qdisc del may follow a refused readback"
            );
        }
    }

    #[test]
    fn tbf_parameters_options_path_keeps_the_existing_tolerance_boundaries() {
        // expected: 256000 bit/s (1% -> 2560 bit/s = 320 B/s), 4096 B (2% -> 82 B),
        // 1_000_000 us (max(1000, 2%) -> 20000 us). The options path must not widen these.
        let task = tbf_task();
        let at = |rate: u64, burst: u64, lat: u64| {
            let mut item = captured_item(TC_JSON_IPROUTE2_6_15, &task);
            item["options"] = json!({"rate": rate, "burst": burst, "lat": lat});
            tbf_parameters_match(&task, &item)
        };
        assert!(at(32320, 4096, 1_000_000));
        assert!(at(31680, 4096, 1_000_000));
        assert!(!at(32321, 4096, 1_000_000));
        assert!(!at(31679, 4096, 1_000_000));
        assert!(at(32000, 4178, 1_000_000));
        assert!(at(32000, 4014, 1_000_000));
        assert!(!at(32000, 4179, 1_000_000));
        assert!(!at(32000, 4013, 1_000_000));
        assert!(at(32000, 4096, 1_020_000));
        assert!(at(32000, 4096, 980_000));
        assert!(!at(32000, 4096, 1_020_001));
        assert!(!at(32000, 4096, 979_999));
    }

    #[test]
    fn tc_release_never_deletes_a_non_tbf_qdisc_with_tbf_like_options() {
        let path = test_path("ledger.json");
        let task = due_throttle(&path);
        let impostor = TC_JSON_IPROUTE2_6_15
            .replace("\"1a:\"", &format!("\"{}\"", task.tc_handle))
            .replace("\"kind\":\"tbf\"", "\"kind\":\"netem\"");
        let runner = FakeRunner::new(vec![ok_raw(&impostor)]);
        let outcomes =
            process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "retry_pending");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn release_command_allowlist_rejects_arbitrary_mutation_and_zero_handle() {
        assert!(!allowed_release_command(&strings(&[
            "nft", "flush", "ruleset",
        ])));
        assert!(!allowed_release_command(&strings(&[
            "nft", "delete", "rule", "inet", "azazel_edge", "input", "handle", "0",
        ])));
        assert!(!allowed_release_command(&strings(&[
            "tc", "qdisc", "del", "dev", "br0;id", "root", "handle", "1:",
        ])));
    }

    #[test]
    fn malformed_nonfinite_or_unknown_status_ledger_is_rejected() {
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let mut bad = task.clone();
        bad.status = "magic".to_string();
        assert!(validate_task(&bad).is_err());
        bad = task;
        bad.due_epoch = f64::INFINITY;
        assert!(validate_task(&bad).is_err());
    }

    struct OrderingRunner {
        audit_path: PathBuf,
        task_id: String,
        seen_at_first_call: Mutex<Option<(bool, u64)>>,
        calls: Mutex<u32>,
    }

    impl ReleaseCommandRunner for OrderingRunner {
        fn run(&self, _argv: &[String]) -> Result<CommandResult, String> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            let mut seen = self.seen_at_first_call.lock().unwrap();
            if seen.is_none() {
                let text = fs::read_to_string(&self.audit_path).unwrap_or_default();
                let present = text.lines().any(|line| {
                    let row: Value = serde_json::from_str(line).unwrap_or(Value::Null);
                    row["kind"] == json!(ROLLBACK_STARTED_KIND) && row["release_task_id"] == json!(self.task_id)
                });
                *seen = Some((present, audit_chain::SYNC_CALLS.with(|c| c.get())));
            }
            ok_json(json!({"nftables": []}))
        }
    }

    fn rollback_rows(ledger: &str) -> Vec<Value> {
        fs::read_to_string(rollback_audit_path(ledger))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    // fsync(2) is counted by interposing the libc symbol; Linux only.
    #[cfg_attr(not(target_os = "linux"), ignore)]
    fn rollback_start_record_is_durable_before_the_first_rollback_command() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = OrderingRunner {
            audit_path: rollback_audit_path(&path),
            task_id: task.task_id.clone(),
            seen_at_first_call: Mutex::new(None),
            calls: Mutex::new(0),
        };
        audit_chain::SYNC_CALLS.with(|c| c.set(0));
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(*runner.calls.lock().unwrap() >= 1);
        let (present, syncs) = runner.seen_at_first_call.lock().unwrap().unwrap();
        assert!(present, "no rollback_started record when the first rollback command ran");
        assert!(syncs >= 1, "the rollback_started record was not fsynced before the first rollback command");
    }

    #[test]
    fn rollback_start_record_names_the_lease_and_decision_on_integer_clocks() {
        let path = test_path("release-ledger.json");
        assert!(rollback_audit_path(&path)
            .to_string_lossy()
            .ends_with("/release-ledger.rollback-audit.jsonl"));
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let before = audit_chain::monotonic_ns().unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(outcomes[0].rollback_start_audit, "recorded");
        let after = audit_chain::monotonic_ns().unwrap();
        let rows = rollback_rows(&path);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row["kind"], json!("rollback_started"));
        assert_eq!(row["record_schema"], json!(ROLLBACK_STARTED_SCHEMA));
        assert_eq!(row["release_task_id"], json!(task.task_id));
        assert_eq!(row["trace_id"], json!("trace-a"));
        assert_eq!(row["action"], json!("isolate"));
        assert_eq!(row["attempt"], json!(1));
        assert_eq!(row["trigger"], json!("lease_expired"));
        assert_eq!(row["lease_due_epoch_ns"], json!(101_000_000_000_i64));
        assert_eq!(row["chain_prev"], json!(""));
        let mono = row["started_monotonic_ns"].as_u64().unwrap();
        assert!(before <= mono && mono <= after);
        assert!(row["started_wall_epoch_ns"].as_i64().unwrap() > 0);
        let mut unhashed = row.clone();
        let hash = unhashed.as_object_mut().unwrap().remove("chain_hash").unwrap();
        assert_eq!(
            hash,
            json!(audit_chain::sha256_hex(audit_chain::canonical_json(&unhashed).unwrap().as_bytes()))
        );
    }

    #[test]
    fn each_retry_records_its_own_start_on_the_same_chain() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        let first = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(first[0].status, "retry_pending");
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        process_due_releases_with_runner(&path, &LeaseNow::wall_only(200.0), &runner).unwrap();
        let rows = rollback_rows(&path);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["attempt"], json!(1));
        assert_eq!(rows[1]["attempt"], json!(2));
        assert_eq!(rows[1]["chain_prev"], rows[0]["chain_hash"]);
    }

    #[test]
    fn a_superseded_throttle_writes_no_rollback_start_record() {
        let path = test_path("ledger.json");
        let mut old = build_release_task(
            "trace-old", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 10, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let mut newer = build_release_task(
            "trace-new", "throttle", "br0", "10.0.0.9", 22, 12222, 1000, 100, &LeaseNow::wall_only(105.0),
        )
        .unwrap();
        // Both active, as a ledger written before activation superseded the
        // older owner leaves them; the sweep then supersedes the older one.
        old.status = "active".to_string();
        newer.status = "active".to_string();
        let mut ledger = ReleaseLedger::default();
        ledger.tasks = vec![old.clone(), newer];
        save_ledger(&path, &mut ledger).unwrap();
        let runner = FakeRunner::new(Vec::new());
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(111.0), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "superseded");
        assert_eq!(outcomes[0].rollback_start_audit, "not_applicable");
        assert!(runner.calls.lock().unwrap().is_empty());
        assert!(rollback_rows(&path).is_empty(), "a superseded lease issued no rollback and must not claim one");
    }

    #[test]
    fn an_ambiguous_deferred_throttle_writes_no_rollback_start_record() {
        let path = test_path("ledger.json");
        let old = build_release_task(
            "trace-old", "throttle", "br0", "10.0.0.8", 22, 12222, 1000, 10, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        let mut newer = build_release_task(
            "trace-new", "throttle", "br0", "10.0.0.9", 22, 12222, 1000, 100, &LeaseNow::wall_only(105.0),
        )
        .unwrap();
        newer.tc_handle = old.tc_handle.clone();
        prepare_release_task(&path, &old).unwrap();
        activate_release_task(&path, &old.task_id, 101.0).unwrap();
        prepare_release_task(&path, &newer).unwrap();
        let runner = FakeRunner::new(Vec::new());
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(111.0), &runner).unwrap();
        assert_eq!(outcomes[0].result, "ambiguous_newer_throttle_owner");
        assert_eq!(outcomes[0].rollback_start_audit, "not_applicable");
        assert!(rollback_rows(&path).is_empty(), "a deferred lease issued no rollback and must not claim one");
    }

    #[test]
    fn nothing_due_writes_no_rollback_start_record() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(Vec::new());
        process_due_releases_with_runner(&path, &LeaseNow::wall_only(101.0), &runner).unwrap();
        assert!(!rollback_audit_path(&path).exists());
    }

    #[test]
    fn an_unwritable_rollback_audit_chain_never_holds_the_rollback_back() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-a", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        // A directory where the chain file should be: the append fails.
        fs::create_dir_all(rollback_audit_path(&path)).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(102.0), &runner).unwrap();
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        assert_eq!(outcomes[0].status, "released");
        // The failure is visible in the outcome, not only on stderr.
        assert!(outcomes[0].rollback_start_audit.starts_with("failed:"), "{}", outcomes[0].rollback_start_audit);
    }

    // ------------------------------------------------ monotonic lease deadline

    const BOOT_A: &str = "0f0e0d0c-0b0a-4908-8706-050403020100";
    const BOOT_B: &str = "1f1e1d1c-1b1a-4918-9716-151413121110";
    const SEC: u64 = 1_000_000_000;

    fn clocks(wall_epoch: f64, boottime_s: u64, boot_id: &str) -> LeaseNow {
        LeaseNow {
            wall_epoch,
            boottime_ns: Some(boottime_s * SEC),
            boot_id: Some(boot_id.to_string()),
        }
    }

    /// An isolate lease created at wall 100 s / boottime 1000 s on BOOT_A
    /// with a 300 s TTL: due at wall 400 s or boottime 1300 s.
    fn monotonic_lease(path: &str) -> ReleaseTask {
        let task = build_release_task(
            "trace-mono", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        prepare_release_task(path, &task).unwrap();
        task
    }

    fn released_runner() -> FakeRunner {
        FakeRunner::new(vec![ok_json(json!({"nftables": []}))])
    }

    #[test]
    fn a_lease_records_both_deadlines_and_the_boot_they_belong_to() {
        let task = build_release_task(
            "trace-mono", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        assert_eq!(task.due_epoch, 400.0);
        assert_eq!(task.due_boottime_ns, Some(1300 * SEC));
        assert_eq!(task.due_boot_id, BOOT_A);
        // Without a readable boot identity no monotonic deadline is made up.
        let no_boot = LeaseNow { boot_id: None, ..clocks(100.0, 1000, BOOT_A) };
        let task = build_release_task("trace-mono", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &no_boot).unwrap();
        assert_eq!((task.due_boottime_ns, task.due_boot_id.as_str()), (None, ""));
        let no_clock = LeaseNow { boottime_ns: None, ..clocks(100.0, 1000, BOOT_A) };
        let task = build_release_task("trace-mono", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &no_clock).unwrap();
        assert_eq!((task.due_boottime_ns, task.due_boot_id.as_str()), (None, ""));
    }

    #[test]
    fn the_monotonic_deadline_wins_when_it_passes_before_the_wall_one() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        // Boottime 1300 s has passed; the wall clock (stepped back 60 s) says 340 s.
        assert_eq!(lease_expiry(&task, &clocks(340.0, 1299, BOOT_A)), None);
        assert_eq!(lease_expiry(&task, &clocks(340.0, 1300, BOOT_A)), Some(ExpiryClock::Monotonic));
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(340.0, 1300, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].expiry_clock, "monotonic");
        let row = &rollback_rows(&path)[0];
        assert_eq!(row["expiry_clock"], json!("monotonic"));
        assert_eq!(row["lease_clock"], json!("earlier_of_wall_clock_and_boottime"));
        assert_eq!(row["lease_due_boottime_ns"], json!(1300 * SEC));
        assert_eq!(row["lease_due_epoch_ns"], json!(400 * SEC));
        assert_eq!(row["lease_boot_id"], json!(BOOT_A));
        assert_eq!(row["boottime_clock"], json!("CLOCK_BOOTTIME"));
    }

    #[test]
    fn the_wall_deadline_wins_when_it_passes_before_the_monotonic_one() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        // The wall clock was stepped forward: wall 401 s, boottime only 1200 s.
        assert_eq!(lease_expiry(&task, &clocks(399.0, 1200, BOOT_A)), None);
        assert_eq!(lease_expiry(&task, &clocks(401.0, 1200, BOOT_A)), Some(ExpiryClock::Wall));
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(401.0, 1200, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "wall");
        assert_eq!(rollback_rows(&path)[0]["expiry_clock"], json!("wall"));
    }

    #[test]
    fn both_passed_names_the_wall_clock_only_when_it_fired_materially_earlier() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        // Both passed by about the same amount: the same instant read twice.
        assert_eq!(lease_expiry(&task, &clocks(400.04, 1300, BOOT_A)), Some(ExpiryClock::Monotonic));
        // The wall deadline passed 10 s before the monotonic one.
        assert_eq!(lease_expiry(&task, &clocks(410.0, 1300, BOOT_A)), Some(ExpiryClock::Wall));
        // The monotonic deadline passed first.
        assert_eq!(lease_expiry(&task, &clocks(401.0, 1310, BOOT_A)), Some(ExpiryClock::Monotonic));
    }

    #[test]
    fn a_wall_clock_stepped_backward_no_longer_extends_the_lease() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        // The wall clock was stepped back an hour, to before the lease was
        // created. Wall-only, the lease would now last another hour.
        let before = clocks(40.0, 1299, BOOT_A);
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &before, &runner).unwrap().is_empty());
        assert!(runner.calls.lock().unwrap().is_empty());
        let mut wall_only = task.clone();
        wall_only.due_boottime_ns = None;
        assert_eq!(lease_expiry(&wall_only, &clocks(40.0, 1300, BOOT_A)), None);
        // On the monotonic deadline it expires all the same.
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        let outcomes = process_due_releases_with_runner(&path, &clocks(40.0, 1300, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "monotonic");
        assert_eq!(outcomes[0].status, "retry_pending");
        // The ledger stays loadable although the wall retry time (42 s) lies
        // before the task's creation (100 s).
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks[0].next_attempt_epoch, 42.0);
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(42.0, 1302, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks[0].status, "released");
    }

    #[test]
    fn a_changed_boot_id_expires_the_lease_at_once() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        // After a reboot boottime restarts near zero; the wall deadline is far off.
        let rebooted = clocks(101.0, 5, BOOT_B);
        assert_eq!(lease_expiry(&task, &rebooted), Some(ExpiryClock::BootChanged));
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &rebooted, &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "boot_changed");
        assert_eq!(rollback_rows(&path)[0]["expiry_clock"], json!("boot_changed"));
    }

    #[test]
    fn an_unreadable_boot_id_or_clock_expires_the_lease_at_once() {
        let path = test_path("ledger.json");
        let task = monotonic_lease(&path);
        let no_boot = LeaseNow { boot_id: None, ..clocks(101.0, 1001, BOOT_A) };
        assert_eq!(lease_expiry(&task, &no_boot), Some(ExpiryClock::BootUnknown));
        let no_clock = LeaseNow { boottime_ns: None, ..clocks(101.0, 1001, BOOT_A) };
        assert_eq!(lease_expiry(&task, &no_clock), Some(ExpiryClock::BootUnknown));
        assert_eq!(lease_expiry(&task, &LeaseNow::wall_only(101.0)), Some(ExpiryClock::BootUnknown));
        // A deadline that names no boot cannot be checked either.
        let mut unbound = task.clone();
        unbound.due_boot_id.clear();
        assert_eq!(lease_expiry(&unbound, &clocks(101.0, 1001, BOOT_A)), Some(ExpiryClock::BootUnknown));
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &no_boot, &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "boot_unknown");
    }

    #[test]
    fn a_legacy_lease_keeps_wall_clock_only_expiry_and_says_so() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-legacy", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        // A ledger entry written before the monotonic fields existed.
        let mut raw = serde_json::to_value(&task).unwrap();
        assert!(raw.get("due_boottime_ns").is_none() && raw.get("due_boot_id").is_none());
        raw["status"] = json!("active");
        fs::write(&path, json!({"schema_version": LEDGER_SCHEMA_VERSION, "tasks": [raw]}).to_string()).unwrap();
        let legacy = load_ledger(&path).unwrap().tasks[0].clone();
        assert_eq!((legacy.due_boottime_ns, legacy.due_boot_id.as_str()), (None, ""));
        // No deadline is invented: neither a reboot nor any boottime expires it.
        assert_eq!(lease_expiry(&legacy, &clocks(399.0, 99_999, BOOT_B)), None);
        assert_eq!(lease_expiry(&legacy, &LeaseNow::wall_only(399.0)), None);
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &clocks(399.0, 99_999, BOOT_B), &runner).unwrap().is_empty());
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(400.0, 99_999, BOOT_B), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "legacy");
        let row = &rollback_rows(&path)[0];
        assert_eq!(row["expiry_clock"], json!("legacy"));
        assert_eq!(row["lease_clock"], json!("wall_clock"));
        assert_eq!(row["lease_due_boottime_ns"], Value::Null);
        // Saved again, it is still a legacy entry.
        let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(saved["tasks"][0].get("due_boottime_ns").is_none());
    }

    #[test]
    fn a_malformed_boot_id_or_monotonic_deadline_expires_only_that_lease_at_once() {
        let path = test_path("ledger.json");
        let good = build_release_task(
            "trace-good", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        let mut bad_id = build_release_task(
            "trace-bad-id", "isolate", "br0", "10.0.0.9", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        bad_id.due_boot_id = "not a boot id".repeat(1000);
        let mut bad_deadline = build_release_task(
            "trace-bad-due", "isolate", "br0", "10.0.0.10", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        bad_deadline.due_boottime_ns = Some(u64::MAX);
        let now = clocks(101.0, 1001, BOOT_A);
        assert_eq!(lease_expiry(&good, &now), None);
        assert_eq!(lease_expiry(&bad_id, &now), Some(ExpiryClock::BootInvalid));
        assert_eq!(lease_expiry(&bad_deadline, &now), Some(ExpiryClock::BootInvalid));
        // The ledger is still read: the malformed leases are rolled back, the
        // well-formed one is left alone.
        let mut ledger = ReleaseLedger::default();
        ledger.tasks = vec![good.clone(), bad_id.clone(), bad_deadline.clone()];
        save_ledger(&path, &mut ledger).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []})), ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &now, &runner).unwrap();
        let ids: Vec<&str> = outcomes.iter().map(|o| o.release_task_id.as_str()).collect();
        assert_eq!(ids, vec![bad_id.task_id.as_str(), bad_deadline.task_id.as_str()]);
        assert!(outcomes.iter().all(|o| o.expiry_clock == "boot_invalid"));
        let rows = rollback_rows(&path);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r["expiry_clock"] == json!("boot_invalid")));
        // The malformed id is not copied into the chain.
        assert_eq!(rows[0]["lease_boot_id"], json!("invalid"));
        assert_eq!(rows[1]["lease_boot_id"], json!(BOOT_A));
    }

    /// A failed first attempt of a lease expired on its monotonic deadline,
    /// with the wall clock stepped back an hour (to 40 s, before creation).
    fn failed_after_backward_step(path: &str) -> ReleaseTask {
        monotonic_lease(path);
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        let outcomes = process_due_releases_with_runner(path, &clocks(40.0, 1300, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes[0].status, "retry_pending");
        let task = load_ledger(path).unwrap().tasks[0].clone();
        // Backoff after the first attempt: 2 s, on both clocks.
        assert_eq!(task.next_attempt_epoch, 42.0);
        assert_eq!(task.next_attempt_boottime_ns, Some(1302 * SEC));
        assert_eq!(task.next_attempt_boot_id, BOOT_A);
        task
    }

    #[test]
    fn a_wall_clock_stepped_backward_never_delays_a_retry_beyond_its_backoff() {
        let path = test_path("ledger.json");
        failed_after_backward_step(&path);
        // Before the backoff on either clock: no retry (no hot loop).
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &clocks(41.0, 1301, BOOT_A), &runner).unwrap().is_empty());
        // The wall clock is stepped back again, by another hour: the retry is
        // still due once the backoff has passed on CLOCK_BOOTTIME.
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &clocks(1.0, 1301, BOOT_A), &runner).unwrap().is_empty());
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(1.0, 1302, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(rollback_rows(&path).len(), 2);
        let task = load_ledger(&path).unwrap().tasks[0].clone();
        assert_eq!(task.status, "released");
        assert_eq!(task.next_attempt_boottime_ns, None);
    }

    #[test]
    fn a_retry_is_still_due_on_the_wall_clock() {
        let path = test_path("ledger.json");
        failed_after_backward_step(&path);
        // CLOCK_BOOTTIME has not reached the retry time, the wall clock has.
        let runner = released_runner();
        let outcomes = process_due_releases_with_runner(&path, &clocks(42.0, 1301, BOOT_A), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
    }

    #[test]
    fn a_retry_scheduled_in_another_boot_is_due_once_then_backs_off_again() {
        let path = test_path("ledger.json");
        failed_after_backward_step(&path);
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        let outcomes = process_due_releases_with_runner(&path, &clocks(1.0, 5, BOOT_B), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].expiry_clock, "boot_changed");
        let task = load_ledger(&path).unwrap().tasks[0].clone();
        assert_eq!(task.next_attempt_boot_id, BOOT_B);
        assert_eq!(task.next_attempt_boottime_ns, Some((5 + 4) * SEC));
        // The next retry waits for its backoff in the new boot.
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &clocks(1.0, 8, BOOT_B), &runner).unwrap().is_empty());
        let runner = released_runner();
        assert_eq!(process_due_releases_with_runner(&path, &clocks(1.0, 9, BOOT_B), &runner).unwrap().len(), 1);
    }

    #[test]
    fn with_no_readable_boot_a_retry_waits_for_its_wall_backoff_not_every_sweep() {
        let path = test_path("ledger.json");
        failed_after_backward_step(&path);
        let unreadable = LeaseNow { boot_id: None, ..clocks(41.0, 1400, BOOT_A) };
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &unreadable, &runner).unwrap().is_empty());
        // A retry scheduled while the boot cannot be read has no monotonic
        // retry time, and is never due on every sweep.
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        let unreadable = LeaseNow { boot_id: None, ..clocks(42.0, 1400, BOOT_A) };
        assert_eq!(process_due_releases_with_runner(&path, &unreadable, &runner).unwrap().len(), 1);
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks[0].next_attempt_boottime_ns, None);
        assert_eq!(ledger.tasks[0].next_attempt_epoch, 46.0);
        let runner = FakeRunner::new(Vec::new());
        assert!(process_due_releases_with_runner(&path, &clocks(43.0, 1500, BOOT_A), &runner).unwrap().is_empty());
    }

    #[test]
    fn a_legacy_lease_gets_no_monotonic_retry_time() {
        let path = test_path("ledger.json");
        let task = build_release_task(
            "trace-legacy", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 1, &LeaseNow::wall_only(100.0),
        )
        .unwrap();
        prepare_release_task(&path, &task).unwrap();
        let runner = FakeRunner::new(vec![Err("nft unavailable".to_string())]);
        process_due_releases_with_runner(&path, &clocks(102.0, 1000, BOOT_A), &runner).unwrap();
        let task = load_ledger(&path).unwrap().tasks[0].clone();
        assert_eq!((task.next_attempt_boottime_ns, task.next_attempt_boot_id.as_str()), (None, ""));
        assert_eq!(task.next_attempt_epoch, 104.0);
        let saved: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(saved["tasks"][0].get("next_attempt_boottime_ns").is_none());
    }

    #[test]
    fn a_retry_time_before_creation_is_impossible_only_before_any_attempt() {
        let mut task = build_release_task(
            "trace-mono", "isolate", "br0", "10.0.0.8", 22, 12222, 0, 300, &clocks(100.0, 1000, BOOT_A),
        )
        .unwrap();
        task.next_attempt_epoch = 42.0;
        assert!(validate_task(&task).is_err());
        task.attempts = 1;
        assert!(validate_task(&task).is_ok());
    }

    #[test]
    fn the_node_clocks_are_read_together() {
        let now = LeaseNow::read(1.0);
        if cfg!(target_os = "linux") {
            assert!(now.boottime_ns.is_some());
            if let Some(id) = &now.boot_id {
                assert!(valid_boot_id(id), "{id}");
            }
        } else {
            assert_eq!(now.boottime_ns, None);
        }
    }

    // -- flow-scoped throttle, admission bounds, generation migration ------

    fn flow(src: &str) -> FlowScope {
        FlowScope { source_ip: src.to_string(), destination_ip: "10.20.0.5".to_string(), protocol: "tcp".to_string(), destination_port: 22 }
    }

    fn flow_rule(task: &ReleaseTask, handle: u64, rate: u64) -> Value {
        json!({"rule": {
            "family": "inet", "table": "azazel_edge", "chain": "throttle", "handle": handle,
            "comment": task.owner_token,
            "expr": [
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": task.source_ip}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": task.destination_ip}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}},
                {"limit": {"rate": rate, "burst": 32, "per": "second", "rate_unit": "kbytes", "burst_unit": "kbytes", "inv": true}},
                {"counter": {"packets": 3, "bytes": 180}},
                {"drop": null}
            ]
        }})
    }

    #[test]
    fn a_flow_throttle_is_released_by_its_owned_nft_rule_and_never_touches_a_qdisc() {
        let path = test_path("ledger.json");
        let task = build_flow_throttle_task("trace-f", &flow("10.0.0.8"), 32, 32, 30, &LeaseNow::wall_only(100.0)).unwrap();
        assert_eq!(task.resource_key, "nft:inet:azazel_edge:throttle:10.0.0.8>10.20.0.5:tcp:22");
        assert!(task.tc_handle.is_empty() && task.iface.is_empty());
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": [flow_rule(&task, 7, 32)]})),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: String::new() }),
            ok_json(json!({"nftables": []})),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released", "{outcomes:?}");
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls[1], strings(&["nft", "delete", "rule", "inet", "azazel_edge", "throttle", "handle", "7"]));
        assert!(calls.iter().all(|c| c[0] == "nft"), "{calls:?}");
    }

    #[test]
    fn a_deviating_owned_rule_is_never_read_back_as_applied_but_is_removed() {
        let path = test_path("ledger.json");
        let task = build_flow_throttle_task("trace-g", &flow("10.0.0.8"), 32, 32, 30, &LeaseNow::wall_only(100.0)).unwrap();
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        // Our owner token on our flow, but another rate: not applied as
        // planned, yet ours to remove -- leaving it would keep a restriction
        // no lease accounts for.
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": [flow_rule(&task, 7, 4096)]})),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: String::new() }),
            ok_json(json!({"nftables": []})),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released", "{outcomes:?}");
        assert_eq!(outcomes[0].postcondition["deleted_deviating_rules"], 1);
        assert_eq!(runner.calls.lock().unwrap()[1], strings(&["nft", "delete", "rule", "inet", "azazel_edge", "throttle", "handle", "7"]));
        // Our owner token on another flow: not ours, nothing is deleted.
        let path = test_path("ledger.json");
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let mut foreign = flow_rule(&task, 9, 32);
        foreign["rule"]["expr"][1]["match"]["right"] = json!("10.99.0.1");
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": [foreign]}))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "retry_pending");
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        // Readback after apply: exactly one matching rule, nothing else.
        let one = FakeRunner::new(vec![ok_json(json!({"nftables": [flow_rule(&task, 7, 32)]}))]);
        assert_eq!(owned_state_matches_plan_with_runner(&task, &one), Ok(true));
        let none = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        assert_eq!(owned_state_matches_plan_with_runner(&task, &none), Ok(false));
        let two = FakeRunner::new(vec![ok_json(json!({"nftables": [flow_rule(&task, 7, 32), flow_rule(&task, 8, 32)]}))]);
        assert_eq!(owned_state_matches_plan_with_runner(&task, &two), Ok(false));
        let wrong = FakeRunner::new(vec![ok_json(json!({"nftables": [flow_rule(&task, 7, 4096)]}))]);
        assert_eq!(owned_state_matches_plan_with_runner(&task, &wrong), Ok(false));
    }

    #[test]
    fn the_release_allowlist_admits_the_throttle_chain_and_nothing_wider() {
        assert!(allowed_release_command(&strings(&["nft", "-a", "-j", "list", "chain", "inet", "azazel_edge", "throttle"])));
        assert!(allowed_release_command(&strings(&["nft", "delete", "rule", "inet", "azazel_edge", "throttle", "handle", "9"])));
        assert!(!allowed_release_command(&strings(&["nft", "delete", "rule", "inet", "azazel_edge", "forward", "handle", "9"])));
        assert!(!allowed_release_command(&strings(&["nft", "flush", "chain", "inet", "azazel_edge", "throttle", "x", "y"])));
    }

    fn now_at(wall: f64) -> LeaseNow {
        LeaseNow { wall_epoch: wall, boottime_ns: Some(5_000_000_000_000), boot_id: Some("b001-1".to_string()) }
    }

    #[test]
    fn admission_extends_a_held_lease_at_most_n_times_and_never_past_the_cumulative_bound() {
        let path = test_path("ledger.json");
        let t0 = 10_000.0;
        let first = build_flow_throttle_task("tr-0", &flow("10.0.0.8"), 32, 32, 600, &now_at(t0)).unwrap();
        let Admission::Prepared(held) = admit_release_task(&path, &first, 600, &now_at(t0)).unwrap() else { panic!() };
        activate_release_task(&path, &held.task_id, t0).unwrap();
        let mut at = t0;
        for n in 1..=MAX_LEASE_EXTENSIONS {
            at += 590.0;
            let next = build_flow_throttle_task(&format!("tr-{n}"), &flow("10.0.0.8"), 32, 32, 600, &now_at(at)).unwrap();
            match admit_release_task(&path, &next, 600, &now_at(at)).unwrap() {
                Admission::Extended { task_id, due_epoch, extensions } => {
                    assert_eq!(task_id, held.task_id);
                    assert_eq!(extensions, n);
                    assert!(due_epoch <= t0 + MAX_CUMULATIVE_LEASE_SEC as f64);
                }
                other => panic!("{other:?}"),
            }
        }
        at += 590.0;
        let over = build_flow_throttle_task("tr-over", &flow("10.0.0.8"), 32, 32, 600, &now_at(at)).unwrap();
        assert_eq!(admit_release_task(&path, &over, 600, &now_at(at)), Err("lease extension limit reached".to_string()));
        // A replay of a merged alert is refused by its tombstone.
        let replay = build_flow_throttle_task("tr-1", &flow("10.0.0.8"), 32, 32, 600, &now_at(at)).unwrap();
        assert!(admit_release_task(&path, &replay, 600, &now_at(at)).unwrap_err().contains("replayed"));
        // The monotonic deadline moved with the wall one.
        let ledger = load_ledger(&path).unwrap();
        let lease = ledger.tasks.iter().find(|t| t.task_id == held.task_id).unwrap();
        let wall_added = lease.due_epoch - held.due_epoch;
        let mono_added = (lease.due_boottime_ns.unwrap() - held.due_boottime_ns.unwrap()) as f64 / 1e9;
        assert!((wall_added - mono_added).abs() < 1e-3, "{wall_added} {mono_added}");
    }

    #[test]
    fn a_new_family_lease_ends_no_later_than_the_cumulative_bound_of_the_family() {
        let path = test_path("ledger.json");
        let t0 = 20_000.0;
        let first = build_flow_throttle_task("fa-0", &flow("10.0.0.9"), 32, 32, 900, &now_at(t0)).unwrap();
        let Admission::Prepared(held) = admit_release_task(&path, &first, 900, &now_at(t0)).unwrap() else { panic!() };
        activate_release_task(&path, &held.task_id, t0).unwrap();
        // Released, then the flow is seen again close to the family's end.
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        process_due_releases_with_runner(&path, &now_at(t0 + 901.0), &runner).unwrap();
        let late = t0 + MAX_CUMULATIVE_LEASE_SEC as f64 - 100.0;
        let again = build_flow_throttle_task("fa-1", &flow("10.0.0.9"), 32, 32, 900, &now_at(late)).unwrap();
        let Admission::Prepared(second) = admit_release_task(&path, &again, 900, &now_at(late)).unwrap() else { panic!() };
        assert_eq!(second.family_started_epoch, Some(t0));
        assert_eq!(second.due_epoch, t0 + MAX_CUMULATIVE_LEASE_SEC as f64);
        // Within MIN_LEASE_TTL_SEC of the bound: refused.
        let edge = t0 + MAX_CUMULATIVE_LEASE_SEC as f64 - 10.0;
        let path2 = test_path("ledger.json");
        let one = build_flow_throttle_task("fb-0", &flow("10.0.0.9"), 32, 32, 900, &now_at(t0)).unwrap();
        let Admission::Prepared(h2) = admit_release_task(&path2, &one, 900, &now_at(t0)).unwrap() else { panic!() };
        activate_release_task(&path2, &h2.task_id, t0).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        process_due_releases_with_runner(&path2, &now_at(t0 + 901.0), &runner).unwrap();
        let near = build_flow_throttle_task("fb-1", &flow("10.0.0.9"), 32, 32, 900, &now_at(edge)).unwrap();
        assert_eq!(admit_release_task(&path2, &near, 900, &now_at(edge)), Err("lease cumulative limit reached".to_string()));
    }

    fn terminal_filler(n: usize, at: f64) -> ReleaseTask {
        let mut task = build_release_task(&format!("fill-{n}"), "redirect", "br0", "10.1.0.1", 22, 12222, 0, 30, &LeaseNow::wall_only(at)).unwrap();
        task.status = "released".to_string();
        task.event_epoch = Some(at - 1.0);
        task
    }

    fn write_ledger(path: &str, tasks: Vec<ReleaseTask>) {
        let mut ledger = ReleaseLedger::default();
        ledger.tasks = tasks;
        save_ledger(path, &mut ledger).unwrap();
    }

    #[test]
    fn a_full_ledger_migrates_a_generation_and_still_refuses_every_compacted_replay() {
        let path = test_path("ledger.json");
        let old = 1_000.0;
        let count = COMPACT_AT_TASKS + 10;
        let tasks: Vec<ReleaseTask> = (0..count).map(|n| terminal_filler(n, old + n as f64 * 0.001)).collect();
        let replayed = tasks[5].clone();
        write_ledger(&path, tasks);
        assert_ne!(ledger_capacity(&path).unwrap()["state"], "ok");
        let now = old + COMPACT_MIN_AGE_SEC + 10.0;
        let fresh = build_flow_throttle_task("fresh", &flow("10.0.0.20"), 32, 32, 300, &now_at(now)).unwrap();
        assert!(matches!(admit_release_task(&path, &fresh, 300, &now_at(now)).unwrap(), Admission::Prepared(_)));
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks.len(), 1, "every old terminal task was compacted");
        assert_eq!(ledger.checkpoint.generation, 1);
        assert_eq!(ledger.checkpoint.compacted_total, count as u64);
        assert!(ledger.checkpoint.replay_watermark_epoch >= replayed.created_epoch);
        // The compacted task's identity is gone, its replay is still refused.
        let mut replay = replayed.clone();
        replay.status = "prepared".to_string();
        let error = admit_release_task(&path, &replay, 300, &now_at(now)).unwrap_err();
        assert!(error.contains("replay checkpoint"), "{error}");
        // A ledger saved as v2 keeps the checkpoint across a reload.
        let raw: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(raw["schema_version"], "azazel-release-ledger/v2");
        assert_eq!(raw["checkpoint"]["generation"], 1);
    }

    #[test]
    fn when_nothing_can_be_compacted_new_restrictions_are_refused_but_release_continues() {
        let path = test_path("ledger.json");
        let now = 50_000.0;
        // Recent terminal tasks (younger than COMPACT_MIN_AGE_SEC) fill it.
        let mut tasks: Vec<ReleaseTask> = (0..ADMIT_MAX_TASKS).map(|n| terminal_filler(n, now - 10.0)).collect();
        let mut held = build_release_task("held", "redirect", "br0", "10.2.0.1", 22, 12222, 0, 30, &LeaseNow::wall_only(now - 60.0)).unwrap();
        held.status = "active".to_string();
        tasks.push(held.clone());
        write_ledger(&path, tasks);
        assert_eq!(ledger_capacity(&path).unwrap()["state"], "full");
        let fresh = build_flow_throttle_task("fresh", &flow("10.0.0.21"), 32, 32, 300, &now_at(now)).unwrap();
        let error = admit_release_task(&path, &fresh, 300, &now_at(now)).unwrap_err();
        assert!(error.contains("capacity reached"), "{error}");
        // The held lease is due and is still released.
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(now), &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
        // The maintenance entry compacts nothing that is recent.
        assert_eq!(compact_release_ledger(&path, now).unwrap()["compacted"], 0);
        // Later it compacts the old terminal tasks and admission resumes.
        let later = now + COMPACT_MIN_AGE_SEC + 1.0;
        let report = compact_release_ledger(&path, later).unwrap();
        assert!(report["compacted"].as_u64().unwrap() as usize >= ADMIT_MAX_TASKS);
        assert_eq!(report["capacity"]["state"], "ok");
        let later_task = build_flow_throttle_task("later", &flow("10.0.0.21"), 32, 32, 300, &now_at(later)).unwrap();
        assert!(admit_release_task(&path, &later_task, 300, &now_at(later)).is_ok());
    }

    #[test]
    fn a_lease_left_prepared_by_a_crash_is_released_at_restart_never_activated() {
        let path = test_path("ledger.json");
        let task = build_flow_throttle_task("crash", &flow("10.0.0.30"), 32, 32, 300, &now_at(100.0)).unwrap();
        prepare_release_task(&path, &task).unwrap();
        assert_eq!(recover_unconfirmed_on_start(&path, &now_at(110.0)).unwrap(), 1);
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks[0].status, "uncertain");
        assert_eq!(ledger.tasks[0].due_epoch, 110.0);
        assert!(activate_release_task(&path, &task.task_id, 111.0).is_err());
        // The next sweep deletes whatever owned rule exists.
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": [flow_rule(&task, 3, 32)]})),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: String::new() }),
            ok_json(json!({"nftables": []})),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &now_at(110.5), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        // A second start finds nothing to recover.
        assert_eq!(recover_unconfirmed_on_start(&path, &now_at(120.0)).unwrap(), 0);
    }

    #[test]
    fn an_abandoned_apply_is_due_at_once_on_both_clocks() {
        let path = test_path("ledger.json");
        let task = build_flow_throttle_task("ab", &flow("10.0.0.31"), 32, 32, 300, &now_at(100.0)).unwrap();
        prepare_release_task(&path, &task).unwrap();
        let later = LeaseNow { wall_epoch: 101.0, boottime_ns: Some(5_001_000_000_000), boot_id: Some("b001-1".to_string()) };
        abandon_release_task(&path, &task.task_id, "apply_unconfirmed", &later).unwrap();
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.tasks[0].status, "uncertain");
        assert_eq!(lease_expiry(&ledger.tasks[0], &later), Some(ExpiryClock::Monotonic));
        assert!(abandon_release_task(&path, &task.task_id, "again", &later).is_err());
    }

    #[test]
    fn a_v1_ledger_is_read_and_an_unknown_schema_or_mechanism_is_refused() {
        let path = test_path("ledger.json");
        let task = build_release_task("v1", "redirect", "br0", "10.0.0.8", 22, 12222, 0, 30, &LeaseNow::wall_only(100.0)).unwrap();
        fs::write(&path, json!({"schema_version": "azazel-release-ledger/v1", "tasks": [task]}).to_string()).unwrap();
        assert_eq!(load_ledger(&path).unwrap().tasks.len(), 1);
        fs::write(&path, json!({"schema_version": "azazel-release-ledger/v9", "tasks": []}).to_string()).unwrap();
        assert!(load_ledger(&path).is_err());
        let mut odd = task.clone();
        odd.mechanism = "tc_magic".to_string();
        assert!(validate_task(&odd).is_err());
        let mut flow_task = build_flow_throttle_task("v2", &flow("10.0.0.8"), 32, 32, 30, &LeaseNow::wall_only(100.0)).unwrap();
        assert!(validate_task(&flow_task).is_ok());
        flow_task.destination_ip = "2001:db8::1".to_string();
        assert!(validate_task(&flow_task).is_err());
    }

    #[test]
    fn the_sweep_never_releases_a_lease_whose_apply_is_in_flight() {
        let path = test_path("ledger.json");
        let at = LeaseNow { wall_epoch: 1_000.0, boottime_ns: Some(9_000_000_000_000), boot_id: Some("b001-2".to_string()) };
        let task = build_flow_throttle_task("inflight", &flow("10.0.0.40"), 32, 32, 30, &at).unwrap();
        let Admission::Prepared(task) = admit_release_task(&path, &task, 30, &at).unwrap() else { panic!() };
        // Due on every clock (another boot), yet being applied: untouched.
        let later = LeaseNow::wall_only(2_000.0);
        let runner = FakeRunner::new(vec![]);
        assert!(process_due_releases_with_runner(&path, &later, &runner).unwrap().is_empty());
        assert!(runner.calls.lock().unwrap().is_empty());
        // Once the apply is over (here: abandoned), the sweep releases it.
        abandon_release_task(&path, &task.task_id, "apply_unconfirmed", &later).unwrap();
        let runner = FakeRunner::new(vec![ok_json(json!({"nftables": []}))]);
        let outcomes = process_due_releases_with_runner(&path, &later, &runner).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, "released");
    }

    #[test]
    fn the_same_alert_is_refused_whatever_action_or_mechanism_it_maps_to() {
        let path = test_path("ledger.json");
        let mut first = build_flow_throttle_task("tr-a", &flow("10.0.0.50"), 32, 32, 300, &now_at(500.0)).unwrap();
        first.event_key = "event-00000000000000aa".to_string();
        assert!(admit_release_task(&path, &first, 300, &now_at(500.0)).is_ok());
        // The same alert decided differently (another trace, action, scope).
        let mut other = build_flow_redirect_task("tr-b", &flow("10.0.0.50"), "lan0", 12222, 300, &now_at(501.0)).unwrap();
        other.event_key = first.event_key.clone();
        let error = admit_release_task(&path, &other, 300, &now_at(501.0)).unwrap_err();
        assert!(error.contains("this alert already led to a lease"), "{error}");
    }

    #[test]
    fn a_v1_ledger_sets_a_migration_boundary_at_its_last_write() {
        let path = test_path("ledger.json");
        let task = build_release_task("v1", "redirect", "br0", "10.0.0.8", 22, 12222, 0, 30, &LeaseNow::wall_only(100.0)).unwrap();
        fs::write(&path, json!({"schema_version": "azazel-release-ledger/v1", "tasks": [task]}).to_string()).unwrap();
        let written = fs::metadata(&path).unwrap().modified().unwrap().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let ledger = load_ledger(&path).unwrap();
        assert_eq!(ledger.checkpoint.generation, 1);
        assert_eq!(ledger.checkpoint.replay_watermark_epoch, written);
        // Read again: the same boundary.
        assert_eq!(load_ledger(&path).unwrap().checkpoint.replay_watermark_epoch, written);
        // An empty v1 ledger handled nothing: no boundary.
        fs::write(&path, json!({"schema_version": "azazel-release-ledger/v1", "tasks": []}).to_string()).unwrap();
        assert_eq!(load_ledger(&path).unwrap().checkpoint.generation, 0);
    }

    fn redirect_rule(task: &ReleaseTask, handle: u64) -> Value {
        json!({"rule": {
            "chain": "prerouting", "handle": handle, "comment": task.owner_token,
            "expr": [
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": task.iface}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": task.source_ip}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": task.destination_ip}},
                {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": task.destination_port}},
                {"redirect": {"port": task.redirect_port}}
            ]
        }})
    }

    #[test]
    fn a_redirect_release_clears_only_the_owned_flows_connections_and_reports_it_apart() {
        let path = test_path("ledger.json");
        let task = build_flow_redirect_task("rd", &flow("10.0.0.60"), "lan0", 12222, 30, &LeaseNow::wall_only(100.0)).unwrap();
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let one = FakeRunner::new(vec![ok_json(json!({"nftables": [redirect_rule(&task, 4)]}))]);
        assert_eq!(owned_state_matches_plan_with_runner(&task, &one), Ok(true));
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": [redirect_rule(&task, 4)]})),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: String::new() }),
            ok_json(json!({"nftables": []})),
            Ok(CommandResult { returncode: 0, stdout: String::new(), stderr: "1 flow entries have been deleted.".to_string() }),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].postcondition["existing_connections"], "cleared");
        let calls = runner.calls.lock().unwrap();
        let conntrack = strings(&["conntrack", "-D", "-p", "tcp", "--orig-src", "10.0.0.60", "--orig-dst", "10.20.0.5", "--dport", "22"]);
        assert_eq!(calls[3], conntrack);
        assert!(allowed_release_command(&conntrack));
        // Anything wider is not an allowed release command.
        assert!(!allowed_release_command(&strings(&["conntrack", "-F"])));
        assert!(!allowed_release_command(&strings(&["conntrack", "-D", "-p", "tcp", "--orig-src", "10.0.0.0/8", "--dport", "22"])));
        assert!(!allowed_release_command(&strings(&["conntrack", "-D", "-p", "udp", "--orig-src", "10.0.0.60", "--dport", "22"])));
        // No match is reported as such; no tool is reported, not hidden.
        let path = test_path("ledger.json");
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": []})),
            Ok(CommandResult { returncode: 1, stdout: String::new(), stderr: "conntrack v1.4.7 (conntrack-tools): 0 flow entries have been deleted.".to_string() }),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].postcondition["existing_connections"], "none_found");
        let path = test_path("ledger.json");
        prepare_release_task(&path, &task).unwrap();
        activate_release_task(&path, &task.task_id, 100.5).unwrap();
        let runner = FakeRunner::new(vec![
            ok_json(json!({"nftables": []})),
            Err("release binary not found in trusted directories: conntrack".to_string()),
        ]);
        let outcomes = process_due_releases_with_runner(&path, &LeaseNow::wall_only(131.0), &runner).unwrap();
        assert_eq!(outcomes[0].status, "released");
        assert_eq!(outcomes[0].postcondition["existing_connections"], "conntrack_unavailable");
    }

    // -- flow cooldown after a used-up lease family (owner decision 2026-10-30)

    fn release_all(path: &str, at: f64) {
        let runner = FakeRunner::new((0..8).map(|_| ok_json(json!({"nftables": []}))).collect());
        process_due_releases_with_runner(path, &now_at(at), &runner).unwrap();
    }

    #[test]
    fn a_used_up_family_puts_the_flow_in_cooldown_across_restart_and_migration() {
        assert_eq!(FLOW_COOLDOWN_SEC, 900);
        let path = test_path("ledger.json");
        let t0 = 100_000.0;
        let cap = t0 + MAX_CUMULATIVE_LEASE_SEC as f64;
        let first = build_flow_throttle_task("cd-0", &flow("10.0.0.70"), 32, 32, 900, &now_at(t0)).unwrap();
        let Admission::Prepared(lease) = admit_release_task(&path, &first, 900, &now_at(t0)).unwrap() else { panic!() };
        assert_eq!(lease.cooldown_until_epoch, None, "a lease that ends before the bound sets no cooldown");
        activate_release_task(&path, &lease.task_id, t0).unwrap();
        release_all(&path, t0 + 901.0);
        // Near the family's end: the new lease is cut at the bound and the
        // flow's cooldown is recorded with it.
        let late = build_flow_throttle_task("cd-1", &flow("10.0.0.70"), 32, 32, 900, &now_at(cap - 200.0)).unwrap();
        let Admission::Prepared(last) = admit_release_task(&path, &late, 900, &now_at(cap - 200.0)).unwrap() else { panic!() };
        assert_eq!(last.due_epoch, cap);
        assert_eq!(last.cooldown_until_epoch, Some(cap + FLOW_COOLDOWN_SEC as f64));
        activate_release_task(&path, &last.task_id, cap - 200.0).unwrap();
        release_all(&path, cap + 1.0);

        let alert = |n: u32, at: f64| {
            let mut t = build_flow_throttle_task(&format!("cd-a{n}"), &flow("10.0.0.70"), 32, 32, 900, &now_at(at)).unwrap();
            t.event_key = format!("event-{:016x}", n);
            t
        };
        let before = load_ledger(&path).unwrap().tasks.len();
        // In cooldown: nothing is admitted, nothing is written; the TTL asked
        // for makes no difference.
        for (n, ttl) in [(1, 30), (2, 900), (3, u64::MAX)] {
            assert_eq!(
                admit_release_task(&path, &alert(n, cap + 10.0), ttl, &now_at(cap + 10.0)),
                Ok(Admission::Cooldown { until_epoch: cap + FLOW_COOLDOWN_SEC as f64 })
            );
        }
        assert_eq!(load_ledger(&path).unwrap().tasks.len(), before);
        // A restart reads the same ledger: still in cooldown.
        let mut reloaded = load_ledger(&path).unwrap();
        save_ledger(&path, &mut reloaded).unwrap();
        assert!(matches!(admit_release_task(&path, &alert(4, cap + 300.0), 900, &now_at(cap + 300.0)), Ok(Admission::Cooldown { .. })));
        // A generation migration during the cooldown keeps it: its lease is
        // younger than COMPACT_MIN_AGE_SEC.
        let mut ledger = load_ledger(&path).unwrap();
        for n in 0..COMPACT_AT_TASKS {
            ledger.tasks.push(terminal_filler(n, 1_000.0));
        }
        save_ledger(&path, &mut ledger).unwrap();
        let other = build_flow_throttle_task("cd-other", &flow("10.0.0.71"), 32, 32, 300, &now_at(cap + 400.0)).unwrap();
        assert!(matches!(admit_release_task(&path, &other, 300, &now_at(cap + 400.0)), Ok(Admission::Prepared(_))));
        assert!(load_ledger(&path).unwrap().checkpoint.generation >= 1, "the migration ran");
        assert!(matches!(admit_release_task(&path, &alert(5, cap + 500.0), 900, &now_at(cap + 500.0)), Ok(Admission::Cooldown { .. })));
        // After the cooldown: a new family may start, on a new alert only.
        let after = cap + FLOW_COOLDOWN_SEC as f64 + 1.0;
        let Admission::Prepared(fresh) = admit_release_task(&path, &alert(6, after), 900, &now_at(after)).unwrap() else { panic!() };
        assert_eq!(fresh.family_started_epoch, Some(after));
        assert_eq!(fresh.cooldown_until_epoch, None);
    }

    #[test]
    fn an_extension_that_reaches_the_bound_records_the_cooldown_and_replays_stay_refused() {
        let path = test_path("ledger.json");
        let t0 = 200_000.0;
        let cap = t0 + MAX_CUMULATIVE_LEASE_SEC as f64;
        let mut first = build_flow_throttle_task("ce-0", &flow("10.0.0.72"), 32, 32, 900, &now_at(t0)).unwrap();
        first.event_key = "event-00000000000000e0".to_string();
        let Admission::Prepared(lease) = admit_release_task(&path, &first, 900, &now_at(t0)).unwrap() else { panic!() };
        activate_release_task(&path, &lease.task_id, t0).unwrap();
        // Keep the lease near its end and extend it up to the bound.
        let mut at = t0;
        for (n, offset) in (1..=MAX_LEASE_EXTENSIONS).zip([890.0, 1780.0, 2700.0]) {
            at = t0 + offset;
            let mut next = build_flow_throttle_task(&format!("ce-{n}"), &flow("10.0.0.72"), 32, 32, 900, &now_at(at)).unwrap();
            next.event_key = format!("event-00000000000000e{n}");
            assert!(matches!(admit_release_task(&path, &next, 900, &now_at(at)).unwrap(), Admission::Extended { .. }));
        }
        let held = load_ledger(&path).unwrap().tasks.into_iter().find(|t| t.task_id == lease.task_id).unwrap();
        assert_eq!(held.due_epoch, cap, "extended to the bound (last at {at})");
        assert_eq!(held.cooldown_until_epoch, Some(cap + FLOW_COOLDOWN_SEC as f64));
        release_all(&path, cap + 1.0);
        let mut again = build_flow_throttle_task("ce-x", &flow("10.0.0.72"), 32, 32, 900, &now_at(cap + 5.0)).unwrap();
        again.event_key = "event-00000000000000ef".to_string();
        assert!(matches!(admit_release_task(&path, &again, 900, &now_at(cap + 5.0)), Ok(Admission::Cooldown { .. })));
        // After the cooldown a replay of an alert that was executed (or
        // merged) is still refused by its event key: the cooldown neither
        // adds nor removes a replay guard.
        let after = cap + FLOW_COOLDOWN_SEC as f64 + 1.0;
        let mut replay = build_flow_throttle_task("ce-0b", &flow("10.0.0.72"), 32, 32, 900, &now_at(after)).unwrap();
        replay.event_key = "event-00000000000000e1".to_string();
        assert!(admit_release_task(&path, &replay, 900, &now_at(after)).unwrap_err().contains("already led to a lease"));
    }
}
