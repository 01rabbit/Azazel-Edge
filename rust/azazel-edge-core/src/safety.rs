//! Deterministic safety rules of the automatic path (ADR 0003 in
//! `docs/architecture/scoped-temporary-actions.md`).
//!
//! Nothing here runs a command or changes the node. The rules decide
//! whether a temporary restriction or a decoy redirect may be executed, and
//! with which bounds; every refusal carries a reason.

use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::release::{MAX_LEASE_TTL_SEC, MIN_LEASE_TTL_SEC};

pub const DEFAULT_LEASE_TTL_SEC: u64 = 300;
/// An alert older than this (by its own EVE time) does not start a
/// restriction: it is notified only.
pub const MAX_ALERT_AGE_SEC: f64 = 300.0;
/// An alert this far in the future is not trusted either.
pub const MAX_ALERT_FUTURE_SEC: f64 = 60.0;
/// Each apply command (nft) is killed and counted as failed past this.
pub const APPLY_COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

/// Restriction strengths, as nft `limit rate over <rate> kbytes/second
/// burst <burst> kbytes`: packets of the flow above the rate are dropped,
/// the flow itself keeps going slower. Critical alerts get the stricter one.
pub const STRENGTH_STRICT: (&str, u32, u32) = ("strict", 16, 16);
pub const STRENGTH_STANDARD: (&str, u32, u32) = ("standard", 32, 32);

/// The TTL a lease is granted: the configured value bounded to the
/// Edge-fixed range. Returns the TTL and how it was obtained.
pub fn bounded_ttl(raw: Option<&str>) -> (u64, &'static str) {
    match raw.map(str::trim) {
        None | Some("") => (DEFAULT_LEASE_TTL_SEC, "default"),
        Some(value) => match value.parse::<u64>() {
            Ok(v) if v > MAX_LEASE_TTL_SEC => (MAX_LEASE_TTL_SEC, "clamped_to_max"),
            Ok(v) if v < MIN_LEASE_TTL_SEC => (MIN_LEASE_TTL_SEC, "raised_to_min"),
            Ok(v) => (v, "configured"),
            Err(_) => (DEFAULT_LEASE_TTL_SEC, "invalid_default"),
        },
    }
}

/// Seconds since the epoch of an EVE timestamp
/// (`2026-01-01T00:00:00.000000+0000`, also `Z` and `+hh:mm`). `None` for
/// anything else: such an alert cannot be dated and does not start a
/// restriction.
pub fn parse_eve_epoch(ts: &str) -> Option<f64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = ts.get(r)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut rest = &ts[19..];
    let mut fraction = 0.0;
    if let Some(after) = rest.strip_prefix('.') {
        let digits = after.bytes().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || digits > 9 {
            return None;
        }
        fraction = format!("0.{}", &after[..digits]).parse::<f64>().ok()?;
        rest = &after[digits..];
    }
    let offset = match rest {
        "Z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let body = rest[1..].replace(':', "");
            if body.len() != 4 || !body.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let h: i64 = body[..2].parse().ok()?;
            let m: i64 = body[2..].parse().ok()?;
            if h > 23 || m > 59 {
                return None;
            }
            sign * (h * 3600 + m * 60)
        }
    };
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    if secs < 0 {
        return None;
    }
    Some(secs as f64 + fraction)
}

/// Whether an alert is recent enough to start a restriction.
pub fn alert_freshness(ts: &str, now_epoch: f64) -> Result<f64, String> {
    let at = parse_eve_epoch(ts).ok_or_else(|| "alert_time_unreadable".to_string())?;
    if at > now_epoch + MAX_ALERT_FUTURE_SEC {
        return Err("alert_time_in_future".to_string());
    }
    if now_epoch - at > MAX_ALERT_AGE_SEC {
        return Err("alert_stale".to_string());
    }
    Ok(at)
}

// -- the protected communications set -------------------------------------

pub const ROLES: [&str; 3] = ["management", "expert_contact", "mission"];
const MAX_PROTECTED_ENTRIES: usize = 256;
const MAX_DECLARATION_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedFile {
    protected_flows: ProtectedDecl,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedDecl {
    version: u32,
    entries: Vec<EntryDecl>,
    /// Roles the deployment states it has none of, each with who approved
    /// that statement. A role neither declared nor stated not applicable is
    /// a missing declaration and execution is refused.
    #[serde(default)]
    roles_not_applicable: Vec<NotApplicableDecl>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotApplicableDecl {
    role: String,
    approved_by: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryDecl {
    name: String,
    role: String,
    network: String,
    #[serde(default)]
    ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr, prefix) = match raw.split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
            None => {
                let a = raw.parse::<IpAddr>().ok()?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Network { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix as u32) };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix as u32) };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedEntry {
    pub name: String,
    pub role: String,
    pub network: Network,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProtectedSet {
    /// No declaration file. Dry run still plans; execution is refused.
    NotConfigured,
    /// A declaration that could not be read or is invalid: execution is
    /// refused (never treated as "nothing to protect").
    Invalid(String),
    /// The entries, and the roles approved as not applicable.
    Loaded(Vec<ProtectedEntry>, Vec<String>),
}

/// A match: the flow touches a protected endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedMatch {
    pub name: String,
    pub role: String,
    /// `source`: the restricted source is protected (every port);
    /// `destination`: the flow's destination (and port, when listed) is.
    pub side: &'static str,
}

impl ProtectedSet {
    pub fn load(path: &str) -> Self {
        let source = Path::new(path);
        let meta = match fs::symlink_metadata(source) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ProtectedSet::NotConfigured,
            Err(e) => return ProtectedSet::Invalid(format!("metadata:{e}")),
        };
        if let Err(reason) = trusted_file(&meta, MAX_DECLARATION_BYTES) {
            return ProtectedSet::Invalid(reason);
        }
        let raw = match fs::read_to_string(source) {
            Ok(raw) => raw,
            Err(e) => return ProtectedSet::Invalid(format!("read:{e}")),
        };
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Self {
        let parsed: ProtectedFile = match serde_yaml::from_str(raw) {
            Ok(parsed) => parsed,
            Err(e) => return ProtectedSet::Invalid(format!("parse:{}", e.to_string().chars().take(160).collect::<String>())),
        };
        if parsed.protected_flows.version != 1 {
            return ProtectedSet::Invalid("unsupported_version".to_string());
        }
        let entries = parsed.protected_flows.entries;
        let mut not_applicable = Vec::new();
        for item in parsed.protected_flows.roles_not_applicable {
            let text_ok = |v: &str| !v.trim().is_empty() && v.len() <= 256 && !v.chars().any(char::is_control);
            if !ROLES.contains(&item.role.as_str()) || item.role == "management" {
                return ProtectedSet::Invalid(format!("invalid_not_applicable_role:{}", item.role.chars().take(32).collect::<String>()));
            }
            if !text_ok(&item.approved_by) || !text_ok(&item.reason) {
                return ProtectedSet::Invalid(format!("not_applicable_without_approval:{}", item.role));
            }
            if not_applicable.contains(&item.role) {
                return ProtectedSet::Invalid(format!("duplicate_not_applicable:{}", item.role));
            }
            not_applicable.push(item.role);
        }
        if entries.len() > MAX_PROTECTED_ENTRIES {
            return ProtectedSet::Invalid("too_many_entries".to_string());
        }
        let mut out = Vec::new();
        for entry in entries {
            let name_ok = !entry.name.is_empty()
                && entry.name.len() <= 64
                && entry.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !name_ok {
                return ProtectedSet::Invalid("invalid_entry_name".to_string());
            }
            if !ROLES.contains(&entry.role.as_str()) {
                return ProtectedSet::Invalid(format!("invalid_role:{}", entry.name));
            }
            let Some(network) = Network::parse(&entry.network) else {
                return ProtectedSet::Invalid(format!("invalid_network:{}", entry.name));
            };
            if entry.ports.contains(&0) || entry.ports.len() > 64 {
                return ProtectedSet::Invalid(format!("invalid_ports:{}", entry.name));
            }
            out.push(ProtectedEntry { name: entry.name, role: entry.role, network, ports: entry.ports });
        }
        if let Some(both) = not_applicable.iter().find(|role| out.iter().any(|e| &e.role == *role)) {
            return ProtectedSet::Invalid(format!("role_both_declared_and_not_applicable:{both}"));
        }
        ProtectedSet::Loaded(out, not_applicable)
    }

    pub fn status(&self) -> String {
        match self {
            ProtectedSet::NotConfigured => "not_configured".to_string(),
            ProtectedSet::Invalid(reason) => format!("invalid:{reason}"),
            ProtectedSet::Loaded(entries, not_applicable) => {
                if not_applicable.is_empty() {
                    format!("loaded:{}", entries.len())
                } else {
                    format!("loaded:{}:not_applicable:{}", entries.len(), not_applicable.join(","))
                }
            }
        }
    }

    /// Whether execution may rely on this set: loaded, with at least one
    /// management entry (the management path always exists), and each of
    /// the other roles either declared or approved as not applicable. A
    /// role left out is a missing declaration, not "nothing to protect".
    pub fn ready_for_execution(&self) -> Result<(), String> {
        match self {
            ProtectedSet::NotConfigured => Err("protected_set_not_configured".to_string()),
            ProtectedSet::Invalid(_) => Err("protected_set_invalid".to_string()),
            ProtectedSet::Loaded(entries, _) if !entries.iter().any(|e| e.role == "management") => {
                Err("protected_set_has_no_management_entry".to_string())
            }
            ProtectedSet::Loaded(entries, not_applicable) => {
                for role in ROLES {
                    if !entries.iter().any(|e| e.role == role) && !not_applicable.iter().any(|r| r == role) {
                        return Err(format!("protected_set_role_undeclared:{role}"));
                    }
                }
                Ok(())
            }
        }
    }

    /// The first protected entry the action's scope touches. A protected
    /// source is matched on every port: restricting a source affects its
    /// protected communication whatever the port. A destination is matched
    /// on the listed ports (every port when none is listed); a scope with no
    /// port (`port == 0`: an ICMP flow) is matched on any destination entry,
    /// so no listed port is ever excluded from the check.
    pub fn matches(&self, source: &IpAddr, destination: Option<&IpAddr>, port: u16) -> Option<ProtectedMatch> {
        let ProtectedSet::Loaded(entries, _) = self else {
            return None;
        };
        for entry in entries {
            if entry.network.contains(source) {
                return Some(ProtectedMatch { name: entry.name.clone(), role: entry.role.clone(), side: "source" });
            }
            if let Some(destination) = destination {
                let port_hit = port == 0 || entry.ports.is_empty() || entry.ports.contains(&port);
                if entry.network.contains(destination) && port_hit {
                    return Some(ProtectedMatch { name: entry.name.clone(), role: entry.role.clone(), side: "destination" });
                }
            }
        }
        None
    }
}

extern "C" {
    fn geteuid() -> u32;
}

/// A declaration or evidence file is trusted only as a regular file (not a
/// symlink), owned by root or by this process's user, writable by no one
/// else, and within its size bound.
fn trusted_file(meta: &fs::Metadata, max_bytes: u64) -> Result<(), String> {
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err("not_a_regular_file".to_string());
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err("untrusted_owner".to_string());
    }
    if meta.mode() & 0o022 != 0 {
        return Err("group_or_world_writable".to_string());
    }
    if meta.len() > max_bytes {
        return Err("too_large".to_string());
    }
    Ok(())
}

// -- decoy redirect preconditions -----------------------------------------

pub const DECOY_EVIDENCE_SCHEMA: &str = "azazel-edge/decoy-separation/v1";
const MAX_EVIDENCE_BYTES: u64 = 16 * 1024;
/// The evidence is never older than this, whatever the policy says.
pub const MAX_DECOY_EVIDENCE_AGE_SEC: u64 = 3600;
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);
const PROBE_CACHE: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
struct DecoyEvidence {
    schema: String,
    boot_id: String,
    observed_epoch: f64,
    separation: String,
    decoy_ports: Vec<u16>,
    /// The interface the redirected traffic arrives on: the redirect rule is
    /// bound to it, and `nft redirect` delivers to its primary address.
    ingress_interface: String,
    /// The deployment's own check of the real path: a connection from the
    /// ingress side, through `ingress_interface`, to the decoy port. The
    /// core's local probe cannot see the ingress path (an INPUT rule on that
    /// interface, say); this can.
    ingress_path_check: Option<PathCheck>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathCheck {
    result: String,
    checked_epoch: f64,
    via_interface: String,
    decoy_ports: Vec<u16>,
}

/// The separation evidence: written by the deployment that set the decoy up
/// (for example Nexus, after placing it in its own network namespace), for
/// this boot, naming the decoy port, recent. Any doubt is a refusal.
pub fn check_decoy_evidence(path: &str, max_age_sec: u64, port: u16, iface: &str, now_epoch: f64, boot_id: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("decoy_separation_evidence_not_configured".to_string());
    }
    let meta = fs::symlink_metadata(path).map_err(|_| "decoy_separation_evidence_missing".to_string())?;
    trusted_file(&meta, MAX_EVIDENCE_BYTES).map_err(|r| format!("decoy_separation_evidence_untrusted:{r}"))?;
    let raw = fs::read_to_string(path).map_err(|_| "decoy_separation_evidence_unreadable".to_string())?;
    let evidence: DecoyEvidence =
        serde_json::from_str(&raw).map_err(|_| "decoy_separation_evidence_invalid".to_string())?;
    if evidence.schema != DECOY_EVIDENCE_SCHEMA {
        return Err("decoy_separation_evidence_invalid".to_string());
    }
    if boot_id.is_empty() || evidence.boot_id != boot_id {
        return Err("decoy_separation_evidence_other_boot".to_string());
    }
    if !matches!(evidence.separation.as_str(), "network_namespace" | "separate_host") {
        return Err("decoy_separation_not_established".to_string());
    }
    let max_age = max_age_sec.min(MAX_DECOY_EVIDENCE_AGE_SEC) as f64;
    if !evidence.observed_epoch.is_finite()
        || evidence.observed_epoch > now_epoch + MAX_ALERT_FUTURE_SEC
        || now_epoch - evidence.observed_epoch > max_age
    {
        return Err("decoy_separation_evidence_stale".to_string());
    }
    if !evidence.decoy_ports.contains(&port) {
        return Err("decoy_port_not_in_evidence".to_string());
    }
    if evidence.ingress_interface != iface {
        return Err("decoy_evidence_other_interface".to_string());
    }
    let Some(path) = evidence.ingress_path_check else {
        return Err("decoy_ingress_path_unverified".to_string());
    };
    if path.via_interface != iface || !path.decoy_ports.contains(&port) {
        return Err("decoy_ingress_path_unverified".to_string());
    }
    if path.result != "reachable" {
        return Err("decoy_ingress_path_unreachable".to_string());
    }
    if !path.checked_epoch.is_finite()
        || path.checked_epoch > now_epoch + MAX_ALERT_FUTURE_SEC
        || now_epoch - path.checked_epoch > max_age
    {
        return Err("decoy_ingress_path_check_stale".to_string());
    }
    Ok(())
}

/// The primary IPv4 address of `iface`, where `nft redirect` delivers
/// traffic arriving on it. `None` when the interface has none or cannot be
/// read.
#[cfg(target_os = "linux")]
pub fn interface_ipv4(iface: &str) -> Option<std::net::Ipv4Addr> {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int, c_uint, c_void};
    #[repr(C)]
    struct IfAddrs {
        ifa_next: *mut IfAddrs,
        ifa_name: *mut c_char,
        ifa_flags: c_uint,
        ifa_addr: *mut SockAddrIn,
        ifa_netmask: *mut c_void,
        ifa_ifu: *mut c_void,
        ifa_data: *mut c_void,
    }
    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: [u8; 4],
    }
    extern "C" {
        fn getifaddrs(ifap: *mut *mut IfAddrs) -> c_int;
        fn freeifaddrs(ifa: *mut IfAddrs);
    }
    const AF_INET: u16 = 2;
    let mut head: *mut IfAddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list this function frees before returning;
    // every pointer is checked for null before it is read.
    unsafe {
        if getifaddrs(&mut head) != 0 {
            return None;
        }
        let mut found = None;
        let mut cursor = head;
        while !cursor.is_null() {
            let item = &*cursor;
            if !item.ifa_name.is_null() && !item.ifa_addr.is_null() && (*item.ifa_addr).sin_family == AF_INET {
                if CStr::from_ptr(item.ifa_name).to_bytes() == iface.as_bytes() {
                    found = Some(std::net::Ipv4Addr::from((*item.ifa_addr).sin_addr));
                    break;
                }
            }
            cursor = item.ifa_next;
        }
        freeifaddrs(head);
        found
    }
}

#[cfg(not(target_os = "linux"))]
pub fn interface_ipv4(_iface: &str) -> Option<std::net::Ipv4Addr> {
    None
}

static PROBES: Mutex<Vec<(SocketAddr, Instant, bool)>> = Mutex::new(Vec::new());

/// The decoy answers where the redirect delivers: `nft redirect` in
/// prerouting sends traffic arriving on `iface` to that interface's primary
/// address, so the probe connects there (a listener bound to loopback only
/// does not count). A TCP connect within 300 ms, cached 5 s per address and
/// port so a burst of alerts costs one probe.
pub fn decoy_reachable(iface: &str, port: u16) -> Result<(), String> {
    let address = interface_ipv4(iface).ok_or_else(|| "decoy_ingress_interface_has_no_ipv4".to_string())?;
    let target = SocketAddr::from((address, port));
    let now = Instant::now();
    {
        let cache = PROBES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, _, ok)) = cache.iter().find(|(t, at, _)| *t == target && now.duration_since(*at) < PROBE_CACHE) {
            return if *ok { Ok(()) } else { Err("decoy_unreachable".to_string()) };
        }
    }
    let ok = TcpStream::connect_timeout(&target, PROBE_TIMEOUT).is_ok();
    let mut cache = PROBES.lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|(t, _, _)| *t != target);
    cache.push((target, now, ok));
    if ok { Ok(()) } else { Err("decoy_unreachable".to_string()) }
}

/// The `safety` block every enforcement outcome carries (fixed shape).
#[allow(clippy::too_many_arguments)]
pub fn safety_block(
    protected_set: &str,
    protected_match: Option<&ProtectedMatch>,
    scope: &str,
    gate: &str,
    ttl_sec: u64,
    ttl_source: &str,
    strength: &str,
    decoy: &str,
) -> Value {
    json!({
        "protected_set": protected_set,
        "protected_match": protected_match.map(|m| json!({"name": m.name, "role": m.role, "side": m.side})).unwrap_or(Value::Null),
        "scope": scope,
        "gate": gate,
        "ttl_sec": ttl_sec,
        "ttl_source": ttl_source,
        "strength": strength,
        "decoy_preconditions": decoy,
        "isolate_automatic": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_is_bounded_by_edge_constants_whatever_the_environment_says() {
        assert_eq!(bounded_ttl(None), (300, "default"));
        assert_eq!(bounded_ttl(Some("600")), (600, "configured"));
        assert_eq!(bounded_ttl(Some("86400")), (MAX_LEASE_TTL_SEC, "clamped_to_max"));
        assert_eq!(bounded_ttl(Some("18446744073709551615")), (MAX_LEASE_TTL_SEC, "clamped_to_max"));
        assert_eq!(bounded_ttl(Some("1")), (MIN_LEASE_TTL_SEC, "raised_to_min"));
        assert_eq!(bounded_ttl(Some("-5")), (300, "invalid_default"));
        assert_eq!(bounded_ttl(Some("1e9")), (300, "invalid_default"));
    }

    #[test]
    fn eve_timestamps_parse_to_epoch_and_anything_else_is_refused() {
        assert_eq!(parse_eve_epoch("1970-01-01T00:00:00.000000+0000"), Some(0.0));
        assert_eq!(parse_eve_epoch("2026-01-01T00:00:00Z"), Some(1_767_225_600.0));
        assert_eq!(parse_eve_epoch("2026-01-01T09:00:00+0900"), Some(1_767_225_600.0));
        assert_eq!(parse_eve_epoch("2026-01-01T09:00:00+09:00"), Some(1_767_225_600.0));
        let frac = parse_eve_epoch("2026-01-01T00:00:00.250000+0000").unwrap();
        assert!((frac - 1_767_225_600.25).abs() < 1e-6);
        for bad in ["", "2026-01-01", "2026-13-01T00:00:00Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+9", "x026-01-01T00:00:00Z"] {
            assert_eq!(parse_eve_epoch(bad), None, "{bad}");
        }
    }

    #[test]
    fn stale_future_and_undated_alerts_do_not_start_a_restriction() {
        let now = 1_767_225_600.0;
        assert!(alert_freshness("2026-01-01T00:00:00Z", now + 10.0).is_ok());
        assert_eq!(alert_freshness("2026-01-01T00:00:00Z", now + 301.0), Err("alert_stale".to_string()));
        assert_eq!(alert_freshness("2026-01-01T00:02:00Z", now), Err("alert_time_in_future".to_string()));
        assert_eq!(alert_freshness("garbage", now), Err("alert_time_unreadable".to_string()));
    }

    fn sample_set() -> ProtectedSet {
        ProtectedSet::parse(
            "protected_flows:\n  version: 1\n  entries:\n    - {name: mgmt, role: management, network: 192.0.2.0/28}\n    - {name: expert, role: expert_contact, network: 198.51.100.7, ports: [443]}\n    - {name: radio, role: mission, network: '2001:db8::/64'}\n",
        )
    }

    #[test]
    fn protected_flows_match_deterministically_by_source_destination_and_port() {
        let set = sample_set();
        assert_eq!(set.status(), "loaded:3");
        assert!(set.ready_for_execution().is_ok());
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // A protected source is never restricted, on any port.
        let m = set.matches(&ip("192.0.2.5"), Some(&ip("203.0.113.1")), 8080).unwrap();
        assert_eq!((m.name.as_str(), m.role.as_str(), m.side), ("mgmt", "management", "source"));
        // A protected destination only on its listed port.
        assert_eq!(set.matches(&ip("203.0.113.9"), Some(&ip("198.51.100.7")), 443).unwrap().role, "expert_contact");
        assert!(set.matches(&ip("203.0.113.9"), Some(&ip("198.51.100.7")), 22).is_none());
        assert!(set.matches(&ip("192.0.2.16"), Some(&ip("203.0.113.1")), 22).is_none());
        assert_eq!(set.matches(&ip("2001:db8::9"), None, 0).unwrap().name, "radio");
        assert!(set.matches(&ip("2001:db9::9"), None, 0).is_none());
    }

    #[test]
    fn every_role_must_be_declared_or_approved_as_not_applicable() {
        let base = "protected_flows:\n  version: 1\n  entries:\n    - {name: mgmt, role: management, network: 192.0.2.0/28}\n";
        // Only management: both other roles are missing declarations.
        assert_eq!(ProtectedSet::parse(base).ready_for_execution(), Err("protected_set_role_undeclared:expert_contact".to_string()));
        let with_expert = format!("{base}    - {{name: ex, role: expert_contact, network: 198.51.100.7}}\n");
        assert_eq!(ProtectedSet::parse(&with_expert).ready_for_execution(), Err("protected_set_role_undeclared:mission".to_string()));
        let na = format!("{with_expert}  roles_not_applicable:\n    - {{role: mission, approved_by: field-lead, reason: no mission link on this site}}\n");
        let set = ProtectedSet::parse(&na);
        assert_eq!(set.ready_for_execution(), Ok(()), "{set:?}");
        assert_eq!(set.status(), "loaded:2:not_applicable:mission");
        // Not applicable needs who approved it; management can never be.
        for bad in [
            format!("{with_expert}  roles_not_applicable:\n    - {{role: mission, approved_by: '', reason: r}}\n"),
            format!("{with_expert}  roles_not_applicable:\n    - {{role: mission, reason: r}}\n"),
            format!("{with_expert}  roles_not_applicable:\n    - {{role: management, approved_by: a, reason: r}}\n"),
            format!("{with_expert}  roles_not_applicable:\n    - {{role: expert_contact, approved_by: a, reason: r}}\n"),
            format!("{with_expert}  roles_not_applicable:\n    - {{role: mission, approved_by: a, reason: r}}\n    - {{role: mission, approved_by: b, reason: r}}\n"),
        ] {
            assert!(matches!(ProtectedSet::parse(&bad), ProtectedSet::Invalid(_)), "{bad}");
        }
    }

    #[test]
    fn a_portless_scope_is_matched_against_every_destination_entry() {
        let set = sample_set();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // The expert lists port 443 only; an ICMP scope (port 0) toward it
        // is still a protected destination.
        assert_eq!(set.matches(&ip("203.0.113.9"), Some(&ip("198.51.100.7")), 0).unwrap().role, "expert_contact");
    }

    #[test]
    fn an_absent_invalid_or_management_less_set_refuses_execution() {
        assert_eq!(ProtectedSet::NotConfigured.ready_for_execution(), Err("protected_set_not_configured".to_string()));
        for raw in [
            "protected_flows: {version: 2, entries: []}",
            "protected_flows: {version: 1, entries: [{name: a, role: boss, network: 10.0.0.1}]}",
            "protected_flows: {version: 1, entries: [{name: a, role: mission, network: 10.0.0.0/33}]}",
            "protected_flows: {version: 1, entries: [{name: a, role: mission, network: 10.0.0.1, ports: [0]}]}",
            "protected_flows: {version: 1, entries: [{name: 'a b', role: mission, network: 10.0.0.1}]}",
            "protected_flows: {version: 1, entries: [], extra: 1}",
            "not yaml: [",
        ] {
            let set = ProtectedSet::parse(raw);
            assert!(matches!(set, ProtectedSet::Invalid(_)), "{raw}: {set:?}");
            assert_eq!(set.ready_for_execution(), Err("protected_set_invalid".to_string()));
        }
        let no_mgmt = ProtectedSet::parse("protected_flows: {version: 1, entries: [{name: a, role: mission, network: 10.0.0.1}]}");
        assert_eq!(no_mgmt.ready_for_execution(), Err("protected_set_has_no_management_entry".to_string()));
    }

    fn evidence_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("az-decoy-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_evidence(dir: &Path, body: &Value) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("decoy.json");
        fs::write(&path, body.to_string()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn decoy_evidence_must_be_this_boot_recent_separated_and_name_the_port() {
        let dir = evidence_dir("ev");
        let now = 1_800_000_000.0;
        let good = json!({"schema": DECOY_EVIDENCE_SCHEMA, "boot_id": "abc-1", "observed_epoch": now - 10.0, "separation": "network_namespace", "decoy_ports": [12222], "ingress_interface": "lan0",
            "ingress_path_check": {"result": "reachable", "checked_epoch": now - 5.0, "via_interface": "lan0", "decoy_ports": [12222]}});
        let path = write_evidence(&dir, &good);
        assert_eq!(check_decoy_evidence(&path, 600, 12222, "lan0", now, "abc-1"), Ok(()));
        assert_eq!(check_decoy_evidence(&path, 600, 12222, "lan0", now, "abc-2"), Err("decoy_separation_evidence_other_boot".to_string()));
        assert_eq!(check_decoy_evidence(&path, 600, 18080, "lan0", now, "abc-1"), Err("decoy_port_not_in_evidence".to_string()));
        assert_eq!(check_decoy_evidence(&path, 5, 12222, "lan0", now, "abc-1"), Err("decoy_separation_evidence_stale".to_string()));
        // The policy cannot raise the age bound past the Edge constant.
        let mut old = good.clone();
        old["observed_epoch"] = json!(now - 7200.0);
        let path = write_evidence(&dir, &old);
        assert_eq!(check_decoy_evidence(&path, 999_999, 12222, "lan0", now, "abc-1"), Err("decoy_separation_evidence_stale".to_string()));
        let mut none = good.clone();
        none["separation"] = json!("same_host");
        let path = write_evidence(&dir, &none);
        assert_eq!(check_decoy_evidence(&path, 600, 12222, "lan0", now, "abc-1"), Err("decoy_separation_not_established".to_string()));
        assert_eq!(check_decoy_evidence("", 600, 12222, "lan0", now, "abc-1"), Err("decoy_separation_evidence_not_configured".to_string()));
        assert_eq!(
            check_decoy_evidence(&dir.join("absent.json").to_string_lossy(), 600, 12222, "lan0", now, "abc-1"),
            Err("decoy_separation_evidence_missing".to_string())
        );
        // The real ingress path must have been checked, for this interface
        // and port, recently, and found reachable.
        for (patch, reason) in [
            (json!(null), "decoy_ingress_path_unverified"),
            (json!({"result": "unreachable", "checked_epoch": now - 5.0, "via_interface": "lan0", "decoy_ports": [12222]}), "decoy_ingress_path_unreachable"),
            (json!({"result": "reachable", "checked_epoch": now - 5.0, "via_interface": "wan0", "decoy_ports": [12222]}), "decoy_ingress_path_unverified"),
            (json!({"result": "reachable", "checked_epoch": now - 5.0, "via_interface": "lan0", "decoy_ports": [18080]}), "decoy_ingress_path_unverified"),
            (json!({"result": "reachable", "checked_epoch": now - 7200.0, "via_interface": "lan0", "decoy_ports": [12222]}), "decoy_ingress_path_check_stale"),
        ] {
            let mut body = good.clone();
            body["ingress_path_check"] = patch;
            let path = write_evidence(&dir, &body);
            assert_eq!(check_decoy_evidence(&path, 600, 12222, "lan0", now, "abc-1"), Err(reason.to_string()));
        }
        // Evidence for another ingress interface does not count here.
        let path = write_evidence(&dir, &good);
        assert_eq!(check_decoy_evidence(&path, 600, 12222, "wan0", now, "abc-1"), Err("decoy_evidence_other_interface".to_string()));
        // A world-writable evidence file is not trusted.
        use std::os::unix::fs::PermissionsExt;
        let path = write_evidence(&dir, &good);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            check_decoy_evidence(&path, 600, 12222, "lan0", now, "abc-1"),
            Err("decoy_separation_evidence_untrusted:group_or_world_writable".to_string())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_decoy_is_probed_on_the_ingress_interface_address_not_loopback() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_eq!(interface_ipv4("lo"), Some(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(decoy_reachable("lo", port), Ok(()));
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert_eq!(decoy_reachable("lo", closed), Err("decoy_unreachable".to_string()));
        assert_eq!(decoy_reachable("no-such-if0", port), Err("decoy_ingress_interface_has_no_ipv4".to_string()));
        // A non-loopback interface: the loopback-only listener is not where
        // traffic arriving there is delivered.
        if let Some(name) = ["eth0", "ens3", "enp0s1"].into_iter().find(|n| interface_ipv4(n).is_some()) {
            assert_eq!(decoy_reachable(name, port), Err("decoy_unreachable".to_string()), "{name}");
        }
        drop(listener);
    }
}
