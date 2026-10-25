//! Append-only, hash-chained audit records in the format `P0AuditLogger` writes.
//!
//! One record per line. Each record carries `chain_prev` (the previous record's
//! `chain_hash`, empty for the first) and `chain_hash`, the SHA-256 of the
//! record without `chain_hash`, serialised exactly as Python's
//! `json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(',', ':'))`.
//! `P0AuditLogger.verify_chain` therefore verifies a file written here
//! unchanged; the format is not versioned separately and this module does not
//! change it.
//!
//! Records carry only strings, integers, booleans and null. A float would be
//! re-serialised by the Python verifier with Python's own float formatting and
//! could hash differently, so callers convert instants to integer nanoseconds.
//!
//! Every append is written with one `write` and then `fsync`ed before it
//! returns: a caller that appends a record and then acts may rely on the
//! record surviving a crash or power loss that happens during the act.

use serde_json::{Map, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// How much of the file's end is read to find the chain head.
const HEAD_WINDOW: u64 = 64 * 1024;

static APPEND_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
thread_local! {
    pub static SYNC_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Flush the file's data and metadata to stable storage.
fn sync_durable(file: &File) -> io::Result<()> {
    file.sync_all()?;
    #[cfg(test)]
    SYNC_CALLS.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// The node's monotonic clock (`CLOCK_MONOTONIC`) in nanoseconds: the clock
/// Python's `time.monotonic_ns()` reads on the same host.
pub fn monotonic_ns() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::raw::{c_int, c_long};
        #[repr(C)]
        struct Timespec {
            tv_sec: c_long,
            tv_nsec: c_long,
        }
        extern "C" {
            fn clock_gettime(clock_id: c_int, tp: *mut Timespec) -> c_int;
        }
        #[cfg(target_os = "linux")]
        const CLOCK_MONOTONIC: c_int = 1;
        #[cfg(target_os = "macos")]
        const CLOCK_MONOTONIC: c_int = 6;
        let mut ts = Timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: clock_gettime only writes the timespec it is given, which
        // lives on this stack frame for the whole call.
        let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
            return None;
        }
        (ts.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(ts.tv_nsec as u64))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// The wall clock in nanoseconds since the Unix epoch.
pub fn wall_epoch_ns() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
}

/// This boot's identity, so a monotonic instant can be tied to the boot it
/// belongs to. Empty where the kernel does not expose one.
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// `datetime.now(timezone.utc).isoformat(timespec='milliseconds')`.
pub fn iso_utc_millis(epoch_ns: i64) -> String {
    let ms_total = epoch_ns.div_euclid(1_000_000);
    let secs = ms_total.div_euclid(1000);
    let ms = ms_total.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}+00:00",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        ms
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Python's `json.dumps(value, ensure_ascii=True, sort_keys=True,
/// separators=(',', ':'))` for values without floats.
pub fn canonical_json(value: &Value) -> Result<String, String> {
    if contains_float(value) {
        return Err("audit record must not carry floats".to_string());
    }
    // serde_json's Map is ordered by key (no preserve_order feature), and its
    // compact writer uses the same separators and short escapes as Python.
    let raw = serde_json::to_string(value).map_err(|e| format!("audit record serialize failed: {e}"))?;
    // Outside strings JSON is ASCII, so escaping every character Python's
    // ensure_ascii escapes and serde_json leaves raw is exact: DEL and
    // everything above it, as UTF-16 code units.
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if (ch as u32) < 0x7f {
            out.push(ch);
        } else {
            let mut units = [0u16; 2];
            for unit in ch.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    Ok(out)
}

fn contains_float(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_f64(),
        Value::Array(items) => items.iter().any(contains_float),
        Value::Object(map) => map.values().any(contains_float),
        _ => false,
    }
}

/// The `chain_hash` of the last record, read the way
/// `P0AuditLogger._read_last_chain_hash` reads it: the last line, or empty
/// when the file is absent, empty, or ends in a line that does not parse.
fn read_chain_head(path: &Path) -> Result<String, String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(format!("audit chain open failed: {e}")),
    };
    let len = file.metadata().map_err(|e| format!("audit chain metadata failed: {e}"))?.len();
    let mut start = len.saturating_sub(HEAD_WINDOW);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        file.seek(SeekFrom::Start(start)).map_err(|e| format!("audit chain seek failed: {e}"))?;
        file.read_to_end(&mut buf).map_err(|e| format!("audit chain read failed: {e}"))?;
        let mut body: &[u8] = &buf;
        if body.last() == Some(&b'\n') {
            body = &body[..body.len() - 1];
        }
        match body.iter().rposition(|b| *b == b'\n') {
            Some(pos) => {
                body = &body[pos + 1..];
            }
            None if start > 0 => {
                start = 0;
                continue;
            }
            None => {}
        }
        if body.is_empty() {
            return Ok(String::new());
        }
        let last: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return Ok(String::new()),
        };
        return Ok(last
            .get("chain_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string());
    }
}

/// Chain `fields` onto the file at `path`, write it, and `fsync` it before
/// returning. `fields` must not contain `chain_prev` or `chain_hash`. Returns
/// the record as written.
pub fn append(path: &Path, fields: Map<String, Value>) -> Result<Value, String> {
    if fields.contains_key("chain_prev") || fields.contains_key("chain_hash") {
        return Err("audit record must not set its own chain fields".to_string());
    }
    let _guard = APPEND_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let parent = path.parent().ok_or_else(|| "audit chain path has no parent".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("audit chain mkdir failed: {e}"))?;
    let existed = match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err("audit chain must be a regular non-symlink file".to_string());
            }
            true
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("audit chain metadata failed: {e}")),
    };
    let prev = read_chain_head(path)?;
    let mut record = fields;
    record.insert("chain_prev".to_string(), Value::String(prev));
    let unhashed = Value::Object(record.clone());
    let hash = sha256_hex(canonical_json(&unhashed)?.as_bytes());
    record.insert("chain_hash".to_string(), Value::String(hash));
    let written = Value::Object(record);
    let mut line = canonical_json(&written)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("audit chain open failed: {e}"))?;
    file.write_all(line.as_bytes())
        .map_err(|e| format!("audit chain write failed: {e}"))?;
    sync_durable(&file).map_err(|e| format!("audit chain fsync failed: {e}"))?;
    if !existed {
        // A new file is durable only once its directory entry is.
        let dir = File::open(parent).map_err(|e| format!("audit chain dir open failed: {e}"))?;
        sync_durable(&dir).map_err(|e| format!("audit chain dir fsync failed: {e}"))?;
    }
    Ok(written)
}

/// SHA-256 (FIPS 180-4), lower-case hex.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "azazel-audit-chain-{}-{}-{}",
            name,
            std::process::id(),
            wall_epoch_ns().unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join("chain.jsonl")
    }

    #[test]
    fn sha256_matches_fips_vectors() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(&vec![b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn canonical_json_matches_python_ensure_ascii_sort_keys_compact() {
        let v = json!({"b": 1, "a": "x\u{7f}\u{e9}\u{1f600}\n\u{1}\"\\/", "c": [true, null, -3]});
        // json.dumps(..., ensure_ascii=True, sort_keys=True, separators=(',', ':'))
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":"x\u007f\u00e9\ud83d\ude00\n\u0001\"\\/","b":1,"c":[true,null,-3]}"#
        );
        assert!(canonical_json(&json!({"f": 1.5})).is_err());
    }

    #[test]
    fn iso_timestamp_matches_python_isoformat() {
        assert_eq!(iso_utc_millis(0), "1970-01-01T00:00:00.000+00:00");
        assert_eq!(iso_utc_millis(1_761_350_400_123_456_789), "2025-10-25T00:00:00.123+00:00");
        assert_eq!(iso_utc_millis(951_782_400_999_000_000), "2000-02-29T00:00:00.999+00:00");
    }

    #[test]
    fn append_chains_and_fsyncs_every_record() {
        let path = test_path("chain");
        SYNC_CALLS.with(|c| c.set(0));
        let mut fields = Map::new();
        fields.insert("kind".into(), json!("k"));
        let first = append(&path, fields.clone()).unwrap();
        // The record and, for a new file, its directory entry.
        assert_eq!(SYNC_CALLS.with(|c| c.get()), 2);
        let second = append(&path, fields).unwrap();
        assert_eq!(SYNC_CALLS.with(|c| c.get()), 3);
        assert_eq!(first["chain_prev"], json!(""));
        assert_eq!(second["chain_prev"], first["chain_hash"]);
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let mut row: Value = serde_json::from_str(lines[1]).unwrap();
        let hash = row.as_object_mut().unwrap().remove("chain_hash").unwrap();
        assert_eq!(hash, json!(sha256_hex(canonical_json(&row).unwrap().as_bytes())));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn append_refuses_a_symlinked_chain_and_caller_chain_fields() {
        let path = test_path("symlink");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = path.with_file_name("elsewhere");
        fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(append(&path, Map::new()).is_err());
        let mut forged = Map::new();
        forged.insert("chain_prev".into(), json!(""));
        assert!(append(&path.with_file_name("other.jsonl"), forged).is_err());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn monotonic_clock_is_available_and_does_not_go_back() {
        let a = monotonic_ns().expect("monotonic clock");
        let b = monotonic_ns().expect("monotonic clock");
        assert!(b >= a);
    }
}
