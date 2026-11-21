//! Optional private inherited stream. Capture failure never changes defense.
//! No path/socket listener, command, key, retry, replay or reattachment API.
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const MAX_EVENT: usize = 60000;
const MAX_FRAME: usize = 65536;
const QUEUE: usize = 32;
const CLOSED: u64 = 1 << 63;
const COUNT_MASK: u64 = CLOSED - 1;
const CAS_ATTEMPTS: usize = 16;
static CAPTURE: OnceLock<Capture> = OnceLock::new();

enum Message {
    Event(&'static str, Vec<u8>),
    End(SyncSender<bool>),
}
#[derive(Default)]
struct Counts {
    produced: AtomicU64,
    admitted: AtomicU64,
    enqueued: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
}
impl Counts {
    fn increment(counter: &AtomicU64) -> bool {
        let mut value = counter.load(Ordering::SeqCst);
        for _ in 0..CAS_ATTEMPTS {
            if value >= COUNT_MASK { return false; }
            match counter.compare_exchange_weak(value, value + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(current) => value = current,
            }
        }
        false
    }
    fn terminal(&self, gate: &AtomicU64) -> io::Result<Value> {
        let p = self.produced.load(Ordering::SeqCst);
        let a = self.admitted.load(Ordering::SeqCst);
        let q = self.enqueued.load(Ordering::SeqCst);
        let w = self.written.load(Ordering::SeqCst);
        let d = self.dropped.load(Ordering::SeqCst);
        let i = gate.load(Ordering::SeqCst) & COUNT_MASK;
        if p != a || a != q || q != w || d != 0 || i != 0 {
            return Err(io::Error::other("capture accounting incomplete"));
        }
        Ok(json!({"produced":p,"admitted":a,"enqueued":q,"written":w,"dropped":d,"inflight":i}))
    }
}
struct Capture {
    tx: SyncSender<Message>,
    failed: Arc<AtomicBool>,
    gate: Arc<AtomicU64>,
    counts: Arc<Counts>,
    shutdown: UnixStream,
    session: String,
    close_receipts: bool,
    ingress_accounting: bool,
    load_cost: bool,
    receipt_attempted: AtomicBool,
}
struct Admission<'a>(&'a AtomicU64);
impl Drop for Admission<'_> {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
}
impl Capture {
    fn fail(&self) {
        self.gate.fetch_or(CLOSED, Ordering::SeqCst);
        if !self.failed.swap(true, Ordering::SeqCst) {
            let _ = self.shutdown.shutdown(Shutdown::Both);
        }
    }
    fn admit(&self) -> Option<Admission<'_>> {
        self.admit_with(CAS_ATTEMPTS)
    }
    fn admit_with(&self, attempts: usize) -> Option<Admission<'_>> {
        let mut value = self.gate.load(Ordering::SeqCst);
        for _ in 0..attempts {
            if value & CLOSED != 0 { return None; }
            if value == COUNT_MASK { self.fail(); return None; }
            match self.gate.compare_exchange_weak(value, value + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Admission(&self.gate)),
                Err(current) => value = current,
            }
        }
        self.fail();
        None
    }
    fn record(&self, kind: &'static str, event: &Value) {
        self.record_with(kind, event, || {});
    }
    fn record_with(&self, kind: &'static str, event: &Value, after_admission: impl FnOnce()) {
        let Some(_guard) = self.admit() else { return; };
        if !Counts::increment(&self.counts.produced) { self.fail(); return; }
        after_admission();
        // Stop allocation at the record bound, before cloning into the queue.
        struct Bound(Vec<u8>);
        impl Write for Bound {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0.len() + bytes.len() > MAX_EVENT {
                    return Err(io::Error::other("capture record bound"));
                }
                self.0.extend_from_slice(bytes); Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut bytes = Bound(Vec::new());
        if serde_json::to_writer(&mut bytes, event).is_err() {
            let _ = Counts::increment(&self.counts.dropped);
            self.fail(); return;
        }
        if !Counts::increment(&self.counts.admitted) { self.fail(); return; }
        if self.failed.load(Ordering::SeqCst) || self.tx.try_send(Message::Event(kind, bytes.0)).is_err() {
            let _ = Counts::increment(&self.counts.dropped);
            self.fail(); return;
        }
        if !Counts::increment(&self.counts.enqueued) { self.fail(); }
    }
    fn finish(&self) -> bool {
        self.finish_with(Duration::from_secs(1))
    }
    fn finish_with(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        // Only this transition's owner may queue End. Late callbacks cannot join.
        if self.gate.fetch_or(CLOSED, Ordering::SeqCst) & CLOSED != 0 { return false; }
        while self.gate.load(Ordering::SeqCst) & COUNT_MASK != 0 {
            if self.failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
                self.fail(); return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
        if self.failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
            self.fail(); return false;
        }
        let (ack, wait) = sync_channel(1);
        if self.tx.try_send(Message::End(ack)).is_err() { self.fail(); return false; }
        // An ack timeout does not retract an End already written or signed.
        if wait.recv_timeout(deadline.saturating_duration_since(Instant::now())).is_err() {
            self.fail(); return false;
        }
        true
    }
}
fn frame(stream: &mut impl Write, session: &str, seq: u64, kind: &str, event: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&json!({"schema_version":"outcome-live-origin/v1",
        "session_ref":session,"seq":seq,"kind":kind,"event":event}))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME { return Err(io::Error::other("capture frame bound")); }
    stream.write_all(&bytes)
}
fn lifecycle(state: &str, accounting: bool, counts: Option<Value>) -> Value {
    let mut lifecycle = json!({"state":state});
    if accounting {
        lifecycle["schema_version"] = json!("outcome-live-origin-lifecycle/v2");
        lifecycle["accounting_profile"] = json!("v1");
        if let Some(counts) = counts { lifecycle["counts"] = counts; }
    }
    json!({"pipeline":"rust_live_origin_v1","source":"rust_core", "capture_lifecycle":lifecycle})
}
#[cfg(test)]
fn start(stream: UnixStream, session: String) -> io::Result<Capture> {
    start_profile(stream, session, false)
}
fn start_profile(mut stream: UnixStream, session: String, accounting: bool) -> io::Result<Capture> {
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    let shutdown = stream.try_clone()?;
    let failed = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(AtomicU64::new(0));
    let counts = Arc::new(Counts::default());
    let capture_session = session.clone();
    let flag = failed.clone();
    let worker_gate = gate.clone();
    let worker_counts = counts.clone();
    let (tx, rx) = sync_channel(QUEUE);
    thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            frame(&mut stream, &session, 1, "session_start", lifecycle("start", accounting, None))?;
            let mut seq = 1u64;
            while let Ok(message) = rx.recv() {
                if flag.load(Ordering::SeqCst) { return Err(io::Error::other("capture poisoned")); }
                seq = seq.checked_add(1).filter(|n| *n < CLOSED).ok_or_else(|| io::Error::other("capture sequence exhausted"))?;
                match message {
                    Message::Event(kind, bytes) => {
                        frame(&mut stream, &session, seq, kind, serde_json::from_slice(&bytes)?)?;
                        if !Counts::increment(&worker_counts.written) { return Err(io::Error::other("capture count exhausted")); }
                    }
                    Message::End(ack) => {
                        let counts = worker_counts.terminal(&worker_gate)?;
                        frame(&mut stream, &session, seq, "session_end", lifecycle("end", accounting, Some(counts)))?;
                        let _ = stream.shutdown(Shutdown::Write);
                        let _ = ack.try_send(true);
                        return Ok(());
                    }
                }
            }
            Err(io::Error::other("capture sender lost"))
        })();
        if result.is_err() {
            worker_gate.fetch_or(CLOSED, Ordering::SeqCst);
            flag.store(true, Ordering::SeqCst);
            eprintln!("live origin stream failed; no capture reconnect; defense continues");
        }
        let _ = stream.shutdown(Shutdown::Both);
    });
    Ok(Capture { tx, failed, gate, counts, shutdown, session: capture_session, close_receipts: false, ingress_accounting: false, load_cost:false, receipt_attempted: AtomicBool::new(false) })
}

/// Only a supervising trusted launcher supplies the private connected fd.
/// Ownership transfers to this module, never to a command or external endpoint.
pub fn install(args: &[String]) -> Result<(), String> {
    if !args.iter().any(|a| a.starts_with("--live-origin")) { return Ok(()); }
    if args.len() != 5 || args[1] != "--live-origin-fd" || args[3] != "--live-origin-session" {
        return Err("live origin arguments refused".into());
    }
    let fd: i32 = args[2].parse().map_err(|_| "live origin fd")?;
    if fd < 3 || args[4].len() != 32 || !args[4].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("live origin identity refused".into());
    }
    let metadata = std::fs::metadata(format!("/dev/fd/{}", fd)).map_err(|_| "live origin descriptor missing")?;
    if !metadata.file_type().is_socket() { return Err("live origin descriptor is not a socket".into()); }
    extern "C" { fn fcntl(fd: i32, command: i32, ...) -> i32; }
    // F_GETFD/F_SETFD and FD_CLOEXEC are the same on supported Linux/macOS.
    // Prevent the inherited capture endpoint from reaching provider commands.
    let flags = unsafe { fcntl(fd, 1) };
    if flags < 0 || unsafe { fcntl(fd, 2, flags | 1) } < 0 { return Err("live origin close-on-exec unavailable".into()); }
    // SAFETY: checked open socket, explicit launcher ownership, consumed once.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.peer_addr().map_err(|_| "live origin must be a connected Unix stream")?;
    let accounting = match std::env::var("AZAZEL_LIVE_ORIGIN_ACCOUNTING") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "v1" => true,
        _ => return Err("live origin accounting profile refused".into()),
    };
    let close_receipts = match std::env::var("AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "v1" && accounting
            && std::env::var("AZAZEL_EVENT_STDOUT").as_deref() == Ok("off") => true,
        _ => return Err("live origin close receipt profile refused".into()),
    };
    let ingress_accounting=match std::env::var("AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING") {
        Err(std::env::VarError::NotPresent)=>false,
        Ok(value) if value=="v1" && accounting && close_receipts=>true,
        _=>return Err("live origin ingress accounting profile refused".into()),
    };
    let load_cost=match std::env::var("AZAZEL_LIVE_ORIGIN_LOAD_COST") {
        Err(std::env::VarError::NotPresent)=>false,
        Ok(value) if value=="v1" && ingress_accounting=>true,
        _=>return Err("live origin load cost profile refused".into()),
    };
    if close_receipts { prepare_receipt_stdout()?; }
    let mut capture = start_profile(stream, args[4].clone(), accounting).map_err(|_| "live origin unavailable")?;
    capture.close_receipts = close_receipts;
    capture.ingress_accounting=ingress_accounting;
    capture.load_cost=load_cost;
    CAPTURE.set(capture).map_err(|_| "live origin already configured".into())
}
pub fn record(kind: &'static str, event: &Value) {
    if let Some(capture) = CAPTURE.get() { capture.record(kind, event); }
}
pub fn ingress_session()->Option<&'static str> {
    CAPTURE.get().filter(|c|c.ingress_accounting).map(|c|c.session.as_str())
}
pub fn load_cost_enabled()->bool {CAPTURE.get().is_some_and(|c|c.load_cost)}
fn ingress_event(event:&Value,session:&str,span:crate::ingress::IngressSpan<'_>)->Value {
    let mut copy=event.clone();
    copy["ingress_origin"]=json!({"schema_version":"azazel-edge/ingress-origin/v1","range_ref":session,
        "device":span.device,"inode":span.inode,"start_offset":span.start_offset,
        "end_offset":span.end_offset,"raw_sha256":crate::audit_chain::sha256_hex(span.raw)});
    copy
}
pub fn record_with_span(event:&Value,span:crate::ingress::IngressSpan<'_>) {
    if let Some(capture)=CAPTURE.get() {
        if capture.ingress_accounting {
            let copy=ingress_event(event,&capture.session,span);
            capture.record("decision_execution",&copy);
        } else {capture.record("decision_execution",event);}
    }
}
fn prepare_receipt_stdout() -> Result<(), String> {
    let metadata = std::fs::metadata("/dev/fd/1").map_err(|_| "close receipt stdout missing")?;
    if !metadata.file_type().is_fifo() { return Err("close receipt stdout must be private pipe".into()); }
    extern "C" { fn fcntl(fd: i32, command: i32, ...) -> i32; }
    #[cfg(target_os = "linux")]
    const NONBLOCK: i32 = 0x800;
    #[cfg(not(target_os = "linux"))]
    const NONBLOCK: i32 = 0x4;
    let flags = unsafe { fcntl(1, 1) };
    let status = unsafe { fcntl(1, 3) };
    if flags < 0 || status < 0 || unsafe { fcntl(1, 2, flags | 1) } < 0
        || unsafe { fcntl(1, 4, status | NONBLOCK) } < 0 {
        return Err("close receipt stdout flags unavailable".into());
    }
    Ok(())
}
fn close_receipt(session: &str, acknowledged: bool) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "schema_version":"outcome-native-close-receipt/v1", "session_ref":session,
        "native_pid":std::process::id(), "local_worker_ack_observed":acknowledged
    })).unwrap_or_default();
    bytes.push(b'\n');
    bytes
}
fn close_receipt_v2(session:&str,acknowledged:bool,ingress:Value)->Vec<u8> {
    let mut bytes=serde_json::to_vec(&json!({"schema_version":"outcome-native-close-receipt/v2",
        "session_ref":session,"native_pid":std::process::id(),
        "local_worker_ack_observed":acknowledged,"ingress":ingress})).unwrap_or_default();
    bytes.push(b'\n');bytes
}
fn close_receipt_v3(session:&str,acknowledged:bool,ingress:Value,cost:Value)->Vec<u8> {
    let mut bytes=serde_json::to_vec(&json!({"schema_version":"outcome-native-close-receipt/v3",
        "session_ref":session,"native_pid":std::process::id(),
        "local_worker_ack_observed":acknowledged,"ingress":ingress,"cost":cost})).unwrap_or_default();
    bytes.push(b'\n');bytes
}
pub fn finish() {finish_with_ingress(None);}
pub fn finish_with_ingress(ingress:Option<Value>) {finish_with_cost(ingress,None);}
pub fn finish_with_cost(ingress:Option<Value>,cost:Option<Value>) {
    if let Some(capture) = CAPTURE.get() {
        let report = capture.close_receipts && !capture.receipt_attempted.swap(true, Ordering::SeqCst);
        let acknowledged = capture.finish();
        if report {
            let bytes=if capture.load_cost {
                close_receipt_v3(&capture.session,acknowledged,ingress.unwrap_or(Value::Null),cost.unwrap_or(Value::Null))
            } else if capture.ingress_accounting {
                close_receipt_v2(&capture.session,acknowledged,ingress.unwrap_or(Value::Null))
            } else {close_receipt(&capture.session, acknowledged)};
            if bytes.len() <= if capture.ingress_accounting {4096} else {1024} {
                extern "C" { fn write(fd: i32, bytes: *const u8, count: usize) -> isize; }
                // One nonblocking attempt, never stdout locks/retries or process failure.
                let _ = unsafe { write(1, bytes.as_ptr(), bytes.len()) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    #[test]
    fn preserves_provider_facts_and_order_without_recalculation() {
        let (send, recv) = UnixStream::pair().unwrap();
        recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let capture = start(send,"a".repeat(32)).unwrap();
        let event = json!({"enforcement":{"mode":"enforced","result":"applied","executed_count":2},"marker":"unchanged"});
        capture.record("decision_execution", &event);
        let (ack, wait) = sync_channel(1);
        capture.tx.try_send(Message::End(ack)).unwrap();
        let frames: Vec<Value> = BufReader::new(recv).lines().map(|l| serde_json::from_str(&l.unwrap()).unwrap()).collect();
        assert!(wait.recv_timeout(Duration::from_secs(1)).unwrap());
        assert_eq!(frames.len(),3);
        assert_eq!(frames[0]["kind"],"session_start");
        assert_eq!(frames[1]["seq"],2);
        assert_eq!(frames[1]["event"],event);
        assert_eq!(frames[2]["kind"],"session_end");
    }
    #[test]
    fn capacity_and_disconnected_receiver_poison_without_blocking_caller() {
        let (send, recv) = UnixStream::pair().unwrap();
        let capture = start(send,"b".repeat(32)).unwrap();
        drop(recv);
        let before = std::time::Instant::now();
        for _ in 0..1000 { capture.record("decision_execution", &json!({"x": "z".repeat(59000)})); }
        assert!(before.elapsed() < Duration::from_secs(2));
        assert!(capture.failed.load(Ordering::SeqCst));
        let (send, _recv) = UnixStream::pair().unwrap();
        let capture = start(send,"c".repeat(32)).unwrap();
        capture.record("decision_execution", &json!({"x":"z".repeat(MAX_EVENT)}));
        assert!(capture.failed.load(Ordering::SeqCst));
    }
    fn read_frames(recv: UnixStream) -> Vec<Value> {
        recv.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        BufReader::new(recv).lines().filter_map(|line| {
            line.ok().and_then(|line| serde_json::from_str(&line).ok())
        }).collect()
    }
    fn has_end(frames: &[Value]) -> bool {
        frames.iter().any(|f| f["kind"] == "session_end")
    }
    #[test]
    fn accounted_finite_close_is_exact_and_repeated_finish_rejects() {
        let (send, recv) = UnixStream::pair().unwrap();
        let capture = start_profile(send, "d".repeat(32), true).unwrap();
        for n in 0..4 { capture.record("decision_execution", &json!({"n":n})); }
        assert!(capture.finish());
        capture.record("release", &json!({"late":true}));
        assert!(!capture.finish());
        let frames = read_frames(recv);
        assert_eq!(frames.len(), 6);
        assert_eq!(frames[0]["event"]["capture_lifecycle"]["accounting_profile"], "v1");
        assert_eq!(frames[5]["event"]["capture_lifecycle"]["counts"], json!({
            "produced":4,"admitted":4,"enqueued":4,"written":4,"dropped":0,"inflight":0
        }));
        assert_eq!(capture.counts.produced.load(Ordering::SeqCst), 4);
    }
    #[test]
    fn close_waits_for_preclose_serialization_and_fences_late_callbacks() {
        let (send, recv) = UnixStream::pair().unwrap();
        let capture = Arc::new(start_profile(send, "e".repeat(32), true).unwrap());
        let (entered, entered_rx) = sync_channel(1);
        let (release, release_rx) = sync_channel(1);
        let writer = capture.clone();
        let record = thread::spawn(move || writer.record_with("decision_execution", &json!({"preclose":true}), || {
            entered.send(()).unwrap(); release_rx.recv().unwrap();
        }));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let closer = capture.clone();
        let finish = thread::spawn(move || closer.finish());
        let deadline = Instant::now() + Duration::from_secs(1);
        while capture.gate.load(Ordering::SeqCst) & CLOSED == 0 {
            assert!(Instant::now() < deadline); thread::yield_now();
        }
        capture.record("release", &json!({"late":true}));
        assert_eq!(capture.counts.enqueued.load(Ordering::SeqCst), 0);
        release.send(()).unwrap(); record.join().unwrap();
        assert!(finish.join().unwrap());
        let frames = read_frames(recv);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[1]["event"], json!({"preclose":true}));
        assert_eq!(frames[2]["event"]["capture_lifecycle"]["counts"]["produced"], 1);
    }
    #[test]
    fn concurrent_finish_has_one_owner() {
        let (send, recv) = UnixStream::pair().unwrap();
        let capture = Arc::new(start_profile(send, "f".repeat(32), true).unwrap());
        let a = capture.clone(); let b = capture.clone();
        let a = thread::spawn(move || a.finish());
        let b = thread::spawn(move || b.finish());
        assert_ne!(a.join().unwrap(), b.join().unwrap());
        let frames = read_frames(recv);
        assert_eq!(frames.iter().filter(|f| f["kind"] == "session_end").count(), 1);
    }
    fn stalled_capture(capacity: usize) -> (Capture, std::sync::mpsc::Receiver<Message>, UnixStream) {
        let (shutdown, recv) = UnixStream::pair().unwrap();
        let (tx, rx) = sync_channel(capacity);
        (Capture { tx, shutdown, failed:Arc::new(AtomicBool::new(false)),
            gate:Arc::new(AtomicU64::new(0)), counts:Arc::new(Counts::default()),
            session:"a".repeat(32), close_receipts:false, ingress_accounting:false, load_cost:false, receipt_attempted:AtomicBool::new(false) }, rx, recv)
    }
    #[test]
    fn deterministic_queue_full_and_checked_overflow_leave_no_terminal() {
        let (capture, _rx, recv) = stalled_capture(1);
        capture.record("release", &json!({"n":1}));
        capture.record("release", &json!({"n":2}));
        assert!(capture.failed.load(Ordering::SeqCst));
        assert!(!capture.finish());
        assert_eq!(capture.counts.produced.load(Ordering::SeqCst), 2);
        assert_eq!(capture.counts.enqueued.load(Ordering::SeqCst), 1);
        assert_eq!(capture.counts.dropped.load(Ordering::SeqCst), 1);
        assert!(!has_end(&read_frames(recv)));
        let (capture, _rx, recv) = stalled_capture(1);
        capture.counts.produced.store(COUNT_MASK, Ordering::SeqCst);
        capture.record("release", &json!({}));
        assert!(capture.failed.load(Ordering::SeqCst));
        assert_eq!(capture.gate.load(Ordering::SeqCst) & COUNT_MASK, 0);
        assert_eq!(capture.counts.produced.load(Ordering::SeqCst), COUNT_MASK);
        assert!(!has_end(&read_frames(recv)));
    }
    #[test]
    fn bounded_cas_and_drain_timeout_poison_without_terminal() {
        let (capture, _rx, recv) = stalled_capture(1);
        assert!(capture.admit_with(0).is_none());
        assert!(capture.failed.load(Ordering::SeqCst));
        assert!(!has_end(&read_frames(recv)));
        let (capture, _rx, recv) = stalled_capture(1);
        let guard = capture.admit().unwrap();
        let before = Instant::now();
        assert!(!capture.finish_with(Duration::from_millis(10)));
        assert!(before.elapsed() < Duration::from_secs(1));
        drop(guard);
        assert_eq!(capture.gate.load(Ordering::SeqCst) & COUNT_MASK, 0);
        assert!(!has_end(&read_frames(recv)));
    }
    #[test]
    fn ack_timeout_cannot_retract_already_written_terminal() {
        let (capture, rx, mut recv) = stalled_capture(1);
        // Model an independently scheduled worker that emits End/EOF before
        // delivering its local acknowledgement. These facts are separate.
        let mut writer = capture.shutdown.try_clone().unwrap();
        let worker = thread::spawn(move || {
            if let Message::End(ack) = rx.recv().unwrap() {
                frame(&mut writer, &"a".repeat(32), 1, "session_start", lifecycle("start", true, None)).unwrap();
                frame(&mut writer, &"a".repeat(32), 2, "session_end", lifecycle("end", true, Some(json!({
                    "produced":0,"admitted":0,"enqueued":0,"written":0,"dropped":0,"inflight":0
                })))).unwrap();
                writer.shutdown(Shutdown::Write).unwrap();
                thread::sleep(Duration::from_millis(30));
                let _ = ack.try_send(true);
            }
        });
        assert!(!capture.finish_with(Duration::from_millis(10)));
        let mut bytes = String::new();
        use std::io::Read;
        recv.read_to_string(&mut bytes).unwrap();
        let frames: Vec<Value> = bytes.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert!(has_end(&frames));
        worker.join().unwrap();
    }
    #[test]
    fn partial_socket_write_failure_never_adds_terminal() {
        let (send, mut recv) = UnixStream::pair().unwrap();
        let capture = start_profile(send, "a".repeat(32), true).unwrap();
        let reader = thread::spawn(move || {
            use std::io::Read;
            let mut prefix = [0u8; 128];
            recv.read_exact(&mut prefix).unwrap();
            // Close while a large queued frame may be incomplete.
        });
        for _ in 0..8 { capture.record("release", &json!({"blob":"x".repeat(59000)})); }
        reader.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !capture.failed.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline); thread::yield_now();
        }
        assert!(!capture.finish());
        assert!(capture.counts.written.load(Ordering::SeqCst) < capture.counts.enqueued.load(Ordering::SeqCst));
    }

    #[test]
    fn partial_frame_write_error_is_not_complete_write() {
        struct PartialFailure { prefix: Vec<u8> }
        impl Write for PartialFailure {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.prefix.is_empty() { return Err(io::Error::new(io::ErrorKind::BrokenPipe, "partial test failure")); }
                let n = bytes.len().min(19); self.prefix.extend_from_slice(&bytes[..n]); Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut writer = PartialFailure { prefix: Vec::new() };
        assert!(frame(&mut writer, &"a".repeat(32), 2, "release", json!({"x":1})).is_err());
        assert_eq!(writer.prefix.len(), 19);
        assert!(!writer.prefix.ends_with(b"\n"));
    }
    #[test]
    fn stalled_socket_write_has_bounded_failure_without_terminal() {
        let (send, recv) = UnixStream::pair().unwrap();
        let capture = start_profile(send, "a".repeat(32), true).unwrap();
        for _ in 0..16 { capture.record("release", &json!({"blob":"x".repeat(59000)})); }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !capture.failed.load(Ordering::SeqCst) {
            assert!(Instant::now() < deadline); thread::yield_now();
        }
        assert!(!capture.finish());
        assert!(!has_end(&read_frames(recv)));
    }

    #[test]
    fn close_diagnostic_is_bounded_and_does_not_claim_receiver_ack() {
        for acknowledged in [true, false] {
            let raw = close_receipt(&"a".repeat(32), acknowledged);
            assert!(raw.len() <= 1024 && raw.ends_with(b"\n"));
            let value: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 4);
            assert_eq!(value["local_worker_ack_observed"], acknowledged);
            assert_eq!(value["native_pid"], std::process::id());
            assert_eq!(value["session_ref"], "a".repeat(32));
        }
    }

    #[test]
    fn finite_origin_changes_only_signed_copy_and_hashes_original_lf_bytes() {
        let original=json!({"marker":"original core_event"});
        let raw=b"  {\"event_type\":\"alert\"} \n";
        let span=crate::ingress::IngressSpan {device:1,inode:2,start_offset:10,end_offset:10+raw.len() as u64,raw};
        let mut copy=ingress_event(&original,&"a".repeat(32),span);
        assert_eq!(copy["ingress_origin"]["raw_sha256"],crate::audit_chain::sha256_hex(raw));
        copy.as_object_mut().unwrap().remove("ingress_origin");assert_eq!(copy,original);
        assert!(original.get("ingress_origin").is_none());
    }

    #[test]
    fn finite_receipt_uses_explicit_v2_and_existing_atomic_pipe_bound() {
        let mut reader=crate::ingress::IngressReader::new(0,crate::ingress::IngressLimits::DECLARED);
        reader.enable_finite(&"a".repeat(32),None);let snapshot=reader.finite_snapshot().unwrap();
        let bytes=close_receipt_v2(&"a".repeat(32),false,snapshot.clone());
        assert!(bytes.len()<=4096 && bytes.ends_with(b"\n"));
        let receipt:Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(receipt.as_object().unwrap().len(),5);assert_eq!(receipt["ingress"],snapshot);
        assert_eq!(receipt["schema_version"],"outcome-native-close-receipt/v2");
        let old:Value=serde_json::from_slice(&close_receipt(&"a".repeat(32),false)).unwrap();
        assert_eq!(old.as_object().unwrap().len(),4);assert!(old.get("ingress").is_none());
    }

    #[test]
    fn load_cost_uses_only_explicit_v3_receipt_and_existing_bound() {
        let meter=crate::load_cost::Meter::new();
        let raw=close_receipt_v3(&"a".repeat(32),true,Value::Null,meter.snapshot());
        let receipt:Value=serde_json::from_slice(&raw).unwrap();
        assert_eq!(receipt.as_object().unwrap().len(),6);assert_eq!(receipt["schema_version"],"outcome-native-close-receipt/v3");
        assert!(receipt["cost"]["phases"]["poll_total"].is_null());assert!(raw.len()<=4096);
        let legacy:Value=serde_json::from_slice(&close_receipt(&"a".repeat(32),true)).unwrap();
        assert!(legacy.get("cost").is_none());
    }

}
