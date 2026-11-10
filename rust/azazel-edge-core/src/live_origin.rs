//! Optional private inherited stream. Capture failure never changes defense.
//! No path/socket listener, command, key, retry, replay or reattachment API.
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

const MAX_EVENT: usize = 60000;
const MAX_FRAME: usize = 65536;
const QUEUE: usize = 32;
static CAPTURE: OnceLock<Capture> = OnceLock::new();

enum Message {
    Event(&'static str, Vec<u8>),
    End(SyncSender<bool>),
}
struct Capture {
    tx: SyncSender<Message>,
    failed: Arc<AtomicBool>,
    shutdown: UnixStream,
}
impl Capture {
    fn fail(&self) {
        if !self.failed.swap(true, Ordering::SeqCst) {
            let _ = self.shutdown.shutdown(Shutdown::Both);
        }
    }
    fn record(&self, kind: &'static str, event: &Value) {
        if self.failed.load(Ordering::SeqCst) { return; }
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
        if serde_json::to_writer(&mut bytes, event).is_err()
            || self.tx.try_send(Message::Event(kind, bytes.0)).is_err() {
            self.fail();
        }
    }
}
fn frame(stream: &mut UnixStream, session: &str, seq: u64, kind: &str, event: Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(&json!({"schema_version":"outcome-live-origin/v1",
        "session_ref":session,"seq":seq,"kind":kind,"event":event}))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME { return Err(io::Error::other("capture frame bound")); }
    stream.write_all(&bytes)
}
fn lifecycle(state: &str) -> Value {
    json!({"pipeline":"rust_live_origin_v1","source":"rust_core",
        "capture_lifecycle":{"state":state}})
}
fn start(mut stream: UnixStream, session: String) -> io::Result<Capture> {
    stream.set_write_timeout(Some(Duration::from_millis(250)))?;
    let shutdown = stream.try_clone()?;
    let failed = Arc::new(AtomicBool::new(false));
    let flag = failed.clone();
    let (tx, rx) = sync_channel(QUEUE);
    thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            frame(&mut stream, &session, 1, "session_start", lifecycle("start"))?;
            let mut seq = 1u64;
            while let Ok(message) = rx.recv() {
                if flag.load(Ordering::SeqCst) { return Err(io::Error::other("capture poisoned")); }
                seq = seq.checked_add(1).ok_or_else(|| io::Error::other("capture sequence exhausted"))?;
                match message {
                    Message::Event(kind, bytes) => frame(&mut stream, &session, seq, kind, serde_json::from_slice(&bytes)?)?,
                    Message::End(ack) => {
                        frame(&mut stream, &session, seq, "session_end", lifecycle("end"))?;
                        let _ = ack.try_send(true);
                        return Ok(());
                    }
                }
            }
            Err(io::Error::other("capture sender lost"))
        })();
        if result.is_err() {
            flag.store(true, Ordering::SeqCst);
            eprintln!("live origin stream failed; no capture reconnect; defense continues");
        }
        let _ = stream.shutdown(Shutdown::Both);
    });
    Ok(Capture { tx, failed, shutdown })
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
    let capture = start(stream, args[4].clone()).map_err(|_| "live origin unavailable")?;
    CAPTURE.set(capture).map_err(|_| "live origin already configured".into())
}
pub fn record(kind: &'static str, event: &Value) {
    if let Some(capture) = CAPTURE.get() { capture.record(kind, event); }
}
pub fn finish() {
    if let Some(capture) = CAPTURE.get() {
        if capture.failed.load(Ordering::SeqCst) { return; }
        let (ack, wait) = sync_channel(1);
        if capture.tx.try_send(Message::End(ack)).is_err()
            || wait.recv_timeout(Duration::from_secs(1)).is_err() { capture.fail(); }
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
}
