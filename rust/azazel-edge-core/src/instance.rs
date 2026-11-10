//! Lifetime singleton for one release-state directory. Not the short ledger lock.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, DirBuilderExt};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn geteuid() -> u32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}
pub struct InstanceGuard { _file: File }
pub fn path(ledger: &str) -> PathBuf { Path::new(ledger).with_file_name("core-instance.lock") }
fn safe(info: &std::fs::Metadata, uid: u32, directory: bool) -> bool {
    if directory {
        info.is_dir() && ((info.uid() == uid || info.uid() == 0) && info.mode() & 0o022 == 0
            || info.uid() == 0 && info.mode() & 0o1000 != 0)
    } else { info.is_file() && info.uid() == uid && info.nlink() == 1 && info.mode() & 0o777 == 0o600 }
}
impl InstanceGuard {
    pub fn acquire(ledger: &str, inherited: Option<i32>) -> Result<Self,String> {
        let destination = path(ledger);
        if !destination.is_absolute() || destination.components().any(|c| matches!(c,Component::ParentDir)) {
            return Err("core instance state must be physical absolute".into());
        }
        let uid = unsafe { geteuid() };
        let parent = destination.parent().ok_or("core instance directory")?;
        let mut walked = PathBuf::new();
        for part in parent.components() {
            walked.push(part.as_os_str());
            match std::fs::symlink_metadata(&walked) {
                Ok(info) if safe(&info,uid,true) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::DirBuilder::new().mode(0o700).create(&walked).map_err(|_| "core instance directory creation refused")?;
                    if !safe(&std::fs::symlink_metadata(&walked).map_err(|_| "core instance directory")?,uid,true) {
                        return Err("unsafe core instance directory".into());
                    }
                },
                _ => return Err("unsafe core instance ancestor".into()),
            }
        }
        let file = if let Some(fd) = inherited {
            if fd < 3 { return Err("core instance descriptor refused".into()); }
            let info = std::fs::metadata(format!("/dev/fd/{fd}")).map_err(|_| "core instance descriptor missing")?;
            if !safe(&info,uid,false) { return Err("unsafe inherited core instance descriptor".into()); }
            // SAFETY: validated live descriptor, explicitly transferred by launcher.
            unsafe { File::from_raw_fd(fd) }
        } else {
            OpenOptions::new().read(true).write(true).create(true).mode(0o600)
                .custom_flags(crate::release::O_NOFOLLOW).open(&destination).map_err(|_| "core instance lock open refused")?
        };
        let info = file.metadata().map_err(|_| "core instance metadata")?;
        let named = std::fs::symlink_metadata(&destination).map_err(|_| "core instance lock missing")?;
        if !safe(&info,uid,false) || !safe(&named,uid,false) || (info.dev(),info.ino()) != (named.dev(),named.ino()) {
            return Err("core instance namespace refused".into());
        }
        let fd = file.as_raw_fd();
        if unsafe { flock(fd, 2 | 4) } != 0 { return Err("another core owns this release-state directory".into()); }
        let flags = unsafe { fcntl(fd,1) };
        if flags < 0 || unsafe { fcntl(fd,2,flags|1) } < 0 { return Err("core instance close-on-exec refused".into()); }
        Ok(Self { _file:file })
    }
}
/// Remove only our exact private inherited descriptor option before ordinary
/// subcommand/live-origin parsing; no environment or public reset bypass.
pub fn arguments(args: &[String]) -> Result<(Vec<String>,Option<i32>),String> {
    let mut out=Vec::new(); let mut inherited=None; let mut at=0;
    while at<args.len() {
        if args[at]=="--core-instance-fd" {
            if inherited.is_some() || at+1>=args.len() { return Err("core instance arguments refused".into()); }
            inherited=Some(args[at+1].parse().map_err(|_| "core instance fd")?); at+=2;
        } else { out.push(args[at].clone()); at+=1; }
    }
    Ok((out,inherited))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_second_writer_and_never_unlinks_lock() {
        let dir=std::env::temp_dir().join(format!("edge-instance-{}",std::process::id()));
        let _=std::fs::remove_dir_all(&dir); std::fs::create_dir(&dir).unwrap();
        let dir=dir.canonicalize().unwrap();
        let ledger=dir.join("ledger.json"); let ledger=ledger.to_str().unwrap();
        let guard=InstanceGuard::acquire(ledger,None).unwrap();
        assert!(InstanceGuard::acquire(ledger,None).is_err());
        let ino=std::fs::metadata(path(ledger)).unwrap().ino();
        drop(guard); drop(InstanceGuard::acquire(ledger,None).unwrap());
        assert_eq!(std::fs::metadata(path(ledger)).unwrap().ino(),ino);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
