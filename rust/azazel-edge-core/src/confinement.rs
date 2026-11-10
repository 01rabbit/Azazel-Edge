//! One-way application confinement after sealed exec, before any core work.
//! No exec of a mutable copy, disconnected-path flags, policy load or fallback.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub fn arguments(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut out = Vec::new();
    let mut profile = None;
    let mut at = 0;
    while at < args.len() {
        if args[at] == "--native-apparmor-profile" {
            if profile.is_some() || at + 1 >= args.len() {
                return Err("native AppArmor arguments refused".into());
            }
            let name = &args[at + 1];
            if name.is_empty() || name.len() > 128 || name == "unconfined"
                || !name.bytes().enumerate().all(|(i, b)| b.is_ascii_alphanumeric()
                    || b == b'_' || i > 0 && (b == b'.' || b == b'-')) {
                return Err("literal native AppArmor profile required".into());
            }
            profile = Some(name.clone());
            at += 2;
        } else {
            out.push(args[at].clone());
            at += 1;
        }
    }
    Ok((out, profile))
}

pub fn enter(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let (out, profile) = arguments(args)?;
    if let Some(ref name) = profile {
        apply(name)?;
    }
    Ok((out, profile))
}

#[cfg(target_os = "linux")]
fn apply(profile: &str) -> Result<(), String> {
    extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
        fn prctl(option: i32, ...) -> i32;
    }
    // Check the actual running image, not a pathname to a replacement. All
    // seals are irreversible; the original launcher verified its enrolled hash.
    let image = File::open("/proc/self/exe").map_err(|_| "native sealed image unavailable")?;
    let info = image.metadata().map_err(|_| "native image metadata unavailable")?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o7777 != 0o500
        || info.nlink() != 0 || unsafe { fcntl(image.as_raw_fd(), 1034) } != 15 {
        return Err("native AppArmor requires the fully sealed root image".into());
    }
    drop(image);
    if unsafe { prctl(38, 1 as std::os::raw::c_ulong, 0 as std::os::raw::c_ulong,
                       0 as std::os::raw::c_ulong, 0 as std::os::raw::c_ulong) } != 0 {
        return Err("native no-new-privileges refused".into());
    }
    // AppArmor change_profile kernel interface (one way; target grants no
    // change_profile, exec or policy-management permission). No helper process.
    OpenOptions::new().write(true).open("/proc/self/attr/apparmor/current")
        .and_then(|mut f| f.write_all(format!("changeprofile {}", profile).as_bytes()))
        .map_err(|_| "native AppArmor transition refused")?;
    let actual = std::fs::read_to_string("/proc/self/attr/apparmor/current")
        .map_err(|_| "native AppArmor label unavailable")?;
    if actual.trim() != format!("{} (enforce)", profile) {
        return Err("native AppArmor label not enforced".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply(_: &str) -> Result<(), String> {
    Err("native AppArmor requires Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_unique_private_option_only() {
        for name in ["", "unconfined", "-bad", ".bad", "a b", "x\ny", "x/y", "x\0y", &"a".repeat(129)] {
            assert!(arguments(&["core".into(), "--native-apparmor-profile".into(), name.into()]).is_err());
        }
        assert!(arguments(&["core".into(), "--native-apparmor-profile".into()]).is_err());
        assert!(arguments(&["--native-apparmor-profile".into(), "x".into(), "--native-apparmor-profile".into(), "x".into()]).is_err());
        let (args, p) = arguments(&["core".into(), "--native-apparmor-profile".into(), "edge400-native".into(), "--health".into()]).unwrap();
        assert_eq!(args, vec!["core", "--health"]);
        assert_eq!(p.as_deref(), Some("edge400-native"));
    }
    #[test]
    fn mutable_disk_image_cannot_enter() {
        assert!(apply("edge400-native").is_err());
    }
}
