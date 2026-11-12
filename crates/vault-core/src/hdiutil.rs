//! Native macOS encrypted disk images (SPEC §3). The Disk Key is only ever
//! written to the child's stdin — never argv, env, Keychain or temp files.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use crate::error::{Error, Result};

const HDIUTIL: &str = "/usr/bin/hdiutil";
const MDUTIL: &str = "/usr/bin/mdutil";
const DISKUTIL: &str = "/usr/sbin/diskutil";

/// Volume name of every vault. Neutral on purpose: an unlocked vault shows
/// up in `mount` / `diskutil list`, and the name must not say what it is.
pub const VOLUME_NAME: &str = "Data";

/// How long each tool may run before it is killed. A wedged `hdiutil`
/// must never hang a lock (SPEC §6) or the app forever.
fn timeout_for(tool: &str) -> Duration {
    match tool {
        "hdiutil create" => Duration::from_secs(600),
        "hdiutil attach" => Duration::from_secs(120),
        "hdiutil detach" => Duration::from_secs(60),
        _ => Duration::from_secs(30),
    }
}

fn run(tool: &'static str, cmd: &mut Command, stdin_secret: Option<&str>) -> Result<()> {
    run_with_timeout(tool, cmd, stdin_secret, timeout_for(tool))
}

fn run_with_timeout(
    tool: &'static str,
    cmd: &mut Command,
    stdin_secret: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    cmd.stdin(if stdin_secret.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    crate::trace::emit(&format!("{tool}: start"));
    let mut child = cmd.spawn().map_err(|e| Error::Command {
        tool,
        detail: e.to_string(),
    })?;
    if let Some(secret) = stdin_secret {
        // `-stdinpass` takes the passphrase verbatim: no trailing newline.
        let mut stdin = child.stdin.take().ok_or(Error::Command {
            tool,
            detail: "no stdin".into(),
        })?;
        stdin.write_all(secret.as_bytes())?;
        drop(stdin);
    }
    // Drain stderr on a thread so a chatty tool can't block on a full pipe.
    let stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut e) = stderr {
            let _ = e.read_to_end(&mut buf);
        }
        buf
    });
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        sleep(Duration::from_millis(50));
    };
    let err = reader.join().unwrap_or_default();
    match status {
        Some(st) if st.success() => {
            crate::trace::emit(&format!("{tool}: ok"));
            Ok(())
        }
        Some(_) => {
            let detail = String::from_utf8_lossy(&err).trim().to_string();
            crate::trace::emit(&format!("{tool}: failed: {detail}"));
            Err(Error::Command { tool, detail })
        }
        None => {
            crate::trace::emit(&format!("{tool}: timed out after {timeout:?}"));
            Err(Error::Command {
                tool,
                detail: format!("timed out after {} s", timeout.as_secs()),
            })
        }
    }
}

/// `hdiutil create -size <N>g -type SPARSEBUNDLE -fs APFS -encryption AES-256 -stdinpass -volname Data <path>`
pub fn create(image: &Path, size_gb: u32, disk_key: &str) -> Result<()> {
    if size_gb == 0 {
        return Err(Error::Invalid("vault size must be at least 1 GB"));
    }
    run(
        "hdiutil create",
        Command::new(HDIUTIL)
            .arg("create")
            .args(["-size", &format!("{size_gb}g")])
            .args(["-type", "SPARSEBUNDLE", "-fs", "APFS"])
            .args(["-encryption", "AES-256", "-stdinpass"])
            .args(["-volname", VOLUME_NAME])
            .arg(image),
        Some(disk_key),
    )
}

/// `hdiutil attach -stdinpass -nobrowse -noautoopen -owners on -mountpoint <dir> <image>`
pub fn attach(image: &Path, mountpoint: &Path, disk_key: &str) -> Result<()> {
    run(
        "hdiutil attach",
        Command::new(HDIUTIL)
            .args(["attach", "-stdinpass", "-nobrowse", "-noautoopen"])
            .args(["-owners", "on", "-mountpoint"])
            .arg(mountpoint)
            .arg(image),
        Some(disk_key),
    )
}

pub fn detach(mountpoint: &Path, force: bool) -> Result<()> {
    let mut cmd = Command::new(HDIUTIL);
    cmd.arg("detach").arg(mountpoint);
    if force {
        cmd.arg("-force");
    }
    run("hdiutil detach", &mut cmd, None)
}

/// SPEC §6 step 2: plain detach, then `-force`, up to 3 attempts total.
pub fn detach_with_retries(mountpoint: &Path) -> Result<()> {
    let mut last = None;
    for attempt in 0..3 {
        if !is_mounted(mountpoint) {
            return Ok(());
        }
        match detach(mountpoint, attempt > 0) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
        sleep(Duration::from_millis(500));
    }
    if !is_mounted(mountpoint) {
        return Ok(());
    }
    Err(last.unwrap_or(Error::Command {
        tool: "hdiutil detach",
        detail: "volume still mounted".into(),
    }))
}

/// Vaults made by older versions are named `BV-<id>`; give them the neutral
/// name. Best effort and idempotent, run after every attach.
pub fn neutralize_volume_name(mountpoint: &Path) -> Result<()> {
    run(
        "diskutil rename",
        Command::new(DISKUTIL)
            .arg("rename")
            .arg(mountpoint)
            .arg(VOLUME_NAME),
        None,
    )
}

/// SPEC §3: `mdutil -i off <mountdir>` (no Spotlight index of vault contents).
pub fn disable_spotlight(mountpoint: &Path) -> Result<()> {
    run(
        "mdutil",
        Command::new(MDUTIL).args(["-i", "off"]).arg(mountpoint),
        None,
    )
}

/// A directory is a mountpoint when it lives on a different device than its parent.
pub fn is_mounted(mountpoint: &Path) -> bool {
    let (Ok(m), Some(parent)) = (std::fs::metadata(mountpoint), mountpoint.parent()) else {
        return false;
    };
    match std::fs::metadata(parent) {
        Ok(p) => m.dev() != p.dev(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_dir_is_not_mounted() {
        let d = tempfile::tempdir().unwrap();
        let sub = d.path().join("mnt");
        std::fs::create_dir(&sub).unwrap();
        assert!(!is_mounted(&sub));
        assert!(!is_mounted(&d.path().join("missing")));
    }

    #[test]
    fn detach_of_unmounted_is_noop() {
        let d = tempfile::tempdir().unwrap();
        assert!(detach_with_retries(d.path()).is_ok());
    }

    #[test]
    fn volume_name_is_neutral() {
        assert!(!VOLUME_NAME.to_lowercase().contains("bv"));
        assert!(!VOLUME_NAME.to_lowercase().contains("vault"));
    }

    #[test]
    fn secret_goes_through_stdin_only() {
        // Use `cat` as a stand-in to prove the secret arrives on stdin verbatim
        // (no newline appended) and is not part of argv.
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("out");
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "cat > \"$0\""]).arg(&out);
        run("test", &mut cmd, Some("deadbeef")).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"deadbeef");
    }

    #[test]
    fn hung_tool_is_killed_after_timeout() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let t = std::time::Instant::now();
        let e = run_with_timeout("test", &mut cmd, None, Duration::from_millis(300)).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(e.to_string().contains("timed out"));
    }

    #[test]
    fn failure_reports_stderr() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo boom >&2; exit 3"]);
        let e = run("test", &mut cmd, None).unwrap_err();
        assert_eq!(e.to_string(), "test failed: boom");
    }
}
