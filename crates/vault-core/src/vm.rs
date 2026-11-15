//! Parallels Desktop virtual machines in a vault.
//!
//! The whole `.pvm` bundle (disks, configuration, snapshots, suspended
//! memory) lives in `<mnt>/profile/<Name>.pvm`. Unlocking registers it with
//! Parallels (keeping its UUID, so Windows activation and MAC addresses
//! stay the same: it was moved, not copied) and starts or resumes it.
//! Locking **suspends** it — its memory goes into the encrypted vault, the
//! guest loses nothing — and unregisters it, so Parallels' VM list keeps
//! neither its name nor its path. Everything goes through `prlctl`
//! (Parallels Desktop Pro/Business).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// Parallels' command-line tool inside the app, else the usual symlink.
pub fn prlctl_for(app: &Path) -> Option<PathBuf> {
    [
        app.join("Contents/MacOS/prlctl"),
        PathBuf::from("/usr/local/bin/prlctl"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// The VM bundle in a mounted vault (the first `*.pvm` in its profile dir).
pub fn find_pvm(mnt: &Path) -> Option<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(crate::browser::profile_dir(mnt))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "pvm") && p.is_dir())
        .collect();
    v.sort();
    v.into_iter().next()
}

/// `<VmUuid>{…}</VmUuid>` from the bundle's `config.pvs`.
pub fn vm_uuid(pvm: &Path) -> Option<String> {
    let xml = std::fs::read_to_string(pvm.join("config.pvs")).ok()?;
    uuid_in_config(&xml)
}

fn uuid_in_config(xml: &str) -> Option<String> {
    let start = xml.find("<VmUuid>")? + "<VmUuid>".len();
    let end = start + xml[start..].find("</VmUuid>")?;
    let id = xml[start..end].trim();
    let bare = id.trim_start_matches('{').trim_end_matches('}');
    uuid::Uuid::parse_str(bare).ok().map(|_| id.to_string())
}

fn run(prlctl: &Path, args: &[&std::ffi::OsStr], timeout: Duration) -> Result<String> {
    let mut child = Command::new(prlctl)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let mut out = String::new();
            if let Some(mut s) = child.stdout.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut out);
            }
            return if status.success() {
                Ok(out)
            } else {
                Err(Error::Command {
                    tool: "prlctl",
                    detail: format!(
                        "{} failed",
                        args.first()
                            .map(|a| a.to_string_lossy())
                            .unwrap_or_default()
                    ),
                })
            };
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            return Err(Error::Command {
                tool: "prlctl",
                detail: "timed out".into(),
            });
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `running`, `suspended`, `stopped`, `paused`, … or `None` when Parallels
/// does not know the VM (not registered).
pub fn status(prlctl: &Path, uuid: &str) -> Option<String> {
    let out = run(
        prlctl,
        &["status".as_ref(), uuid.as_ref()],
        Duration::from_secs(20),
    )
    .ok()?;
    parse_status(&out)
}

fn parse_status(out: &str) -> Option<String> {
    // "VM {uuid} exist running"
    out.split_whitespace().last().map(str::to_lowercase)
}

/// Whether the VM is (still) up in any form.
pub fn is_active(state: &str) -> bool {
    !matches!(state, "stopped" | "suspended")
}

/// Register a moved bundle, keeping its UUID. Already registered is fine.
pub fn register(prlctl: &Path, pvm: &Path) -> Result<()> {
    let _ = run(
        prlctl,
        &[
            "register".as_ref(),
            pvm.as_os_str(),
            "--preserve-uuid".as_ref(),
        ],
        Duration::from_secs(60),
    );
    Ok(())
}

pub fn unregister(prlctl: &Path, uuid: &str) {
    let _ = run(
        prlctl,
        &["unregister".as_ref(), uuid.as_ref()],
        Duration::from_secs(60),
    );
}

/// Start, or resume a suspended VM.
pub fn start(prlctl: &Path, uuid: &str) -> Result<()> {
    match status(prlctl, uuid).as_deref() {
        Some(s) if is_active(s) => Ok(()),
        _ => run(
            prlctl,
            &["start".as_ref(), uuid.as_ref()],
            Duration::from_secs(180),
        )
        .map(|_| ()),
    }
}

/// Suspend (memory saved into the bundle). Already down is fine. Waits
/// until Parallels reports it suspended or stopped.
pub fn suspend(prlctl: &Path, uuid: &str) -> Result<()> {
    match status(prlctl, uuid).as_deref() {
        None => return Ok(()),
        Some(s) if !is_active(s) => return Ok(()),
        _ => {}
    }
    run(
        prlctl,
        &["suspend".as_ref(), uuid.as_ref()],
        Duration::from_secs(300),
    )?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        match status(prlctl, uuid).as_deref() {
            Some(s) if is_active(s) => std::thread::sleep(Duration::from_secs(1)),
            _ => return Ok(()),
        }
    }
    Err(Error::Command {
        tool: "prlctl",
        detail: "VM did not suspend".into(),
    })
}

/// What a lock needs to put an open VM vault away: written at unlock to
/// `<root>/run/<id>.vm` as `<prlctl path>\n<uuid>`.
pub fn marker_text(prlctl: &Path, uuid: &str) -> String {
    format!("{}\n{}\n", prlctl.display(), uuid)
}

pub fn parse_marker(s: &str) -> Option<(PathBuf, String)> {
    let mut l = s.lines();
    let p = PathBuf::from(l.next()?.trim());
    let u = l.next()?.trim().to_string();
    (!u.is_empty() && p.is_absolute()).then_some((p, u))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_uuid_status_and_marker() {
        let xml = "<ParallelsVirtualMachine><Identification>\
            <VmUuid>{a3761211-d92e-4f48-8528-6ddc68eee96c}</VmUuid>\
            <VmName>Windows 11</VmName></Identification></ParallelsVirtualMachine>";
        assert_eq!(
            uuid_in_config(xml).as_deref(),
            Some("{a3761211-d92e-4f48-8528-6ddc68eee96c}")
        );
        assert_eq!(uuid_in_config("<VmUuid>evil; rm -rf</VmUuid>"), None);
        assert_eq!(
            parse_status("VM {a3761211-d92e-4f48-8528-6ddc68eee96c} exist running\n").as_deref(),
            Some("running")
        );
        assert!(is_active("running") && is_active("paused") && !is_active("suspended"));
        let m = marker_text(Path::new("/A/prlctl"), "{x}");
        assert_eq!(
            parse_marker(&m),
            Some((PathBuf::from("/A/prlctl"), "{x}".to_string()))
        );
        assert_eq!(parse_marker("relative\n{x}"), None);
    }

    #[test]
    fn finds_the_bundle() {
        let d = tempfile::tempdir().unwrap();
        let pvm = d.path().join("profile/Windows 11 Work.pvm");
        std::fs::create_dir_all(&pvm).unwrap();
        std::fs::write(
            pvm.join("config.pvs"),
            "<VmUuid>{5681d811-e628-4c9b-9e4e-46a5cec0418a}</VmUuid>",
        )
        .unwrap();
        assert_eq!(find_pvm(d.path()), Some(pvm.clone()));
        assert_eq!(
            vm_uuid(&pvm).as_deref(),
            Some("{5681d811-e628-4c9b-9e4e-46a5cec0418a}")
        );
    }
}
