//! Lock triggers support and post-crash recovery (SPEC §6). Milestone M7.
//!
//! The app owns the event loop (screen lock / sleep observers, hotkey, idle
//! polling); this module provides the platform queries and the lock / cleanup
//! / recovery steps it calls.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::browser::{self, Browser};
use crate::error::{Error, Result};
use crate::hdiutil;
use crate::store::{Store, Unlocked};

/// Seconds since the last user input (`CGEventSourceSecondsSinceLastEventType`).
/// `None` when unavailable (non-macOS).
pub fn idle_seconds() -> Option<f64> {
    platform::idle_seconds()
}

#[cfg(target_os = "macos")]
mod platform {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(state_id: i32, event_type: u32) -> f64;
    }

    /// `kCGEventSourceStateCombinedSessionState`
    const COMBINED_SESSION_STATE: i32 = 0;
    /// `kCGAnyInputEventType` (`~0`)
    const ANY_INPUT_EVENT: u32 = u32::MAX;

    pub fn idle_seconds() -> Option<f64> {
        // SAFETY: pure query without pointers; documented thread-safe.
        let s = unsafe {
            CGEventSourceSecondsSinceLastEventType(COMBINED_SESSION_STATE, ANY_INPUT_EVENT)
        };
        (s.is_finite() && s >= 0.0).then_some(s)
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn idle_seconds() -> Option<f64> {
        None
    }
}

/// Bundle id whose `Saved Application State` is shared by the vault instance
/// and the regular browser (SPEC §6 step 4).
fn saved_state_bundle(browser: Browser) -> &'static str {
    match browser {
        Browser::Brave => "com.brave.Browser",
        Browser::Firefox => "org.mozilla.firefox",
    }
}

/// `<home>/Library/Saved Application State/<bundle>.savedState`
pub fn saved_state_dir(home: &Path, browser: Browser) -> PathBuf {
    home.join("Library/Saved Application State")
        .join(format!("{}.savedState", saved_state_bundle(browser)))
}

fn remove_dir_if_exists(p: &Path) -> Result<()> {
    match fs::remove_dir_all(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Testable core of [`cleanup_traces`]. Returns whether anything was attempted.
fn cleanup_traces_in(home: &Path, browser: Browser, regular_running: bool) -> Result<bool> {
    if regular_running {
        // The regular browser owns that state right now; leave it alone.
        return Ok(false);
    }
    remove_dir_if_exists(&saved_state_dir(home, browser))?;
    Ok(true)
}

/// SPEC §6 step 4: remove `~/Library/Saved Application State/<bundle>.savedState`
/// for `browser`, but only if the regular browser is not running.
pub fn cleanup_traces(browser: Browser) -> Result<()> {
    let home = std::env::var_os("HOME").ok_or(Error::Invalid("HOME is not set"))?;
    let running = crate::profiles::regular_browser_running(browser);
    cleanup_traces_in(Path::new(&home), browser, running).map(|_| ())
}

/// Lock procedure for an open session: [`Store::close`] (stop browser,
/// detach, then `profiles::mark_reviewed` so SPEC §5.1 `reviewed` can flip),
/// then clean traces. Keys are wiped when `session` is dropped inside.
pub fn close_vault(store: &Store, session: Unlocked) -> Result<()> {
    let browser = session.header.try_meta().map(|m| m.browser);
    store.close(session)?;
    if let Some(b) = browser {
        let _ = cleanup_traces(b);
    }
    Ok(())
}

/// Full lock procedure when no session is held (crash leftovers, CLI
/// mounts): stop browser, detach (with retries), clean traces. Prefer
/// [`close_vault`] whenever the `Unlocked` session is available.
/// Trace cleanup is best effort and never fails the lock.
pub fn lock_vault(store: &Store, id: &str) -> Result<()> {
    // v2: the browser is only known from the open metadata or this Mac's
    // index; when unknown, the shared state of no browser is touched.
    let browser = store
        .load(id)
        .ok()
        .and_then(|h| store.label(&h))
        .map(|e| e.browser);
    store.lock(id)?;
    if let Some(b) = browser {
        let _ = cleanup_traces(b);
    }
    Ok(())
}

/// One disk image attached in the system, from `hdiutil info -plist`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AttachedImage {
    pub image_path: String,
    pub dev_entries: Vec<String>,
    pub mount_points: Vec<String>,
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// The `<string>` values that directly follow `<key>{key}</key>`.
fn string_values(xml: &str, key: &str) -> Vec<String> {
    let needle = format!("<key>{key}</key>");
    let mut out = vec![];
    let mut rest = xml;
    while let Some(i) = rest.find(&needle) {
        rest = &rest[i + needle.len()..];
        let trimmed = rest.trim_start();
        if let Some(body) = trimmed.strip_prefix("<string>") {
            if let Some(end) = body.find("</string>") {
                out.push(xml_unescape(&body[..end]));
            }
        }
    }
    out
}

/// Minimal reader for `hdiutil info -plist`. hdiutil writes each image dict
/// with sorted keys, so `image-path` precedes that image's `system-entities`;
/// splitting on `image-path` therefore groups entities per image.
pub fn parse_hdiutil_info(xml: &str) -> Vec<AttachedImage> {
    let marker = "<key>image-path</key>";
    let mut parts = xml.split(marker);
    parts.next(); // preamble
    parts
        .filter_map(|seg| {
            let seg_with_key = format!("{marker}{seg}");
            let image_path = string_values(&seg_with_key, "image-path")
                .into_iter()
                .next()?;
            Some(AttachedImage {
                image_path,
                dev_entries: string_values(seg, "dev-entry"),
                mount_points: string_values(seg, "mount-point"),
            })
        })
        .collect()
}

fn hdiutil_info() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = Command::new("/usr/bin/hdiutil")
        .args(["info", "-plist"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// What to detach for a leftover vault volume.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Leftover {
    Mounted(PathBuf),
    /// Attached without a mount point: detach the device node.
    Device(String),
}

fn canonical(p: &Path) -> PathBuf {
    p.canonicalize().unwrap_or_else(|_| p.to_path_buf())
}

/// Map attached images / mounted dirs to vault ids of this store.
fn find_leftovers(store: &Store, images: &[AttachedImage]) -> BTreeMap<String, Leftover> {
    let mut found = BTreeMap::new();
    let mnt_root = store.root().join("mnt");
    if let Ok(entries) = fs::read_dir(&mnt_root) {
        for e in entries.flatten() {
            let p = e.path();
            if let Some(id) = e.file_name().to_str() {
                if hdiutil::is_mounted(&p) {
                    found.insert(id.to_string(), Leftover::Mounted(p));
                }
            }
        }
    }
    let vaults_root = canonical(&store.root().join("vaults"));
    let mnt_root_c = canonical(&mnt_root);
    for img in images {
        // `<root>/vaults/<id>/image.sparsebundle`
        let ip = canonical(Path::new(&img.image_path));
        let by_image = ip
            .strip_prefix(&vaults_root)
            .ok()
            .and_then(|rel| rel.components().next())
            .and_then(|c| c.as_os_str().to_str().map(str::to_string));
        // Mounted under `<root>/mnt/<id>`.
        let by_mount = img.mount_points.iter().find_map(|m| {
            canonical(Path::new(m))
                .strip_prefix(&mnt_root_c)
                .ok()
                .and_then(|rel| rel.components().next())
                .and_then(|c| c.as_os_str().to_str().map(str::to_string))
        });
        let Some(id) = by_mount.or(by_image) else {
            continue;
        };
        if found.contains_key(&id) {
            continue;
        }
        let what = match img.mount_points.first() {
            Some(m) => Leftover::Mounted(PathBuf::from(m)),
            None => match img.dev_entries.first() {
                Some(d) => Leftover::Device(d.clone()),
                None => continue,
            },
        };
        found.insert(id, what);
    }
    found
}

/// Whether `pid` is a browser started for the vault mounted at `mnt` (its
/// command line points into the mount). Guards against PID reuse: a stale
/// pid file must never make us kill an unrelated process.
fn pid_belongs_to_mount(pid: i32, mnt: &Path) -> bool {
    if !browser::is_alive(pid) {
        return false;
    }
    let Ok(out) = Command::new("ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let args = String::from_utf8_lossy(&out.stdout);
    let m = mnt.to_string_lossy();
    !m.is_empty() && args.contains(m.as_ref())
}

fn pid_file(store: &Store, id: &str) -> PathBuf {
    store.root().join("run").join(format!("{id}.pid"))
}

/// PIDs of processes (other than ours, the crash guard and tooling) whose
/// command line points into the vault mount: the vault's browser, including
/// one that relaunched itself under a new PID.
pub fn browser_pids_in(mnt: &Path) -> Vec<i32> {
    let Ok(out) = Command::new("/bin/ps")
        .args(["-axww", "-o", "pid=,command="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return vec![];
    };
    let real = std::fs::canonicalize(mnt).unwrap_or_else(|_| mnt.to_path_buf());
    pids_matching(
        &String::from_utf8_lossy(&out.stdout),
        mnt,
        &real,
        std::process::id() as i32,
    )
}

/// [`browser_pids_in`] on a given `ps -o pid=,command=` listing.
pub fn pids_matching(ps: &str, mnt: &Path, real: &Path, own_pid: i32) -> Vec<i32> {
    let (a, b) = (mnt.to_string_lossy(), real.to_string_lossy());
    ps.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, cmd) = l.split_once(char::is_whitespace)?;
            let pid: i32 = pid.parse().ok()?;
            let hit = (!a.is_empty() && cmd.contains(a.as_ref()))
                || (!b.is_empty() && cmd.contains(b.as_ref()));
            // Only the browser itself (its main binary or helpers inside an
            // .app bundle) counts. Tools that merely mention the mount path
            // — the crash guard's `grep`/`mount`/`sh`, hdiutil, ps — must
            // never keep a vault open after its browser quit.
            let exe = cmd.split(" --").next().unwrap_or(cmd);
            let browser = exe.contains(".app/Contents/");
            let tooling = [
                crate::identity::GUARD_NAME,
                "hdiutil",
                "mdutil",
                "/bin/ps",
                "grep",
            ]
            .iter()
            .any(|t| exe.contains(t));
            (hit && browser && !tooling && pid != own_pid).then_some(pid)
        })
        .collect()
}

/// Crash guard: a tiny detached shell process that outlives the app. While
/// the vault stays mounted it waits; if the app process dies first (crash,
/// force quit), it stops the vault's browser (only if that PID's command
/// line points into the vault) and force-detaches the volume. It exits on
/// its own once the vault is locked normally (mount gone). Arguments are a
/// PID and a path — no secrets.
pub fn spawn_crash_guard(app_pid: u32, browser_pid: u32, mnt: &Path) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let real_mnt = std::fs::canonicalize(mnt).unwrap_or_else(|_| mnt.to_path_buf());
    const SCRIPT: &str = r#"
APP="$1"; BR="$2"; MNT="$3"; ORIG="$4"
mounted() { /sbin/mount | /usr/bin/grep -qF " on $MNT ("; }
while kill -0 "$APP" 2>/dev/null; do
  mounted || exit 0
  sleep 1
done
mounted || exit 0
# Every process using the vault (the browser may have relaunched itself
# under a new PID), never this guard itself.
users() { /bin/ps -axww -o pid=,command= | /usr/bin/grep -F -e "$MNT" -e "$ORIG" | /usr/bin/grep -v -e "$0" -e grep | /usr/bin/awk '{print $1}'; }
kill -TERM "$BR" 2>/dev/null
for p in $(users); do kill -TERM "$p" 2>/dev/null; done
i=0; while [ -n "$(users)" ] && [ $i -lt 8 ]; do sleep 1; i=$((i+1)); done
for p in $(users); do kill -KILL "$p" 2>/dev/null; done
for n in 1 2 3; do
  /usr/bin/hdiutil detach "$MNT" -force >/dev/null 2>&1 && exit 0
  mounted || exit 0
  sleep 1
done
"#;
    std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(SCRIPT)
        .arg(crate::identity::GUARD_NAME)
        .arg(app_pid.to_string())
        .arg(browser_pid.to_string())
        // `mount` lists the resolved path (/var → /private/var); the
        // browser's command line has the path as we passed it.
        .arg(&real_mnt)
        .arg(mnt)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // Own process group: not killed together with the app.
        .process_group(0)
        .spawn()?;
    crate::trace::emit(&format!("crash guard started for {}", mnt.display()));
    Ok(())
}

/// SPEC §6: at startup, detach leftover `BV-*` volumes from a crash.
/// Returns the vault ids that were recovered.
///
/// Also stops a vault browser that survived the crash (only when its command
/// line points into the leftover mount) and removes stale pid files of vaults
/// that are not mounted, so a later lock cannot signal a reused PID.
pub fn recover_after_crash(store: &Store) -> Result<Vec<String>> {
    let images = hdiutil_info()
        .map(|x| parse_hdiutil_info(&x))
        .unwrap_or_default();
    let leftovers = find_leftovers(store, &images);

    let mut recovered = vec![];
    let mut first_err = None;
    for (id, what) in &leftovers {
        let mnt = store.mountpoint(id);
        if let Some(pid) = store.browser_pid(id) {
            if pid_belongs_to_mount(pid, &mnt) {
                browser::terminate(pid, browser::TERMINATE_GRACE);
            }
        }
        let _ = fs::remove_file(pid_file(store, id));
        let r = match what {
            Leftover::Mounted(p) => hdiutil::detach_with_retries(p),
            Leftover::Device(dev) => hdiutil::detach(Path::new(dev), true),
        };
        match r {
            Ok(()) => recovered.push(id.clone()),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }

    // Stale pid files of vaults that are not mounted.
    if let Ok(entries) = fs::read_dir(store.root().join("run")) {
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".pid")) else {
                continue;
            };
            if !leftovers.contains_key(id) && !hdiutil::is_mounted(&store.mountpoint(id)) {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    if !recovered.is_empty() {
        for b in [Browser::Brave, Browser::Firefox] {
            let _ = cleanup_traces(b);
        }
    }
    first_err.map_or(Ok(recovered), Err)
}

#[cfg(test)]
mod relaunch_tests {
    use super::*;

    #[test]
    fn finds_relaunched_browser_but_not_tooling() {
        let mnt = Path::new("/Users/a/Library/Application Support/BrowserVault/mnt/x");
        let real = mnt;
        let ps = "  101 /Applications/Firefox.app/Contents/MacOS/firefox --new-instance -profile /Users/a/Library/Application Support/BrowserVault/mnt/x/profile
  102 /bin/sh -c ... idle-watch 1 2 /Users/a/Library/Application Support/BrowserVault/mnt/x
  103 /usr/bin/hdiutil detach /Users/a/Library/Application Support/BrowserVault/mnt/x
  104 /Applications/Firefox.app/Contents/MacOS/firefox -profile /Users/a/Other/profile
  105 /Applications/Brave Browser.app/Contents/MacOS/Brave Browser --user-data-dir=/Users/a/Library/Application Support/BrowserVault/mnt/x/profile
";
        assert_eq!(pids_matching(ps, mnt, real, 999), vec![101, 105]);
        // The crash guard's helpers mention the path but are not browsers.
        let tools =
            "  201 /usr/bin/grep -qF  on /Users/a/Library/Application Support/BrowserVault/mnt/x (
  202 /bin/sh -c x /Users/a/Library/Application Support/BrowserVault/mnt/x
";
        assert!(pids_matching(tools, mnt, real, 999).is_empty());
        assert_eq!(pids_matching(ps, mnt, real, 101), vec![105]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>framework</key>
	<string>671.100.2</string>
	<key>images</key>
	<array>
		<dict>
			<key>image-encrypted</key>
			<true/>
			<key>image-path</key>
			<string>/Users/me/Library/Application Support/BrowserVault/vaults/abc/image.sparsebundle</string>
			<key>system-entities</key>
			<array>
				<dict>
					<key>content-hint</key>
					<string>GUID_partition_scheme</string>
					<key>dev-entry</key>
					<string>/dev/disk4</string>
				</dict>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk5s1</string>
					<key>mount-point</key>
					<string>/Users/me/Library/Application Support/BrowserVault/mnt/abc</string>
				</dict>
			</array>
		</dict>
		<dict>
			<key>image-path</key>
			<string>/tmp/R&amp;D.dmg</string>
			<key>system-entities</key>
			<array>
				<dict>
					<key>dev-entry</key>
					<string>/dev/disk6</string>
				</dict>
			</array>
		</dict>
	</array>
</dict>
</plist>"#;

    #[test]
    fn parses_hdiutil_info() {
        let imgs = parse_hdiutil_info(INFO);
        assert_eq!(imgs.len(), 2);
        assert!(imgs[0]
            .image_path
            .ends_with("vaults/abc/image.sparsebundle"));
        assert_eq!(imgs[0].dev_entries, ["/dev/disk4", "/dev/disk5s1"]);
        assert_eq!(
            imgs[0].mount_points,
            ["/Users/me/Library/Application Support/BrowserVault/mnt/abc"]
        );
        assert_eq!(imgs[1].image_path, "/tmp/R&D.dmg");
        assert!(imgs[1].mount_points.is_empty());
        assert!(parse_hdiutil_info("garbage").is_empty());
    }

    #[test]
    fn leftovers_match_only_this_store() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(d.path());
        let root = d.path().to_string_lossy().into_owned();
        let id = "11111111-1111-4111-8111-111111111111";
        let imgs = vec![
            AttachedImage {
                image_path: format!("{root}/vaults/{id}/image.sparsebundle"),
                dev_entries: vec!["/dev/disk9".into()],
                mount_points: vec![],
            },
            AttachedImage {
                image_path: "/elsewhere/x.dmg".into(),
                dev_entries: vec!["/dev/disk10".into()],
                mount_points: vec!["/Volumes/X".into()],
            },
            AttachedImage {
                image_path: "/moved/image.sparsebundle".into(),
                dev_entries: vec!["/dev/disk11".into(), "/dev/disk11s1".into()],
                mount_points: vec![format!("{root}/mnt/other")],
            },
        ];
        let found = find_leftovers(&store, &imgs);
        assert_eq!(found.len(), 2);
        assert_eq!(found[id], Leftover::Device("/dev/disk9".into()));
        assert_eq!(
            found["other"],
            Leftover::Mounted(PathBuf::from(format!("{root}/mnt/other")))
        );
    }

    #[test]
    fn recovery_without_mounts_removes_stale_pid_files() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(d.path());
        let run = d.path().join("run");
        fs::create_dir_all(&run).unwrap();
        fs::create_dir_all(d.path().join("mnt/abc")).unwrap();
        // PID 1 must never be signalled: the file is stale (nothing mounted).
        fs::write(run.join("abc.pid"), "1").unwrap();
        assert!(recover_after_crash(&store).unwrap().is_empty());
        assert!(!run.join("abc.pid").exists());
    }

    #[test]
    fn pid_check_requires_mount_in_command_line() {
        // `sleep 30; :` (not a lone `sleep 30`) so the shell can't exec into
        // `sleep` and drop the marker argument from its command line.
        let mut c = Command::new("sh")
            .args(["-c", "sleep 30; :", "/some/vault/mnt/xyz"])
            .spawn()
            .unwrap();
        let pid = c.id() as i32;
        assert!(pid_belongs_to_mount(pid, Path::new("/some/vault/mnt/xyz")));
        assert!(!pid_belongs_to_mount(pid, Path::new("/other/mnt")));
        c.kill().unwrap();
        c.wait().unwrap();
        assert!(!pid_belongs_to_mount(pid, Path::new("/some/vault/mnt/xyz")));
    }

    #[test]
    fn traces_removed_only_when_regular_browser_closed() {
        let d = tempfile::tempdir().unwrap();
        let dir = saved_state_dir(d.path(), Browser::Brave);
        assert!(dir.ends_with("Library/Saved Application State/com.brave.Browser.savedState"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("windows.plist"), b"x").unwrap();

        assert!(!cleanup_traces_in(d.path(), Browser::Brave, true).unwrap());
        assert!(dir.exists());
        assert!(cleanup_traces_in(d.path(), Browser::Brave, false).unwrap());
        assert!(!dir.exists());
        // Idempotent; Firefox path is separate.
        assert!(cleanup_traces_in(d.path(), Browser::Brave, false).unwrap());
        assert!(
            saved_state_dir(d.path(), Browser::Firefox).ends_with("org.mozilla.firefox.savedState")
        );
    }

    #[test]
    fn idle_seconds_platform() {
        let v = idle_seconds();
        if cfg!(target_os = "macos") {
            // Headless CI may have no event source; just never negative.
            assert!(v.is_none_or(|s| s >= 0.0));
        } else {
            assert!(v.is_none());
        }
    }

    #[test]
    fn lock_vault_unknown_id_fails() {
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(d.path());
        assert!(lock_vault(&store, "../x").is_err());
    }
}
