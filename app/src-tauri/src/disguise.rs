//! Disguise (Settings → General → Privacy): run the app under an invented,
//! neutral name and icon so a casual look at the Mac (Finder, Launchpad,
//! Activity Monitor, ~/Library) does not show "Browser Vault". This is
//! plausible deniability against a glance, not forensic invisibility.
//!
//! Applying one (macOS only, all vaults locked) copies the running bundle to
//! `/Applications/<Name>.app` (or next to the current bundle), renames the
//! executable, rewrites `Info.plist` (name, id, executable, icon and the
//! custom `BVStoreName`), re-signs ad hoc, renames the data and log
//! directories, removes the old bundle, starts the copy and quits. "None"
//! does the same back to "Browser Vault". The names and icons are invented
//! for this app (icons drawn by `disguises/generate.py`); none imitates a
//! real product or brand.

use std::path::{Path, PathBuf};

use vault_core::identity::{self, DEFAULT_DISPLAY_NAME, DEFAULT_STORE_NAME};

#[derive(Debug, PartialEq, Eq)]
pub struct Disguise {
    pub id: &'static str,
    /// Bundle name (`<name>.app`, CFBundleName / CFBundleDisplayName).
    pub name: &'static str,
    /// `Contents/MacOS/<exe>`: the process name in Activity Monitor / `ps`.
    pub exe: &'static str,
    pub bundle_id: &'static str,
    /// Data / log directory name (`BVStoreName`).
    pub store: &'static str,
    /// `.icns` under the bundled resources `disguises/`.
    pub icon: &'static str,
}

/// Must equal `identifier` in `tauri.conf.json` (checked by a test): the
/// single-instance socket in /tmp is named after it at build time.
pub const BASE_BUNDLE_ID: &str = "local.statusbar.helper";

/// Bundle id of versions before the trace cleanup. Its ~/Library folders and
/// stale /tmp socket are removed on start.
pub const LEGACY_BUNDLE_ID: &str = "com.browservault.app";

pub const NONE: Disguise = Disguise {
    id: "none",
    name: DEFAULT_DISPLAY_NAME,
    exe: "browser-vault",
    bundle_id: BASE_BUNDLE_ID,
    store: DEFAULT_STORE_NAME,
    icon: "browser-vault.icns",
};

pub const DISGUISES: [Disguise; 4] = [
    NONE,
    Disguise {
        id: "fontcache",
        name: "Font Cache Helper",
        exe: "fontcache-helper",
        bundle_id: "local.fontcache.helper",
        store: "com.fontcache.store",
        icon: "fontcache.icns",
    },
    Disguise {
        id: "displayprofile",
        name: "Display Profile Tool",
        exe: "displayprofile-tool",
        bundle_id: "local.displayprofile.tool",
        store: "com.displayprofile.data",
        icon: "displayprofile.icns",
    },
    Disguise {
        id: "archiveindex",
        name: "Archive Index",
        exe: "archive-index",
        bundle_id: "local.archiveindex.app",
        store: "com.archiveindex.data",
        icon: "archiveindex.icns",
    },
];

pub fn by_id(id: &str) -> Option<&'static Disguise> {
    DISGUISES.iter().find(|d| d.id == id)
}

pub fn by_exe(exe: &str) -> Option<&'static Disguise> {
    DISGUISES.iter().find(|d| d.exe == exe)
}

/// The running bundle (`…/X.app`), if the app runs from one.
pub fn current_bundle() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|e| identity::bundle_for_exe(&e))
}

/// The disguise this process runs as, from its executable name. Outside a
/// bundle (dev builds) always [`NONE`].
pub fn current() -> &'static Disguise {
    if current_bundle().is_none() {
        return &NONE;
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.file_name().map(|n| n.to_string_lossy().into_owned()))
        .and_then(|n| by_exe(&n))
        .unwrap_or(&NONE)
}

/// Where the disguised copy goes: `/Applications` when writable, else the
/// folder the current bundle is in.
pub fn target_bundle(current: &Path, applications_writable: bool, d: &Disguise) -> PathBuf {
    let dir = if applications_writable {
        PathBuf::from("/Applications")
    } else {
        current
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/Applications"))
    };
    dir.join(format!("{}.app", d.name))
}

/// `plutil` invocations (arguments before the plist path) that turn a copy
/// of the bundle's Info.plist into `d`'s identity. Values come from the
/// fixed table above, never from user input. The final `-convert xml1`
/// keeps the file readable by `identity::plist_string`.
pub fn plist_edits(d: &Disguise) -> Vec<Vec<String>> {
    let set = |k: &str, v: &str| -> Vec<String> {
        vec!["-replace".into(), k.into(), "-string".into(), v.into()]
    };
    let mut out = vec![
        set("CFBundleName", d.name),
        set("CFBundleDisplayName", d.name),
        set("CFBundleExecutable", d.exe),
        set("CFBundleIdentifier", d.bundle_id),
        set("CFBundleIconFile", d.icon),
    ];
    if d.store == DEFAULT_STORE_NAME {
        out.push(vec!["-remove".into(), identity::STORE_NAME_KEY.into()]);
    } else {
        out.push(set(identity::STORE_NAME_KEY, d.store));
    }
    out.push(vec!["-convert".into(), "xml1".into()]);
    out
}

/// Whether an edited Info.plist really carries `d`'s identity.
pub fn plist_matches(info_xml: &str, d: &Disguise) -> bool {
    let get = |k| identity::plist_string(info_xml, k);
    get("CFBundleExecutable").as_deref() == Some(d.exe)
        && get("CFBundleIdentifier").as_deref() == Some(d.bundle_id)
        && get("CFBundleName").as_deref() == Some(d.name)
        && identity::store_name_from(info_xml) == d.store
}

/// Whether an existing bundle at the target path is one of ours (left over
/// from an earlier attempt) and may be replaced.
/// A bundle the app can replace: not on a mounted disk image / other volume
/// (`/Volumes/...`) and not a Gatekeeper App Translocation path.
pub fn is_installed_location(bundle: &Path) -> bool {
    let s = bundle.to_string_lossy();
    !s.starts_with("/Volumes/") && !s.contains("/AppTranslocation/")
}

pub fn is_our_bundle(info_xml: &str) -> bool {
    identity::plist_string(info_xml, "CFBundleExecutable").is_some_and(|e| by_exe(&e).is_some())
}

/// Per-app folders macOS / WebKit create under the bundle id; the old ones
/// are removed after switching so the old id does not linger in ~/Library.
pub fn bundle_id_traces(home: &Path, bundle_id: &str) -> Vec<PathBuf> {
    let lib = home.join("Library");
    vec![
        lib.join("WebKit").join(bundle_id),
        lib.join("Caches").join(bundle_id),
        lib.join("HTTPStorages").join(bundle_id),
        lib.join("HTTPStorages")
            .join(format!("{bundle_id}.binarycookies")),
        lib.join("Preferences").join(format!("{bundle_id}.plist")),
        lib.join("Saved Application State")
            .join(format!("{bundle_id}.savedState")),
    ]
}

/// Move a directory for the new store name. `Ok(false)`: nothing to move.
/// A non-empty target is refused (`disguise_data_exists`); an empty one is
/// replaced. Same volume, so this is one `rename`.
pub fn move_dir(from: &Path, to: &Path) -> Result<bool, &'static str> {
    if from == to || !from.is_dir() {
        return Ok(false);
    }
    if to.exists() {
        let empty = std::fs::read_dir(to)
            .map(|mut r| r.next().is_none())
            .unwrap_or(false);
        if !empty {
            return Err("disguise_data_exists");
        }
        std::fs::remove_dir(to).map_err(|_| "disguise_failed")?;
    }
    if let Some(p) = to.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    // Mark the move first: if the switch is interrupted, only the app it
    // was meant for may finish it at startup (see adopt_store).
    let target_name = to
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let _ = std::fs::write(from.join(SWITCH_MARKER), &target_name);
    if std::fs::rename(from, to).is_err() {
        let _ = std::fs::remove_file(from.join(SWITCH_MARKER));
        return Err("disguise_failed");
    }
    Ok(true)
}

/// Whether anything is mounted at or under `root` (`mount` output).
pub fn mounted_under(mount_output: &str, root: &Path) -> bool {
    let r = root.to_string_lossy();
    let r = r.trim_end_matches('/');
    mount_output.lines().any(|l| {
        l.split_once(" on ")
            .map(|(_, rest)| rest)
            .is_some_and(|rest| {
                rest.starts_with(&format!("{r}/")) || rest.starts_with(&format!("{r} ("))
            })
    })
}

pub fn mount_output() -> String {
    std::process::Command::new("/sbin/mount")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Marker written into the data directory right before a disguise switch
/// renames it; holds the store name the directory is moving to.
pub const SWITCH_MARKER: &str = ".switch-to";

/// Startup fallback for an interrupted switch: this bundle's data directory
/// is missing and exactly one other known store directory carries a switch
/// marker naming THIS store → finish the move. Without the marker nothing
/// is adopted: another copy of the app (e.g. one started from the DMG) must
/// never pull the vaults away from the installed one.
pub fn adopt_store(base: &Path, own: &str, is_mounted: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let target = base.join(own);
    if target.exists() {
        return None;
    }
    let found: Vec<PathBuf> = DISGUISES
        .iter()
        .map(|d| d.store)
        .filter(|s| *s != own)
        .map(|s| base.join(s))
        .filter(|p| {
            p.is_dir()
                && std::fs::read_to_string(p.join(SWITCH_MARKER))
                    .map(|m| m.trim() == own)
                    .unwrap_or(false)
        })
        .collect();
    let [only] = found.as_slice() else {
        return None;
    };
    if is_mounted(only) {
        return None;
    }
    std::fs::rename(only, &target).ok()?;
    let _ = std::fs::remove_file(target.join(SWITCH_MARKER));
    Some(only.clone())
}

/// Called first thing in `main` (before the log or the store are opened).
pub fn adopt_on_start() {
    if current_bundle().is_none() {
        return;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return;
    };
    let own = identity::store_name();
    if std::env::var_os(vault_core::store::HOME_ENV).is_none() {
        let mounts = mount_output();
        let base = identity::data_dir(&home, "");
        adopt_store(&base, &own, |p| mounted_under(&mounts, p));
        // The switch completed: drop its marker from our own directory.
        let _ = std::fs::remove_file(base.join(&own).join(SWITCH_MARKER));
    }
    adopt_store(&identity::log_dir(&home, ""), &own, |_| false);
    remove_legacy_traces(&home);
}

/// Folders and the socket left by versions that used [`LEGACY_BUNDLE_ID`].
fn remove_legacy_traces(home: &Path) {
    if current().bundle_id == LEGACY_BUNDLE_ID {
        return;
    }
    for p in bundle_id_traces(home, LEGACY_BUNDLE_ID) {
        if p.exists() {
            let _ = if p.is_dir() {
                std::fs::remove_dir_all(&p)
            } else {
                std::fs::remove_file(&p)
            };
        }
    }
    let sock = legacy_socket();
    // Only a stale one: a live old copy still answers on it.
    if sock.exists() && std::os::unix::net::UnixStream::connect(&sock).is_err() {
        let _ = std::fs::remove_file(&sock);
    }
}

fn legacy_socket() -> PathBuf {
    // Same rule as tauri-plugin-single-instance: identifier with '.'/'-' → '_'.
    std::env::temp_dir().join(format!(
        "{}_si.sock",
        LEGACY_BUNDLE_ID.replace(['.', '-'], "_")
    ))
}

/// Shell run detached after a switch: waits for this process to exit (so
/// the single-instance socket is free), removes the old bundle id's
/// folders (absolute paths built by [`bundle_id_traces`]) and opens the new
/// bundle. Arguments: pid, new bundle, then the paths to remove.
pub const RELAUNCH_SCRIPT: &str = r#"
PID="$1"; NEW="$2"; shift 2
i=0; while kill -0 "$PID" 2>/dev/null && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done
for d in "$@"; do case "$d" in "$HOME"/Library/*) /bin/rm -rf -- "$d" ;; esac; done
/usr/bin/open -n "$NEW"
"#;

// The switch only uses std, tauri and macOS command-line tools, so it is
// compiled (and clippy-checked) everywhere; it refuses to run off macOS.
pub use mac::apply;

mod mac {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use tauri::{AppHandle, Manager};
    use tauri_plugin_autostart::ManagerExt as _;
    use vault_core::identity;

    use super::*;
    use crate::state::{self, lock};
    use crate::{applog, lockctl};

    fn run(cmd: &str, args: &[&std::ffi::OsStr]) -> bool {
        Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    fn applications_writable() -> bool {
        let probe = Path::new("/Applications").join(format!(".bv-probe-{}", std::process::id()));
        let ok = std::fs::create_dir(&probe).is_ok();
        let _ = std::fs::remove_dir(&probe);
        ok
    }

    /// Copy + rewrite + re-sign the bundle at `dst`. On error the caller
    /// removes `dst`.
    fn build_copy(
        src: &Path,
        dst: &Path,
        icon_src: &Path,
        d: &Disguise,
    ) -> Result<(), &'static str> {
        const FAIL: &str = "disguise_failed";
        if !run("/usr/bin/ditto", &[src.as_os_str(), dst.as_os_str()]) {
            return Err(FAIL);
        }
        // Quarantine and other xattrs: codesign refuses "detritus".
        let _ = run("/usr/bin/xattr", &["-cr".as_ref(), dst.as_os_str()]);
        let macos = dst.join("Contents/MacOS");
        let exe_now = std::env::current_exe()
            .ok()
            .and_then(|e| e.file_name().map(|n| n.to_os_string()))
            .ok_or(FAIL)?;
        if exe_now != d.exe {
            std::fs::rename(macos.join(&exe_now), macos.join(d.exe)).map_err(|_| FAIL)?;
        }
        std::fs::copy(icon_src, dst.join("Contents/Resources").join(d.icon)).map_err(|_| FAIL)?;
        let plist = dst.join("Contents/Info.plist");
        for edit in plist_edits(d) {
            let mut args: Vec<&std::ffi::OsStr> = edit.iter().map(|s| s.as_ref()).collect();
            args.push(plist.as_os_str());
            let ok = run("/usr/bin/plutil", &args);
            // `-remove` of a key that is not there fails harmlessly.
            if !ok && edit[0] != "-remove" {
                return Err(FAIL);
            }
        }
        let xml = std::fs::read_to_string(&plist).map_err(|_| FAIL)?;
        if !plist_matches(&xml, d) {
            return Err(FAIL);
        }
        let _ = run("/usr/bin/xattr", &["-cr".as_ref(), dst.as_os_str()]);
        if !run(
            "/usr/bin/codesign",
            &[
                "--force".as_ref(),
                "--deep".as_ref(),
                "--sign".as_ref(),
                "-".as_ref(),
                dst.as_os_str(),
            ],
        ) || !run(
            "/usr/bin/codesign",
            &[
                "--verify".as_ref(),
                "--deep".as_ref(),
                "--strict".as_ref(),
                dst.as_os_str(),
            ],
        ) {
            return Err(FAIL);
        }
        Ok(())
    }

    /// The whole switch. Blocking; on success the process exits shortly
    /// after and the new bundle starts. Returns the new bundle's name.
    pub fn apply(app: &AppHandle, d: &'static Disguise) -> Result<String, &'static str> {
        if !cfg!(target_os = "macos") {
            return Err("disguise_unsupported");
        }
        let st = state::get(app);
        let cur = super::current();
        if cur.id == d.id {
            return Err("disguise_same");
        }
        let src = current_bundle().ok_or("disguise_unsupported")?;
        // Started from the DMG (read-only) or a Gatekeeper-translocated copy:
        // the switch could not remove that copy and the real one in
        // /Applications would stay. Ask the user to install first.
        if !is_installed_location(&src) {
            return Err("disguise_install_first");
        }
        if !lockctl::lockable_ids(&st).is_empty() || !lock(&st.drafts).is_empty() {
            return Err("disguise_unlocked");
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("disguise_failed")?;
        let custom_home = std::env::var_os(vault_core::store::HOME_ENV).is_some();
        // The names this process really uses (its Info.plist), in case they
        // ever differ from the table entry matched by the executable name.
        let cur_store = identity::store_name();
        let (data_from, data_to) = (
            identity::data_dir(&home, &cur_store),
            identity::data_dir(&home, d.store),
        );
        let root = st.store.root().to_path_buf();
        if super::mounted_under(&super::mount_output(), &root) {
            return Err("disguise_unlocked");
        }
        // Preflight: a non-empty data dir under the new name is never touched.
        if !custom_home
            && data_from.is_dir()
            && data_to.exists()
            && std::fs::read_dir(&data_to)
                .map(|mut r| r.next().is_some())
                .unwrap_or(true)
        {
            return Err("disguise_data_exists");
        }
        let dst = target_bundle(&src, applications_writable(), d);
        if dst == src {
            return Err("disguise_same");
        }
        if dst.exists() {
            let ours = std::fs::read_to_string(dst.join("Contents/Info.plist"))
                .map(|x| is_our_bundle(&x))
                .unwrap_or(false);
            if !ours {
                return Err("disguise_target_exists");
            }
            std::fs::remove_dir_all(&dst).map_err(|_| "disguise_failed")?;
        }
        let icon_src = app
            .path()
            .resource_dir()
            .map_err(|_| "disguise_failed")?
            .join("disguises")
            .join(d.icon);
        applog::log(&format!("disguise: building {} ({})", d.id, dst.display()));
        if let Err(e) = build_copy(&src, &dst, &icon_src, d) {
            let _ = std::fs::remove_dir_all(&dst);
            applog::log("disguise: building the copy failed");
            return Err(e);
        }

        // From here on the old process must not touch the store or the log.
        let before = st.settings();
        let mut after = before.clone();
        after.disguise = d.id.into();
        let rollback = |e: &'static str| {
            let _ = before.save(&root);
            *lock(&st.settings) = before.clone();
            let _ = std::fs::remove_dir_all(&dst);
            Err(e)
        };
        if after.save(&root).is_err() {
            return rollback("disguise_failed");
        }
        *lock(&st.settings) = after.clone();
        if !custom_home {
            if let Err(e) = move_dir(&data_from, &data_to) {
                return rollback(e);
            }
        }
        applog::log("disguise: data moved; switching");
        applog::suspend();
        let (log_from, log_to) = (
            identity::log_dir(&home, &cur_store),
            identity::log_dir(&home, d.store),
        );
        if log_from.is_dir() {
            let _ = std::fs::remove_dir_all(&log_to);
            let _ = std::fs::rename(&log_from, &log_to);
        }
        // The new instance re-registers it under its own name and path.
        if after.launch_at_login {
            let _ = app.autolaunch().disable();
        }
        st.relaunching
            .store(true, std::sync::atomic::Ordering::SeqCst);
        st.quitting.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&src);
        // Any other copy of this app (original name or an older disguise) in
        // the Applications folders would give the app away: remove the ones
        // that are verifiably ours (by their executable name), never others.
        for dir in [PathBuf::from("/Applications"), home.join("Applications")] {
            for other in &DISGUISES {
                let p = dir.join(format!("{}.app", other.name));
                if p == dst || !p.exists() {
                    continue;
                }
                let ours = std::fs::read_to_string(p.join("Contents/Info.plist"))
                    .map(|x| is_our_bundle(&x))
                    .unwrap_or(false);
                if ours {
                    let _ = std::fs::remove_dir_all(&p);
                    applog::log("disguise: removed an older copy");
                }
            }
        }

        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(RELAUNCH_SCRIPT)
            .arg("relaunch")
            .arg(std::process::id().to_string())
            .arg(&dst);
        for p in bundle_id_traces(&home, cur.bundle_id) {
            cmd.arg(p);
        }
        use std::os::unix::process::CommandExt;
        let _ = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(400));
            app.exit(0);
        });
        Ok(d.name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_location() {
        assert!(is_installed_location(Path::new(
            "/Applications/Browser Vault.app"
        )));
        assert!(is_installed_location(Path::new(
            "/Users/a/Applications/X.app"
        )));
        assert!(!is_installed_location(Path::new(
            "/Volumes/Browser Vault/Browser Vault.app"
        )));
        assert!(!is_installed_location(Path::new(
            "/private/var/folders/x/AppTranslocation/ABC/d/Browser Vault.app"
        )));
    }

    #[test]
    fn table_is_consistent() {
        assert_eq!(DISGUISES[0], NONE);
        for (i, d) in DISGUISES.iter().enumerate() {
            assert!(identity::valid_store_name(d.store), "{}", d.id);
            assert!(d.icon.ends_with(".icns"));
            assert!(d.exe.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
            assert!(d
                .bundle_id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '.'));
            assert!(!d.name.contains('/'));
            assert_eq!(by_id(d.id), Some(d));
            assert_eq!(by_exe(d.exe), Some(d));
            for o in &DISGUISES[i + 1..] {
                assert_ne!(d.id, o.id);
                assert_ne!(d.name, o.name);
                assert_ne!(d.exe, o.exe);
                assert_ne!(d.bundle_id, o.bundle_id);
                assert_ne!(d.store, o.store);
                assert_ne!(d.icon, o.icon);
            }
        }
        // Disguises never mention the real name.
        for d in &DISGUISES[1..] {
            for s in [d.name, d.exe, d.bundle_id, d.store, d.icon] {
                let l = s.to_lowercase();
                assert!(
                    !l.contains("vault") && !l.contains("browser") && !l.contains("bv"),
                    "{s}"
                );
            }
        }
        assert!(by_id("nope").is_none());
    }

    #[test]
    fn bundle_location() {
        let cur = Path::new("/Users/a/Downloads/Browser Vault.app");
        let d = by_id("fontcache").unwrap();
        assert_eq!(
            target_bundle(cur, true, d),
            Path::new("/Applications/Font Cache Helper.app")
        );
        assert_eq!(
            target_bundle(cur, false, d),
            Path::new("/Users/a/Downloads/Font Cache Helper.app")
        );
        assert_eq!(
            target_bundle(Path::new("/Applications/Archive Index.app"), true, &NONE),
            Path::new("/Applications/Browser Vault.app")
        );
    }

    fn apply_edits(xml: &str, d: &Disguise) -> String {
        // Tiny model of `plutil -replace/-remove` on a flat XML dict.
        let mut pairs: Vec<(String, String)> = vec![];
        let mut rest = xml;
        while let Some(i) = rest.find("<key>") {
            let k_end = rest[i..].find("</key>").unwrap() + i;
            let key = rest[i + 5..k_end].to_string();
            if let Some(v) = identity::plist_string(&rest[i..], &key) {
                pairs.push((key, v));
            }
            rest = &rest[k_end..];
        }
        for e in plist_edits(d) {
            match e[0].as_str() {
                "-replace" => {
                    pairs.retain(|(k, _)| *k != e[1]);
                    pairs.push((e[1].clone(), e[3].clone()));
                }
                "-remove" => pairs.retain(|(k, _)| *k != e[1]),
                "-convert" => assert_eq!(e[1], "xml1"),
                other => panic!("{other}"),
            }
        }
        pairs
            .iter()
            .map(|(k, v)| format!("<key>{k}</key><string>{v}</string>"))
            .collect()
    }

    #[test]
    fn plist_round_trip() {
        let orig = "<dict><key>CFBundleName</key><string>Browser Vault</string>\
            <key>CFBundleExecutable</key><string>browser-vault</string>\
            <key>CFBundleIdentifier</key><string>local.statusbar.helper</string></dict>";
        assert!(plist_matches(orig, &NONE));
        assert!(is_our_bundle(orig));
        let fc = by_id("fontcache").unwrap();
        let disguised = apply_edits(orig, fc);
        assert!(plist_matches(&disguised, fc));
        assert!(!plist_matches(&disguised, &NONE));
        assert_eq!(identity::store_name_from(&disguised), "com.fontcache.store");
        assert!(is_our_bundle(&disguised));
        let back = apply_edits(&disguised, &NONE);
        assert!(plist_matches(&back, &NONE));
        assert!(!back.contains(identity::STORE_NAME_KEY));
        assert!(!is_our_bundle(
            "<key>CFBundleExecutable</key><string>Other</string>"
        ));
    }

    #[test]
    fn traces_stay_in_library() {
        let t = bundle_id_traces(Path::new("/Users/a"), NONE.bundle_id);
        assert!(t.iter().all(|p| p.starts_with("/Users/a/Library/")));
        assert!(t.contains(&PathBuf::from(
            "/Users/a/Library/WebKit/local.statusbar.helper"
        )));
    }

    #[test]
    fn base_bundle_id_matches_tauri_conf() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(conf["identifier"], BASE_BUNDLE_ID);
        for s in [BASE_BUNDLE_ID, NONE.bundle_id] {
            assert!(!s.contains("vault"), "{s}");
        }
        assert!(legacy_socket()
            .to_string_lossy()
            .ends_with("com_browservault_app_si.sock"));
    }

    #[test]
    fn mounts() {
        let out = "/dev/disk1s1 on / (apfs, local)\n\
            /dev/disk5s1 on /Users/a/Library/Application Support/BrowserVault/mnt/x (apfs, local, nodev)\n";
        let root = Path::new("/Users/a/Library/Application Support/BrowserVault");
        assert!(mounted_under(out, root));
        assert!(!mounted_under(
            out,
            Path::new("/Users/a/Library/Application Support/BrowserVaultX")
        ));
        assert!(!mounted_under("", root));
        assert!(mounted_under(
            "/dev/x on /Volumes/BV (apfs)",
            Path::new("/Volumes/BV")
        ));
    }

    #[test]
    fn moving_dirs() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("BrowserVault");
        let b = d.path().join("com.fontcache.store");
        assert_eq!(move_dir(&a, &b), Ok(false)); // nothing there yet
        std::fs::create_dir_all(a.join("vaults/x")).unwrap();
        std::fs::create_dir(&b).unwrap(); // empty target is replaced
        assert_eq!(move_dir(&a, &b), Ok(true));
        assert!(b.join("vaults/x").is_dir() && !a.exists());
        std::fs::create_dir_all(a.join("vaults/y")).unwrap();
        assert_eq!(move_dir(&a, &b), Err("disguise_data_exists"));
        assert!(a.join("vaults/y").is_dir() && b.join("vaults/x").is_dir());
        assert_eq!(move_dir(&b, &b), Ok(false));
    }

    #[test]
    fn adopting_an_orphaned_store() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path();
        let mark =
            |dir: &str, to: &str| std::fs::write(base.join(dir).join(SWITCH_MARKER), to).unwrap();
        // Nothing to adopt.
        assert_eq!(adopt_store(base, "com.fontcache.store", |_| false), None);
        std::fs::create_dir_all(base.join("BrowserVault/vaults")).unwrap();
        // Unmarked (e.g. another copy of the app is simply installed): never taken.
        assert_eq!(adopt_store(base, "com.fontcache.store", |_| false), None);
        // Marked for a different store: not ours to take.
        mark("BrowserVault", "com.archiveindex.data");
        assert_eq!(adopt_store(base, "com.fontcache.store", |_| false), None);
        // Marked for us, but mounted → left alone.
        mark("BrowserVault", "com.fontcache.store");
        assert_eq!(adopt_store(base, "com.fontcache.store", |_| true), None);
        assert_eq!(
            adopt_store(base, "com.fontcache.store", |_| false),
            Some(base.join("BrowserVault"))
        );
        assert!(base.join("com.fontcache.store/vaults").is_dir());
        assert!(!base
            .join("com.fontcache.store")
            .join(SWITCH_MARKER)
            .exists());
        // Own dir exists → nothing happens.
        std::fs::create_dir_all(base.join("com.archiveindex.data")).unwrap();
        mark("com.archiveindex.data", "com.fontcache.store");
        assert_eq!(adopt_store(base, "com.fontcache.store", |_| false), None);
        // The DMG-copy case: own dir missing, the installed app's dir is
        // unmarked → the DMG copy must not pull it away.
        std::fs::remove_file(base.join("com.archiveindex.data").join(SWITCH_MARKER)).unwrap();
        assert_eq!(adopt_store(base, "BrowserVault", |_| false), None);
        assert!(base.join("com.archiveindex.data").is_dir());
        assert!(base.join("com.fontcache.store").is_dir());
    }

    #[test]
    fn move_dir_marks_and_cleans_up() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (
            d.path().join("BrowserVault"),
            d.path().join("com.fontcache.store"),
        );
        std::fs::create_dir_all(a.join("vaults")).unwrap();
        assert_eq!(move_dir(&a, &b), Ok(true));
        assert_eq!(
            std::fs::read_to_string(b.join(SWITCH_MARKER)).unwrap(),
            "com.fontcache.store"
        );
    }
}
