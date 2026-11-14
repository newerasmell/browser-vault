//! Browser discovery, launch and shutdown (SPEC §5, §6).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Browser {
    Brave,
    Firefox,
    /// Telegram Desktop (telegram.org, `com.tdesktop.Telegram`), not the
    /// App Store "Telegram" app, which cannot be told where to keep data.
    Telegram,
}

impl Browser {
    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Brave => "brave",
            Browser::Firefox => "firefox",
            Browser::Telegram => "telegram",
        }
    }

    pub fn parse(s: &str) -> Option<Browser> {
        match s.to_ascii_lowercase().as_str() {
            "brave" => Some(Browser::Brave),
            "firefox" => Some(Browser::Firefox),
            "telegram" => Some(Browser::Telegram),
            _ => None,
        }
    }

    /// `.app` bundle name and the binary inside `Contents/MacOS/`.
    fn bundle(self) -> (&'static str, &'static str) {
        match self {
            Browser::Brave => ("Brave Browser.app", "Brave Browser"),
            Browser::Firefox => ("Firefox.app", "firefox"),
            Browser::Telegram => ("Telegram.app", "Telegram"),
        }
    }

    pub fn download_url(self) -> &'static str {
        match self {
            Browser::Brave => "https://brave.com/download/",
            Browser::Firefox => "https://www.mozilla.org/firefox/new/",
            Browser::Telegram => "https://desktop.telegram.org/",
        }
    }
}

/// Binary path inside an `.app` bundle.
pub fn binary_in_app(browser: Browser, app: &Path) -> PathBuf {
    app.join("Contents/MacOS").join(browser.bundle().1)
}

/// Bundle id an app must have to be used for `browser`, when the bundle
/// name alone is ambiguous: the App Store "Telegram" is also
/// `Telegram.app` (same executable name) but keeps its data in a
/// sandbox container that cannot be moved into a vault.
pub fn required_bundle_id(browser: Browser) -> Option<&'static str> {
    match browser {
        Browser::Telegram => Some("com.tdesktop.Telegram"),
        Browser::Brave | Browser::Firefox => None,
    }
}

/// `CFBundleIdentifier` of an `.app` (via `plutil`, which reads binary and
/// XML plists alike).
fn bundle_id_of(app: &Path) -> Option<String> {
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleIdentifier", "raw", "-o", "-"])
        .arg(app.join("Contents/Info.plist"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Whether `app` is an installation this vault type can run.
pub fn app_is_usable(browser: Browser, app: &Path) -> bool {
    binary_in_app(browser, app).is_file()
        && required_bundle_id(browser).is_none_or(|want| bundle_id_of(app).as_deref() == Some(want))
}

/// Auto-detect in `/Applications`, then `~/Applications` (SPEC §5).
pub fn detect(browser: Browser) -> Option<PathBuf> {
    let (app, _) = browser.bundle();
    let mut roots = vec![PathBuf::from("/Applications")];
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(PathBuf::from(home).join("Applications"));
    }
    roots
        .into_iter()
        .map(|r| r.join(app))
        .find(|a| app_is_usable(browser, a))
        .map(|a| binary_in_app(browser, &a))
}

pub fn profile_dir(mnt: &Path) -> PathBuf {
    mnt.join("profile")
}

pub fn cache_dir(mnt: &Path) -> PathBuf {
    mnt.join("cache")
}

/// Command-line arguments for a vault instance (SPEC §5).
pub fn launch_args(browser: Browser, mnt: &Path) -> Result<Vec<OsString>> {
    match browser {
        Browser::Brave => {
            let mut user_data = OsString::from("--user-data-dir=");
            user_data.push(profile_dir(mnt));
            let mut disk_cache = OsString::from("--disk-cache-dir=");
            disk_cache.push(cache_dir(mnt));
            Ok(vec![
                user_data,
                disk_cache,
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                // A crash dump holds browser memory (cookies, page content):
                // keep Crashpad from writing dumps under ~/Library.
                "--disable-crash-reporter".into(),
                "--disable-breakpad".into(),
            ])
        }
        // Cache location etc. come from the managed block in `user.js`
        // (see [`write_firefox_user_js`]).
        Browser::Firefox => {
            let mut profile = OsString::new();
            profile.push(profile_dir(mnt));
            Ok(vec!["--new-instance".into(), "-profile".into(), profile])
        }
        // All of Telegram Desktop's data (tdata: session, cache, media,
        // logs, crash dumps) lives under its working directory. Its
        // single-instance lock is per working directory, so a regular
        // Telegram can run next to it.
        Browser::Telegram => {
            let mut dir = OsString::new();
            dir.push(profile_dir(mnt));
            Ok(vec!["-workdir".into(), dir])
        }
    }
}

/// Environment for a vault instance (paths/flags only, never secrets).
/// Firefox: no crash reporter, so no minidumps under
/// `~/Library/Application Support/Firefox/Crash Reports`.
pub fn launch_env(browser: Browser) -> Vec<(&'static str, &'static str)> {
    match browser {
        Browser::Brave | Browser::Telegram => vec![],
        Browser::Firefox => vec![("MOZ_CRASHREPORTER_DISABLE", "1")],
    }
}

const USER_JS_BEGIN: &str = "// BEGIN Browser Vault (managed, rewritten on every unlock)";
const USER_JS_END: &str = "// END Browser Vault";
const FXA_OFF: &str = "user_pref(\"identity.fxaccounts.enabled\", false);";

fn js_string(p: &Path) -> String {
    let s = p.to_string_lossy();
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Split `user.js` into (text outside our managed block, the block if any).
fn split_user_js(text: &str) -> (String, Option<String>) {
    match (text.find(USER_JS_BEGIN), text.find(USER_JS_END)) {
        (Some(b), Some(e)) if e > b => {
            let end = e + USER_JS_END.len();
            let mut outside = String::from(&text[..b]);
            outside.push_str(text[end..].trim_start_matches(['\r', '\n']));
            (outside, Some(text[b..end].to_string()))
        }
        _ => (text.to_string(), None),
    }
}

/// SPEC §5: write the vault's prefs into `<mnt>/profile/user.js`.
///
/// Called at creation and again on every unlock: the mountpoint is stable
/// (`mnt/<id>`), but rewriting keeps the cache path right even if the store
/// moved (other home, restored backup) and repairs a user.js the user edited.
/// Only a marked block is managed; anything else in user.js (e.g. from an
/// imported profile) is kept. `disable_fxa`: `None` keeps the current choice.
pub fn write_firefox_user_js(mnt: &Path, disable_fxa: Option<bool>) -> Result<()> {
    let path = profile_dir(mnt).join("user.js");
    let current = match std::fs::read(&path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let (outside, block) = split_user_js(&current);
    let fxa_off = disable_fxa.unwrap_or_else(|| block.is_some_and(|b| b.contains(FXA_OFF)));
    let mut out = outside.trim_end().to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(USER_JS_BEGIN);
    out.push('\n');
    out.push_str(&format!(
        "user_pref(\"browser.cache.disk.parent_directory\", {});\n",
        js_string(&cache_dir(mnt))
    ));
    out.push_str("user_pref(\"browser.shell.checkDefaultBrowser\", false);\n");
    out.push_str("user_pref(\"browser.sessionstore.resume_from_crash\", true);\n");
    // Locking quits Firefox cleanly, so it must restore the previous
    // session itself (Brave behaves this way by default).
    out.push_str("user_pref(\"browser.startup.page\", 3);\n");
    // The vault quits Firefox with a normal "quit" when it locks; a
    // "close N tabs?" prompt would block that and force a hard stop.
    out.push_str("user_pref(\"browser.warnOnQuit\", false);\n");
    out.push_str("user_pref(\"browser.warnOnQuitShortcut\", false);\n");
    out.push_str("user_pref(\"browser.tabs.warnOnClose\", false);\n");
    if fxa_off {
        out.push_str(FXA_OFF);
        out.push('\n');
    }
    out.push_str(USER_JS_END);
    out.push('\n');
    if out == current {
        return Ok(());
    }
    let tmp = path.with_extension("js.bvtmp");
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(out.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Start the browser binary directly (not `open -a`) so we own the PID and get
/// a separate instance even when the regular browser is running.
pub fn launch(browser: Browser, binary: &Path, mnt: &Path) -> Result<Child> {
    launch_with(browser, binary, mnt, false)
}

/// Like [`launch`]; `portable_keys` makes Brave use a Mac-independent key
/// for cookies and saved passwords (`--use-mock-keychain`, see portable.rs).
pub fn launch_with(
    browser: Browser,
    binary: &Path,
    mnt: &Path,
    portable_keys: bool,
) -> Result<Child> {
    if !binary.is_file() {
        return Err(Error::BrowserMissing);
    }
    let mut args = launch_args(browser, mnt)?;
    if portable_keys && browser == Browser::Brave {
        args.push(crate::portable::MOCK_KEYCHAIN_FLAG.into());
    }
    Command::new(binary)
        .args(args)
        .envs(launch_env(browser))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Error::Io)
}

pub fn is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill(2) with signal 0 only checks for existence/permission.
    let r = unsafe { libc::kill(pid, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn signal(pid: i32, sig: libc::c_int) {
    if pid > 0 {
        // SAFETY: plain kill(2) on a positive PID we launched.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// SPEC §6 step 1: SIGTERM, wait up to `grace` (8 s in production), then SIGKILL.
/// Returns `true` if the process had to be killed.
pub fn terminate(pid: i32, grace: Duration) -> bool {
    if !is_alive(pid) {
        return false;
    }
    signal(pid, libc::SIGTERM);
    let start = Instant::now();
    while start.elapsed() < grace {
        if !is_alive(pid) {
            return false;
        }
        sleep(Duration::from_millis(100));
    }
    signal(pid, libc::SIGKILL);
    let start = Instant::now();
    while is_alive(pid) && start.elapsed() < Duration::from_secs(2) {
        sleep(Duration::from_millis(50));
    }
    true
}

pub const TERMINATE_GRACE: Duration = Duration::from_secs(8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brave_args_point_inside_mount() {
        let mnt = Path::new("/mnt/x");
        let args = launch_args(Browser::Brave, mnt).unwrap();
        let s: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            s,
            [
                "--user-data-dir=/mnt/x/profile",
                "--disk-cache-dir=/mnt/x/cache",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-crash-reporter",
                "--disable-breakpad"
            ]
        );
    }

    #[test]
    fn firefox_args_point_inside_mount() {
        let args = launch_args(Browser::Firefox, Path::new("/mnt/x")).unwrap();
        assert_eq!(args, ["--new-instance", "-profile", "/mnt/x/profile"]);
        assert_eq!(
            launch_env(Browser::Firefox),
            [("MOZ_CRASHREPORTER_DISABLE", "1")]
        );
    }

    #[test]
    fn telegram_args_point_inside_mount() {
        let args = launch_args(Browser::Telegram, Path::new("/mnt/x")).unwrap();
        assert_eq!(args, ["-workdir", "/mnt/x/profile"]);
        assert!(launch_env(Browser::Telegram).is_empty());
        assert_eq!(
            binary_in_app(Browser::Telegram, Path::new("/Applications/Telegram.app")),
            Path::new("/Applications/Telegram.app/Contents/MacOS/Telegram")
        );
    }

    #[test]
    fn user_js_written_and_rewritten() {
        let d = tempfile::tempdir().unwrap();
        let mnt = d.path().join("m \"q\"");
        std::fs::create_dir_all(profile_dir(&mnt)).unwrap();
        let uj = profile_dir(&mnt).join("user.js");
        // Imported profile's own prefs stay.
        std::fs::write(&uj, "user_pref(\"mine\", 1);\n").unwrap();
        write_firefox_user_js(&mnt, Some(true)).unwrap();
        let t = std::fs::read_to_string(&uj).unwrap();
        assert!(t.starts_with("user_pref(\"mine\", 1);\n"));
        let want_cache = format!(
            "user_pref(\"browser.cache.disk.parent_directory\", \"{}/m \\\"q\\\"/cache\");",
            d.path().display()
        );
        assert!(t.contains(&want_cache), "{t}");
        assert!(t.contains("\"browser.shell.checkDefaultBrowser\", false"));
        assert!(t.contains("\"browser.sessionstore.resume_from_crash\", true"));
        assert!(t.contains("\"browser.startup.page\", 3"));
        assert!(t.contains(FXA_OFF));

        // Unlock path: same choice kept, block not duplicated, idempotent.
        write_firefox_user_js(&mnt, None).unwrap();
        let t2 = std::fs::read_to_string(&uj).unwrap();
        assert_eq!(t, t2);
        assert_eq!(t2.matches(USER_JS_BEGIN).count(), 1);

        write_firefox_user_js(&mnt, Some(false)).unwrap();
        let t3 = std::fs::read_to_string(&uj).unwrap();
        assert!(!t3.contains(FXA_OFF));
        write_firefox_user_js(&mnt, None).unwrap();
        assert!(!std::fs::read_to_string(&uj).unwrap().contains(FXA_OFF));
        assert!(!profile_dir(&mnt).join("user.js.bvtmp").exists());
    }

    #[test]
    fn binary_paths() {
        assert_eq!(
            binary_in_app(Browser::Brave, Path::new("/Applications/Brave Browser.app")),
            Path::new("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser")
        );
        assert_eq!(
            binary_in_app(Browser::Firefox, Path::new("/Applications/Firefox.app")),
            Path::new("/Applications/Firefox.app/Contents/MacOS/firefox")
        );
    }

    #[test]
    fn parse_roundtrip() {
        for b in [Browser::Brave, Browser::Firefox, Browser::Telegram] {
            assert_eq!(Browser::parse(b.as_str()), Some(b));
        }
        assert_eq!(Browser::parse("Chrome"), None);
    }

    #[test]
    fn missing_binary_is_browser_missing() {
        assert!(matches!(
            launch(
                Browser::Brave,
                Path::new("/nonexistent/brave"),
                Path::new("/m")
            ),
            Err(Error::BrowserMissing)
        ));
    }

    #[test]
    fn terminate_graceful_and_forced() {
        // Graceful: `sleep` dies on SIGTERM.
        let mut c = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = c.id() as i32;
        let reaper = std::thread::spawn(move || c.wait());
        assert!(!terminate(pid, Duration::from_secs(5)));
        reaper.join().unwrap().unwrap();
        assert!(!is_alive(pid));

        // Forced: a shell that ignores SIGTERM.
        let mut c = Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 30 & wait"])
            .spawn()
            .unwrap();
        let pid = c.id() as i32;
        sleep(Duration::from_millis(200));
        let reaper = std::thread::spawn(move || c.wait());
        assert!(terminate(pid, Duration::from_millis(300)));
        reaper.join().unwrap().unwrap();
        assert!(!is_alive(pid));
    }
}
