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
    /// WhatsApp Web in its own app-style window (Brave `--app=`): the Mac
    /// WhatsApp app keeps its data in a sandbox container that cannot be
    /// moved into a vault.
    WhatsApp,
    /// Slack desktop (slack.com, `com.tinyspeck.slackmacgap`, Electron).
    Slack,
    /// A Parallels Desktop virtual machine (see `vm.rs`).
    Vm,
}

impl Browser {
    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Brave => "brave",
            Browser::Firefox => "firefox",
            Browser::Telegram => "telegram",
            Browser::WhatsApp => "whatsapp",
            Browser::Slack => "slack",
            Browser::Vm => "vm",
        }
    }

    /// The installed app that runs this vault kind (WhatsApp runs in Brave).
    pub fn engine(self) -> Browser {
        match self {
            Browser::WhatsApp => Browser::Brave,
            b => b,
        }
    }

    /// Chromium-based: `--user-data-dir`, and the mock keychain for
    /// Mac-independent cookie/password keys.
    pub fn is_chromium(self) -> bool {
        matches!(self.engine(), Browser::Brave | Browser::Slack)
    }

    pub fn parse(s: &str) -> Option<Browser> {
        match s.to_ascii_lowercase().as_str() {
            "brave" => Some(Browser::Brave),
            "firefox" => Some(Browser::Firefox),
            "telegram" => Some(Browser::Telegram),
            "whatsapp" => Some(Browser::WhatsApp),
            "slack" => Some(Browser::Slack),
            "vm" => Some(Browser::Vm),
            _ => None,
        }
    }

    /// `.app` bundle name and the binary inside `Contents/MacOS/`.
    fn bundle(self) -> (&'static str, &'static str) {
        match self {
            Browser::Brave | Browser::WhatsApp => ("Brave Browser.app", "Brave Browser"),
            Browser::Firefox => ("Firefox.app", "firefox"),
            Browser::Telegram => ("Telegram.app", "Telegram"),
            Browser::Slack => ("Slack.app", "Slack"),
            Browser::Vm => ("Parallels Desktop.app", "prl_client_app"),
        }
    }

    pub fn download_url(self) -> &'static str {
        match self {
            Browser::Brave | Browser::WhatsApp => "https://brave.com/download/",
            Browser::Firefox => "https://www.mozilla.org/firefox/new/",
            Browser::Telegram => "https://desktop.telegram.org/",
            Browser::Slack => "https://slack.com/downloads/mac",
            Browser::Vm => "https://www.parallels.com/products/desktop/",
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
        // The App Store Slack is sandboxed as well.
        Browser::Slack => Some("com.tinyspeck.slackmacgap"),
        Browser::Vm => Some("com.parallels.desktop.console"),
        Browser::Brave | Browser::Firefox | Browser::WhatsApp => None,
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

/// Where a vault keeps its own copy of the app (`<mnt>/app/<Name>.app`),
/// so the app is not in /Applications while the vault is locked.
pub fn vault_app(browser: Browser, mnt: &Path) -> PathBuf {
    mnt.join("app").join(browser.bundle().0)
}

/// The vault's own copy, if it has a usable one.
pub fn vault_binary(browser: Browser, mnt: &Path) -> Option<PathBuf> {
    let app = vault_app(browser, mnt);
    app_is_usable(browser, &app).then(|| binary_in_app(browser, &app))
}

/// Copy `src_app` into the mounted vault as its own copy (replacing an
/// older one). `ditto` keeps the code signature, extended attributes and
/// symlinks intact; the copy goes to a temporary name first, so a failed
/// copy never leaves a half app where [`vault_binary`] would find it.
pub fn copy_app_into(browser: Browser, src_app: &Path, mnt: &Path) -> Result<PathBuf> {
    if !app_is_usable(browser, src_app) {
        return Err(Error::BrowserMissing);
    }
    let dst = vault_app(browser, mnt);
    let dir = dst.parent().ok_or(Error::Invalid("bad app path"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".copy-{}.app", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let tool = if cfg!(target_os = "macos") {
        ("/usr/bin/ditto", vec![])
    } else {
        ("cp", vec!["-a"])
    };
    let ok = Command::new(tool.0)
        .args(tool.1)
        .arg(src_app)
        .arg(&tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !ok || !app_is_usable(browser, &tmp) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(Error::Command {
            tool: "ditto",
            detail: "copying the app failed".into(),
        });
    }
    if dst.exists() {
        std::fs::remove_dir_all(&dst)?;
    }
    std::fs::rename(&tmp, &dst)?;
    Ok(dst)
}

pub fn profile_dir(mnt: &Path) -> PathBuf {
    mnt.join("profile")
}

pub fn cache_dir(mnt: &Path) -> PathBuf {
    mnt.join("cache")
}

/// Command-line arguments for a vault instance (SPEC §5).
pub fn launch_args(browser: Browser, mnt: &Path) -> Result<Vec<OsString>> {
    let user_data = || {
        let mut a = OsString::from("--user-data-dir=");
        a.push(profile_dir(mnt));
        a
    };
    match browser {
        Browser::Brave | Browser::WhatsApp => {
            let mut disk_cache = OsString::from("--disk-cache-dir=");
            disk_cache.push(cache_dir(mnt));
            let mut args = vec![
                user_data(),
                disk_cache,
                "--no-first-run".into(),
                "--no-default-browser-check".into(),
                // A crash dump holds browser memory (cookies, page content):
                // keep Crashpad from writing dumps under ~/Library.
                "--disable-crash-reporter".into(),
                "--disable-breakpad".into(),
            ];
            if browser == Browser::WhatsApp {
                args.push(format!("--app={WHATSAPP_URL}").into());
            }
            Ok(args)
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
        // Electron: user data (session, cache, logs, Crashpad) follows
        // Chromium's --user-data-dir.
        Browser::Slack => Ok(vec![user_data()]),
        // Started through prlctl, not with arguments (see `vm.rs`).
        Browser::Vm => Ok(vec![]),
    }
}

/// The page a WhatsApp vault opens as its app window.
pub const WHATSAPP_URL: &str = "https://web.whatsapp.com/";

/// Environment for a vault instance (paths/flags only, never secrets).
/// Firefox: no crash reporter, so no minidumps under
/// `~/Library/Application Support/Firefox/Crash Reports`.
pub fn launch_env(browser: Browser) -> Vec<(&'static str, &'static str)> {
    match browser {
        Browser::Brave | Browser::Telegram | Browser::WhatsApp | Browser::Slack | Browser::Vm => {
            vec![]
        }
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

/// What a platform launcher needs to start a vault app.
pub struct LaunchSpec<'a> {
    pub binary: &'a Path,
    /// The `.app` that contains `binary`.
    pub app_bundle: Option<PathBuf>,
    pub args: Vec<OsString>,
    pub env: Vec<(&'static str, &'static str)>,
}

/// Starts an app as its own process (not a child of this one) and returns
/// its PID. Set by the app on macOS ([`set_launcher`]): an app spawned as
/// our child is "ours" to macOS privacy checks, so its microphone/camera
/// requests and self-updates were attributed to (and blocked for) this app.
pub type Launcher = fn(&LaunchSpec<'_>) -> std::result::Result<u32, String>;

static LAUNCHER: std::sync::OnceLock<Launcher> = std::sync::OnceLock::new();

pub fn set_launcher(f: Launcher) {
    let _ = LAUNCHER.set(f);
}

/// A started vault app.
pub enum Launched {
    /// Spawned as our child (no launcher, tests, other platforms).
    Child(Child),
    /// Started through the platform launcher.
    Pid(u32),
    /// A Parallels VM: no process of ours to watch; its state comes from
    /// `prlctl status`.
    Vm { prlctl: PathBuf, uuid: String },
}

impl Launched {
    pub fn id(&self) -> u32 {
        match self {
            Launched::Child(c) => c.id(),
            Launched::Pid(p) => *p,
            Launched::Vm { .. } => 0,
        }
    }

    /// `(prlctl, uuid)` for a VM vault.
    pub fn vm(&self) -> Option<(PathBuf, String)> {
        match self {
            Launched::Vm { prlctl, uuid } => Some((prlctl.clone(), uuid.clone())),
            _ => None,
        }
    }

    /// Block until the process exits.
    pub fn wait(self) {
        match self {
            Launched::Child(mut c) => {
                let _ = c.wait();
            }
            Launched::Pid(p) => {
                while is_alive(p as i32) {
                    sleep(Duration::from_millis(500));
                }
            }
            // Down (suspended or shut down) on two checks in a row.
            Launched::Vm { prlctl, uuid } => {
                let mut down = 0;
                while down < 2 {
                    sleep(Duration::from_secs(3));
                    match crate::vm::status(&prlctl, &uuid) {
                        Some(s) if crate::vm::is_active(&s) => down = 0,
                        _ => down += 1,
                    }
                }
            }
        }
    }
}

/// Start the vault app with our arguments as a separate instance (even when
/// the regular app is running) and get its PID.
pub fn launch(browser: Browser, binary: &Path, mnt: &Path) -> Result<Launched> {
    launch_with(browser, binary, mnt, false)
}

/// Like [`launch`]; `portable_keys` makes Chromium apps use a
/// Mac-independent key for cookies and saved passwords
/// (`--use-mock-keychain`, see portable.rs).
pub fn launch_with(
    browser: Browser,
    binary: &Path,
    mnt: &Path,
    portable_keys: bool,
) -> Result<Launched> {
    if !binary.is_file() {
        return Err(Error::BrowserMissing);
    }
    let mut args = launch_args(browser, mnt)?;
    if portable_keys && browser.is_chromium() {
        args.push(crate::portable::MOCK_KEYCHAIN_FLAG.into());
    }
    let env = launch_env(browser);
    let app_bundle = binary
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf);
    if let (Some(launcher), Some(_)) = (LAUNCHER.get(), &app_bundle) {
        let spec = LaunchSpec {
            binary,
            app_bundle: app_bundle.clone(),
            args: args.clone(),
            env: env.clone(),
        };
        match launcher(&spec) {
            Ok(pid) => return Ok(Launched::Pid(pid)),
            // Still usable as our child; only privacy prompts suffer.
            Err(e) => crate::trace::emit(&format!("launcher failed, spawning directly: {e}")),
        }
    }
    Command::new(binary)
        .args(args)
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(Launched::Child)
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
    fn app_copied_into_vault_is_preferred() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("Applications/Brave Browser.app");
        let bin = binary_in_app(Browser::Brave, &src);
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"exe").unwrap();
        let mnt = d.path().join("mnt");
        assert_eq!(vault_binary(Browser::Brave, &mnt), None);
        let dst = copy_app_into(Browser::Brave, &src, &mnt).unwrap();
        assert_eq!(dst, mnt.join("app/Brave Browser.app"));
        assert_eq!(
            vault_binary(Browser::Brave, &mnt).unwrap(),
            mnt.join("app/Brave Browser.app/Contents/MacOS/Brave Browser")
        );
        // Replacing an older copy works; no temp dirs are left.
        copy_app_into(Browser::Brave, &src, &mnt).unwrap();
        let names: Vec<_> = std::fs::read_dir(mnt.join("app"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["Brave Browser.app"]);
        // Not an app of that kind: refused.
        assert!(copy_app_into(Browser::Firefox, &src, &mnt).is_err());
    }

    #[test]
    fn whatsapp_and_slack_args() {
        let mnt = Path::new("/mnt/x");
        let wa = launch_args(Browser::WhatsApp, mnt).unwrap();
        assert_eq!(wa[0], "--user-data-dir=/mnt/x/profile");
        assert_eq!(wa.last().unwrap(), "--app=https://web.whatsapp.com/");
        assert_eq!(
            binary_in_app(Browser::WhatsApp, Path::new("/A/Brave Browser.app")),
            Path::new("/A/Brave Browser.app/Contents/MacOS/Brave Browser")
        );
        assert_eq!(Browser::WhatsApp.engine(), Browser::Brave);
        assert_eq!(
            launch_args(Browser::Slack, mnt).unwrap(),
            ["--user-data-dir=/mnt/x/profile"]
        );
        assert!(Browser::Slack.is_chromium() && Browser::WhatsApp.is_chromium());
        assert!(!Browser::Telegram.is_chromium() && !Browser::Firefox.is_chromium());
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
        for b in [
            Browser::Brave,
            Browser::Firefox,
            Browser::Telegram,
            Browser::WhatsApp,
            Browser::Slack,
        ] {
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
