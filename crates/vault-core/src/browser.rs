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
}

impl Browser {
    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Brave => "brave",
            Browser::Firefox => "firefox",
        }
    }

    pub fn parse(s: &str) -> Option<Browser> {
        match s.to_ascii_lowercase().as_str() {
            "brave" => Some(Browser::Brave),
            "firefox" => Some(Browser::Firefox),
            _ => None,
        }
    }

    /// `.app` bundle name and the binary inside `Contents/MacOS/`.
    fn bundle(self) -> (&'static str, &'static str) {
        match self {
            Browser::Brave => ("Brave Browser.app", "Brave Browser"),
            Browser::Firefox => ("Firefox.app", "firefox"),
        }
    }

    pub fn download_url(self) -> &'static str {
        match self {
            Browser::Brave => "https://brave.com/download/",
            Browser::Firefox => "https://www.mozilla.org/firefox/new/",
        }
    }
}

/// Binary path inside an `.app` bundle.
pub fn binary_in_app(browser: Browser, app: &Path) -> PathBuf {
    app.join("Contents/MacOS").join(browser.bundle().1)
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
        .map(|r| binary_in_app(browser, &r.join(app)))
        .find(|p| p.is_file())
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
            ])
        }
        // Firefox needs user.js (cache dir etc.) written at creation: milestone M5.
        Browser::Firefox => Err(Error::Unsupported("Firefox vaults arrive in milestone M5")),
    }
}

/// Start the browser binary directly (not `open -a`) so we own the PID and get
/// a separate instance even when the regular browser is running.
pub fn launch(browser: Browser, binary: &Path, mnt: &Path) -> Result<Child> {
    if !binary.is_file() {
        return Err(Error::BrowserMissing);
    }
    let args = launch_args(browser, mnt)?;
    Command::new(binary)
        .args(args)
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
                "--no-default-browser-check"
            ]
        );
    }

    #[test]
    fn firefox_not_yet() {
        assert!(matches!(
            launch_args(Browser::Firefox, Path::new("/m")),
            Err(Error::Unsupported(_))
        ));
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
        for b in [Browser::Brave, Browser::Firefox] {
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
