//! Diagnostic log at `~/Library/Logs/<store name>/app.log` (`BrowserVault`,
//! or a disguise's neutral name, see `vault_core::identity`; rotated at
//! 1 MiB to `app.log.1`). Only step names, reasons, vault ids, PIDs and
//! error codes/messages are written — never passwords, PINs, codes,
//! recovery words or keys.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use vault_core::identity;

const MAX_BYTES: u64 = 1024 * 1024;

static LOCK: Mutex<()> = Mutex::new(());
/// Set once the log directory was renamed for a disguise: from then on
/// nothing is written, so the old directory is not recreated on exit.
static SUSPENDED: AtomicBool = AtomicBool::new(false);

fn path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(identity::log_dir(Path::new(&home), &identity::store_name()).join("app.log"))
}

/// Stop writing for the rest of this process (see `SUSPENDED`).
pub fn suspend() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    SUSPENDED.store(true, Ordering::SeqCst);
}

pub fn log(msg: &str) {
    let Some(p) = path() else { return };
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if SUSPENDED.load(Ordering::SeqCst) {
        return;
    }
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if fs::metadata(&p)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = fs::rename(&p, p.with_extension("log.1"));
    }
    let thread = std::thread::current();
    let tname = thread.name().unwrap_or("worker");
    let ts = time_now();
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&p)
    {
        let _ = writeln!(f, "{ts} [{tname}] {msg}");
    }
}

fn time_now() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", d.as_secs(), d.subsec_millis())
}

/// Route `vault_core::trace` messages into this log.
pub fn install() {
    vault_core::trace::set_sink(log);
    log(&format!("start: {}", env!("CARGO_PKG_VERSION")));
}
