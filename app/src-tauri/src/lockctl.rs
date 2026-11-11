//! The app side of the lock procedure (SPEC §6): drop keys, stop the
//! browser, detach, clean traces, notify, update the icon. Blocking — call
//! from a worker thread, never from the main thread.

use std::thread;

use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;

use crate::applog;
use crate::error::{CmdError, CmdResult};
use crate::state::{self, lock, AppState, Session};
use crate::texts::{tr, T};
use crate::tray;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Manual,
    BrowserExit,
    Idle,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    ScreenLock,
    KeyRemoved,
    Hotkey,
    Quit,
}

pub fn notify(app: &AppHandle, body: &str) {
    if state::get(app).is_quitting() {
        return;
    }
    let _ = app
        .notification()
        .builder()
        .title("Browser Vault")
        .body(body)
        .show();
}

pub fn vaults_changed(app: &AppHandle) {
    if state::get(app).is_quitting() {
        return; // see AppState::quitting
    }
    let _ = app.emit("vaults_changed", ());
    tray::refresh(app);
}

/// Lock one vault. Idempotent; concurrent calls for the same id collapse.
pub fn lock_one(app: &AppHandle, id: &str, reason: Reason) -> CmdResult<()> {
    let st = state::get(app);
    if !lock(&st.locking).insert(id.to_string()) {
        applog::log(&format!("lock {id} ({reason:?}): already in progress"));
        return Ok(()); // another trigger is already locking it
    }
    applog::log(&format!("lock {id} ({reason:?}): begin"));
    let session = lock(&st.sessions).remove(id);
    let was_open = session.is_some() || st.store.is_unlocked(id);
    // Ask the browser to quit like ⌘Q first, so it shuts down cleanly
    // (Firefox treats SIGTERM as a crash and offers "Restore session").
    // Store::lock still sends SIGTERM/SIGKILL if it doesn't exit in time.
    if let Some(pid) = session
        .as_ref()
        .and_then(|s| s.browser_pid)
        .or_else(|| st.store.browser_pid(id).map(|p| p as u32))
    {
        graceful_quit(pid);
    }
    // With a session: Store::close (also flips SPEC §5.1 `reviewed`).
    // Keys are wiped when the session is dropped inside (SPEC §6 step 3).
    let result = match session {
        Some(s) => vault_core::lock::close_vault(&st.store, s.unlocked),
        None => vault_core::lock::lock_vault(&st.store, id),
    };
    lock(&st.locking).remove(id);
    match &result {
        Ok(()) => applog::log(&format!("lock {id}: done")),
        Err(e) => applog::log(&format!("lock {id}: error {e}")),
    }

    let bg = st.is_bg();
    match &result {
        Ok(()) => {
            lock(&st.errors).remove(id);
            if was_open && reason != Reason::Quit {
                notify(app, tr(bg, T::VaultLocked));
            }
        }
        Err(_) => {
            lock(&st.errors).insert(id.to_string());
            notify(app, tr(bg, T::DetachFailed));
        }
    }
    vaults_changed(app);
    applog::log(&format!("lock {id}: ui refreshed"));
    result.map_err(CmdError::from)
}

/// Every vault that may hold decrypted data: open sessions, anything still
/// mounted (e.g. from the CLI) and vaults in error state.
fn lockable_ids(st: &AppState) -> Vec<String> {
    let mut ids: Vec<String> = lock(&st.sessions).keys().cloned().collect();
    ids.extend(lock(&st.errors).iter().cloned());
    if let Ok(list) = st.store.list() {
        ids.extend(
            list.into_iter()
                .map(|h| h.vault_id)
                .filter(|id| st.store.is_unlocked(id)),
        );
    }
    ids.sort();
    ids.dedup();
    ids
}

/// Lock the vaults whose session matches `pred`, in parallel.
pub fn lock_matching(
    app: &AppHandle,
    reason: Reason,
    pred: impl Fn(&Session) -> bool,
) -> CmdResult<()> {
    let st = state::get(app);
    let ids: Vec<String> = lock(&st.sessions)
        .iter()
        .filter(|(_, s)| pred(s))
        .map(|(id, _)| id.clone())
        .collect();
    lock_ids(app, ids, reason)
}

pub fn lock_all(app: &AppHandle, reason: Reason) -> CmdResult<()> {
    let ids = lockable_ids(&state::get(app));
    lock_ids(app, ids, reason)
}

fn lock_ids(app: &AppHandle, ids: Vec<String>, reason: Reason) -> CmdResult<()> {
    let handles: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let app = app.clone();
            thread::spawn(move || lock_one(&app, &id, reason))
        })
        .collect();
    let mut first_err = None;
    for h in handles {
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                first_err.get_or_insert(e);
            }
            Err(_) => {
                first_err.get_or_insert(CmdError::new("io"));
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Fire-and-forget variant for triggers running on the main thread.
pub fn spawn_lock_all(app: &AppHandle, reason: Reason) {
    let app = app.clone();
    thread::spawn(move || {
        let _ = lock_all(&app, reason);
    });
}

/// Send the standard macOS "quit" (as ⌘Q would) to one process and wait up
/// to 8 s for it to exit. Only that PID is addressed, never other windows
/// of the same browser outside the vault.
#[cfg(target_os = "macos")]
fn graceful_quit(pid: u32) {
    use objc2_app_kit::NSRunningApplication;
    use std::time::{Duration, Instant};
    let pid_i = pid as i32;
    if !vault_core::browser::is_alive(pid_i) {
        return;
    }
    if let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid_i) {
        let sent = app.terminate();
        applog::log(&format!("graceful quit sent to pid {pid}: {sent}"));
    }
    let start = Instant::now();
    while vault_core::browser::is_alive(pid_i) && start.elapsed() < Duration::from_secs(8) {
        thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(not(target_os = "macos"))]
fn graceful_quit(_pid: u32) {}
