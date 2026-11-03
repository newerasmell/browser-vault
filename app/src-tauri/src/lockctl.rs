//! The app side of the lock procedure (SPEC §6): drop keys, stop the
//! browser, detach, clean traces, notify, update the icon. Blocking — call
//! from a worker thread, never from the main thread.

use std::thread;

use tauri::{AppHandle, Emitter};
use tauri_plugin_notification::NotificationExt;
use vault_core::header::OriginalState;

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
    let _ = app
        .notification()
        .builder()
        .title("Browser Vault")
        .body(body)
        .show();
}

pub fn vaults_changed(app: &AppHandle) {
    let _ = app.emit("vaults_changed", ());
    tray::refresh(app);
}

/// SPEC §5.1 step 3: `reviewed` becomes true once the vault was opened and
/// closed after an import. Needs the VMK to re-seal the header MAC, so it
/// happens here, before the session (and its key) is dropped. Never re-seals
/// a header whose MAC does not verify (that would hide tampering).
fn mark_reviewed(st: &AppState, s: &Session) {
    let id = &s.unlocked.header.vault_id;
    let Ok(mut h) = st.store.load(id) else {
        return;
    };
    let pending = h
        .original
        .as_ref()
        .is_some_and(|o| !o.reviewed && o.state == OriginalState::Pending);
    let vmk = s.unlocked.key.vmk();
    if !pending || !h.verify_mac(vmk) {
        return;
    }
    if let Some(o) = h.original.as_mut() {
        o.reviewed = true;
    }
    if h.seal_mac(vmk).is_ok() {
        let _ = st.store.save_header(&h);
    }
}

/// Lock one vault. Idempotent; concurrent calls for the same id collapse.
pub fn lock_one(app: &AppHandle, id: &str, reason: Reason) -> CmdResult<()> {
    let st = state::get(app);
    if !lock(&st.locking).insert(id.to_string()) {
        return Ok(()); // another trigger is already locking it
    }
    let session = lock(&st.sessions).remove(id);
    let was_open = session.is_some() || st.store.is_unlocked(id);
    if let Some(s) = &session {
        mark_reviewed(&st, s);
    }
    let result = vault_core::lock::lock_vault(&st.store, id);
    // Step 3: wipe keys (Unlocked/UnlockedKey zeroize on drop).
    drop(session);
    lock(&st.locking).remove(id);

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
