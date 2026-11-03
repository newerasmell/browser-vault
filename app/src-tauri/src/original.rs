//! Imported original profile (SPEC §5.1, M7b): preview, delete, keep.
//!
//! Everything that changes the header needs the open session (VMK for the
//! MAC; in-memory password verifier for the delete). When the vault is
//! locked, the unlock window opens first and the action resumes right after
//! a successful unlock (see [`Pending`]).

use std::collections::BTreeMap;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use vault_core::events::Event;
use vault_core::profiles::{self, Roots};

use crate::error::{CmdError, CmdResult};
use crate::lockctl;
use crate::state::{self, lock};
use crate::windows;

/// An action waiting for the vault to be unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    OpenCleanup,
    Keep,
    UndoKeep,
    Delete,
}

fn id_params(id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([("id".to_string(), id.to_string())])
}

pub fn is_open(app: &AppHandle, id: &str) -> bool {
    lock(&state::get(app).sessions).contains_key(id)
}

/// Open the unlock window and remember what to do afterwards.
pub fn require_unlock(app: &AppHandle, id: &str, then: Pending) -> CmdResult<()> {
    lock(&state::get(app).pending).insert(id.to_string(), then);
    windows::open(app, "unlock", &id_params(id))
}

/// Called after a successful unlock.
pub fn resume(app: &AppHandle, id: &str) {
    let Some(p) = lock(&state::get(app).pending).remove(id) else {
        return;
    };
    let _ = match p {
        Pending::OpenCleanup => windows::open(app, "cleanup", &id_params(id)),
        Pending::Keep => set_kept(app, id, true).map(|_| ()),
        Pending::UndoKeep => set_kept(app, id, false).map(|_| ()),
        Pending::Delete => crate::commands::delete_unlocked_vault(app, id).map(|_| ()),
    };
}

/// `open_window('cleanup')`: only for an unlocked vault.
pub fn open_cleanup(app: &AppHandle, id: &str) -> CmdResult<()> {
    if is_open(app, id) {
        windows::open(app, "cleanup", &id_params(id))
    } else {
        require_unlock(app, id, Pending::OpenCleanup)
    }
}

pub fn preview(app: &AppHandle, id: &str) -> CmdResult<Value> {
    let st = state::get(app);
    let p = profiles::cleanup_preview(&st.store, &Roots::system()?, id)?;
    let items: Vec<String> = p
        .items
        .iter()
        .map(|i| i.to_string_lossy().into_owned())
        .collect();
    Ok(json!({
        "items": items,
        "sizeMb": crate::commands::bytes_to_mb(p.size_bytes),
        "reviewed": p.reviewed,
        // Unknown counts as off, so the recommendation is shown.
        "fileVault": p.file_vault.unwrap_or(false),
        "profileName": p.profile_name,
        "browser": p.browser.as_str(),
    }))
}

/// `cleanup_original`: vault-core re-checks MAC, `reviewed`, regular
/// browser closed and the password (via the session's in-memory verifier).
pub fn cleanup(app: &AppHandle, id: &str, password: &str) -> CmdResult<()> {
    let st = state::get(app);
    let roots = Roots::system()?;
    let app2 = app.clone();
    let notify = move |e: Event| {
        if let Event::CleanupProgress { pct } = e {
            let _ = app2.emit("cleanup_progress", json!({ "pct": pct }));
        }
    };
    let r = {
        let mut sessions = lock(&st.sessions);
        // Locked meanwhile (e.g. the vault browser was closed): re-unlock.
        let s = sessions.get_mut(id).ok_or(CmdError::new("unlock_failed"))?;
        profiles::cleanup_original(&st.store, &roots, &mut s.unlocked, password, &notify)
    };
    lockctl::vaults_changed(app);
    Ok(r?)
}

/// `keep_original` (true) / `restore_original_notice` (false).
pub fn set_kept(app: &AppHandle, id: &str, kept: bool) -> CmdResult<Value> {
    if !is_open(app, id) {
        let p = if kept {
            Pending::Keep
        } else {
            Pending::UndoKeep
        };
        require_unlock(app, id, p)?;
        return Ok(json!({ "ok": false, "pending": "unlock" }));
    }
    let st = state::get(app);
    let r = {
        let mut sessions = lock(&st.sessions);
        let s = sessions.get_mut(id).ok_or(CmdError::not_found())?;
        if kept {
            profiles::keep_original(&st.store, &mut s.unlocked)
        } else {
            profiles::undo_keep_original(&st.store, &mut s.unlocked)
        }
    };
    r?;
    lockctl::vaults_changed(app);
    Ok(json!({ "ok": true }))
}
