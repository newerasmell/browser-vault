//! Adapters for vault-core features that other milestones are still
//! building. Each returns `{ code: "unsupported" }` until wired up.

use vault_core::Browser;

use crate::error::{CmdError, CmdResult};
use crate::state::AppState;

/// TODO(integrate M7b): `profiles::cleanup_preview` → `{ items, sizeMb,
/// reviewed, fileVault, profileName, browser }` (docs/UI.md).
pub fn cleanup_preview(_st: &AppState, _id: &str) -> CmdResult<serde_json::Value> {
    Err(CmdError::unsupported())
}

/// TODO(integrate M7b): `profiles::cleanup_original` — Rust re-checks
/// `reviewed`, closed browser and the password; emits `cleanup_progress`.
pub fn cleanup_original(_st: &AppState, _id: &str, _password: &str) -> CmdResult<()> {
    Err(CmdError::unsupported())
}

/// TODO(integrate M7b): set `original.state = "kept"` (needs the VMK to
/// re-seal the header MAC, so it must go through vault-core).
pub fn keep_original(_st: &AppState, _id: &str) -> CmdResult<()> {
    Err(CmdError::unsupported())
}

/// TODO(integrate M7b): undo `keep_original` (`state = "pending"`).
pub fn restore_original_notice(_st: &AppState, _id: &str) -> CmdResult<()> {
    Err(CmdError::unsupported())
}

/// TODO(integrate M7b): copy the chosen profile into the freshly created
/// vault (SPEC §5.1 step 2). Called by `wizard_finish` when requested.
pub fn import_profile(
    _st: &AppState,
    _vault_id: &str,
    _browser: Browser,
    _profile_id: &str,
) -> CmdResult<()> {
    Err(CmdError::unsupported())
}
