//! Lock triggers support and post-crash recovery (SPEC §6). Milestone M7.
//!
//! STUB — interface fixed, implementation pending. The app owns the event
//! loop (screen lock / sleep observers, hotkey); this module provides the
//! platform queries and cleanup steps it calls.

use crate::browser::Browser;
use crate::error::Result;
use crate::store::Store;

/// Seconds since the last user input (`CGEventSourceSecondsSinceLastEventType`).
/// `None` when unavailable (non-macOS).
pub fn idle_seconds() -> Option<f64> {
    None
}

/// SPEC §6 step 4: remove `~/Library/Saved Application State/<bundle>.savedState`
/// for `browser`, but only if the regular browser is not running.
pub fn cleanup_traces(_browser: Browser) -> Result<()> {
    Ok(())
}

/// Full lock procedure: stop browser, detach (with retries), clean traces.
pub fn lock_vault(store: &Store, id: &str) -> Result<()> {
    store.lock(id)
}

/// SPEC §6: at startup, detach leftover `BV-*` volumes from a crash.
/// Returns the vault ids that were recovered.
pub fn recover_after_crash(_store: &Store) -> Result<Vec<String>> {
    Ok(vec![])
}
