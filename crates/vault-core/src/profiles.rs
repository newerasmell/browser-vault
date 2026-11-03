//! Existing browser profiles: detection, import into a vault and deletion of
//! the original (SPEC §5.1). Milestone M7b.
//!
//! STUB — interface fixed, implementation pending.
//! RULE: the user's existing profiles are read-only everywhere except
//! `cleanup_original`.

use std::path::PathBuf;

use crate::browser::Browser;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProfile {
    /// `Default` / `Profile 1` (Brave) or the profiles.ini `Path` (Firefox).
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

/// Profiles of the regular browser installation, from `Local State` / `profiles.ini`.
pub fn detect_profiles(_browser: Browser) -> Result<Vec<DetectedProfile>> {
    Err(Error::Unsupported(
        "profile import arrives in milestone M7b",
    ))
}

/// Whether the regular (non-vault) browser instance is running.
pub fn regular_browser_running(_browser: Browser) -> bool {
    false
}
