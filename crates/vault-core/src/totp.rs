//! TOTP second factor (SPEC §4.1). Milestone M3.
//!
//! STUB — interface fixed, implementation pending.

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::Header;
use crate::keyslot::{Draft, UnlockedKey};
use crate::se::SecureEnclave;

/// Setup material held in the [`Draft`] until the first code confirms it.
pub struct PendingTotp {
    _private: (),
}

/// Shown once in the wizard: QR + manual key.
pub struct TotpSetup {
    /// Base32 secret for manual entry.
    pub secret: Zeroizing<String>,
    /// `otpauth://` URI (SPEC §4.1).
    pub uri: Zeroizing<String>,
    /// QR code of `uri` as an SVG document.
    pub qr_svg: Zeroizing<String>,
}

/// Generate the seed, SE key and SE_secret; keep them pending in the draft.
pub fn begin(_draft: &mut Draft, _se: &dyn SecureEnclave) -> Result<TotpSetup> {
    Err(Error::Unsupported("TOTP arrives in milestone M3"))
}

/// Verify the first code from the user's app, then add the `totp` slot.
pub fn confirm(_draft: &mut Draft, _code: &str, _se: &dyn SecureEnclave, _now: u64) -> Result<()> {
    Err(Error::Unsupported("TOTP arrives in milestone M3"))
}

/// Unlock: password → SE unwraps seed → code check (±1 step, anti-replay,
/// rate limit) → SE unwraps SE_secret → KEK → VMK. Mutates the slot's
/// counters; the caller must save the header whatever the result.
pub fn unlock(
    _header: &mut Header,
    _password: &str,
    _code: &str,
    _se: &dyn SecureEnclave,
    _now: u64,
) -> Result<UnlockedKey> {
    Err(Error::Unsupported("TOTP arrives in milestone M3"))
}
