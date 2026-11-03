//! YubiKey / FIDO2 hmac-secret second factor (SPEC §4.2). Milestone M4.
//!
//! STUB — interface fixed, implementation pending.

use crate::error::{Error, Result};
use crate::events::Notify;
use crate::header::Header;
use crate::keyslot::{Draft, UnlockedKey};

/// Abstraction over a FIDO2 authenticator so the slot logic is testable
/// without hardware. Implemented by the real `ctap-hid-fido2` backend.
pub trait Authenticator: Send + Sync {
    /// Whether any FIDO2 key is currently plugged in.
    fn present(&self) -> bool;
}

/// The real USB HID backend.
pub fn system() -> Box<dyn Authenticator> {
    Box::new(Unavailable)
}

struct Unavailable;

impl Authenticator for Unavailable {
    fn present(&self) -> bool {
        false
    }
}

/// Register a key (non-resident credential with hmac-secret) and add a
/// `fido2` slot to the draft. Returns the label.
pub fn register(
    _draft: &mut Draft,
    _auth: &dyn Authenticator,
    _pin: &str,
    _label: &str,
    _notify: Notify<'_>,
) -> Result<String> {
    Err(Error::Unsupported("YubiKey arrives in milestone M4"))
}

/// Unlock with password + any registered key (PIN + touch).
pub fn unlock(
    _header: &Header,
    _auth: &dyn Authenticator,
    _password: &str,
    _pin: &str,
    _notify: Notify<'_>,
) -> Result<UnlockedKey> {
    Err(Error::Unsupported("YubiKey arrives in milestone M4"))
}
