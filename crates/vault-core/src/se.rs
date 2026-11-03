//! Secure Enclave key handling for TOTP mode (SPEC §4.1). Milestone M3.
//!
//! STUB — interface fixed, implementation pending.

use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Reference to a non-exportable P-256 key living in the Secure Enclave.
/// `tag` is the `se_key_tag` from the header; `blob` is optional opaque
/// data some implementations need to re-open the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeKeyRef {
    pub tag: String,
    pub blob: Option<Vec<u8>>,
}

/// Abstraction so TOTP logic is testable without hardware.
pub trait SecureEnclave: Send + Sync {
    /// Create a new SE key bound to this device (`WhenUnlockedThisDeviceOnly`).
    fn create_key(&self, tag: &str) -> Result<SeKeyRef>;
    /// Encrypt to the key's public half (ECIES).
    fn encrypt(&self, key: &SeKeyRef, plaintext: &[u8]) -> Result<Vec<u8>>;
    /// Decrypt inside the SE. Fails on any other machine.
    fn decrypt(&self, key: &SeKeyRef, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    fn delete_key(&self, key: &SeKeyRef) -> Result<()>;
}

/// The real Secure Enclave on macOS.
pub fn system() -> Box<dyn SecureEnclave> {
    Box::new(Unavailable)
}

struct Unavailable;

impl SecureEnclave for Unavailable {
    fn create_key(&self, _: &str) -> Result<SeKeyRef> {
        Err(Error::Unsupported("Secure Enclave"))
    }
    fn encrypt(&self, _: &SeKeyRef, _: &[u8]) -> Result<Vec<u8>> {
        Err(Error::Unsupported("Secure Enclave"))
    }
    fn decrypt(&self, _: &SeKeyRef, _: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(Error::Unsupported("Secure Enclave"))
    }
    fn delete_key(&self, _: &SeKeyRef) -> Result<()> {
        Err(Error::Unsupported("Secure Enclave"))
    }
}
