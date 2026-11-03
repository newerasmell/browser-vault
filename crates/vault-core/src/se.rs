//! Secure Enclave key handling for TOTP mode (SPEC §4.1). Milestone M3.
//!
//! # Approach: non-permanent SE key + token object id in the header
//!
//! The app ships unsigned (no Apple Developer account), and keychain-resident
//! Secure Enclave keys need a `keychain-access-groups` / application-identifier
//! entitlement; without it `SecItemAdd`/permanent `SecKeyCreateRandomKey` fail
//! with `errSecMissingEntitlement` (-34018). So we never store the key in the
//! keychain:
//!
//! 1. `create_key` calls `SecKeyCreateRandomKey` with
//!    `kSecAttrTokenID = kSecAttrTokenIDSecureEnclave`, `kSecAttrIsPermanent =
//!    false` and an access control of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//!    + `kSecAccessControlPrivateKeyUsage` (P-256, non-exportable).
//! 2. The private key never leaves the SE. What we get back is a reference
//!    whose attributes contain `kSecAttrTokenOID` (`"toid"`): an opaque blob
//!    holding the private key *encrypted by the SE under this device's
//!    hardware key* (it is what CryptoKit calls `dataRepresentation`). It is
//!    useless on any other Mac. It goes into the header as `se_key_blob`.
//! 3. To use the key later, `SecKeyCreateWithData` with `kSecAttrTokenID =
//!    SecureEnclave` and `kSecAttrTokenOID = blob` re-instantiates it.
//! 4. `encrypt` = ECIES (`kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`)
//!    to the public key; `decrypt` runs inside the SE.
//!
//! `delete_key` is a no-op for such keys: nothing is stored anywhere except
//! the blob, so forgetting the blob (rewriting the header) destroys the key.
//! A keychain-by-tag fallback is not implemented: it cannot work unsigned.

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
#[cfg(target_os = "macos")]
pub fn system() -> Box<dyn SecureEnclave> {
    Box::new(macos::SystemSe)
}

/// No Secure Enclave outside macOS.
#[cfg(not(target_os = "macos"))]
pub fn system() -> Box<dyn SecureEnclave> {
    Box::new(Unavailable)
}

#[cfg(not(target_os = "macos"))]
struct Unavailable;

#[cfg(not(target_os = "macos"))]
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

#[cfg(target_os = "macos")]
mod macos {
    use std::ptr;

    use core_foundation::base::{CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::error::CFError;
    use core_foundation::string::CFString;
    use core_foundation_sys::error::CFErrorRef;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
    use security_framework_sys::access_control::kSecAccessControlPrivateKeyUsage;
    use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};
    use security_framework_sys::key::SecKeyCreateWithData;
    use zeroize::Zeroizing;

    use super::{SeKeyRef, SecureEnclave};
    use crate::error::{Error, Result};

    /// `kSecAttrTokenOID` (declared in the private `SecItemPriv.h`). Its value
    /// is the attribute key string, so we build it instead of linking it.
    const ATTR_TOKEN_OID: &str = "toid";
    const ALG: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

    pub(super) struct SystemSe;

    /// SE errors carry only the operation and the OS error code/domain;
    /// never any data. Callers that unlock collapse them into `UnlockFailed`.
    fn cf_err(op: &str, e: &CFError) -> Error {
        Error::Command {
            tool: "Secure Enclave",
            detail: format!("{op}: {} {}", e.domain(), e.code()),
        }
    }

    fn token_oid(key: &SecKey) -> Option<Vec<u8>> {
        let attrs = key.attributes();
        let k = CFString::from_static_string(ATTR_TOKEN_OID);
        let v = attrs.find(k.as_CFTypeRef())?;
        // SAFETY: `v` is a valid CF object owned by `attrs` (get rule).
        let v = unsafe { CFType::wrap_under_get_rule(*v as _) };
        v.downcast::<CFData>().map(|d| d.bytes().to_vec())
    }

    fn open(key: &SeKeyRef) -> Result<SecKey> {
        let blob = key.blob.as_deref().ok_or(Error::Unsupported(
            "Secure Enclave key without a token object id",
        ))?;
        // SAFETY: static CFString constants exported by Security.framework.
        let (tkid, se) = unsafe {
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave),
            )
        };
        let toid = CFString::from_static_string(ATTR_TOKEN_OID);
        let data = CFData::from_buffer(blob);
        let attrs = CFDictionary::from_CFType_pairs(&[
            (tkid.as_CFType(), se.as_CFType()),
            (toid.as_CFType(), data.as_CFType()),
        ]);
        let empty = CFData::from_buffer(&[]);
        let mut err: CFErrorRef = ptr::null_mut();
        // SAFETY: valid CF objects; on success we own the returned key
        // (create rule), on failure we own `err`.
        let k = unsafe {
            SecKeyCreateWithData(
                empty.as_concrete_TypeRef(),
                attrs.as_concrete_TypeRef(),
                &mut err,
            )
        };
        if k.is_null() {
            if err.is_null() {
                return Err(Error::Command {
                    tool: "Secure Enclave",
                    detail: "open: no key".into(),
                });
            }
            // SAFETY: non-null error returned under the create rule.
            let e = unsafe { CFError::wrap_under_create_rule(err) };
            return Err(cf_err("open", &e));
        }
        // SAFETY: non-null key returned under the create rule.
        Ok(unsafe { SecKey::wrap_under_create_rule(k) })
    }

    impl SecureEnclave for SystemSe {
        fn create_key(&self, tag: &str) -> Result<SeKeyRef> {
            let ac = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
                kSecAccessControlPrivateKeyUsage,
            )
            .map_err(|e| Error::Command {
                tool: "Secure Enclave",
                detail: format!("access control: {}", e.code()),
            })?;
            let mut opts = GenerateKeyOptions::default();
            opts.set_key_type(KeyType::ec_sec_prime_random())
                .set_size_in_bits(256)
                .set_label(tag)
                .set_token(Token::SecureEnclave)
                .set_access_control(ac);
            // No `set_location`: the key is not stored in any keychain.
            let key = SecKey::new(&opts).map_err(|e| cf_err("create", &e))?;
            let blob = token_oid(&key).ok_or(Error::Command {
                tool: "Secure Enclave",
                detail: "create: key has no token object id".into(),
            })?;
            Ok(SeKeyRef {
                tag: tag.to_string(),
                blob: Some(blob),
            })
        }

        fn encrypt(&self, key: &SeKeyRef, plaintext: &[u8]) -> Result<Vec<u8>> {
            let pubkey = open(key)?.public_key().ok_or(Error::Command {
                tool: "Secure Enclave",
                detail: "encrypt: no public key".into(),
            })?;
            pubkey
                .encrypt_data(ALG, plaintext)
                .map_err(|e| cf_err("encrypt", &e))
        }

        fn decrypt(&self, key: &SeKeyRef, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            open(key)?
                .decrypt_data(ALG, ciphertext)
                .map(Zeroizing::new)
                .map_err(|e| cf_err("decrypt", &e))
        }

        fn delete_key(&self, _key: &SeKeyRef) -> Result<()> {
            // Non-permanent key: it exists only as the blob in the header.
            Ok(())
        }
    }
}

/// Software stand-in for tests. "Device-bound": each instance holds a random
/// device secret in memory, so keys created by one instance cannot be used
/// by another (simulating another Mac).
#[cfg(any(test, feature = "test-mocks"))]
pub struct MockSecureEnclave {
    device: crate::crypto::Key,
    decrypts: std::sync::atomic::AtomicUsize,
}

#[cfg(any(test, feature = "test-mocks"))]
impl Default for MockSecureEnclave {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-mocks"))]
impl MockSecureEnclave {
    pub fn new() -> Self {
        MockSecureEnclave {
            device: crate::crypto::random_key(),
            decrypts: Default::default(),
        }
    }

    /// Number of `decrypt` calls so far (lets tests check the unlock order).
    pub fn decrypt_calls(&self) -> usize {
        self.decrypts.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn key_for(&self, key: &SeKeyRef) -> Result<crate::crypto::Key> {
        let blob = key.blob.as_deref().ok_or(Error::Crypto)?;
        Ok(crate::crypto::hkdf_concat(
            self.device.as_ref(),
            blob,
            b"bv-mock-se-v1",
        ))
    }
}

#[cfg(any(test, feature = "test-mocks"))]
impl SecureEnclave for MockSecureEnclave {
    fn create_key(&self, tag: &str) -> Result<SeKeyRef> {
        Ok(SeKeyRef {
            tag: tag.to_string(),
            blob: Some(crate::crypto::random_bytes::<16>().to_vec()),
        })
    }

    fn encrypt(&self, key: &SeKeyRef, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, ct) = crate::crypto::seal(&self.key_for(key)?, key.tag.as_bytes(), plaintext)?;
        Ok([nonce.as_slice(), &ct].concat())
    }

    fn decrypt(&self, key: &SeKeyRef, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.decrypts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let n = crate::crypto::NONCE_LEN;
        if ciphertext.len() < n {
            return Err(Error::Crypto);
        }
        crate::crypto::open(
            &self.key_for(key)?,
            key.tag.as_bytes(),
            &ciphertext[..n],
            &ciphertext[n..],
        )
    }

    fn delete_key(&self, _: &SeKeyRef) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_roundtrip_and_device_binding() {
        let se = MockSecureEnclave::new();
        let k = se.create_key("com.browservault.t").unwrap();
        let ct = se.encrypt(&k, b"secret").unwrap();
        assert_eq!(se.decrypt(&k, &ct).unwrap().as_slice(), b"secret");
        assert_eq!(se.decrypt_calls(), 1);

        let other_mac = MockSecureEnclave::new();
        assert!(other_mac.decrypt(&k, &ct).is_err());
        // Another key on the same device cannot decrypt either.
        let k2 = se.create_key("com.browservault.t").unwrap();
        assert!(se.decrypt(&k2, &ct).is_err());
        let mut bad = ct.clone();
        bad[30] ^= 1;
        assert!(se.decrypt(&k, &bad).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn system_is_unavailable_off_macos() {
        assert!(matches!(
            system().create_key("x"),
            Err(Error::Unsupported(_))
        ));
    }
}
