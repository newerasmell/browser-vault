//! Chromium/Brave "v10" encrypted values on macOS (cookies, saved
//! passwords, cards). This is Chromium's own scheme, implemented only to
//! re-encrypt a copied profile from the Mac's Keychain key to the portable
//! key — Browser Vault's own secrets never use it.
//!
//! Format (Chromium `os_crypt` on macOS):
//! `key = PBKDF2-HMAC-SHA1(password, "saltysalt", 1003, 16 bytes)`,
//! `value = "v10" ‖ AES-128-CBC(key, iv = 16 × ' ', PKCS#7(plaintext))`.
//! The password is the Keychain item "<Browser> Safe Storage", or the fixed
//! [`MOCK_PASSWORD`] when the browser runs with `--use-mock-keychain`.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const PREFIX: &[u8] = b"v10";
/// Password Chromium uses with `--use-mock-keychain` (Mac-independent).
pub const MOCK_PASSWORD: &str = "mock_password";
const SALT: &[u8] = b"saltysalt";
const ITERATIONS: u32 = 1003;
const IV: [u8; 16] = [b' '; 16];

type Enc = cbc::Encryptor<aes::Aes128>;
type Dec = cbc::Decryptor<aes::Aes128>;

/// A derived 128-bit Chromium key, wiped on drop.
pub struct ChromiumKey(Zeroizing<[u8; 16]>);

impl ChromiumKey {
    pub fn from_password(password: &[u8]) -> ChromiumKey {
        let mut k = Zeroizing::new([0u8; 16]);
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, SALT, ITERATIONS, k.as_mut());
        ChromiumKey(k)
    }

    pub fn mock() -> ChromiumKey {
        ChromiumKey::from_password(MOCK_PASSWORD.as_bytes())
    }

    pub fn same_as(&self, other: &ChromiumKey) -> bool {
        *self.0 == *other.0
    }
}

pub fn is_v10(blob: &[u8]) -> bool {
    blob.len() > PREFIX.len() && blob.starts_with(PREFIX)
}

pub fn decrypt(key: &ChromiumKey, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if !is_v10(blob) {
        return Err(Error::Crypto);
    }
    let ct = &blob[PREFIX.len()..];
    if ct.is_empty() || !ct.len().is_multiple_of(16) {
        return Err(Error::Crypto);
    }
    Dec::new(key.0.as_ref().into(), &IV.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

pub fn encrypt(key: &ChromiumKey, plaintext: &[u8]) -> Vec<u8> {
    let ct = Enc::new(key.0.as_ref().into(), &IV.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mut out = Vec::with_capacity(PREFIX.len() + ct.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&ct);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_wrong_key() {
        let a = ChromiumKey::from_password(b"keychain password");
        let b = ChromiumKey::mock();
        let blob = encrypt(&a, b"session=abc123");
        assert!(is_v10(&blob));
        assert_eq!(&*decrypt(&a, &blob).unwrap(), b"session=abc123");
        // A wrong key almost always fails the padding check; if it happens
        // to pass, the plaintext is garbage.
        if let Ok(pt) = decrypt(&b, &blob) {
            assert_ne!(&*pt, b"session=abc123");
        }
        assert!(decrypt(&a, b"v10").is_err());
        assert!(decrypt(&a, b"v11xxxxxxxxxxxxxxxx").is_err());
        assert!(decrypt(&a, b"v10short").is_err());
        assert!(!a.same_as(&b));
        assert!(b.same_as(&ChromiumKey::mock()));
    }

    #[test]
    fn known_vector_matches_independent_implementation() {
        // Computed independently: key = Python hashlib.pbkdf2_hmac('sha1',
        // b'mock_password', b'saltysalt', 1003, 16) = af0f762a…18de;
        // ciphertext = `openssl enc -aes-128-cbc -K <key> -iv 2020…20` of
        // b"peanuts".
        let k = ChromiumKey::mock();
        let expected_key: [u8; 16] = [
            0xaf, 0x0f, 0x76, 0x2a, 0xaf, 0x6d, 0x7d, 0x11, 0x58, 0x1b, 0x7a, 0xa8, 0xce, 0x72,
            0x18, 0xde,
        ];
        assert_eq!(*k.0, expected_key);
        let ct: [u8; 16] = [
            0x46, 0xa0, 0xc6, 0x67, 0x83, 0xf2, 0xa2, 0xd6, 0x9d, 0x43, 0x5c, 0x00, 0x6d, 0x57,
            0x9e, 0xce,
        ];
        let blob = encrypt(&k, b"peanuts");
        assert_eq!(&blob[3..], &ct);
        let mut v = b"v10".to_vec();
        v.extend_from_slice(&ct);
        assert_eq!(&*decrypt(&k, &v).unwrap(), b"peanuts");
    }
}
