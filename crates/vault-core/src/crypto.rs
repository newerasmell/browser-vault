//! Thin wrappers over the approved primitives (SPEC §2, §4). No custom crypto:
//! everything here only composes `argon2`, `hkdf`/`sha2`, `chacha20poly1305`
//! and `rand::rngs::OsRng`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// A 256-bit secret that is wiped from memory on drop.
pub type Key = Zeroizing<[u8; KEY_LEN]>;

/// Upper bound on Argon2 memory we accept from a header (4 GiB), so a tampered
/// header cannot make unlock allocate unbounded memory.
pub const ARGON2_MAX_M_KIB: u32 = 4 * 1024 * 1024;
pub const ARGON2_MAX_T: u32 = 64;
pub const ARGON2_MAX_P: u32 = 16;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// Argon2id with explicit parameters (stored in the header so they can be raised).
pub fn argon2id(secret: &[u8], salt: &[u8], m_kib: u32, t: u32, p: u32) -> Result<Key> {
    if m_kib > ARGON2_MAX_M_KIB || t > ARGON2_MAX_T || p > ARGON2_MAX_P {
        return Err(Error::Invalid("kdf parameters out of range"));
    }
    let params =
        Params::new(m_kib, t, p, Some(KEY_LEN)).map_err(|_| Error::Invalid("kdf parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(out)
}

/// HKDF-SHA256 (no salt) expanding `ikm` into a 32-byte key bound to `info`.
pub fn hkdf(ikm: &[u8], info: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// HKDF over the concatenation `a ‖ b` (SPEC §4: e.g. `HKDF(PW ‖ hmac-secret)`).
pub fn hkdf_concat(a: &[u8], b: &[u8], info: &[u8]) -> Key {
    let mut ikm = Zeroizing::new(Vec::with_capacity(a.len() + b.len()));
    ikm.extend_from_slice(a);
    ikm.extend_from_slice(b);
    hkdf(&ikm, info)
}

/// XChaCha20-Poly1305 encryption with a fresh random nonce.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let nonce = random_bytes::<NONCE_LEN>();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok((nonce, ct))
}

/// XChaCha20-Poly1305 decryption. Any failure (wrong key, tampered data,
/// wrong AAD) is the same opaque [`Error::Crypto`].
pub fn open(key: &Key, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Crypto);
    }
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// Seal a 32-byte key (the VMK) under a KEK.
pub fn wrap_key(kek: &Key, aad: &[u8], key: &Key) -> Result<([u8; NONCE_LEN], Vec<u8>)> {
    seal(kek, aad, key.as_ref())
}

/// Open a 32-byte key sealed with [`wrap_key`].
pub fn unwrap_key(kek: &Key, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Key> {
    let pt = open(kek, aad, nonce, ciphertext)?;
    if pt.len() != KEY_LEN {
        return Err(Error::Crypto);
    }
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    k.copy_from_slice(&pt);
    Ok(k)
}

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &Key, data: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC verification.
pub fn hmac_sha256_verify(key: &Key, data: &[u8], tag: &[u8]) -> bool {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// SPEC §3/§4: Disk Key = HKDF(VMK, "bv-disk-v1"), rendered as 64 lowercase hex
/// characters. This is the passphrase handed to `hdiutil` over stdin.
pub fn disk_key_hex(vmk: &Key) -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let dk = hkdf(vmk.as_ref(), b"bv-disk-v1");
    let mut s = Zeroizing::new(String::with_capacity(KEY_LEN * 2));
    for b in dk.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let k = random_key();
        let (n, ct) = seal(&k, b"aad", b"hello").unwrap();
        assert_eq!(&*open(&k, b"aad", &n, &ct).unwrap(), b"hello");
    }

    #[test]
    fn open_rejects_wrong_key_aad_nonce_and_tamper() {
        let k = random_key();
        let (n, mut ct) = seal(&k, b"aad", b"hello").unwrap();
        assert!(open(&random_key(), b"aad", &n, &ct).is_err());
        assert!(open(&k, b"other", &n, &ct).is_err());
        assert!(open(&k, b"aad", &[0u8; NONCE_LEN], &ct).is_err());
        assert!(open(&k, b"aad", &n[..12], &ct).is_err());
        ct[0] ^= 1;
        assert!(open(&k, b"aad", &n, &ct).is_err());
    }

    #[test]
    fn nonces_are_fresh() {
        let k = random_key();
        let (n1, _) = seal(&k, b"", b"x").unwrap();
        let (n2, _) = seal(&k, b"", b"x").unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn wrap_unwrap_key() {
        let kek = random_key();
        let vmk = random_key();
        let (n, ct) = wrap_key(&kek, b"slot", &vmk).unwrap();
        assert_eq!(*unwrap_key(&kek, b"slot", &n, &ct).unwrap(), *vmk);
        assert!(unwrap_key(&random_key(), b"slot", &n, &ct).is_err());
    }

    #[test]
    fn unwrap_key_rejects_non_key_plaintext() {
        let kek = random_key();
        let (n, ct) = seal(&kek, b"", b"short").unwrap();
        assert!(unwrap_key(&kek, b"", &n, &ct).is_err());
    }

    #[test]
    fn argon2id_is_deterministic_and_salted() {
        let a = argon2id(b"password", b"saltsaltsaltsalt", 1024, 1, 1).unwrap();
        let b = argon2id(b"password", b"saltsaltsaltsalt", 1024, 1, 1).unwrap();
        let c = argon2id(b"password", b"SALTSALTSALTSALT", 1024, 1, 1).unwrap();
        let d = argon2id(b"password", b"saltsaltsaltsalt", 2048, 1, 1).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
    }

    #[test]
    fn argon2id_rejects_absurd_params() {
        assert!(argon2id(b"p", b"saltsaltsaltsalt", ARGON2_MAX_M_KIB + 1, 1, 1).is_err());
        assert!(argon2id(b"p", b"saltsaltsaltsalt", 1024, ARGON2_MAX_T + 1, 1).is_err());
        assert!(argon2id(b"p", b"saltsaltsaltsalt", 1024, 0, 1).is_err());
    }

    #[test]
    fn argon2id_matches_rfc9106_shape() {
        // Same inputs, different passwords → different keys.
        let a = argon2id(b"a", b"saltsaltsaltsalt", 1024, 1, 1).unwrap();
        let b = argon2id(b"b", b"saltsaltsaltsalt", 1024, 1, 1).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn hkdf_domain_separation() {
        let a = hkdf(b"ikm", b"one");
        let b = hkdf(b"ikm", b"two");
        assert_ne!(*a, *b);
        assert_eq!(*hkdf(b"ikm", b"one"), *a);
        assert_eq!(*hkdf_concat(b"ik", b"m", b"one"), *a);
    }

    #[test]
    fn hkdf_rfc5869_vector() {
        // RFC 5869 test case 3 (no salt, no info) — first 32 bytes of OKM.
        let ikm = [0x0bu8; 22];
        let okm = hkdf(&ikm, b"");
        let expected: [u8; 32] = [
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d,
        ];
        assert_eq!(*okm, expected);
    }

    #[test]
    fn hmac_verify() {
        let k = random_key();
        let tag = hmac_sha256(&k, b"data");
        assert!(hmac_sha256_verify(&k, b"data", &tag));
        assert!(!hmac_sha256_verify(&k, b"datb", &tag));
        assert!(!hmac_sha256_verify(&random_key(), b"data", &tag));
        assert!(!hmac_sha256_verify(&k, b"data", &tag[..31]));
    }

    #[test]
    fn disk_key_is_64_hex_and_derived() {
        let vmk = random_key();
        let dk = disk_key_hex(&vmk);
        assert_eq!(dk.len(), 64);
        assert!(dk
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(*dk, *disk_key_hex(&vmk));
        assert_ne!(*dk, *disk_key_hex(&random_key()));
        // Disk key must not simply be the VMK in hex.
        let raw: String = vmk.iter().map(|b| format!("{b:02x}")).collect();
        assert_ne!(*dk, raw);
    }
}
