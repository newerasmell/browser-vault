//! Keyslot creation and unlocking (SPEC §4). Pure functions over a [`Header`];
//! no disk or process side effects, so everything here is unit-testable.

use std::fmt;

use zeroize::Zeroizing;

use crate::browser::Browser;
use crate::crypto::{self, Key};
use crate::error::{Error, Redacted, Result};
use crate::header::{Header, Kdf, Slot, VaultSettings, B64, HEADER_VERSION};
use crate::recovery;

pub const MIN_PASSWORD_CHARS: usize = 12;

/// Argon2id cost. Production values are SPEC §4; `FAST` is for tests only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfCost {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfCost {
    pub const DEFAULT: KdfCost = KdfCost {
        m_kib: 256 * 1024,
        t: 3,
        p: 1,
    };
    /// Test-only: cheap parameters so the suite runs in seconds.
    pub const FAST: KdfCost = KdfCost {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
}

/// Key-encryption-key domain separation per slot type.
fn kek_info(kind: &str) -> Vec<u8> {
    format!("bv-kek-v1/{kind}").into_bytes()
}

/// AAD binds a wrapped VMK to its vault and slot type, so slots cannot be
/// moved between vaults or reinterpreted as another type.
fn slot_aad(vault_id: &str, kind: &str) -> Vec<u8> {
    format!("bv-slot-v1|{vault_id}|{kind}").into_bytes()
}

/// The unwrapped Vault Master Key plus the header-integrity verdict.
pub struct UnlockedKey {
    vmk: Key,
    /// SPEC §8: `false` → the header was modified outside the app; the UI warns.
    pub header_intact: bool,
}

impl fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKey")
            .field("vmk", &Redacted)
            .field("header_intact", &self.header_intact)
            .finish()
    }
}

impl UnlockedKey {
    pub fn vmk(&self) -> &Key {
        &self.vmk
    }

    pub fn disk_key_hex(&self) -> Zeroizing<String> {
        crypto::disk_key_hex(&self.vmk)
    }
}

pub struct NewVault {
    pub header: Header,
    pub key: UnlockedKey,
    /// Shown to the user exactly once (SPEC §4).
    pub recovery_phrase: Zeroizing<String>,
}

pub fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::Invalid("password must be at least 12 characters"));
    }
    Ok(())
}

pub fn validate_name(name: &str) -> Result<()> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 || n.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "vault name must be 1–100 printable characters",
        ));
    }
    Ok(())
}

fn new_vault_id() -> String {
    uuid::Builder::from_random_bytes(crypto::random_bytes::<16>())
        .into_uuid()
        .hyphenated()
        .to_string()
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn wrap_slot(vault_id: &str, kind: &str, kek: &Key, vmk: &Key) -> Result<(B64, B64)> {
    let (nonce, ct) = crypto::wrap_key(kek, &slot_aad(vault_id, kind), vmk)?;
    Ok((nonce.into(), ct.into()))
}

fn password_kek(pw: &Key) -> Key {
    crypto::hkdf_concat(pw.as_ref(), &[], &kek_info("password"))
}

fn recovery_kek(kdf: &Kdf, phrase: &str, salt: &[u8]) -> Result<Key> {
    let rk = kdf.derive_with_salt(phrase.as_bytes(), salt)?;
    Ok(crypto::hkdf(rk.as_ref(), &kek_info("recovery")))
}

/// Build the header for a new vault: random VMK, a (temporary) password slot
/// and a recovery slot. Nothing is written to disk here.
pub fn new_vault(name: &str, browser: Browser, password: &str, cost: KdfCost) -> Result<NewVault> {
    validate_name(name)?;
    validate_password(password)?;

    let vault_id = new_vault_id();
    let vmk = crypto::random_key();
    let kdf = Kdf {
        alg: "argon2id".into(),
        m_kib: cost.m_kib,
        t: cost.t,
        p: cost.p,
        salt: crypto::random_bytes::<16>().into(),
    };

    let pw = kdf.derive(password.as_bytes())?;
    let (nonce, wrapped_vmk) = wrap_slot(&vault_id, "password", &password_kek(&pw), &vmk)?;
    let password_slot = Slot::Password { nonce, wrapped_vmk };

    let phrase = recovery::generate()?;
    let rsalt = crypto::random_bytes::<16>();
    let rkek = recovery_kek(&kdf, &phrase, &rsalt)?;
    let (nonce, wrapped_vmk) = wrap_slot(&vault_id, "recovery", &rkek, &vmk)?;
    let recovery_slot = Slot::Recovery {
        salt: rsalt.into(),
        nonce,
        wrapped_vmk,
    };

    let mut header = Header {
        version: HEADER_VERSION,
        vault_id,
        name: name.trim().to_string(),
        browser,
        created_at: now_rfc3339(),
        kdf,
        slots: vec![password_slot, recovery_slot],
        settings: VaultSettings::default(),
        original: None,
        mac: B64::default(),
    };
    header.seal_mac(&vmk)?;

    Ok(NewVault {
        header,
        key: UnlockedKey {
            vmk,
            header_intact: true,
        },
        recovery_phrase: phrase,
    })
}

fn finish(header: &Header, vmk: Key) -> UnlockedKey {
    let header_intact = header.verify_mac(&vmk);
    UnlockedKey { vmk, header_intact }
}

/// Unlock with the password (temporary M1/M2 password slot).
///
/// Every failure — wrong password, tampered slot, bad KDF params — is
/// [`Error::UnlockFailed`].
pub fn unlock_with_password(header: &Header, password: &str) -> Result<UnlockedKey> {
    let pw = header
        .kdf
        .derive(password.as_bytes())
        .map_err(|_| Error::UnlockFailed)?;
    let kek = password_kek(&pw);
    let aad = slot_aad(&header.vault_id, "password");
    for slot in &header.slots {
        if let Slot::Password { nonce, wrapped_vmk } = slot {
            if let Ok(vmk) = crypto::unwrap_key(&kek, &aad, &nonce.0, &wrapped_vmk.0) {
                return Ok(finish(header, vmk));
            }
        }
    }
    Err(Error::UnlockFailed)
}

/// Unlock with the 24-word recovery phrase alone.
pub fn unlock_with_recovery(header: &Header, phrase: &str) -> Result<UnlockedKey> {
    let phrase = recovery::normalize(phrase)?;
    let aad = slot_aad(&header.vault_id, "recovery");
    for slot in &header.slots {
        if let Slot::Recovery {
            salt,
            nonce,
            wrapped_vmk,
        } = slot
        {
            let kek =
                recovery_kek(&header.kdf, &phrase, &salt.0).map_err(|_| Error::UnlockFailed)?;
            if let Ok(vmk) = crypto::unwrap_key(&kek, &aad, &nonce.0, &wrapped_vmk.0) {
                return Ok(finish(header, vmk));
            }
        }
    }
    Err(Error::UnlockFailed)
}

/// Re-wrap the VMK under a new password (SPEC §4: the container is not
/// re-encrypted). Replaces every password slot and re-seals the MAC.
pub fn change_password(header: &mut Header, key: &UnlockedKey, new_password: &str) -> Result<()> {
    validate_password(new_password)?;
    // A fresh salt for the password KDF. The recovery slot depends only on
    // the cost parameters and its own salt, so it stays valid.
    header.kdf.salt = crypto::random_bytes::<16>().into();
    let pw = header.kdf.derive(new_password.as_bytes())?;
    let (nonce, wrapped_vmk) =
        wrap_slot(&header.vault_id, "password", &password_kek(&pw), &key.vmk)?;
    header.slots.retain(|s| !matches!(s, Slot::Password { .. }));
    header
        .slots
        .insert(0, Slot::Password { nonce, wrapped_vmk });
    header.seal_mac(&key.vmk)
}

/// Replace the recovery slot with a new phrase; returns the new phrase.
pub fn new_recovery(header: &mut Header, key: &UnlockedKey) -> Result<Zeroizing<String>> {
    let phrase = recovery::generate()?;
    let rsalt = crypto::random_bytes::<16>();
    let rkek = recovery_kek(&header.kdf, &phrase, &rsalt)?;
    let (nonce, wrapped_vmk) = wrap_slot(&header.vault_id, "recovery", &rkek, &key.vmk)?;
    header.slots.retain(|s| !matches!(s, Slot::Recovery { .. }));
    header.slots.push(Slot::Recovery {
        salt: rsalt.into(),
        nonce,
        wrapped_vmk,
    });
    header.seal_mac(&key.vmk)?;
    Ok(phrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    fn vault() -> NewVault {
        new_vault("Work – Brave", Browser::Brave, PW, KdfCost::FAST).unwrap()
    }

    #[test]
    fn new_vault_shape() {
        let v = vault();
        let h = &v.header;
        assert_eq!(h.version, HEADER_VERSION);
        assert!(uuid::Uuid::parse_str(&h.vault_id).is_ok());
        assert_eq!(h.kdf.alg, "argon2id");
        assert_eq!(h.kdf.salt.0.len(), 16);
        let kinds: Vec<_> = h.slots.iter().map(Slot::kind).collect();
        assert_eq!(kinds, ["password", "recovery"]);
        assert!(h.verify_mac(v.key.vmk()));
        assert_eq!(v.recovery_phrase.split(' ').count(), 24);
        assert!(h.created_at.ends_with('Z'));
    }

    #[test]
    fn default_cost_matches_spec() {
        assert_eq!(KdfCost::DEFAULT.m_kib, 262144);
        assert_eq!(KdfCost::DEFAULT.t, 3);
        assert_eq!(KdfCost::DEFAULT.p, 1);
    }

    #[test]
    fn vmk_is_never_stored_in_clear() {
        let v = vault();
        let json = v.header.to_json().unwrap();
        let needle = v.key.vmk().to_vec();
        assert!(!json.windows(needle.len()).any(|w| w == needle.as_slice()));
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &needle);
        assert!(!String::from_utf8_lossy(&json).contains(&b64));
        assert!(!String::from_utf8_lossy(&json).contains(v.recovery_phrase.as_str()));
    }

    #[test]
    fn password_unlocks() {
        let v = vault();
        let k = unlock_with_password(&v.header, PW).unwrap();
        assert_eq!(**k.vmk(), **v.key.vmk());
        assert!(k.header_intact);
        assert_eq!(*k.disk_key_hex(), *v.key.disk_key_hex());
    }

    #[test]
    fn wrong_password_is_generic_failure() {
        let v = vault();
        for bad in ["correct horse batterY", "", "correct horse battery "] {
            let e = unlock_with_password(&v.header, bad).unwrap_err();
            assert!(matches!(e, Error::UnlockFailed));
            assert_eq!(e.to_string(), "Unlock failed");
        }
    }

    #[test]
    fn recovery_unlocks_and_yields_same_vmk() {
        let v = vault();
        let k = unlock_with_recovery(&v.header, &v.recovery_phrase).unwrap();
        assert_eq!(**k.vmk(), **v.key.vmk());
        let messy = v.recovery_phrase.to_uppercase();
        assert!(unlock_with_recovery(&v.header, &messy).is_ok());
    }

    #[test]
    fn wrong_recovery_is_generic_failure() {
        let v = vault();
        let other = recovery::generate().unwrap();
        assert!(matches!(
            unlock_with_recovery(&v.header, &other),
            Err(Error::UnlockFailed)
        ));
        assert!(matches!(
            unlock_with_recovery(&v.header, "not a phrase"),
            Err(Error::UnlockFailed)
        ));
        // A password is not a recovery phrase and vice versa.
        assert!(matches!(
            unlock_with_recovery(&v.header, PW),
            Err(Error::UnlockFailed)
        ));
        assert!(matches!(
            unlock_with_password(&v.header, &v.recovery_phrase),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn tampered_wrapped_vmk_fails() {
        let mut v = vault();
        if let Slot::Password { wrapped_vmk, .. } = &mut v.header.slots[0] {
            wrapped_vmk.0[3] ^= 0x40;
        }
        assert!(matches!(
            unlock_with_password(&v.header, PW),
            Err(Error::UnlockFailed)
        ));
        // Recovery still works because its slot is untouched.
        assert!(unlock_with_recovery(&v.header, &v.recovery_phrase).is_ok());
    }

    #[test]
    fn tampered_kdf_params_fail() {
        let v = vault();
        let mut h = v.header.clone();
        h.kdf.m_kib *= 2;
        assert!(matches!(
            unlock_with_password(&h, PW),
            Err(Error::UnlockFailed)
        ));
        let mut h = v.header.clone();
        h.kdf.salt.0[0] ^= 1;
        assert!(matches!(
            unlock_with_password(&h, PW),
            Err(Error::UnlockFailed)
        ));
        let mut h = v.header.clone();
        h.kdf.alg = "pbkdf2".into();
        assert!(matches!(
            unlock_with_password(&h, PW),
            Err(Error::UnlockFailed)
        ));
        let mut h = v.header.clone();
        h.kdf.m_kib = u32::MAX;
        assert!(matches!(
            unlock_with_password(&h, PW),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn slot_moved_to_other_vault_fails() {
        let a = vault();
        let mut b = vault();
        // Graft A's password slot into B under A's password.
        b.header.slots[0] = a.header.slots[0].clone();
        b.header.kdf = a.header.kdf.clone();
        assert!(matches!(
            unlock_with_password(&b.header, PW),
            Err(Error::UnlockFailed)
        ));
        // And changing the vault id of A breaks A.
        let mut h = a.header.clone();
        h.vault_id = b.header.vault_id.clone();
        assert!(matches!(
            unlock_with_password(&h, PW),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn tampered_metadata_unlocks_but_is_flagged() {
        let v = vault();
        let mut h = v.header.clone();
        h.settings.idle_minutes = 0;
        h.name = "Evil".into();
        let k = unlock_with_password(&h, PW).unwrap();
        assert!(!k.header_intact);
    }

    #[test]
    fn rejects_short_password_and_bad_names() {
        assert!(matches!(
            new_vault("x", Browser::Brave, "elevenchars", KdfCost::FAST),
            Err(Error::Invalid(_))
        ));
        // 12 Cyrillic characters count as 12, not as 24 bytes.
        assert!(new_vault("x", Browser::Brave, "дванадесетзн", KdfCost::FAST).is_ok());
        assert!(new_vault("  ", Browser::Brave, PW, KdfCost::FAST).is_err());
        assert!(new_vault("a\nb", Browser::Brave, PW, KdfCost::FAST).is_err());
    }

    #[test]
    fn change_password_rewraps_without_touching_vmk() {
        let mut v = vault();
        let k = unlock_with_password(&v.header, PW).unwrap();
        change_password(&mut v.header, &k, "a brand new passphrase").unwrap();
        assert!(matches!(
            unlock_with_password(&v.header, PW),
            Err(Error::UnlockFailed)
        ));
        let k2 = unlock_with_password(&v.header, "a brand new passphrase").unwrap();
        assert_eq!(**k2.vmk(), **v.key.vmk());
        assert!(k2.header_intact);
        assert!(unlock_with_recovery(&v.header, &v.recovery_phrase).is_ok());
        assert_eq!(
            v.header
                .slots
                .iter()
                .filter(|s| s.kind() == "password")
                .count(),
            1
        );
        assert!(change_password(&mut v.header, &k2, "short").is_err());
    }

    #[test]
    fn new_recovery_invalidates_old_phrase() {
        let mut v = vault();
        let k = unlock_with_password(&v.header, PW).unwrap();
        let fresh = new_recovery(&mut v.header, &k).unwrap();
        assert_ne!(*fresh, *v.recovery_phrase);
        assert!(matches!(
            unlock_with_recovery(&v.header, &v.recovery_phrase),
            Err(Error::UnlockFailed)
        ));
        let k2 = unlock_with_recovery(&v.header, &fresh).unwrap();
        assert!(k2.header_intact);
        assert!(unlock_with_password(&v.header, PW).is_ok());
    }

    #[test]
    fn debug_never_prints_key() {
        let v = vault();
        let s = format!("{:?}", v.key);
        assert!(s.contains("<redacted>"));
        assert!(!s.contains(&format!("{:?}", &v.key.vmk()[..4])));
    }
}
