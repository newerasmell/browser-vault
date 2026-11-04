//! Keyslot creation and unlocking (SPEC §4). Pure functions over a [`Header`];
//! no disk or process side effects, so everything here is unit-testable.
//!
//! New vaults are built with a [`Draft`] (the wizard's in-memory state):
//! `Draft::new` → `set_password` → a second-factor module adds its slot
//! (`totp::begin/confirm`, `fido2::register`) → `generate_recovery` →
//! `finish`. Factor modules compute their KEK with [`factor_kek`] and wrap the
//! VMK with [`Draft::wrap`]; on unlock they use [`unwrap_slot`] + [`unlocked`].

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
pub fn slot_aad(vault_id: &str, kind: &str) -> Vec<u8> {
    format!("bv-slot-v1|{vault_id}|{kind}").into_bytes()
}

/// SPEC §4: KEK = HKDF(PW ‖ factor_secret), domain-separated by slot kind.
/// `factor_secret` is the YubiKey hmac-secret output or the SE_secret.
pub fn factor_kek(pw: &Key, factor_secret: &[u8], kind: &str) -> Key {
    crypto::hkdf_concat(pw.as_ref(), factor_secret, &kek_info(kind))
}

/// Unwrap a VMK from a slot of `kind`. Opaque failure.
pub fn unwrap_slot(
    header: &Header,
    kind: &str,
    kek: &Key,
    nonce: &B64,
    wrapped: &B64,
) -> Result<Key> {
    crypto::unwrap_key(kek, &slot_aad(&header.vault_id, kind), &nonce.0, &wrapped.0)
        .map_err(|_| Error::UnlockFailed)
}

/// Wrap `vmk` for a slot of `kind` in the vault `vault_id`.
pub fn wrap_slot(vault_id: &str, kind: &str, kek: &Key, vmk: &Key) -> Result<(B64, B64)> {
    let (nonce, ct) = crypto::wrap_key(kek, &slot_aad(vault_id, kind), vmk)?;
    Ok((nonce.into(), ct.into()))
}

/// Derive the password key `PW = Argon2id(password, kdf.salt)`; opaque failure.
pub fn password_key(header: &Header, password: &str) -> Result<Key> {
    header
        .kdf
        .derive(password.as_bytes())
        .map_err(|_| Error::UnlockFailed)
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

/// Wrap a freshly unwrapped VMK and check the header MAC against it.
pub fn unlocked(header: &Header, vmk: Key) -> UnlockedKey {
    let header_intact = header.verify_mac(&vmk);
    UnlockedKey { vmk, header_intact }
}

pub struct NewVault {
    pub header: Header,
    pub key: UnlockedKey,
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

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn recovery_kek(kdf: &Kdf, phrase: &str, salt: &[u8]) -> Result<Key> {
    let rk = kdf.derive_with_salt(phrase.as_bytes(), salt)?;
    Ok(crypto::hkdf(rk.as_ref(), &kek_info("recovery")))
}

fn recovery_slot(vault_id: &str, kdf: &Kdf, phrase: &str, vmk: &Key) -> Result<Slot> {
    let rsalt = crypto::random_bytes::<16>();
    let rkek = recovery_kek(kdf, phrase, &rsalt)?;
    let (nonce, wrapped_vmk) = wrap_slot(vault_id, "recovery", &rkek, vmk)?;
    Ok(Slot::Recovery {
        salt: rsalt.into(),
        nonce,
        wrapped_vmk,
    })
}

/// In-memory state of a vault being created (lives only in Rust memory; the
/// UI holds just an opaque draft id). Secrets are zeroized on drop.
pub struct Draft {
    vault_id: String,
    name: String,
    browser: Browser,
    kdf: Kdf,
    vmk: Key,
    pw: Option<Key>,
    slots: Vec<Slot>,
    recovery_phrase: Option<Zeroizing<String>>,
    recovery_verified: bool,
    /// TOTP setup awaiting confirmation with a first code (see `totp`).
    pub(crate) pending_totp: Option<crate::totp::PendingTotp>,
}

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("vault_id", &self.vault_id)
            .field("name", &self.name)
            .field("browser", &self.browser)
            .field("secrets", &Redacted)
            .finish()
    }
}

impl Draft {
    pub fn new(name: &str, browser: Browser, cost: KdfCost) -> Result<Draft> {
        validate_name(name)?;
        Ok(Draft {
            vault_id: new_vault_id(),
            name: name.trim().to_string(),
            browser,
            kdf: Kdf {
                alg: "argon2id".into(),
                m_kib: cost.m_kib,
                t: cost.t,
                p: cost.p,
                salt: crypto::random_bytes::<16>().into(),
            },
            vmk: crypto::random_key(),
            pw: None,
            slots: vec![],
            recovery_phrase: None,
            recovery_verified: false,
            pending_totp: None,
        })
    }

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn browser(&self) -> Browser {
        self.browser
    }
    pub fn set_name(&mut self, name: &str, browser: Browser) -> Result<()> {
        validate_name(name)?;
        self.name = name.trim().to_string();
        self.browser = browser;
        Ok(())
    }
    pub fn kdf(&self) -> &Kdf {
        &self.kdf
    }
    pub fn vmk(&self) -> &Key {
        &self.vmk
    }
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// Set (or reset) the password. Factor slots already wrapped under the old
    /// password are discarded, since their KEKs depend on it.
    pub fn set_password(&mut self, password: &str) -> Result<()> {
        validate_password(password)?;
        self.pw = Some(self.kdf.derive(password.as_bytes())?);
        self.slots.retain(|s| matches!(s, Slot::Recovery { .. }));
        self.pending_totp = None;
        Ok(())
    }

    /// `PW = Argon2id(password)` for factor modules.
    pub fn password_key(&self) -> Result<&Key> {
        self.pw
            .as_ref()
            .ok_or(Error::Invalid("set the password first"))
    }

    /// Wrap this draft's VMK for a slot of `kind` under `kek`.
    pub fn wrap(&self, kind: &str, kek: &Key) -> Result<(B64, B64)> {
        wrap_slot(&self.vault_id, kind, kek, &self.vmk)
    }

    pub fn add_slot(&mut self, slot: Slot) {
        self.slots.push(slot);
    }

    pub fn has_second_factor(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, Slot::Fido2 { .. } | Slot::Totp { .. }))
    }

    /// Generate (or regenerate) the recovery phrase and its slot. Returns the 24 words.
    pub fn generate_recovery(&mut self) -> Result<Vec<Zeroizing<String>>> {
        let phrase = recovery::generate()?;
        let slot = recovery_slot(&self.vault_id, &self.kdf, &phrase, &self.vmk)?;
        self.slots.retain(|s| !matches!(s, Slot::Recovery { .. }));
        self.slots.push(slot);
        let words = recovery::words(&phrase);
        self.recovery_phrase = Some(phrase);
        self.recovery_verified = false;
        Ok(words)
    }

    /// SPEC §4: the user types back 3 random words (1-based positions).
    pub fn verify_recovery(&mut self, answers: &[(usize, &str)]) -> bool {
        let ok = self
            .recovery_phrase
            .as_ref()
            .is_some_and(|p| answers.len() >= 3 && recovery::verify_answers(p, answers));
        if ok {
            self.recovery_verified = true;
        }
        ok
    }

    pub fn recovery_verified(&self) -> bool {
        self.recovery_verified
    }

    /// The phrase, for the CLI's one-time display. `None` before generation.
    pub fn recovery_phrase(&self) -> Option<&str> {
        self.recovery_phrase.as_deref().map(String::as_str)
    }

    /// TEST ONLY: add the temporary password-only slot (KEK = HKDF(PW)).
    #[cfg(any(test, feature = "test-password-slot"))]
    pub fn add_password_only_slot(&mut self) -> Result<()> {
        let kek = factor_kek(self.password_key()?, &[], "password");
        let (nonce, wrapped_vmk) = self.wrap("password", &kek)?;
        self.slots.push(Slot::Password { nonce, wrapped_vmk });
        Ok(())
    }

    /// Build the sealed header. Requires the password, at least one unlock
    /// slot besides recovery, and a recovery slot. (The wizard additionally
    /// requires `recovery_verified()` before calling this.)
    pub fn finish(self, settings: VaultSettings) -> Result<NewVault> {
        self.password_key()?;
        let has_unlock_slot = self
            .slots
            .iter()
            .any(|s| !matches!(s, Slot::Recovery { .. }));
        if !has_unlock_slot {
            return Err(Error::Invalid("add a second factor first"));
        }
        if !self
            .slots
            .iter()
            .any(|s| matches!(s, Slot::Recovery { .. }))
        {
            return Err(Error::Invalid("generate the recovery phrase first"));
        }
        let mut header = Header {
            version: HEADER_VERSION,
            vault_id: self.vault_id.clone(),
            name: self.name.clone(),
            browser: self.browser,
            created_at: now_rfc3339(),
            kdf: self.kdf.clone(),
            slots: self.slots.clone(),
            settings,
            original: None,
            mac: B64::default(),
        };
        header.seal_mac(&self.vmk)?;
        Ok(NewVault {
            header,
            key: UnlockedKey {
                vmk: self.vmk.clone(),
                header_intact: true,
            },
        })
    }
}

/// TEST ONLY: one-shot password-only vault (M1/M2 tests, E2E, CLI dev mode).
/// Returns the vault and its recovery phrase.
#[cfg(any(test, feature = "test-password-slot"))]
pub fn new_vault(
    name: &str,
    browser: Browser,
    password: &str,
    cost: KdfCost,
) -> Result<(NewVault, Zeroizing<String>)> {
    let mut d = Draft::new(name, browser, cost)?;
    d.set_password(password)?;
    d.add_password_only_slot()?;
    d.generate_recovery()?;
    let phrase = Zeroizing::new(d.recovery_phrase().unwrap_or_default().to_string());
    Ok((d.finish(VaultSettings::default())?, phrase))
}

/// TEST ONLY: unlock the temporary password-only slot. Not compiled into
/// release builds, so a shipped app can never open a password-only vault.
#[cfg(any(test, feature = "test-password-slot"))]
pub fn unlock_with_password(header: &Header, password: &str) -> Result<UnlockedKey> {
    let pw = password_key(header, password)?;
    let kek = factor_kek(&pw, &[], "password");
    for slot in &header.slots {
        if let Slot::Password { nonce, wrapped_vmk } = slot {
            if let Ok(vmk) = unwrap_slot(header, "password", &kek, nonce, wrapped_vmk) {
                return Ok(unlocked(header, vmk));
            }
        }
    }
    Err(Error::UnlockFailed)
}

/// Unlock with the 24-word recovery phrase alone.
pub fn unlock_with_recovery(header: &Header, phrase: &str) -> Result<UnlockedKey> {
    let phrase = recovery::normalize(phrase)?;
    for slot in &header.slots {
        if let Slot::Recovery {
            salt,
            nonce,
            wrapped_vmk,
        } = slot
        {
            let kek =
                recovery_kek(&header.kdf, &phrase, &salt.0).map_err(|_| Error::UnlockFailed)?;
            if let Ok(vmk) = unwrap_slot(header, "recovery", &kek, nonce, wrapped_vmk) {
                return Ok(unlocked(header, vmk));
            }
        }
    }
    Err(Error::UnlockFailed)
}

/// TEST ONLY (password slot): re-wrap the VMK under a new password. Factor
/// modules provide their own re-wrap, since they need the factor secret.
#[cfg(any(test, feature = "test-password-slot"))]
pub fn change_password(header: &mut Header, key: &UnlockedKey, new_password: &str) -> Result<()> {
    validate_password(new_password)?;
    // A fresh salt for the password KDF. The recovery slot depends only on
    // the cost parameters and its own salt, so it stays valid.
    header.kdf.salt = crypto::random_bytes::<16>().into();
    let pw = header.kdf.derive(new_password.as_bytes())?;
    let kek = factor_kek(&pw, &[], "password");
    let (nonce, wrapped_vmk) = wrap_slot(&header.vault_id, "password", &kek, &key.vmk)?;
    header.slots.retain(|s| !matches!(s, Slot::Password { .. }));
    header
        .slots
        .insert(0, Slot::Password { nonce, wrapped_vmk });
    header.seal_mac(&key.vmk)
}

/// Replace the recovery slot with a new phrase; returns the new phrase.
pub fn new_recovery(header: &mut Header, key: &UnlockedKey) -> Result<Zeroizing<String>> {
    let phrase = recovery::generate()?;
    set_recovery(header, key, &phrase)?;
    Ok(phrase)
}

/// Replace the recovery slot with one for `phrase` (generated earlier with
/// [`recovery::generate`] and confirmed by the user) and re-seal the MAC.
/// Refuses a header that doesn't verify under this VMK.
pub fn set_recovery(header: &mut Header, key: &UnlockedKey, phrase: &str) -> Result<()> {
    if !header.verify_mac(&key.vmk) {
        return Err(Error::Invalid("header was modified outside the app"));
    }
    let phrase = recovery::normalize(phrase).map_err(|_| Error::Invalid("recovery phrase"))?;
    let slot = recovery_slot(&header.vault_id, &header.kdf, &phrase, &key.vmk)?;
    header.slots.retain(|s| !matches!(s, Slot::Recovery { .. }));
    header.slots.push(slot);
    header.seal_mac(&key.vmk)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    struct V {
        header: Header,
        key: UnlockedKey,
        recovery_phrase: Zeroizing<String>,
    }

    fn vault() -> V {
        let (nv, recovery_phrase) =
            new_vault("Work – Brave", Browser::Brave, PW, KdfCost::FAST).unwrap();
        V {
            header: nv.header,
            key: nv.key,
            recovery_phrase,
        }
    }

    #[test]
    fn draft_flow_requires_password_factor_and_recovery() {
        let mut d = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        assert!(d.password_key().is_err());
        assert!(d.add_password_only_slot().is_err());
        d.set_password(PW).unwrap();
        d.generate_recovery().unwrap();
        assert!(!d.has_second_factor());
        // Recovery alone is not enough.
        let mut d2 = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        d2.set_password(PW).unwrap();
        d2.generate_recovery().unwrap();
        assert!(d2.finish(VaultSettings::default()).is_err());
        // Factor without recovery is not enough.
        let mut d3 = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        d3.set_password(PW).unwrap();
        d3.add_password_only_slot().unwrap();
        assert!(d3.finish(VaultSettings::default()).is_err());

        d.add_password_only_slot().unwrap();
        let id = d.vault_id().to_string();
        let nv = d.finish(VaultSettings::default()).unwrap();
        assert_eq!(nv.header.vault_id, id);
        assert!(nv.header.verify_mac(nv.key.vmk()));
    }

    #[test]
    fn draft_password_reset_drops_factor_slots() {
        let mut d = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        d.generate_recovery().unwrap();
        d.add_password_only_slot().unwrap();
        d.set_password("another long password").unwrap();
        let kinds: Vec<_> = d.slots().iter().map(Slot::kind).collect();
        assert_eq!(kinds, ["recovery"]);
    }

    #[test]
    fn draft_recovery_verification() {
        let mut d = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        assert!(!d.verify_recovery(&[(1, "x"), (2, "y"), (3, "z")]));
        let words = d.generate_recovery().unwrap();
        assert_eq!(words.len(), 24);
        assert!(
            !d.verify_recovery(&[(1, words[0].as_str())]),
            "needs 3 words"
        );
        assert!(!d.verify_recovery(&[(1, words[0].as_str()), (2, words[1].as_str()), (3, "nope")]));
        assert!(!d.recovery_verified());
        assert!(d.verify_recovery(&[
            (1, words[0].as_str()),
            (5, words[4].as_str()),
            (24, words[23].as_str())
        ]));
        assert!(d.recovery_verified());
        // Regenerating resets verification.
        d.generate_recovery().unwrap();
        assert!(!d.recovery_verified());
    }

    #[test]
    fn draft_debug_is_redacted() {
        let mut d = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        let s = format!("{d:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains(PW));
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
    fn set_recovery_uses_given_phrase_and_checks_mac() {
        let mut v = vault();
        let k = unlock_with_password(&v.header, PW).unwrap();
        let p = recovery::generate().unwrap();
        set_recovery(&mut v.header, &k, &p).unwrap();
        assert!(unlock_with_recovery(&v.header, &p).is_ok());
        assert!(unlock_with_recovery(&v.header, &v.recovery_phrase).is_err());
        let mut t = v.header.clone();
        t.name = "evil".into();
        assert!(set_recovery(&mut t, &k, &p).is_err());
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
