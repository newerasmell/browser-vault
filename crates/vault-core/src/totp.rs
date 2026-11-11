//! TOTP second factor (SPEC §4.1). Milestone M3.
//!
//! Setup: a 160-bit seed (OsRng) is shown as an `otpauth://` QR; a Secure
//! Enclave key wraps both the seed and a random 32-byte `SE_secret`. The
//! slot's KEK is `factor_kek(PW, SE_secret, "totp")`.
//!
//! Unlock (order fixed by SPEC): password → Argon2id → SE unwraps the seed →
//! code check (±1 step, counter must be > `last_counter`) → SE unwraps
//! `SE_secret` → KEK → VMK.
//!
//! Counter state (`last_counter`, `failures`, `locked_until`) lives in the
//! slot and is MACed with `HKDF(seed, "bv-totp-state-v1")`, because a failed
//! attempt never learns the VMK. That state is excluded from the VMK header
//! MAC (`Header::mac_input`). An invalid state MAC fails closed: the slot is
//! put into the maximal lockout (see [`MAX_DELAY_SECS`]) and the attempt is
//! not evaluated; the state is rewritten with a valid MAC, so after the wait
//! the right password + code work again.
//!
//! Every failure is `Error::UnlockFailed`, except `Error::RateLimited`.

use totp_rs::{Algorithm, Builder, Secret, Totp};
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::header::{Header, Slot, B64};
use crate::keyslot::{self, factor_kek, Draft, UnlockedKey};
use crate::se::{SeKeyRef, SecureEnclave};

pub const STEP_SECS: u64 = 30;
pub const DIGITS: u8 = 6;
/// RFC 4226 §4 recommended seed length (160 bits).
pub const SEED_LEN: usize = 20;
pub const ISSUER: &str = "BrowserVault";
/// Failed attempts allowed before the first lockout.
pub const FREE_FAILURES: u32 = 5;
/// First lockout; doubles with every further failure.
pub const BASE_DELAY_SECS: u64 = 30;
/// Cap of the exponential lockout.
pub const MAX_DELAY_SECS: u64 = 3600;
/// Failure count used when the counter state MAC is invalid.
const TAMPERED_FAILURES: u32 = 64;
const KIND: &str = "totp";
const SE_SECRET_LEN: usize = 32;

/// Setup material held in the [`Draft`] until the first code confirms it.
pub struct PendingTotp {
    seed: Zeroizing<Vec<u8>>,
    se_secret: Key,
    key: SeKeyRef,
    wrapped_seed: Vec<u8>,
    wrapped_se_secret: Vec<u8>,
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

/// Lockout after the `failures`-th consecutive failure (0 = none).
pub fn delay_after(failures: u32) -> u64 {
    if failures < FREE_FAILURES {
        return 0;
    }
    let doublings = failures - FREE_FAILURES;
    if doublings >= 32 {
        return MAX_DELAY_SECS;
    }
    BASE_DELAY_SECS
        .saturating_mul(1u64 << doublings)
        .min(MAX_DELAY_SECS)
}

fn se_key_tag(vault_id: &str) -> String {
    format!("com.browservault.{vault_id}")
}

/// Context prefix inside each SE-encrypted plaintext. ECIES via SecKey has no
/// AAD, so this binds a blob to its vault and role (seed vs SE_secret).
fn se_context(vault_id: &str, what: &str) -> Vec<u8> {
    format!("bv-totp-v1|{vault_id}|{what}|").into_bytes()
}

fn se_wrap(
    se: &dyn SecureEnclave,
    key: &SeKeyRef,
    vault_id: &str,
    what: &str,
    secret: &[u8],
) -> Result<Vec<u8>> {
    let mut pt = Zeroizing::new(se_context(vault_id, what));
    pt.extend_from_slice(secret);
    se.encrypt(key, &pt)
}

fn se_unwrap(
    se: &dyn SecureEnclave,
    key: &SeKeyRef,
    vault_id: &str,
    what: &str,
    len: usize,
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let pt = se.decrypt(key, ct).map_err(|_| Error::UnlockFailed)?;
    let ctx = se_context(vault_id, what);
    if pt.len() != ctx.len() + len || !pt.starts_with(&ctx) {
        return Err(Error::UnlockFailed);
    }
    Ok(Zeroizing::new(pt[ctx.len()..].to_vec()))
}

/// The RFC 6238 generator for `seed` (SHA1, 6 digits, 30 s). Skew 0: the
/// ±1 window is walked explicitly so the matched counter is known.
fn generator(seed: &[u8], account: Option<&str>) -> Result<Totp> {
    let mut b = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(0)
        .with_step_duration(STEP_SECS)
        .with_secret(Secret::from(seed));
    if let Some(a) = account {
        b = b.with_account_name(a).with_issuer(Some(ISSUER));
    }
    b.build().map_err(|_| Error::Invalid("TOTP parameters"))
}

/// The counter of the code if it is valid within ±1 step of `now` and newer
/// than `last_counter` (anti-replay).
fn matching_counter(seed: &[u8], code: &str, now: u64, last_counter: u64) -> Option<u64> {
    let code: Zeroizing<String> = Zeroizing::new(code.chars().filter(|c| *c != ' ').collect());
    let totp = generator(seed, None).ok()?;
    let t = now / STEP_SECS;
    let mut found = None;
    // Walk the whole window (no early exit) to keep timing independent of
    // which step matched.
    for c in t.saturating_sub(1)..=t.saturating_add(1) {
        let ok = totp.check(&code, c.saturating_mul(STEP_SECS)).is_some();
        if ok && c > last_counter && found.is_none() {
            found = Some(c);
        }
    }
    found
}

/// The `otpauth://` label must not contain ':'.
fn account_name(vault_name: &str) -> String {
    let n: String = vault_name.replace(':', "-");
    if n.trim().is_empty() {
        "vault".into()
    } else {
        n
    }
}

/// Generate the seed, SE key and SE_secret; keep them pending in the draft.
pub fn begin(draft: &mut Draft, se: &dyn SecureEnclave) -> Result<TotpSetup> {
    draft.password_key()?;
    if draft.slots().iter().any(|s| matches!(s, Slot::Totp { .. })) {
        return Err(Error::Invalid("the authenticator is already set up"));
    }
    if let Some(old) = draft.pending_totp.take() {
        let _ = se.delete_key(&old.key);
    }
    let (setup, pending) = prepare(draft.vault_id(), draft.name(), se)?;
    draft.pending_totp = Some(pending);
    Ok(setup)
}

/// New seed, SE key and SE_secret, wrapped and round-trip checked, plus the
/// QR / manual key to show. Shared by the wizard and "replace authenticator".
fn prepare(
    vault_id: &str,
    vault_name: &str,
    se: &dyn SecureEnclave,
) -> Result<(TotpSetup, PendingTotp)> {
    let seed = Zeroizing::new(crypto::random_bytes::<SEED_LEN>().to_vec());
    let se_secret = crypto::random_key();
    let key = se.create_key(&se_key_tag(vault_id))?;

    let result = (|| {
        let wrapped_seed = se_wrap(se, &key, vault_id, "seed", &seed)?;
        let wrapped_se_secret = se_wrap(se, &key, vault_id, "se_secret", se_secret.as_ref())?;
        // Prove the SE can open what it wrapped before the user scans the QR:
        // a vault whose blobs cannot be unwrapped would be unopenable.
        let s = se_unwrap(se, &key, vault_id, "seed", SEED_LEN, &wrapped_seed);
        let k = se_unwrap(
            se,
            &key,
            vault_id,
            "se_secret",
            SE_SECRET_LEN,
            &wrapped_se_secret,
        );
        match (s, k) {
            (Ok(s), Ok(k)) if *s == *seed && k.as_slice() == se_secret.as_ref() => {}
            _ => {
                return Err(Error::Command {
                    tool: "Secure Enclave",
                    detail: "round trip check failed".into(),
                })
            }
        }
        let totp = generator(&seed, Some(&account_name(vault_name)))?;
        let uri = Zeroizing::new(
            totp.to_url()
                .map_err(|_| Error::Invalid("TOTP parameters"))?,
        );
        let secret = Zeroizing::new(totp.secret().to_base32());
        let qr_svg = Zeroizing::new(
            qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
                .map_err(|_| Error::Invalid("QR code"))?
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(240, 240)
                .build(),
        );
        Ok((wrapped_seed, wrapped_se_secret, secret, uri, qr_svg))
    })();
    let (wrapped_seed, wrapped_se_secret, secret, uri, qr_svg) = match result {
        Ok(v) => v,
        Err(e) => {
            let _ = se.delete_key(&key);
            return Err(e);
        }
    };
    Ok((
        TotpSetup {
            secret,
            uri,
            qr_svg,
        },
        PendingTotp {
            seed,
            se_secret,
            key,
            wrapped_seed,
            wrapped_se_secret,
        },
    ))
}

/// Settings → "replace authenticator" (e.g. new phone), step 1: fresh
/// seed + SE key for an existing vault. Nothing is written yet.
pub fn replace_begin(header: &Header, se: &dyn SecureEnclave) -> Result<(TotpSetup, PendingTotp)> {
    if slot_data(header).is_none() {
        return Err(Error::Invalid("vault has no authenticator slot"));
    }
    prepare(&header.vault_id, &header.name, se)
}

/// Step 2: the first code from the new app confirms it; the VMK is re-wrapped
/// under PW ‖ new SE_secret and the old TOTP slot is replaced.
///
/// `password` must be the password that just produced `key` (the app
/// re-authenticates with password + current code right before).
pub fn replace_confirm(
    header: &mut Header,
    key: &UnlockedKey,
    password: &str,
    pending: &PendingTotp,
    code: &str,
    now: u64,
) -> Result<()> {
    if !header.verify_mac(key.vmk()) {
        return Err(Error::Invalid("header was modified outside the app"));
    }
    let d = slot_data(header).ok_or(Error::Invalid("vault has no authenticator slot"))?;
    let counter = matching_counter(&pending.seed, code, now, 0).ok_or(Error::UnlockFailed)?;
    let pw = keyslot::password_key(header, password)?;
    let kek = factor_kek(&pw, pending.se_secret.as_ref(), KIND);
    let (nonce, wrapped_vmk) = keyslot::wrap_slot(&header.vault_id, KIND, &kek, key.vmk())?;
    let state = State {
        last_counter: counter,
        failures: 0,
        locked_until: 0,
    };
    header.slots[d.index] = Slot::Totp {
        se_key_tag: pending.key.tag.clone(),
        se_key_blob: pending.key.blob.clone().map(B64),
        wrapped_se_secret: B64(pending.wrapped_se_secret.clone()),
        wrapped_seed: B64(pending.wrapped_seed.clone()),
        last_counter: state.last_counter,
        failures: state.failures,
        locked_until: state.locked_until,
        state_mac: state_mac(&pending.seed, &header.vault_id, &state),
        nonce,
        wrapped_vmk,
    };
    header.seal_mac(key.vmk())
}

/// Counter state of a TOTP slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    last_counter: u64,
    failures: u32,
    locked_until: u64,
}

fn state_key(seed: &[u8]) -> Key {
    crypto::hkdf(seed, b"bv-totp-state-v1")
}

fn state_mac_input(vault_id: &str, s: &State) -> Vec<u8> {
    format!(
        "bv-totp-state-v1|{vault_id}|{}|{}|{}",
        s.last_counter, s.failures, s.locked_until
    )
    .into_bytes()
}

fn state_mac(seed: &[u8], vault_id: &str, s: &State) -> B64 {
    B64(crypto::hmac_sha256(&state_key(seed), &state_mac_input(vault_id, s)).to_vec())
}

/// Verify the first code from the user's app, then add the `totp` slot.
pub fn confirm(draft: &mut Draft, code: &str, _se: &dyn SecureEnclave, now: u64) -> Result<()> {
    let p = draft
        .pending_totp
        .as_ref()
        .ok_or(Error::Invalid("start the authenticator setup first"))?;
    let counter = matching_counter(&p.seed, code, now, 0).ok_or(Error::UnlockFailed)?;
    let kek = factor_kek(draft.password_key()?, p.se_secret.as_ref(), KIND);
    let (nonce, wrapped_vmk) = draft.wrap(KIND, &kek)?;
    let state = State {
        last_counter: counter,
        failures: 0,
        locked_until: 0,
    };
    let slot = Slot::Totp {
        se_key_tag: p.key.tag.clone(),
        se_key_blob: p.key.blob.clone().map(B64),
        wrapped_se_secret: B64(p.wrapped_se_secret.clone()),
        wrapped_seed: B64(p.wrapped_seed.clone()),
        last_counter: state.last_counter,
        failures: state.failures,
        locked_until: state.locked_until,
        state_mac: state_mac(&p.seed, draft.vault_id(), &state),
        nonce,
        wrapped_vmk,
    };
    draft.add_slot(slot);
    draft.pending_totp = None;
    Ok(())
}

/// New Mac / forgotten password: after unlocking with the RECOVERY PHRASE
/// (`key`), set a new password AND a new authenticator bound to this Mac's
/// Secure Enclave in one step. `pending` comes from [`replace_begin`]; the
/// first code from the new app confirms it. The old TOTP slot (whose SE key
/// may live on another Mac) is replaced.
pub fn reset_with_recovery(
    header: &mut Header,
    key: &UnlockedKey,
    new_password: &str,
    pending: &PendingTotp,
    code: &str,
    now: u64,
) -> Result<()> {
    keyslot::validate_password(new_password)?;
    if !header.verify_mac(key.vmk()) {
        return Err(Error::Invalid("header was modified outside the app"));
    }
    if header
        .slots
        .iter()
        .any(|s| !matches!(s, Slot::Totp { .. } | Slot::Recovery { .. }))
    {
        return Err(Error::Unsupported(
            "authenticator reset for vaults with other factors",
        ));
    }
    let d = slot_data(header).ok_or(Error::Invalid("vault has no authenticator slot"))?;
    let counter = matching_counter(&pending.seed, code, now, 0).ok_or(Error::UnlockFailed)?;
    let mut kdf = header.kdf.clone();
    kdf.salt = crypto::random_bytes::<16>().into();
    let pw = kdf.derive(new_password.as_bytes())?;
    let kek = factor_kek(&pw, pending.se_secret.as_ref(), KIND);
    let (nonce, wrapped_vmk) = keyslot::wrap_slot(&header.vault_id, KIND, &kek, key.vmk())?;
    let state = State {
        last_counter: counter,
        failures: 0,
        locked_until: 0,
    };
    header.kdf = kdf;
    header.slots[d.index] = Slot::Totp {
        se_key_tag: pending.key.tag.clone(),
        se_key_blob: pending.key.blob.clone().map(B64),
        wrapped_se_secret: B64(pending.wrapped_se_secret.clone()),
        wrapped_seed: B64(pending.wrapped_seed.clone()),
        last_counter: state.last_counter,
        failures: state.failures,
        locked_until: state.locked_until,
        state_mac: state_mac(&pending.seed, &header.vault_id, &state),
        nonce,
        wrapped_vmk,
    };
    header.seal_mac(key.vmk())
}

/// Immutable parts of the TOTP slot, copied out so the header can be mutated.
struct SlotData {
    index: usize,
    key: SeKeyRef,
    wrapped_seed: Vec<u8>,
    wrapped_se_secret: Vec<u8>,
    nonce: B64,
    wrapped_vmk: B64,
    state: State,
    state_mac: Vec<u8>,
}

fn slot_data(header: &Header) -> Option<SlotData> {
    header
        .slots
        .iter()
        .enumerate()
        .find_map(|(index, s)| match s {
            Slot::Totp {
                se_key_tag,
                se_key_blob,
                wrapped_se_secret,
                wrapped_seed,
                last_counter,
                failures,
                locked_until,
                state_mac,
                nonce,
                wrapped_vmk,
            } => Some(SlotData {
                index,
                key: SeKeyRef {
                    tag: se_key_tag.clone(),
                    blob: se_key_blob.as_ref().map(|b| b.0.clone()),
                },
                wrapped_seed: wrapped_seed.0.clone(),
                wrapped_se_secret: wrapped_se_secret.0.clone(),
                nonce: nonce.clone(),
                wrapped_vmk: wrapped_vmk.clone(),
                state: State {
                    last_counter: *last_counter,
                    failures: *failures,
                    locked_until: *locked_until,
                },
                state_mac: state_mac.0.clone(),
            }),
            _ => None,
        })
}

fn store_state(header: &mut Header, index: usize, seed: &[u8], s: State) {
    let mac = state_mac(seed, &header.vault_id, &s);
    if let Some(Slot::Totp {
        last_counter,
        failures,
        locked_until,
        state_mac,
        ..
    }) = header.slots.get_mut(index)
    {
        *last_counter = s.last_counter;
        *failures = s.failures;
        *locked_until = s.locked_until;
        *state_mac = mac;
    }
}

/// Record one failed attempt and start a lockout if due.
fn fail(header: &mut Header, d: &SlotData, seed: &[u8], mut s: State, now: u64) -> Error {
    s.failures = s.failures.saturating_add(1);
    let delay = delay_after(s.failures);
    if delay > 0 {
        s.locked_until = now.saturating_add(delay);
    }
    store_state(header, d.index, seed, s);
    Error::UnlockFailed
}

/// Unlock: password → SE unwraps seed → code check (±1 step, anti-replay,
/// rate limit) → SE unwraps SE_secret → KEK → VMK. Mutates the slot's
/// counters; the caller must save the header whatever the result.
pub fn unlock(
    header: &mut Header,
    password: &str,
    code: &str,
    se: &dyn SecureEnclave,
    now: u64,
) -> Result<UnlockedKey> {
    let d = slot_data(header).ok_or(Error::UnlockFailed)?;

    // Cheap early refusal on the not-yet-verified lockout. Values beyond the
    // maximal lockout can only come from tampering (or a clock change) and
    // are left to the verified path below, so they cannot lock the user out
    // for good.
    let lu = d.state.locked_until;
    if lu > now && lu - now <= MAX_DELAY_SECS {
        return Err(Error::RateLimited {
            retry_after: lu - now,
        });
    }

    // 1. password → Argon2id.
    let pw = keyslot::password_key(header, password);

    // 2. SE unwraps the seed (fails on any other Mac; nothing to record then).
    let seed = se_unwrap(
        se,
        &d.key,
        &header.vault_id,
        "seed",
        SEED_LEN,
        &d.wrapped_seed,
    )?;

    // Counter state integrity: fail closed into the maximal lockout.
    let mac_ok = crypto::hmac_sha256_verify(
        &state_key(&seed),
        &state_mac_input(&header.vault_id, &d.state),
        &d.state_mac,
    );
    let t = now / STEP_SECS;
    if !mac_ok {
        let s = State {
            last_counter: d.state.last_counter.max(t.saturating_add(1)),
            failures: TAMPERED_FAILURES,
            locked_until: now.saturating_add(MAX_DELAY_SECS),
        };
        store_state(header, d.index, &seed, s);
        return Err(Error::RateLimited {
            retry_after: MAX_DELAY_SECS,
        });
    }
    let mut state = d.state;
    if state.locked_until > now {
        let wait = state.locked_until - now;
        if wait > MAX_DELAY_SECS {
            // Clock moved backwards: never wait longer than the cap.
            state.locked_until = now + MAX_DELAY_SECS;
            store_state(header, d.index, &seed, state);
        }
        return Err(Error::RateLimited {
            retry_after: wait.min(MAX_DELAY_SECS),
        });
    }

    // 3. Code check, ±1 step, strictly newer than the last accepted counter.
    let Some(counter) = matching_counter(&seed, code, now, state.last_counter) else {
        return Err(fail(header, &d, &seed, state, now));
    };
    // The code is consumed even if the password turns out wrong below.
    state.last_counter = counter;

    // 4. Only now: SE unwraps SE_secret → KEK → VMK.
    let vmk = (|| {
        let pw = pw.map_err(|_| Error::UnlockFailed)?;
        let se_secret = se_unwrap(
            se,
            &d.key,
            &header.vault_id,
            "se_secret",
            SE_SECRET_LEN,
            &d.wrapped_se_secret,
        )?;
        let kek = factor_kek(&pw, &se_secret, KIND);
        keyslot::unwrap_slot(header, KIND, &kek, &d.nonce, &d.wrapped_vmk)
    })();
    let vmk = match vmk {
        Ok(v) => v,
        Err(_) => return Err(fail(header, &d, &seed, state, now)),
    };

    state.failures = 0;
    state.locked_until = 0;
    store_state(header, d.index, &seed, state);
    let key = keyslot::unlocked(header, vmk);
    if key.header_intact {
        // Counter state is outside the VMK MAC, so this only refreshes it;
        // a tampered header is never re-sealed (the UI must still warn).
        header.seal_mac(key.vmk())?;
    }
    Ok(key)
}

/// Re-wrap the VMK of a TOTP vault under a new password (SPEC §4: the
/// container is not re-encrypted). Needs this Mac's SE for `SE_secret`.
/// Refused for vaults with other password-bound slots (they would break).
pub fn change_password(
    header: &mut Header,
    key: &UnlockedKey,
    new_password: &str,
    se: &dyn SecureEnclave,
) -> Result<()> {
    keyslot::validate_password(new_password)?;
    if header
        .slots
        .iter()
        .any(|s| !matches!(s, Slot::Totp { .. } | Slot::Recovery { .. }))
    {
        return Err(Error::Unsupported(
            "password change for vaults with other factors",
        ));
    }
    let d = slot_data(header).ok_or(Error::Invalid("vault has no authenticator slot"))?;
    let se_secret = se_unwrap(
        se,
        &d.key,
        &header.vault_id,
        "se_secret",
        SE_SECRET_LEN,
        &d.wrapped_se_secret,
    )?;
    let mut kdf = header.kdf.clone();
    kdf.salt = crypto::random_bytes::<16>().into();
    let pw = kdf.derive(new_password.as_bytes())?;
    let kek = factor_kek(&pw, &se_secret, KIND);
    let (n, w) = keyslot::wrap_slot(&header.vault_id, KIND, &kek, key.vmk())?;
    header.kdf = kdf;
    if let Some(Slot::Totp {
        nonce, wrapped_vmk, ..
    }) = header.slots.get_mut(d.index)
    {
        *nonce = n;
        *wrapped_vmk = w;
    }
    header.seal_mac(key.vmk())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::Browser;
    use crate::header::VaultSettings;
    use crate::keyslot::{unlock_with_recovery, KdfCost};
    use crate::se::MockSecureEnclave;

    const PW: &str = "correct horse battery";
    /// An arbitrary fixed "now" in the middle of a 30 s step.
    const T0: u64 = 1_800_000_015;

    struct V {
        header: Header,
        seed: Vec<u8>,
        phrase: String,
        se: MockSecureEnclave,
        vmk: Key,
    }

    fn code_at(seed: &[u8], time: u64) -> String {
        generator(seed, None).unwrap().generate(time).to_string()
    }

    fn vault_with(se: MockSecureEnclave, name: &str) -> V {
        let mut d = Draft::new(name, Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        let setup = begin(&mut d, &se).unwrap();
        let seed = Secret::try_from_base32(setup.secret.as_str())
            .unwrap()
            .as_bytes()
            .to_vec();
        // Setup consumes the code of step T0 - 60 s.
        confirm(&mut d, &code_at(&seed, T0 - 60), &se, T0 - 60).unwrap();
        d.generate_recovery().unwrap();
        let phrase = d.recovery_phrase().unwrap().to_string();
        let nv = d.finish(VaultSettings::default()).unwrap();
        V {
            header: nv.header,
            seed,
            phrase,
            se,
            vmk: nv.key.vmk().clone(),
        }
    }

    fn vault() -> V {
        vault_with(MockSecureEnclave::new(), "Work – Brave")
    }

    fn state(h: &Header) -> State {
        slot_data(h).unwrap().state
    }

    #[test]
    fn recovery_reset_on_another_mac() {
        let v = vault();
        // "New Mac": a different Secure Enclave can't open the old slot.
        let other_mac = MockSecureEnclave::new();
        let mut h = v.header.clone();
        assert!(unlock(&mut h, PW, &code_at(&v.seed, T0), &other_mac, T0).is_err());
        let mut h = v.header.clone();
        let key = unlock_with_recovery(&h, &v.phrase).unwrap();
        let (setup, pending) = replace_begin(&h, &other_mac).unwrap();
        let seed = Secret::try_from_base32(setup.secret.as_str())
            .unwrap()
            .as_bytes()
            .to_vec();
        assert!(
            reset_with_recovery(&mut h, &key, "short", &pending, &code_at(&seed, T0), T0).is_err()
        );
        reset_with_recovery(
            &mut h,
            &key,
            "new mac passphrase",
            &pending,
            &code_at(&seed, T0),
            T0,
        )
        .unwrap();
        assert!(h.verify_mac(key.vmk()));
        let mut h2 = h.clone();
        assert!(unlock(&mut h2, PW, &code_at(&seed, T0 + 60), &other_mac, T0 + 60).is_err());
        let mut h2 = h.clone();
        let k2 = unlock(
            &mut h2,
            "new mac passphrase",
            &code_at(&seed, T0 + 60),
            &other_mac,
            T0 + 60,
        )
        .unwrap();
        assert_eq!(**k2.vmk(), *v.vmk);
        assert!(unlock_with_recovery(&h, &v.phrase).is_ok());
    }

    #[test]
    fn replace_authenticator_switches_seed() {
        let mut v = vault();
        let mut h = v.header.clone();
        let key = unlock(&mut h, PW, &code_at(&v.seed, T0), &v.se, T0).unwrap();
        v.header = h;
        let (setup, pending) = replace_begin(&v.header, &v.se).unwrap();
        let new_seed = Secret::try_from_base32(setup.secret.as_str())
            .unwrap()
            .as_bytes()
            .to_vec();
        // Wrong code: nothing changes.
        let before = v.header.clone();
        assert!(
            replace_confirm(&mut v.header, &key, PW, &pending, "000000", T0 + 30).is_err()
                || code_at(&new_seed, T0 + 30) == "000000"
        );
        assert_eq!(v.header, before);
        replace_confirm(
            &mut v.header,
            &key,
            PW,
            &pending,
            &code_at(&new_seed, T0 + 30),
            T0 + 30,
        )
        .unwrap();
        assert!(v.header.verify_mac(key.vmk()));
        // Old app's code no longer works; new app's does.
        let mut h = v.header.clone();
        assert!(unlock(&mut h, PW, &code_at(&v.seed, T0 + 90), &v.se, T0 + 90).is_err());
        let mut h = v.header.clone();
        let k2 = unlock(&mut h, PW, &code_at(&new_seed, T0 + 90), &v.se, T0 + 90).unwrap();
        assert_eq!(**k2.vmk(), *v.vmk);
        assert!(unlock_with_recovery(&v.header, &v.phrase).is_ok());
    }

    #[test]
    fn setup_uri_qr_and_secret() {
        let se = MockSecureEnclave::new();
        let mut d = Draft::new("Acme: Work", Browser::Brave, KdfCost::FAST).unwrap();
        assert!(begin(&mut d, &se).is_err(), "password first");
        d.set_password(PW).unwrap();
        let s = begin(&mut d, &se).unwrap();
        assert!(s
            .uri
            .starts_with("otpauth://totp/BrowserVault:Acme-%20Work?secret="));
        assert!(s.uri.contains(&format!("secret={}", s.secret.as_str())));
        assert!(s.uri.ends_with("&issuer=BrowserVault"));
        // SHA1 / 6 digits / 30 s are the defaults and therefore implicit.
        assert!(!s.uri.contains("algorithm=") && !s.uri.contains("period="));
        assert_eq!(s.secret.len(), 32, "160 bits base32 = 32 chars");
        assert!(s.qr_svg.starts_with("<?xml") && s.qr_svg.contains("<svg"));
        // A second begin replaces the pending seed.
        let s2 = begin(&mut d, &se).unwrap();
        assert_ne!(*s.secret, *s2.secret);
    }

    #[test]
    fn confirm_requires_right_code() {
        let se = MockSecureEnclave::new();
        let mut d = Draft::new("D", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        assert!(confirm(&mut d, "123456", &se, T0).is_err(), "begin first");
        let s = begin(&mut d, &se).unwrap();
        let seed = Secret::try_from_base32(s.secret.as_str()).unwrap();
        let seed = seed.as_bytes();
        assert!(matches!(
            confirm(&mut d, &code_at(seed, T0 - 300), &se, T0),
            Err(Error::UnlockFailed)
        ));
        assert!(!d.has_second_factor());
        confirm(&mut d, &code_at(seed, T0), &se, T0).unwrap();
        assert!(d.has_second_factor());
        assert!(begin(&mut d, &se).is_err(), "only one totp slot");
        // Resetting the password drops the slot.
        d.set_password("another long password").unwrap();
        assert!(!d.has_second_factor());
    }

    #[test]
    fn header_holds_no_plain_secrets() {
        let v = vault();
        let json = String::from_utf8(v.header.to_json().unwrap()).unwrap();
        let b32 = Secret::from(v.seed.as_slice()).to_base32();
        assert!(!json.contains(&b32));
        assert!(v.header.verify_mac(&v.vmk));
        let st = state(&v.header);
        assert_eq!(st.last_counter, (T0 - 60) / STEP_SECS);
        assert_eq!(st.failures, 0);
    }

    #[test]
    fn correct_code_unlocks() {
        let mut v = vault();
        let k = unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).unwrap();
        assert_eq!(**k.vmk(), *v.vmk);
        assert!(k.header_intact);
        assert!(v.header.verify_mac(&v.vmk));
        assert_eq!(state(&v.header).last_counter, T0 / STEP_SECS);
        // Spaces are tolerated ("123 456").
        let c = code_at(&v.seed, T0 + 30);
        let spaced = format!("{} {}", &c[..3], &c[3..]);
        assert!(unlock(&mut v.header, PW, &spaced, &v.se, T0 + 30).is_ok());
    }

    #[test]
    fn replayed_code_is_rejected() {
        let mut v = vault();
        let c = code_at(&v.seed, T0);
        unlock(&mut v.header, PW, &c, &v.se, T0).unwrap();
        assert!(matches!(
            unlock(&mut v.header, PW, &c, &v.se, T0 + 5),
            Err(Error::UnlockFailed)
        ));
        // An older (still in-window) code is rejected too.
        let older = code_at(&v.seed, T0 - 30);
        assert!(matches!(
            unlock(&mut v.header, PW, &older, &v.se, T0 + 5),
            Err(Error::UnlockFailed)
        ));
        // The setup code cannot be reused either.
        let mut w = vault();
        assert!(unlock(
            &mut w.header,
            PW,
            &code_at(&w.seed, T0 - 60),
            &w.se,
            T0 - 50
        )
        .is_err());
    }

    #[test]
    fn window_is_plus_minus_one_step() {
        for (offset, ok) in [
            (-60i64, false),
            (-30, true),
            (0, true),
            (30, true),
            (60, false),
        ] {
            let mut v = vault();
            let t = (T0 as i64 + offset) as u64;
            let r = unlock(&mut v.header, PW, &code_at(&v.seed, t), &v.se, T0);
            assert_eq!(r.is_ok(), ok, "offset {offset}");
        }
        // Accepting a +1 code moves the counter forward: the current code is now old.
        let mut v = vault();
        unlock(&mut v.header, PW, &code_at(&v.seed, T0 + 30), &v.se, T0).unwrap();
        assert!(unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).is_err());
    }

    #[test]
    fn wrong_password_with_right_code_fails_generically() {
        let mut v = vault();
        let c = code_at(&v.seed, T0);
        let e = unlock(&mut v.header, "wrong password!!", &c, &v.se, T0).unwrap_err();
        assert!(matches!(e, Error::UnlockFailed));
        assert_eq!(e.to_string(), "Unlock failed");
        assert_eq!(state(&v.header).failures, 1);
        // The code was consumed.
        assert!(unlock(&mut v.header, PW, &c, &v.se, T0).is_err());
        // Wrong code with right password: same error.
        let e = unlock(&mut v.header, PW, "000000", &v.se, T0).unwrap_err();
        assert!(matches!(e, Error::UnlockFailed));
        assert_eq!(state(&v.header).failures, 3);
        // Malformed codes are ordinary failures (the 5th starts the lockout).
        for bad in ["", "abcdef"] {
            assert!(matches!(
                unlock(&mut v.header, PW, bad, &v.se, T0),
                Err(Error::UnlockFailed)
            ));
        }
        for bad in ["12345", "1234567"] {
            assert!(matches!(
                unlock(&mut v.header, PW, bad, &v.se, T0),
                Err(Error::RateLimited { retry_after: 30 })
            ));
        }
        // Next step's code works and resets failures.
        assert!(unlock(
            &mut v.header,
            PW,
            &code_at(&v.seed, T0 + 30),
            &v.se,
            T0 + 30
        )
        .is_ok());
        assert_eq!(state(&v.header).failures, 0);
    }

    #[test]
    fn se_secret_is_unwrapped_only_after_a_valid_code() {
        let mut v = vault();
        let before = v.se.decrypt_calls();
        let _ = unlock(&mut v.header, PW, "000000", &v.se, T0);
        assert_eq!(v.se.decrypt_calls(), before + 1, "seed only");
        unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).unwrap();
        assert_eq!(v.se.decrypt_calls(), before + 3, "seed + SE_secret");
    }

    #[test]
    fn rate_limit_after_five_failures_and_grows() {
        let mut v = vault();
        let mut now = T0;
        for _ in 0..FREE_FAILURES {
            assert!(matches!(
                unlock(&mut v.header, PW, "000000", &v.se, now),
                Err(Error::UnlockFailed)
            ));
        }
        assert_eq!(state(&v.header).locked_until, now + 30);
        // Even the right code is not evaluated while locked.
        let good = code_at(&v.seed, now);
        assert!(matches!(
            unlock(&mut v.header, PW, &good, &v.se, now),
            Err(Error::RateLimited { retry_after: 30 })
        ));
        assert!(matches!(
            unlock(&mut v.header, PW, &good, &v.se, now + 10),
            Err(Error::RateLimited { retry_after: 20 })
        ));
        // Exponential growth: 60, 120, 240 s …
        for expected in [60, 120, 240, 480] {
            now = state(&v.header).locked_until;
            assert!(matches!(
                unlock(&mut v.header, PW, "000000", &v.se, now),
                Err(Error::UnlockFailed)
            ));
            assert_eq!(state(&v.header).locked_until - now, expected);
        }
        // Capped.
        assert_eq!(delay_after(5), 30);
        assert_eq!(delay_after(12), MAX_DELAY_SECS);
        assert_eq!(delay_after(u32::MAX), MAX_DELAY_SECS);
        assert_eq!(delay_after(4), 0);
        // After the wait the right code unlocks and resets the counter.
        now = state(&v.header).locked_until;
        assert!(unlock(&mut v.header, PW, &code_at(&v.seed, now), &v.se, now).is_ok());
        assert_eq!(state(&v.header).failures, 0);
        assert_eq!(state(&v.header).locked_until, 0);
    }

    #[test]
    fn header_stays_intact_after_failed_attempts() {
        let mut v = vault();
        for _ in 0..7 {
            let _ = unlock(&mut v.header, PW, "000000", &v.se, T0 + 4000);
        }
        let _ = unlock(
            &mut v.header,
            "nope nope nope",
            &code_at(&v.seed, T0),
            &v.se,
            T0,
        );
        assert!(v.header.verify_mac(&v.vmk));
        let k = unlock_with_recovery(&v.header, &v.phrase).unwrap();
        assert!(k.header_intact);
    }

    #[test]
    fn tampered_counter_state_fails_closed() {
        // Resetting the failure counter (or anything else) without the seed.
        let mut v = vault();
        for _ in 0..FREE_FAILURES {
            let _ = unlock(&mut v.header, PW, "000000", &v.se, T0);
        }
        if let Slot::Totp {
            failures,
            locked_until,
            ..
        } = &mut v.header.slots[0]
        {
            *failures = 0;
            *locked_until = 0;
        }
        let good = code_at(&v.seed, T0);
        assert!(matches!(
            unlock(&mut v.header, PW, &good, &v.se, T0),
            Err(Error::RateLimited {
                retry_after: MAX_DELAY_SECS
            })
        ));
        // Rewinding last_counter to replay a code: same.
        let mut v = vault();
        let c = code_at(&v.seed, T0);
        unlock(&mut v.header, PW, &c, &v.se, T0).unwrap();
        if let Slot::Totp { last_counter, .. } = &mut v.header.slots[0] {
            *last_counter = 0;
        }
        assert!(matches!(
            unlock(&mut v.header, PW, &c, &v.se, T0),
            Err(Error::RateLimited { .. })
        ));
        // A huge locked_until does not lock out forever.
        let mut v = vault();
        if let Slot::Totp { locked_until, .. } = &mut v.header.slots[0] {
            *locked_until = u64::MAX;
        }
        assert!(matches!(
            unlock(&mut v.header, PW, &good, &v.se, T0),
            Err(Error::RateLimited {
                retry_after: MAX_DELAY_SECS
            })
        ));
        // The state is re-MACed: after the wait the right code works.
        let later = T0 + MAX_DELAY_SECS;
        assert!(matches!(
            unlock(&mut v.header, PW, &code_at(&v.seed, later), &v.se, later),
            Ok(k) if k.header_intact
        ));
    }

    #[test]
    fn clock_moved_back_caps_the_wait() {
        let mut v = vault();
        for _ in 0..FREE_FAILURES {
            let _ = unlock(&mut v.header, PW, "000000", &v.se, T0 + 86_400);
        }
        // Clock now a day earlier: the remaining wait is capped, not a day.
        assert!(matches!(
            unlock(&mut v.header, PW, "000000", &v.se, T0),
            Err(Error::RateLimited {
                retry_after: MAX_DELAY_SECS
            })
        ));
        assert_eq!(state(&v.header).locked_until, T0 + MAX_DELAY_SECS);
    }

    #[test]
    fn slot_moved_between_vaults_fails() {
        let se = MockSecureEnclave::new();
        let a = vault_with(se, "A");
        let mut b = vault_with(MockSecureEnclave::new(), "B");
        // Same Mac (same SE), same password: graft A's slot into B.
        let se = a.se;
        b.header.slots[0] = a.header.slots[0].clone();
        b.header.kdf = a.header.kdf.clone();
        let r = unlock(&mut b.header, PW, &code_at(&a.seed, T0), &se, T0);
        assert!(matches!(r, Err(Error::UnlockFailed)));
    }

    #[test]
    fn se_blobs_are_bound_to_vault_and_role() {
        // Two vaults on the same Mac (same SE).
        let se = MockSecureEnclave::new();
        let a = vault_with(se, "A");
        let mut b = vault_with(MockSecureEnclave::new(), "B");
        let se = a.se;
        let (a_seed, a_sec, a_blob) = match &a.header.slots[0] {
            Slot::Totp {
                wrapped_seed,
                wrapped_se_secret,
                se_key_blob,
                ..
            } => (
                wrapped_seed.clone(),
                wrapped_se_secret.clone(),
                se_key_blob.clone(),
            ),
            _ => unreachable!(),
        };
        // A's wrapped seed inside B's slot (with A's SE key): context mismatch.
        if let Slot::Totp {
            wrapped_seed,
            se_key_blob,
            ..
        } = &mut b.header.slots[0]
        {
            *wrapped_seed = a_seed;
            *se_key_blob = a_blob.clone();
        }
        assert!(matches!(
            unlock(&mut b.header, PW, &code_at(&a.seed, T0), &se, T0),
            Err(Error::UnlockFailed)
        ));
        // Role swap inside A: SE_secret blob presented as the seed.
        let mut h = a.header.clone();
        if let Slot::Totp { wrapped_seed, .. } = &mut h.slots[0] {
            *wrapped_seed = a_sec;
        }
        assert!(matches!(
            unlock(&mut h, PW, &code_at(&a.seed, T0), &se, T0),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn other_mac_cannot_unlock() {
        let mut v = vault();
        let other_mac = MockSecureEnclave::new();
        let before = v.header.clone();
        let r = unlock(&mut v.header, PW, &code_at(&v.seed, T0), &other_mac, T0);
        assert!(matches!(r, Err(Error::UnlockFailed)));
        assert_eq!(v.header, before, "nothing recorded without the seed");
        // A copied header + the right everything still needs this Mac.
        assert!(unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).is_ok());
    }

    #[test]
    fn tampered_slot_fails() {
        let v = vault();
        type Mutation = Box<dyn Fn(&mut Slot)>;
        let muts: Vec<Mutation> = vec![
            Box::new(|s| {
                if let Slot::Totp { wrapped_vmk, .. } = s {
                    wrapped_vmk.0[0] ^= 1;
                }
            }),
            Box::new(|s| {
                if let Slot::Totp { wrapped_seed, .. } = s {
                    wrapped_seed.0[40] ^= 1;
                }
            }),
            Box::new(|s| {
                if let Slot::Totp {
                    wrapped_se_secret, ..
                } = s
                {
                    wrapped_se_secret.0[40] ^= 1;
                }
            }),
            Box::new(|s| {
                if let Slot::Totp { se_key_blob, .. } = s {
                    *se_key_blob = None;
                }
            }),
        ];
        for m in muts {
            let mut h = v.header.clone();
            m(&mut h.slots[0]);
            assert!(matches!(
                unlock(&mut h, PW, &code_at(&v.seed, T0), &v.se, T0),
                Err(Error::UnlockFailed)
            ));
        }
        // No totp slot at all.
        let mut h = v.header.clone();
        h.slots.retain(|s| !matches!(s, Slot::Totp { .. }));
        assert!(matches!(
            unlock(&mut h, PW, &code_at(&v.seed, T0), &v.se, T0),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn tampered_metadata_unlocks_but_is_flagged_and_not_resealed() {
        let mut v = vault();
        v.header.name = "Evil".into();
        let k = unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).unwrap();
        assert!(!k.header_intact);
        assert!(!v.header.verify_mac(&v.vmk), "tampering must stay visible");
    }

    #[test]
    fn recovery_still_works() {
        let mut v = vault();
        for _ in 0..10 {
            let _ = unlock(&mut v.header, PW, "000000", &v.se, T0);
        }
        let k = unlock_with_recovery(&v.header, &v.phrase).unwrap();
        assert_eq!(**k.vmk(), *v.vmk);
        assert!(k.header_intact);
    }

    #[test]
    fn change_password_rewraps() {
        let mut v = vault();
        let k = unlock(&mut v.header, PW, &code_at(&v.seed, T0), &v.se, T0).unwrap();
        assert!(change_password(&mut v.header, &k, "short", &v.se).is_err());
        assert!(change_password(
            &mut v.header,
            &k,
            "a brand new passphrase",
            &MockSecureEnclave::new()
        )
        .is_err());
        change_password(&mut v.header, &k, "a brand new passphrase", &v.se).unwrap();
        let t = T0 + 30;
        assert!(unlock(&mut v.header, PW, &code_at(&v.seed, t), &v.se, t).is_err());
        let t = T0 + 60;
        let k2 = unlock(
            &mut v.header,
            "a brand new passphrase",
            &code_at(&v.seed, t),
            &v.se,
            t,
        )
        .unwrap();
        assert_eq!(**k2.vmk(), *v.vmk);
        assert!(k2.header_intact);
        assert!(unlock_with_recovery(&v.header, &v.phrase).is_ok());
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238 Appendix B, SHA1 seed "12345678901234567890" (8 digits there;
        // the last 6 digits are the 6-digit code).
        let seed = b"12345678901234567890";
        for (t, code8) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
        ] {
            assert_eq!(code_at(seed, t), code8[2..]);
        }
    }
}
