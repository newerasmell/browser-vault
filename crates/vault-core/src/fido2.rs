//! YubiKey / FIDO2 hmac-secret second factor (SPEC §4.2). Milestone M4.
//!
//! Each registered key gets a `fido2` slot holding a *non-resident* credential
//! id (created with the `hmac-secret` extension under [`RP_ID`]) and a random
//! 32-byte `salt_fido`. KEK = HKDF(PW ‖ hmac-secret(credential, salt_fido)).
//! The PIN is always sent (user verification) and the key must be touched, so
//! the hmac-secret output is the "with UV" one, both at setup and at unlock.
//!
//! Unlock first asks every plugged-in key, silently (no touch, no PIN), which
//! of the vault's credential ids it holds; then it asks only that key for the
//! hmac-secret over that slot's salt (PIN + touch). This lets any registered
//! key (main or backup) answer even though every slot has its own salt.
//!
//! All slot logic talks to an [`Authenticator`]; the real USB HID backend
//! ([`system`]) uses `ctap-hid-fido2`. Tests use `MockAuthenticator`.

use std::fmt;

use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::events::{Event, Notify};
use crate::header::{Header, Slot, B64};
use crate::keyslot::UnlockedKey;
use crate::keyslot::{factor_kek, password_key, unlocked, unwrap_slot, wrap_slot, Draft};

/// WebAuthn relying-party id the credentials are scoped to. It is never
/// resolved over the network; it only has to be stable, since a credential is
/// usable only under the RP id it was created for. `.local` keeps it clearly
/// outside any real domain someone could own.
pub const RP_ID: &str = "browservault.local";
/// Slot kind (KEK domain separation and AAD).
pub const KIND: &str = "fido2";
pub const SALT_LEN: usize = 32;
pub const MAX_LABEL_CHARS: usize = 64;

/// Error messages the wizard / settings can match on (all `Error::Invalid`,
/// except [`ERR_UNSUPPORTED_KEY`] which is `Error::Unsupported`). They are
/// returned only while registering a key; unlock failures are always the
/// generic [`Error::UnlockFailed`].
pub const ERR_PIN_NOT_SET: &str = "the security key has no PIN; set a PIN first";
pub const ERR_UNSUPPORTED_KEY: &str = "this security key does not support FIDO2 hmac-secret";
pub const ERR_NO_KEY: &str = "no security key found; insert the key";
pub const ERR_MULTIPLE_KEYS: &str =
    "more than one security key is plugged in; leave only the one to register";
pub const ERR_ALREADY_REGISTERED: &str = "this security key is already registered for this vault";
pub const ERR_WRONG_PIN: &str = "wrong security key PIN";
pub const ERR_PIN_BLOCKED: &str = "the security key PIN is blocked";
pub const ERR_PIN_FORMAT: &str = "the PIN must be 4–63 characters";
pub const ERR_NO_TOUCH: &str = "the security key was not touched in time; try again";
pub const ERR_LABEL: &str = "the key label must be 1–64 printable characters";
pub const ERR_LABEL_TAKEN: &str = "a key with this label already exists";
pub const ERR_LAST_FACTOR: &str = "cannot remove the last key of the vault";
pub const ERR_UNKNOWN_LABEL: &str = "no key with this label";
pub const ERR_FOREIGN_KEY: &str = "the unlocked key does not match this vault";

/// What a single plugged-in key supports (CTAP `authenticatorGetInfo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Speaks CTAP2 (FIDO2), not only U2F.
    pub fido2: bool,
    /// Supports the `hmac-secret` extension.
    pub hmac_secret: bool,
    /// `clientPin` option: `Some(true)` set, `Some(false)` supported but not
    /// set, `None` unsupported.
    pub client_pin: Option<bool>,
}

/// Failure reported by an [`Authenticator`]. Never carries secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FidoError {
    /// No FIDO key plugged in.
    NoDevice,
    /// More than one key plugged in where exactly one is required.
    MultipleDevices,
    /// No plugged-in key holds the requested credential.
    NoCredential,
    PinInvalid,
    /// PIN retries exhausted (or blocked until re-plug).
    PinBlocked,
    PinNotSet,
    /// The key lacks FIDO2 / hmac-secret / clientPin.
    Unsupported,
    /// The key already holds a credential from the exclude list.
    Excluded,
    /// No touch in time, or the user declined.
    NoTouch,
    /// Anything else (transport, parse, unexpected status). No secrets.
    Other(String),
}

/// Abstraction over FIDO2 authenticators so the slot logic is testable
/// without hardware. All methods may block; the ones that need a touch block
/// until it happens (or the key times out, ~30 s on a YubiKey).
pub trait Authenticator: Send + Sync {
    /// Whether any FIDO key is currently plugged in (cheap enumeration).
    fn present(&self) -> bool;

    /// Capabilities of the single plugged-in key ([`FidoError::NoDevice`] /
    /// [`FidoError::MultipleDevices`] otherwise).
    fn info(&self) -> std::result::Result<DeviceInfo, FidoError>;

    /// Create a non-resident credential with `hmac-secret` on the single
    /// plugged-in key, verified with `pin`; needs a touch. Fails with
    /// [`FidoError::Excluded`] if the key holds a credential in `exclude`.
    /// Returns the credential id.
    fn make_credential(
        &self,
        rp_id: &str,
        pin: &str,
        exclude: &[Vec<u8>],
    ) -> std::result::Result<Vec<u8>, FidoError>;

    /// Silent probe (no PIN, no touch): the first id in `allow` held by any
    /// plugged-in key, or `None`.
    fn find_credential(
        &self,
        rp_id: &str,
        allow: &[Vec<u8>],
    ) -> std::result::Result<Option<Vec<u8>>, FidoError>;

    /// hmac-secret(credential, salt) from whichever plugged-in key holds
    /// `credential_id`, with PIN (user verification) and touch.
    fn hmac_secret(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        salt: &[u8; SALT_LEN],
        pin: &str,
    ) -> std::result::Result<Zeroizing<[u8; 32]>, FidoError>;
}

/// The real USB HID backend (`ctap-hid-fido2`).
pub fn system() -> Box<dyn Authenticator> {
    Box::new(hid::HidAuthenticator)
}

// ---------------------------------------------------------------------------
// Slot logic
// ---------------------------------------------------------------------------

/// A registered key, as listed for the UI (no secrets).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub label: String,
    pub credential_id: Vec<u8>,
}

impl fmt::Debug for KeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInfo")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// The vault's registered keys, in header order.
pub fn keys(header: &Header) -> Vec<KeyInfo> {
    keys_in(&header.slots)
}

fn keys_in(slots: &[Slot]) -> Vec<KeyInfo> {
    slots
        .iter()
        .filter_map(|s| match s {
            Slot::Fido2 {
                label,
                credential_id,
                ..
            } => Some(KeyInfo {
                label: label.clone(),
                credential_id: credential_id.0.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn credential_ids(slots: &[Slot]) -> Vec<Vec<u8>> {
    keys_in(slots)
        .into_iter()
        .map(|k| k.credential_id)
        .collect()
}

fn pin_well_formed(pin: &str) -> bool {
    // CTAP2: at least 4 code points, at most 63 bytes of UTF-8.
    pin.chars().count() >= 4 && pin.len() <= 63
}

fn validate_label(label: &str, slots: &[Slot]) -> Result<String> {
    let l = label.trim();
    if l.is_empty() || l.chars().count() > MAX_LABEL_CHARS || l.chars().any(char::is_control) {
        return Err(Error::Invalid(ERR_LABEL));
    }
    if keys_in(slots).iter().any(|k| k.label == l) {
        return Err(Error::Invalid(ERR_LABEL_TAKEN));
    }
    Ok(l.to_string())
}

/// Map an authenticator failure during *registration* to a user-facing error.
/// (Unlock never uses this: every unlock failure is `UnlockFailed`.)
fn setup_error(e: FidoError) -> Error {
    match e {
        FidoError::NoDevice | FidoError::NoCredential => Error::Invalid(ERR_NO_KEY),
        FidoError::MultipleDevices => Error::Invalid(ERR_MULTIPLE_KEYS),
        FidoError::PinInvalid => Error::Invalid(ERR_WRONG_PIN),
        FidoError::PinBlocked => Error::Invalid(ERR_PIN_BLOCKED),
        FidoError::PinNotSet => Error::Invalid(ERR_PIN_NOT_SET),
        FidoError::Unsupported => Error::Unsupported(ERR_UNSUPPORTED_KEY),
        FidoError::Excluded => Error::Invalid(ERR_ALREADY_REGISTERED),
        FidoError::NoTouch => Error::Invalid(ERR_NO_TOUCH),
        FidoError::Other(detail) => Error::Command {
            tool: "fido2",
            detail,
        },
    }
}

/// Run a touch-requiring operation between `FidoTouchNeeded` and
/// `FidoTouchDone` (the latter is emitted on failure too, so the UI overlay
/// always closes).
fn with_touch<T>(
    notify: Notify<'_>,
    op: impl FnOnce() -> std::result::Result<T, FidoError>,
) -> std::result::Result<T, FidoError> {
    notify(Event::FidoTouchNeeded);
    let r = op();
    notify(Event::FidoTouchDone);
    r
}

/// Create a credential on the plugged-in key and build its slot. `wrap`
/// wraps the VMK under the slot's KEK.
fn enroll(
    slots: &[Slot],
    pw: &Key,
    auth: &dyn Authenticator,
    pin: &str,
    label: &str,
    notify: Notify<'_>,
    wrap: impl FnOnce(&Key) -> Result<(B64, B64)>,
) -> Result<Slot> {
    let label = validate_label(label, slots)?;
    if !pin_well_formed(pin) {
        return Err(Error::Invalid(ERR_PIN_FORMAT));
    }
    let info = auth.info().map_err(setup_error)?;
    if !info.fido2 || !info.hmac_secret || info.client_pin.is_none() {
        return Err(Error::Unsupported(ERR_UNSUPPORTED_KEY));
    }
    if info.client_pin != Some(true) {
        return Err(Error::Invalid(ERR_PIN_NOT_SET));
    }
    // The same physical key must not be registered twice (main == backup
    // would defeat the backup). Checked silently before asking for a touch;
    // the exclude list makes the key enforce it as well.
    let existing = credential_ids(slots);
    if !existing.is_empty()
        && auth
            .find_credential(RP_ID, &existing)
            .map_err(setup_error)?
            .is_some()
    {
        return Err(Error::Invalid(ERR_ALREADY_REGISTERED));
    }
    let credential_id =
        with_touch(notify, || auth.make_credential(RP_ID, pin, &existing)).map_err(setup_error)?;
    // makeCredential does not return the hmac-secret output, so a second
    // assertion (second touch) computes it for the fresh salt.
    let salt = crypto::random_bytes::<SALT_LEN>();
    let secret = with_touch(notify, || {
        auth.hmac_secret(RP_ID, &credential_id, &salt, pin)
    })
    .map_err(setup_error)?;
    let kek = factor_kek(pw, secret.as_ref(), KIND);
    let (nonce, wrapped_vmk) = wrap(&kek)?;
    Ok(Slot::Fido2 {
        label,
        credential_id: credential_id.into(),
        salt: salt.into(),
        nonce,
        wrapped_vmk,
    })
}

/// Register a key (non-resident credential with hmac-secret) and add a
/// `fido2` slot to the draft. Returns the label. Needs two touches
/// (create credential, then compute the hmac-secret). Call again with a
/// second key for the recommended backup.
pub fn register(
    draft: &mut Draft,
    auth: &dyn Authenticator,
    pin: &str,
    label: &str,
    notify: Notify<'_>,
) -> Result<String> {
    let pw = draft.password_key()?;
    let slot = enroll(draft.slots(), pw, auth, pin, label, notify, |kek| {
        draft.wrap(KIND, kek)
    })?;
    let Slot::Fido2 { label, .. } = &slot else {
        unreachable!("enroll builds fido2 slots")
    };
    let label = label.clone();
    draft.add_slot(slot);
    Ok(label)
}

/// Unlock with password + any registered key (PIN + touch). Every failure
/// that depends on a credential (password, PIN, wrong/absent key, no touch)
/// is the generic [`Error::UnlockFailed`].
pub fn unlock(
    header: &Header,
    auth: &dyn Authenticator,
    password: &str,
    pin: &str,
    notify: Notify<'_>,
) -> Result<UnlockedKey> {
    let ids = credential_ids(&header.slots);
    if ids.is_empty() {
        return Err(Error::UnlockFailed);
    }
    let pw = password_key(header, password)?;
    if !pin_well_formed(pin) {
        return Err(Error::UnlockFailed);
    }
    let found = auth
        .find_credential(RP_ID, &ids)
        .ok()
        .flatten()
        .ok_or(Error::UnlockFailed)?;
    for slot in &header.slots {
        let Slot::Fido2 {
            credential_id,
            salt,
            nonce,
            wrapped_vmk,
            ..
        } = slot
        else {
            continue;
        };
        if credential_id.0 != found {
            continue;
        }
        let Ok(salt) = <[u8; SALT_LEN]>::try_from(salt.0.as_slice()) else {
            continue;
        };
        let secret = with_touch(notify, || auth.hmac_secret(RP_ID, &found, &salt, pin))
            .map_err(|_| Error::UnlockFailed)?;
        let kek = factor_kek(&pw, secret.as_ref(), KIND);
        if let Ok(vmk) = unwrap_slot(header, KIND, &kek, nonce, wrapped_vmk) {
            return Ok(unlocked(header, vmk));
        }
    }
    Err(Error::UnlockFailed)
}

fn check_key(header: &Header, key: &UnlockedKey) -> Result<()> {
    // Also refuses to re-seal a header modified outside the app.
    if header.verify_mac(key.vmk()) {
        Ok(())
    } else {
        Err(Error::Invalid(ERR_FOREIGN_KEY))
    }
}

/// Settings → "add YubiKey": register another (e.g. backup) key on an
/// existing, unlocked vault and re-seal the header. Returns the label.
///
/// `password` must be the password that just produced `key` (the app's
/// `add_fido2` flow unlocks and adds in one step with the same input): no
/// slot can verify the password on its own, and a mistyped one would yield
/// a slot that never opens.
pub fn add_key(
    header: &mut Header,
    key: &UnlockedKey,
    password: &str,
    auth: &dyn Authenticator,
    pin: &str,
    label: &str,
    notify: Notify<'_>,
) -> Result<String> {
    check_key(header, key)?;
    let pw = header
        .kdf
        .derive(password.as_bytes())
        .map_err(|_| Error::UnlockFailed)?;
    let vault_id = header.vault_id.clone();
    let slot = enroll(&header.slots, &pw, auth, pin, label, notify, |kek| {
        wrap_slot(&vault_id, KIND, kek, key.vmk())
    })?;
    let Slot::Fido2 { label, .. } = &slot else {
        unreachable!("enroll builds fido2 slots")
    };
    let label = label.clone();
    // Keep fido2 slots together, before recovery.
    let pos = header
        .slots
        .iter()
        .rposition(|s| matches!(s, Slot::Fido2 { .. }))
        .map_or(0, |i| i + 1);
    header.slots.insert(pos, slot);
    header.seal_mac(key.vmk())?;
    Ok(label)
}

/// Settings → remove a key by label and re-seal the header. Refuses to
/// remove the vault's last second factor.
pub fn remove_key(header: &mut Header, key: &UnlockedKey, label: &str) -> Result<()> {
    check_key(header, key)?;
    let idx = header
        .slots
        .iter()
        .position(|s| matches!(s, Slot::Fido2 { label: l, .. } if l == label))
        .ok_or(Error::Invalid(ERR_UNKNOWN_LABEL))?;
    let other_unlock_slots = header
        .slots
        .iter()
        .enumerate()
        .filter(|(i, s)| *i != idx && !matches!(s, Slot::Recovery { .. }))
        .count();
    if other_unlock_slots == 0 {
        return Err(Error::Invalid(ERR_LAST_FACTOR));
    }
    header.slots.remove(idx);
    header.seal_mac(key.vmk())
}

/// Password change for YubiKey vaults, one key at a time: the plugged-in
/// registered key (PIN + touch) gives its hmac-secret and the VMK is
/// re-wrapped under `new_pw` (derived by the caller from the NEW kdf).
/// Returns the credential id it handled and the new slot; nothing in
/// `header` changes until [`apply_password_change`].
pub fn rewrap_present(
    header: &Header,
    key: &UnlockedKey,
    new_pw: &Key,
    auth: &dyn Authenticator,
    pin: &str,
    notify: Notify<'_>,
) -> Result<(Vec<u8>, Slot)> {
    check_key(header, key)?;
    if !pin_well_formed(pin) {
        return Err(Error::Invalid(ERR_PIN_FORMAT));
    }
    let ids = credential_ids(&header.slots);
    let found = auth
        .find_credential(RP_ID, &ids)
        .map_err(setup_error)?
        .ok_or(Error::Invalid(ERR_NO_KEY))?;
    for slot in &header.slots {
        let Slot::Fido2 {
            label,
            credential_id,
            salt,
            ..
        } = slot
        else {
            continue;
        };
        if credential_id.0 != found {
            continue;
        }
        let salt_arr = <[u8; SALT_LEN]>::try_from(salt.0.as_slice())
            .map_err(|_| Error::Format("fido2 salt length".into()))?;
        let secret = with_touch(notify, || auth.hmac_secret(RP_ID, &found, &salt_arr, pin))
            .map_err(setup_error)?;
        let kek = factor_kek(new_pw, secret.as_ref(), KIND);
        let (nonce, wrapped_vmk) = wrap_slot(&header.vault_id, KIND, &kek, key.vmk())?;
        return Ok((
            found.clone(),
            Slot::Fido2 {
                label: label.clone(),
                credential_id: credential_id.clone(),
                salt: salt.clone(),
                nonce,
                wrapped_vmk,
            },
        ));
    }
    Err(Error::Invalid(ERR_NO_KEY))
}

/// Labels of registered keys whose credential id is not in `done`.
pub fn remaining_keys(header: &Header, done: &[Vec<u8>]) -> Vec<String> {
    header
        .slots
        .iter()
        .filter_map(|s| match s {
            Slot::Fido2 {
                label,
                credential_id,
                ..
            } if !done.contains(&credential_id.0) => Some(label.clone()),
            _ => None,
        })
        .collect()
}

/// Commit a password change once EVERY fido2 slot was re-wrapped with
/// [`rewrap_present`]: switch to `new_kdf` (new salt), replace the slots,
/// re-seal. Refuses if any registered key is missing from `rewrapped`.
pub fn apply_password_change(
    header: &mut Header,
    key: &UnlockedKey,
    new_kdf: crate::header::Kdf,
    rewrapped: Vec<Slot>,
) -> Result<()> {
    check_key(header, key)?;
    if header
        .slots
        .iter()
        .any(|s| matches!(s, Slot::Totp { .. } | Slot::Password { .. }))
    {
        return Err(Error::Unsupported(
            "password change for vaults with other factors",
        ));
    }
    let mut new_slots = Vec::with_capacity(header.slots.len());
    for s in &header.slots {
        match s {
            Slot::Fido2 { credential_id, .. } => {
                let r = rewrapped
                    .iter()
                    .find(
                        |r| matches!(r, Slot::Fido2 { credential_id: c, .. } if c == credential_id),
                    )
                    .ok_or(Error::Invalid("not every key was re-wrapped"))?;
                new_slots.push(r.clone());
            }
            other => new_slots.push(other.clone()),
        }
    }
    header.kdf = new_kdf;
    header.slots = new_slots;
    header.seal_mac(key.vmk())
}

/// Whether ANY FIDO security key is attached, from the IOKit registry
/// (`ioreg`, HID primary usage page 0xF1D0 = FIDO). Never opens the device:
/// polling through hidapi crashed the app when the key was pulled out
/// mid-probe. Used for the removal trigger (present → absent locks).
#[cfg(target_os = "macos")]
pub fn fido_hid_present() -> bool {
    std::process::Command::new("/usr/sbin/ioreg")
        .args(["-r", "-c", "IOHIDDevice", "-d", "1"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| ioreg_has_fido(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub fn fido_hid_present() -> bool {
    false
}

/// `ioreg` output contains a HID device with the FIDO usage page.
pub fn ioreg_has_fido(out: &str) -> bool {
    out.lines().any(|l| {
        let l = l.trim();
        l.starts_with("\"PrimaryUsagePage\"") && l.ends_with("= 61904")
            || l.starts_with("\"DeviceUsagePairs\"") && l.contains("\"DeviceUsagePage\"=61904")
    })
}

/// SPEC §6 trigger 4: whether one of the vault's registered keys is plugged
/// in. Uses a silent probe (no PIN, no touch). The app polls this (about
/// every 2 s) while a fido2 vault is unlocked and locks when it turns
/// `false`; polling replaces IOKit removal notifications (see NOTES.md).
pub fn key_present(header: &Header, auth: &dyn Authenticator) -> bool {
    let ids = credential_ids(&header.slots);
    !ids.is_empty() && auth.present() && matches!(auth.find_credential(RP_ID, &ids), Ok(Some(_)))
}

// ---------------------------------------------------------------------------
// Real backend
// ---------------------------------------------------------------------------

mod hid {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use ctap_hid_fido2::fidokey::get_info::{InfoOption, InfoParam};
    use ctap_hid_fido2::fidokey::{
        AssertionExtension as Gext, CredentialExtension as Mext, GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder,
    };
    use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, HidParam, LibCfg};
    use zeroize::{Zeroize, Zeroizing};

    use super::{Authenticator, DeviceInfo, FidoError, SALT_LEN};
    use crate::crypto;

    type R<T> = std::result::Result<T, FidoError>;

    /// Stateless: every call enumerates and opens the devices afresh, so
    /// plugging/unplugging between calls just works.
    pub(super) struct HidAuthenticator;

    fn cfg() -> LibCfg {
        let mut c = LibCfg::init();
        c.enable_log = false;
        // The crate would print "touch the sensor" to stdout; the app shows
        // its own prompt via `Event::FidoTouchNeeded`.
        c.enable_keep_alive_msg = false;
        c
    }

    type Job = Box<dyn FnOnce() + Send + 'static>;

    /// The one thread that ever talks to hidapi. On macOS hidapi schedules
    /// its IOHIDManager on the run loop of the thread that first used it;
    /// calling it later from another (short-lived tokio) thread hit a dead
    /// run loop and crashed the app (EXC_BREAKPOINT in CFRunLoopAddSource
    /// during YubiKey registration). All HID work is therefore serialised
    /// onto this long-lived thread.
    fn hid_thread() -> Option<std::sync::mpsc::Sender<Job>> {
        use std::sync::{mpsc, Mutex, OnceLock};
        static TX: OnceLock<Option<Mutex<mpsc::Sender<Job>>>> = OnceLock::new();
        TX.get_or_init(|| {
            let (tx, rx) = mpsc::channel::<Job>();
            std::thread::Builder::new()
                .name("bv-fido-hid".into())
                .spawn(move || {
                    for job in rx {
                        job();
                    }
                })
                .ok()
                .map(|_| Mutex::new(tx))
        })
        .as_ref()
        .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    /// Run `f` on the HID thread and wait for it. hidapi's constructor
    /// panics if HID is unavailable; a panic becomes an error, never a crash.
    fn guard<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
        let tx = hid_thread().ok_or_else(|| FidoError::Other("HID thread unavailable".into()))?;
        let (rtx, rrx) = std::sync::mpsc::sync_channel::<R<T>>(1);
        let job: Job = Box::new(move || {
            let r = catch_unwind(AssertUnwindSafe(f))
                .unwrap_or_else(|_| Err(FidoError::Other("HID backend panicked".into())));
            let _ = rtx.send(r);
        });
        tx.send(job)
            .map_err(|_| FidoError::Other("HID thread stopped".into()))?;
        rrx.recv()
            .unwrap_or_else(|_| Err(FidoError::Other("HID thread stopped".into())))
    }

    fn devices() -> Vec<HidParam> {
        ctap_hid_fido2::get_fidokey_devices()
            .into_iter()
            .map(|d| d.param)
            .collect()
    }

    fn open(param: &HidParam) -> R<FidoKeyHid> {
        FidoKeyHidFactory::create_by_params(std::slice::from_ref(param), &cfg())
            .map_err(|e| classify(&e))
    }

    fn open_single() -> R<FidoKeyHid> {
        let devs = devices();
        match devs.len() {
            0 => Err(FidoError::NoDevice),
            1 => open(&devs[0]),
            _ => Err(FidoError::MultipleDevices),
        }
    }

    /// The crate reports CTAP status codes only as text
    /// ("… 0x31 CTAP2_ERR_PIN_INVALID …").
    fn classify(e: &impl std::fmt::Display) -> FidoError {
        let msg = e.to_string();
        let has = |s: &str| msg.contains(s);
        if has("CTAP2_ERR_PIN_INVALID") || has("CTAP2_ERR_PIN_AUTH_INVALID") {
            FidoError::PinInvalid
        } else if has("CTAP2_ERR_PIN_BLOCKED") || has("CTAP2_ERR_PIN_AUTH_BLOCKED") {
            FidoError::PinBlocked
        } else if has("CTAP2_ERR_PIN_NOT_SET") {
            FidoError::PinNotSet
        } else if has("CTAP2_ERR_NO_CREDENTIALS") || has("CTAP2_ERR_INVALID_CREDENTIAL") {
            FidoError::NoCredential
        } else if has("CTAP2_ERR_CREDENTIAL_EXCLUDED") {
            FidoError::Excluded
        } else if has("CTAP2_ERR_UNSUPPORTED_EXTENSION")
            || has("CTAP2_ERR_UNSUPPORTED_OPTION")
            || has("CTAP1_ERR_INVALID_COMMAND")
        {
            FidoError::Unsupported
        } else if has("CTAP2_ERR_USER_ACTION_TIMEOUT")
            || has("CTAP2_ERR_ACTION_TIMEOUT")
            || has("CTAP2_ERR_OPERATION_DENIED")
            || has("CTAP2_ERR_KEEPALIVE_CANCEL")
        {
            FidoError::NoTouch
        } else if has("FIDO device not found") {
            FidoError::NoDevice
        } else {
            // CTAP status text / transport error; contains no secrets.
            FidoError::Other(msg)
        }
    }

    /// Silent (up = false, no PIN) assertion: which id in `allow` this key holds.
    fn probe(dev: &FidoKeyHid, rp_id: &str, allow: &[Vec<u8>]) -> R<Option<Vec<u8>>> {
        let challenge = crypto::random_bytes::<32>();
        let mut b = GetAssertionArgsBuilder::new(rp_id, &challenge)
            .without_pin_and_uv()
            .without_up();
        for id in allow {
            b = b.add_credential_id(id);
        }
        match dev.get_assertion_with_args(&b.build()) {
            Ok(asss) => {
                let id = asss.into_iter().next().map(|a| a.credential_id);
                Ok(match id {
                    Some(id) if !id.is_empty() => Some(id),
                    // CTAP may omit the id when the allow list has one entry.
                    _ if allow.len() == 1 => Some(allow[0].clone()),
                    _ => None,
                })
            }
            Err(e) => match classify(&e) {
                FidoError::NoCredential => Ok(None),
                other => Err(other),
            },
        }
    }

    impl Authenticator for HidAuthenticator {
        fn present(&self) -> bool {
            guard(|| Ok(!devices().is_empty())).unwrap_or(false)
        }

        fn info(&self) -> R<DeviceInfo> {
            guard(|| {
                let dev = open_single()?;
                let info = dev.get_info().map_err(|e| classify(&e))?;
                let has_version =
                    |p: InfoParam| info.versions.iter().any(|v| v.as_str() == p.as_ref());
                let fido2 = has_version(InfoParam::VersionsFido20)
                    || has_version(InfoParam::VersionsFido21Pre)
                    || has_version(InfoParam::VersionsFido21);
                let hmac_secret = info
                    .extensions
                    .iter()
                    .any(|x| x.as_str() == InfoParam::ExtensionsHmacSecret.as_ref());
                let client_pin = info
                    .options
                    .iter()
                    .find(|(k, _)| k.as_str() == InfoOption::ClientPin.as_ref())
                    .map(|(_, v)| *v);
                Ok(DeviceInfo {
                    fido2,
                    hmac_secret,
                    client_pin,
                })
            })
        }

        fn make_credential(&self, rp_id: &str, pin: &str, exclude: &[Vec<u8>]) -> R<Vec<u8>> {
            let (rp_id, pin, exclude) = (
                rp_id.to_owned(),
                Zeroizing::new(pin.to_owned()),
                exclude.to_vec(),
            );
            guard(move || {
                let dev = open_single()?;
                let challenge = crypto::random_bytes::<32>();
                let ext = [Mext::HmacSecret(Some(true))];
                let mut b = MakeCredentialArgsBuilder::new(&rp_id, &challenge)
                    .pin(&pin)
                    .extensions(&ext);
                for id in &exclude {
                    b = b.exclude_authenticator(id);
                }
                let att = dev
                    .make_credential_with_args(&b.build())
                    .map_err(|e| classify(&e))?;
                let hmac_on = att
                    .extensions
                    .iter()
                    .any(|x| matches!(x, Mext::HmacSecret(Some(true))));
                if !hmac_on {
                    return Err(FidoError::Unsupported);
                }
                let id = att.credential_descriptor.id;
                if id.is_empty() {
                    return Err(FidoError::Other("empty credential id".into()));
                }
                Ok(id)
            })
        }

        fn find_credential(&self, rp_id: &str, allow: &[Vec<u8>]) -> R<Option<Vec<u8>>> {
            let (rp_id, allow) = (rp_id.to_owned(), allow.to_vec());
            guard(move || {
                if allow.is_empty() {
                    return Ok(None);
                }
                for param in devices() {
                    let Ok(dev) = open(&param) else { continue };
                    if let Ok(Some(id)) = probe(&dev, &rp_id, &allow) {
                        return Ok(Some(id));
                    }
                }
                Ok(None)
            })
        }

        fn hmac_secret(
            &self,
            rp_id: &str,
            credential_id: &[u8],
            salt: &[u8; SALT_LEN],
            pin: &str,
        ) -> R<Zeroizing<[u8; 32]>> {
            let (rp_id, credential_id, salt, pin) = (
                rp_id.to_owned(),
                credential_id.to_vec(),
                Zeroizing::new(*salt),
                Zeroizing::new(pin.to_owned()),
            );
            guard(move || {
                let allow = [credential_id.clone()];
                let mut holder = None;
                for param in devices() {
                    let Ok(dev) = open(&param) else { continue };
                    if let Ok(Some(_)) = probe(&dev, &rp_id, &allow) {
                        holder = Some(dev);
                        break;
                    }
                }
                let dev = holder.ok_or(FidoError::NoCredential)?;
                let challenge = crypto::random_bytes::<32>();
                let ext = [Gext::HmacSecret(Some(*salt))];
                let args = GetAssertionArgsBuilder::new(&rp_id, &challenge)
                    .pin(&pin)
                    .credential_id(&credential_id)
                    .extensions(&ext)
                    .build();
                let mut asss = dev
                    .get_assertion_with_args(&args)
                    .map_err(|e| classify(&e))?;
                let mut out = Zeroizing::new([0u8; 32]);
                let mut got = false;
                for a in &mut asss {
                    for x in &mut a.extensions {
                        if let Gext::HmacSecret(Some(o)) = x {
                            if !got {
                                out.copy_from_slice(o);
                                got = true;
                            }
                            o.zeroize();
                        }
                    }
                }
                if got {
                    Ok(out)
                } else {
                    Err(FidoError::Unsupported)
                }
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Software mock (tests only)
// ---------------------------------------------------------------------------

#[cfg(any(test, feature = "test-mocks"))]
pub use mock::MockAuthenticator;

#[cfg(any(test, feature = "test-mocks"))]
mod mock {
    use std::sync::Mutex;

    use hkdf::hmac::{Hmac, Mac};
    use sha2::Sha256;
    use zeroize::Zeroizing;

    use super::{Authenticator, DeviceInfo, FidoError, SALT_LEN};
    use crate::crypto;

    type R<T> = std::result::Result<T, FidoError>;
    const MAX_PIN_RETRIES: u8 = 8;

    fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    struct Key {
        secret: [u8; 32],
        pin: Option<String>,
        retries: u8,
        plugged: bool,
        fido2: bool,
        hmac_secret: bool,
    }

    impl Key {
        /// Like a real key, credential ids are self-authenticating handles
        /// (nonce ‖ MAC) rather than stored state.
        fn owns(&self, rp_id: &str, id: &[u8]) -> bool {
            id.len() == 32 && hmac(&self.secret, &[rp_id.as_bytes(), &id[..16]])[..16] == id[16..]
        }

        fn check_pin(&mut self, pin: &str) -> R<()> {
            let Some(expected) = &self.pin else {
                return Err(FidoError::PinNotSet);
            };
            if self.retries == 0 {
                return Err(FidoError::PinBlocked);
            }
            if expected != pin {
                self.retries -= 1;
                return Err(if self.retries == 0 {
                    FidoError::PinBlocked
                } else {
                    FidoError::PinInvalid
                });
            }
            self.retries = MAX_PIN_RETRIES;
            Ok(())
        }
    }

    #[derive(Default)]
    struct State {
        keys: Vec<Key>,
        touches: usize,
        refuse_touch: bool,
    }

    /// Deterministic software FIDO2 authenticator(s) for tests: simulates
    /// several keys (plug/unplug), PIN checks with retry counter, touch, and
    /// hmac-secret as HMAC-SHA256(HMAC(key secret, credential id), salt).
    /// TEST ONLY — not a security device.
    #[derive(Default)]
    pub struct MockAuthenticator {
        state: Mutex<State>,
    }

    impl MockAuthenticator {
        pub fn new() -> Self {
            Self::default()
        }

        fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
            f(&mut self.state.lock().unwrap_or_else(|p| p.into_inner()))
        }

        /// Add a (plugged-in) key with an optional PIN; returns its index.
        pub fn add_key(&self, pin: Option<&str>) -> usize {
            self.with(|s| {
                s.keys.push(Key {
                    secret: crypto::random_bytes::<32>(),
                    pin: pin.map(str::to_string),
                    retries: MAX_PIN_RETRIES,
                    plugged: true,
                    fido2: true,
                    hmac_secret: true,
                });
                s.keys.len() - 1
            })
        }

        /// Add a key that speaks FIDO2 but lacks hmac-secret (or U2F only
        /// when `fido2` is false).
        pub fn add_unsupported_key(&self, fido2: bool) -> usize {
            let i = self.add_key(Some("1234"));
            self.with(|s| {
                s.keys[i].fido2 = fido2;
                s.keys[i].hmac_secret = false;
            });
            i
        }

        pub fn plug(&self, i: usize) {
            self.with(|s| s.keys[i].plugged = true);
        }

        pub fn unplug(&self, i: usize) {
            self.with(|s| s.keys[i].plugged = false);
        }

        /// Plug only key `i`.
        pub fn only(&self, i: usize) {
            self.with(|s| {
                for (j, k) in s.keys.iter_mut().enumerate() {
                    k.plugged = j == i;
                }
            });
        }

        pub fn unplug_all(&self) {
            self.with(|s| s.keys.iter_mut().for_each(|k| k.plugged = false));
        }

        pub fn set_pin(&self, i: usize, pin: Option<&str>) {
            self.with(|s| s.keys[i].pin = pin.map(str::to_string));
        }

        /// Simulate the user not touching the key (timeout).
        pub fn refuse_touch(&self, refuse: bool) {
            self.with(|s| s.refuse_touch = refuse);
        }

        /// Number of successful touches so far.
        pub fn touches(&self) -> usize {
            self.with(|s| s.touches)
        }

        pub fn pin_retries(&self, i: usize) -> u8 {
            self.with(|s| s.keys[i].retries)
        }
    }

    fn single(s: &mut State) -> R<&mut Key> {
        let mut it = s.keys.iter_mut().filter(|k| k.plugged);
        match (it.next(), it.next()) {
            (None, _) => Err(FidoError::NoDevice),
            (Some(k), None) => Ok(k),
            _ => Err(FidoError::MultipleDevices),
        }
    }

    fn touch(s: &mut State) -> R<()> {
        if s.refuse_touch {
            return Err(FidoError::NoTouch);
        }
        s.touches += 1;
        Ok(())
    }

    impl Authenticator for MockAuthenticator {
        fn present(&self) -> bool {
            self.with(|s| s.keys.iter().any(|k| k.plugged))
        }

        fn info(&self) -> R<DeviceInfo> {
            self.with(|s| {
                let k = single(s)?;
                Ok(DeviceInfo {
                    fido2: k.fido2,
                    hmac_secret: k.hmac_secret,
                    client_pin: k.fido2.then_some(k.pin.is_some()),
                })
            })
        }

        fn make_credential(&self, rp_id: &str, pin: &str, exclude: &[Vec<u8>]) -> R<Vec<u8>> {
            self.with(|s| {
                let k = single(s)?;
                if !k.fido2 || !k.hmac_secret {
                    return Err(FidoError::Unsupported);
                }
                k.check_pin(pin)?;
                let excluded = exclude.iter().any(|id| k.owns(rp_id, id));
                let nonce = crypto::random_bytes::<16>();
                let tag = hmac(&k.secret, &[rp_id.as_bytes(), &nonce]);
                touch(s)?;
                if excluded {
                    return Err(FidoError::Excluded);
                }
                let mut id = nonce.to_vec();
                id.extend_from_slice(&tag[..16]);
                Ok(id)
            })
        }

        fn find_credential(&self, rp_id: &str, allow: &[Vec<u8>]) -> R<Option<Vec<u8>>> {
            self.with(|s| {
                Ok(s.keys
                    .iter()
                    .filter(|k| k.plugged)
                    .find_map(|k| allow.iter().find(|id| k.owns(rp_id, id)).cloned()))
            })
        }

        fn hmac_secret(
            &self,
            rp_id: &str,
            credential_id: &[u8],
            salt: &[u8; SALT_LEN],
            pin: &str,
        ) -> R<Zeroizing<[u8; 32]>> {
            self.with(|s| {
                let k = s
                    .keys
                    .iter_mut()
                    .find(|k| k.plugged && k.owns(rp_id, credential_id))
                    .ok_or(FidoError::NoCredential)?;
                k.check_pin(pin)?;
                let cred_random = Zeroizing::new(hmac(&k.secret, &[b"cred", credential_id]));
                let out = Zeroizing::new(hmac(cred_random.as_ref(), &[salt]));
                touch(s)?;
                Ok(out)
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::browser::Browser;
    use crate::events;
    use crate::header::VaultSettings;
    use crate::keyslot::{unlock_with_recovery, KdfCost};

    const PW: &str = "correct horse battery";
    const PIN_A: &str = "1234";
    const PIN_B: &str = "987654";

    struct V {
        header: Header,
        key: UnlockedKey,
        auth: MockAuthenticator,
        a: usize,
        b: usize,
        phrase: String,
    }

    fn n() -> Notify<'static> {
        &events::ignore
    }

    /// Vault with two registered keys (A = main, B = backup), all unplugged.
    fn vault() -> V {
        let auth = MockAuthenticator::new();
        let a = auth.add_key(Some(PIN_A));
        let b = auth.add_key(Some(PIN_B));
        let mut d = Draft::new("V", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        auth.only(a);
        assert_eq!(
            register(&mut d, &auth, PIN_A, " YubiKey main ", n()).unwrap(),
            "YubiKey main"
        );
        auth.only(b);
        register(&mut d, &auth, PIN_B, "YubiKey backup", n()).unwrap();
        d.generate_recovery().unwrap();
        let phrase = d.recovery_phrase().unwrap().to_string();
        let nv = d.finish(VaultSettings::default()).unwrap();
        auth.unplug_all();
        V {
            header: nv.header,
            key: nv.key,
            auth,
            a,
            b,
            phrase,
        }
    }

    fn failed<T: fmt::Debug>(r: Result<T>) -> bool {
        matches!(r, Err(Error::UnlockFailed))
    }

    #[test]
    fn ioreg_fido_detection() {
        let with = r#"+-o IOHIDDevice  <class IOHIDDevice>
    {
      "Product" = "YubiKey OTP+FIDO+CCID"
      "PrimaryUsagePage" = 61904
      "VendorID" = 4176
    }"#;
        let without = r#"+-o IOHIDDevice  <class IOHIDDevice>
    {
      "Product" = "Apple Internal Keyboard"
      "PrimaryUsagePage" = 1
    }"#;
        assert!(ioreg_has_fido(with));
        assert!(!ioreg_has_fido(without));
        assert!(!ioreg_has_fido(""));
    }

    #[test]
    fn password_change_rewraps_every_key() {
        let mut v = vault();
        let new_pw_str = "a brand new passphrase";
        let mut kdf = v.header.kdf.clone();
        kdf.salt = crypto::random_bytes::<16>().into();
        let new_pw = kdf.derive(new_pw_str.as_bytes()).unwrap();
        let mut done = vec![];
        let mut slots = vec![];
        // Nothing plugged in → clear error, no touch.
        v.auth.unplug_all();
        assert!(rewrap_present(&v.header, &v.key, &new_pw, &v.auth, PIN_A, n()).is_err());
        v.auth.only(v.a);
        let (id, slot) = rewrap_present(&v.header, &v.key, &new_pw, &v.auth, PIN_A, n()).unwrap();
        done.push(id);
        slots.push(slot);
        assert_eq!(
            remaining_keys(&v.header, &done),
            vec!["YubiKey backup".to_string()]
        );
        // Committing with a key missing is refused.
        let mut h = v.header.clone();
        assert!(apply_password_change(&mut h, &v.key, kdf.clone(), slots.clone()).is_err());
        v.auth.only(v.b);
        let (id, slot) = rewrap_present(&v.header, &v.key, &new_pw, &v.auth, PIN_B, n()).unwrap();
        done.push(id);
        slots.push(slot);
        assert!(remaining_keys(&v.header, &done).is_empty());
        apply_password_change(&mut v.header, &v.key, kdf, slots).unwrap();
        assert!(v.header.verify_mac(v.key.vmk()));
        for (k, pin) in [(v.a, PIN_A), (v.b, PIN_B)] {
            v.auth.only(k);
            assert!(failed(unlock(&v.header, &v.auth, PW, pin, n())));
            let u = unlock(&v.header, &v.auth, new_pw_str, pin, n()).unwrap();
            assert_eq!(**u.vmk(), **v.key.vmk());
        }
        assert!(unlock_with_recovery(&v.header, &v.phrase).is_ok());
    }

    #[test]
    fn register_two_keys_shape() {
        let v = vault();
        let kinds: Vec<_> = v.header.slots.iter().map(Slot::kind).collect();
        assert_eq!(kinds, ["fido2", "fido2", "recovery"]);
        let ks = keys(&v.header);
        assert_eq!(ks[0].label, "YubiKey main");
        assert_eq!(ks[1].label, "YubiKey backup");
        assert_ne!(ks[0].credential_id, ks[1].credential_id);
        let salts: Vec<_> = v
            .header
            .slots
            .iter()
            .filter_map(|s| match s {
                Slot::Fido2 { salt, .. } => Some(salt.0.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(salts[0].len(), SALT_LEN);
        assert_ne!(salts[0], salts[1]);
        assert!(v.header.verify_mac(v.key.vmk()));
        // Each registration = 2 touches.
        assert_eq!(v.auth.touches(), 4);
        assert!(!format!("{:?}", ks[0]).contains("credential_id"));
    }

    #[test]
    fn unlock_with_either_key() {
        let v = vault();
        v.auth.only(v.a);
        let k = unlock(&v.header, &v.auth, PW, PIN_A, n()).unwrap();
        assert_eq!(**k.vmk(), **v.key.vmk());
        assert!(k.header_intact);
        v.auth.only(v.b);
        let k = unlock(&v.header, &v.auth, PW, PIN_B, n()).unwrap();
        assert_eq!(**k.vmk(), **v.key.vmk());
        // Both plugged: the first registered key that answers wins.
        v.auth.plug(v.a);
        assert!(unlock(&v.header, &v.auth, PW, PIN_A, n()).is_ok());
    }

    #[test]
    fn unlock_impossible_without_key() {
        let v = vault();
        let before = v.auth.touches();
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
        // An unregistered key does not help either.
        let stranger = v.auth.add_key(Some(PIN_A));
        v.auth.only(stranger);
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
        // No touch was requested from a key that cannot answer.
        assert_eq!(v.auth.touches(), before);
        // Recovery still works.
        assert!(unlock_with_recovery(&v.header, &v.phrase).is_ok());
    }

    #[test]
    fn wrong_pin_or_password_is_generic() {
        let v = vault();
        v.auth.only(v.a);
        for (pw, pin) in [
            ("correct horse batterY", PIN_A),
            ("", PIN_A),
            (PW, "4321"),
            (PW, PIN_B), // the other key's PIN
            (PW, ""),
            (PW, "12"),
        ] {
            let e = unlock(&v.header, &v.auth, pw, pin, n()).unwrap_err();
            assert!(matches!(e, Error::UnlockFailed), "{pw:?}/{pin:?}: {e:?}");
            assert_eq!(e.to_string(), "Unlock failed");
        }
        // Malformed PINs never reach the key (no retry burned).
        assert_eq!(v.auth.pin_retries(v.a), 8 - 2);
        assert!(unlock(&v.header, &v.auth, PW, PIN_A, n()).is_ok());
        assert_eq!(v.auth.pin_retries(v.a), 8);
    }

    #[test]
    fn no_touch_is_generic_failure() {
        let v = vault();
        v.auth.only(v.a);
        v.auth.refuse_touch(true);
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
    }

    #[test]
    fn slot_moved_to_other_vault_fails() {
        let a = vault();
        let mut b = vault();
        // Graft A's key slots (and its KDF, i.e. password salt) into B.
        b.header.slots = a.header.slots.clone();
        b.header.kdf = a.header.kdf.clone();
        a.auth.only(a.a);
        assert!(failed(unlock(&b.header, &a.auth, PW, PIN_A, n())));
        // Changing the vault id of A breaks A.
        let mut h = a.header.clone();
        h.vault_id = b.header.vault_id.clone();
        assert!(failed(unlock(&h, &a.auth, PW, PIN_A, n())));
        // B's own keys do not open A.
        b.auth.only(b.a);
        assert!(failed(unlock(&a.header, &b.auth, PW, PIN_A, n())));
    }

    #[test]
    fn tampered_slot_fails_and_metadata_is_flagged() {
        let v = vault();
        v.auth.only(v.a);
        let mut h = v.header.clone();
        if let Slot::Fido2 { salt, .. } = &mut h.slots[0] {
            salt.0[0] ^= 1;
        }
        assert!(failed(unlock(&h, &v.auth, PW, PIN_A, n())));
        let mut h = v.header.clone();
        if let Slot::Fido2 { wrapped_vmk, .. } = &mut h.slots[0] {
            wrapped_vmk.0[0] ^= 1;
        }
        assert!(failed(unlock(&h, &v.auth, PW, PIN_A, n())));
        let mut h = v.header.clone();
        h.name = "Evil".into();
        if let Slot::Fido2 { label, .. } = &mut h.slots[0] {
            *label = "renamed".into();
        }
        let k = unlock(&h, &v.auth, PW, PIN_A, n()).unwrap();
        assert!(!k.header_intact);
        let k = unlock(&v.header, &v.auth, PW, PIN_A, n()).unwrap();
        assert!(k.header_intact);
    }

    #[test]
    fn notify_events_in_order() {
        let events = Mutex::new(Vec::new());
        let rec = |e: Event| events.lock().unwrap().push(e);
        let auth = MockAuthenticator::new();
        auth.add_key(Some(PIN_A));
        let mut d = Draft::new("V", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        register(&mut d, &auth, PIN_A, "k", &rec).unwrap();
        use Event::{FidoTouchDone as D, FidoTouchNeeded as N};
        assert_eq!(*events.lock().unwrap(), [N, D, N, D]);
        d.generate_recovery().unwrap();
        let nv = d.finish(VaultSettings::default()).unwrap();

        events.lock().unwrap().clear();
        unlock(&nv.header, &auth, PW, PIN_A, &rec).unwrap();
        assert_eq!(*events.lock().unwrap(), [N, D]);

        // Done is emitted even when the operation fails.
        events.lock().unwrap().clear();
        assert!(failed(unlock(&nv.header, &auth, PW, "0000", &rec)));
        assert_eq!(*events.lock().unwrap(), [N, D]);

        // A wrong password is only detected after the touch (it is not
        // verifiable on its own), so the overlay still opens and closes.
        events.lock().unwrap().clear();
        assert!(failed(unlock(
            &nv.header,
            &auth,
            "wrong password!!",
            PIN_A,
            &rec
        )));
        assert_eq!(*events.lock().unwrap(), [N, D]);

        // No touch prompt when no registered key is plugged in.
        events.lock().unwrap().clear();
        auth.unplug_all();
        assert!(failed(unlock(&nv.header, &auth, PW, PIN_A, &rec)));
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn register_errors_are_clear() {
        let auth = MockAuthenticator::new();
        let mut d = Draft::new("V", Browser::Brave, KdfCost::FAST).unwrap();
        // Password first.
        let k = auth.add_key(Some(PIN_A));
        assert!(matches!(
            register(&mut d, &auth, PIN_A, "k", n()),
            Err(Error::Invalid(_))
        ));
        d.set_password(PW).unwrap();
        let err = |d: &mut Draft, pin: &str, label: &str| {
            register(d, &auth, pin, label, n()).unwrap_err().to_string()
        };
        assert_eq!(err(&mut d, PIN_A, " "), ERR_LABEL);
        assert_eq!(err(&mut d, "123", "k"), ERR_PIN_FORMAT);
        assert_eq!(err(&mut d, "0000", "k"), ERR_WRONG_PIN);
        auth.set_pin(k, None);
        assert_eq!(err(&mut d, PIN_A, "k"), ERR_PIN_NOT_SET);
        auth.set_pin(k, Some(PIN_A));
        auth.unplug_all();
        assert_eq!(err(&mut d, PIN_A, "k"), ERR_NO_KEY);
        let k2 = auth.add_key(Some(PIN_A));
        auth.plug(k);
        assert_eq!(err(&mut d, PIN_A, "k"), ERR_MULTIPLE_KEYS);
        let u = auth.add_unsupported_key(true);
        auth.only(u);
        let e = register(&mut d, &auth, PIN_A, "k", n()).unwrap_err();
        assert!(matches!(e, Error::Unsupported(ERR_UNSUPPORTED_KEY)));
        let u2f = auth.add_unsupported_key(false);
        auth.only(u2f);
        assert!(matches!(
            register(&mut d, &auth, PIN_A, "k", n()),
            Err(Error::Unsupported(_))
        ));
        auth.only(k);
        auth.refuse_touch(true);
        assert_eq!(err(&mut d, PIN_A, "k"), ERR_NO_TOUCH);
        auth.refuse_touch(false);
        assert!(d.slots().is_empty());

        register(&mut d, &auth, PIN_A, "main", n()).unwrap();
        // Same key twice, or same label twice, is refused.
        let before = auth.touches();
        assert_eq!(err(&mut d, PIN_A, "backup"), ERR_ALREADY_REGISTERED);
        assert_eq!(auth.touches(), before, "refused before asking for a touch");
        auth.only(k2);
        assert_eq!(err(&mut d, PIN_A, "main"), ERR_LABEL_TAKEN);
        register(&mut d, &auth, PIN_A, "backup", n()).unwrap();
        assert_eq!(keys_in(d.slots()).len(), 2);
    }

    #[test]
    fn pin_blocked_after_retries() {
        let v = vault();
        v.auth.only(v.a);
        for _ in 0..8 {
            assert!(failed(unlock(&v.header, &v.auth, PW, "0000", n())));
        }
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
        // The backup key still opens the vault.
        v.auth.only(v.b);
        assert!(unlock(&v.header, &v.auth, PW, PIN_B, n()).is_ok());
    }

    #[test]
    fn add_backup_key_later() {
        let auth = MockAuthenticator::new();
        let a = auth.add_key(Some(PIN_A));
        let mut d = Draft::new("V", Browser::Brave, KdfCost::FAST).unwrap();
        d.set_password(PW).unwrap();
        register(&mut d, &auth, PIN_A, "main", n()).unwrap();
        d.generate_recovery().unwrap();
        let mut header = d.finish(VaultSettings::default()).unwrap().header;

        let key = unlock(&header, &auth, PW, PIN_A, n()).unwrap();
        // Same key again is refused.
        assert_eq!(
            add_key(&mut header, &key, PW, &auth, PIN_A, "b", n())
                .unwrap_err()
                .to_string(),
            ERR_ALREADY_REGISTERED
        );
        let b = auth.add_key(Some(PIN_B));
        auth.only(b);
        add_key(&mut header, &key, PW, &auth, PIN_B, "backup", n()).unwrap();
        let kinds: Vec<_> = header.slots.iter().map(Slot::kind).collect();
        assert_eq!(kinds, ["fido2", "fido2", "recovery"]);
        let kb = unlock(&header, &auth, PW, PIN_B, n()).unwrap();
        assert!(kb.header_intact);
        assert_eq!(**kb.vmk(), **key.vmk());
        auth.only(a);
        assert!(
            unlock(&header, &auth, PW, PIN_A, n())
                .unwrap()
                .header_intact
        );

        // A key from another vault cannot modify this one.
        let other = vault();
        let c = auth.add_key(Some(PIN_A));
        auth.only(c);
        assert_eq!(
            add_key(&mut header, &other.key, PW, &auth, PIN_A, "c", n())
                .unwrap_err()
                .to_string(),
            ERR_FOREIGN_KEY
        );
        assert_eq!(
            remove_key(&mut header, &other.key, "main")
                .unwrap_err()
                .to_string(),
            ERR_FOREIGN_KEY
        );
    }

    #[test]
    fn remove_key_revokes_it() {
        let mut v = vault();
        let key = unlock_with_recovery(&v.header, &v.phrase).unwrap();
        assert_eq!(
            remove_key(&mut v.header, &key, "nope")
                .unwrap_err()
                .to_string(),
            ERR_UNKNOWN_LABEL
        );
        remove_key(&mut v.header, &key, "YubiKey main").unwrap();
        assert_eq!(keys(&v.header).len(), 1);
        v.auth.only(v.a);
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
        assert!(!key_present(&v.header, &v.auth));
        v.auth.only(v.b);
        let k = unlock(&v.header, &v.auth, PW, PIN_B, n()).unwrap();
        assert!(k.header_intact);
        // The last key cannot be removed.
        assert_eq!(
            remove_key(&mut v.header, &k, "YubiKey backup")
                .unwrap_err()
                .to_string(),
            ERR_LAST_FACTOR
        );
        assert_eq!(keys(&v.header).len(), 1);
    }

    #[test]
    fn key_presence_tracks_registered_keys() {
        let v = vault();
        assert!(!key_present(&v.header, &v.auth));
        v.auth.only(v.a);
        assert!(key_present(&v.header, &v.auth));
        v.auth.only(v.b);
        assert!(key_present(&v.header, &v.auth));
        let stranger = v.auth.add_key(Some(PIN_A));
        v.auth.only(stranger);
        assert!(v.auth.present());
        assert!(!key_present(&v.header, &v.auth));
        // Probing never needs a touch.
        let t = v.auth.touches();
        v.auth.only(v.a);
        key_present(&v.header, &v.auth);
        assert_eq!(v.auth.touches(), t);
    }

    #[test]
    fn header_without_fido2_slots_fails() {
        let mut v = vault();
        v.header.slots.retain(|s| s.kind() != "fido2");
        v.auth.only(v.a);
        assert!(failed(unlock(&v.header, &v.auth, PW, PIN_A, n())));
        assert!(!key_present(&v.header, &v.auth));
    }

    #[test]
    fn hmac_secret_is_deterministic_and_salt_dependent() {
        let auth = MockAuthenticator::new();
        auth.add_key(Some(PIN_A));
        let id = auth.make_credential(RP_ID, PIN_A, &[]).unwrap();
        let s1 = auth.hmac_secret(RP_ID, &id, &[1; 32], PIN_A).unwrap();
        let s2 = auth.hmac_secret(RP_ID, &id, &[1; 32], PIN_A).unwrap();
        let s3 = auth.hmac_secret(RP_ID, &id, &[2; 32], PIN_A).unwrap();
        assert_eq!(*s1, *s2);
        assert_ne!(*s1, *s3);
        // Credentials are scoped to the RP id.
        assert!(matches!(
            auth.hmac_secret("evil.example", &id, &[1; 32], PIN_A),
            Err(FidoError::NoCredential)
        ));
    }
}
