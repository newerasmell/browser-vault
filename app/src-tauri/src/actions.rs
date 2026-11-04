//! Settings → Vaults actions on an existing vault: change password, replace
//! the authenticator, add a YubiKey, new recovery phrase.
//!
//! Flow: `action_auth` re-authenticates with the full credential (password
//! and code, or password, PIN and touch) WITHOUT mounting anything and returns
//! an opaque token. The token holds the VMK (zeroizing) and the password in
//! memory only, for at most `TTL`. Each action step reloads the header from
//! disk, and nothing is written until the action is fully confirmed (first
//! code from the new app, 3 recovery words, every YubiKey touched).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter};
use vault_core::header::{Header, Kdf, Slot};
use vault_core::keyslot::{self, UnlockedKey};
use vault_core::totp::PendingTotp;
use vault_core::{crypto, fido2, recovery, totp};
use zeroize::Zeroizing;

use crate::applog;
use crate::error::{fido_setup_error, CmdError, CmdResult};
use crate::lockctl;
use crate::state::{self, lock};

const TTL: Duration = Duration::from_secs(10 * 60);

/// New kdf, new password key, credential ids done, re-wrapped slots.
type PwChange = (Kdf, crypto::Key, Vec<Vec<u8>>, Vec<Slot>);

pub struct ActionCtx {
    id: String,
    key: UnlockedKey,
    password: Zeroizing<String>,
    created: Instant,
    pending_totp: Option<PendingTotp>,
    pending_recovery: Option<Zeroizing<String>>,
    /// YubiKey password change in progress: new kdf, new PW, re-wrapped slots.
    pw_change: Option<PwChange>,
    /// Authenticated with the recovery phrase (no password known): only the
    /// reset, new-recovery and portable actions are allowed.
    via_recovery: bool,
    /// New password chosen for a TOTP reset, until the first code confirms.
    reset_password: Option<Zeroizing<String>>,
}

pub type Actions = HashMap<String, ActionCtx>;

fn new_token() -> String {
    crypto::random_bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn mode_of(h: &Header) -> &'static str {
    if h.slots.iter().any(|s| matches!(s, Slot::Fido2 { .. })) {
        "fido2"
    } else {
        "totp"
    }
}

fn emit_touch(app: &AppHandle, e: vault_core::events::Event) {
    use vault_core::events::Event;
    let name = match e {
        Event::FidoTouchNeeded => "fido_touch_needed",
        Event::FidoTouchDone => "fido_touch_done",
        _ => return,
    };
    let _ = app.emit(name, json!({}));
}

/// Run `f` with the live context for `token` (expired ones are dropped).
fn with_ctx<R>(
    app: &AppHandle,
    token: &str,
    f: impl FnOnce(&mut ActionCtx) -> CmdResult<R>,
) -> CmdResult<R> {
    let st = state::get(app);
    let mut map = lock(&st.actions);
    map.retain(|_, c| c.created.elapsed() < TTL);
    let ctx = map.get_mut(token).ok_or(CmdError::new("expired"))?;
    f(ctx)
}

/// Load the current header and save `h` after a change; keep an open
/// session's in-memory copy in sync so triggers see the new slots.
fn commit(app: &AppHandle, h: &Header) -> CmdResult<()> {
    let st = state::get(app);
    st.store.save_header(h)?;
    if let Some(s) = lock(&st.sessions).get_mut(&h.vault_id) {
        s.unlocked.header = h.clone();
    }
    lockctl::vaults_changed(app);
    Ok(())
}

/// Step 1 for every action: full re-authentication, no mount.
pub fn auth(
    app: &AppHandle,
    id: &str,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
    pin: Zeroizing<String>,
) -> CmdResult<Value> {
    let st = state::get(app);
    let mut header = st.store.load(id)?;
    let mode = mode_of(&header);
    let key = if mode == "fido2" {
        let app2 = app.clone();
        let notify = move |e| emit_touch(&app2, e);
        vault_core::fido2::unlock(&header, st.fido.as_ref(), &password, &pin, &notify)?
    } else {
        let r = totp::unlock(
            &mut header,
            &password,
            &code,
            st.se.as_ref(),
            vault_core::store::now_unix(),
        );
        // Anti-replay / rate-limit counters change either way.
        commit(app, &header)?;
        r?
    };
    if !key.header_intact {
        return Err(CmdError::new("header_modified"));
    }
    let token = new_token();
    let keys: Vec<String> = fido2::keys(&header).into_iter().map(|k| k.label).collect();
    lock(&st.actions).insert(
        token.clone(),
        ActionCtx {
            id: id.to_string(),
            key,
            password,
            created: Instant::now(),
            pending_totp: None,
            pending_recovery: None,
            pw_change: None,
            via_recovery: false,
            reset_password: None,
        },
    );
    applog::log(&format!("action auth ok for {id}"));
    Ok(json!({ "token": token, "mode": mode, "keys": keys }))
}

pub fn end(app: &AppHandle, token: &str) {
    lock(&state::get(app).actions).remove(token);
}

// ---------------------------------------------------------------- password

pub fn change_password(
    app: &AppHandle,
    token: &str,
    new_password: Zeroizing<String>,
) -> CmdResult<Value> {
    let st = state::get(app);
    keyslot::validate_password(&new_password).map_err(|_| CmdError::invalid())?;
    with_ctx(app, token, |c| {
        let mut h = st.store.load(&c.id)?;
        if mode_of(&h) == "totp" {
            if c.via_recovery {
                return Err(CmdError::invalid()); // use the reset flow
            }
            totp::change_password(&mut h, &c.key, &new_password, st.se.as_ref())?;
            commit(app, &h)?;
            c.password = new_password;
            applog::log(&format!("password changed for {}", c.id));
            return Ok(json!({ "done": true }));
        }
        // YubiKey vault: every registered key must be touched once.
        let mut kdf = h.kdf.clone();
        kdf.salt = crypto::random_bytes::<16>().into();
        let pw = kdf.derive(new_password.as_bytes())?;
        c.pw_change = Some((kdf, pw, vec![], vec![]));
        c.password = new_password;
        Ok(json!({ "done": false, "remaining": fido2::remaining_keys(&h, &[]) }))
    })
}

/// YubiKey password change: re-wrap whichever registered key is plugged in.
pub fn fido_rewrap(app: &AppHandle, token: &str, pin: Zeroizing<String>) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        let mut h = st.store.load(&c.id)?;
        let (_kdf, pw, done, slots) = c.pw_change.as_mut().ok_or(CmdError::invalid())?;
        let app2 = app.clone();
        let notify = move |e| emit_touch(&app2, e);
        let (cred, slot) = fido2::rewrap_present(&h, &c.key, pw, st.fido.as_ref(), &pin, &notify)
            .map_err(fido_setup_error)?;
        if !done.contains(&cred) {
            done.push(cred);
            slots.push(slot);
        }
        let remaining = fido2::remaining_keys(&h, done);
        if !remaining.is_empty() {
            return Ok(json!({ "done": false, "remaining": remaining }));
        }
        let (kdf, _pw, _done, slots) = c.pw_change.take().ok_or(CmdError::invalid())?;
        fido2::apply_password_change(&mut h, &c.key, kdf, slots)?;
        commit(app, &h)?;
        applog::log(&format!("password changed for {}", c.id));
        Ok(json!({ "done": true, "remaining": [] }))
    })
}

// ---------------------------------------------------------------- authenticator

pub fn totp_begin(app: &AppHandle, token: &str) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        if c.via_recovery {
            return Err(CmdError::invalid()); // use the reset flow
        }
        let h = st.store.load(&c.id)?;
        let (setup, pending) = totp::replace_begin(&h, st.se.as_ref())?;
        c.pending_totp = Some(pending);
        Ok(json!({ "secret": setup.secret.as_str(), "qrSvg": setup.qr_svg.as_str() }))
    })
}

pub fn totp_confirm(app: &AppHandle, token: &str, code: Zeroizing<String>) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        let mut h = st.store.load(&c.id)?;
        let pending = c.pending_totp.as_ref().ok_or(CmdError::invalid())?;
        match totp::replace_confirm(
            &mut h,
            &c.key,
            &c.password,
            pending,
            &code,
            vault_core::store::now_unix(),
        ) {
            Ok(()) => {}
            Err(vault_core::Error::UnlockFailed) => return Ok(json!({ "ok": false })),
            Err(e) => return Err(e.into()),
        }
        commit(app, &h)?;
        c.pending_totp = None;
        applog::log(&format!("authenticator replaced for {}", c.id));
        Ok(json!({ "ok": true }))
    })
}

// ---------------------------------------------------------------- YubiKey

pub fn add_fido2(
    app: &AppHandle,
    token: &str,
    pin: Zeroizing<String>,
    label: String,
) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        if c.via_recovery {
            return Err(CmdError::invalid()); // needs the password
        }
        let mut h = st.store.load(&c.id)?;
        let app2 = app.clone();
        let notify = move |e| emit_touch(&app2, e);
        let label = fido2::add_key(
            &mut h,
            &c.key,
            &c.password,
            st.fido.as_ref(),
            &pin,
            &label,
            &notify,
        )
        .map_err(fido_setup_error)?;
        commit(app, &h)?;
        applog::log(&format!("key added to {}", c.id));
        Ok(json!({ "label": label }))
    })
}

// ---------------------------------------------------------------- recovery

pub fn recovery_generate(app: &AppHandle, token: &str) -> CmdResult<Value> {
    with_ctx(app, token, |c| {
        let phrase = recovery::generate()?;
        let words: Vec<String> = recovery::words(&phrase)
            .iter()
            .map(|w| w.as_str().to_string())
            .collect();
        c.pending_recovery = Some(phrase);
        Ok(json!({ "words": words }))
    })
}

pub fn recovery_confirm(
    app: &AppHandle,
    token: &str,
    answers: HashMap<String, String>,
) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        let phrase = c.pending_recovery.as_ref().ok_or(CmdError::invalid())?;
        let parsed: Vec<(usize, &str)> = answers
            .iter()
            .filter_map(|(k, v)| k.parse::<usize>().ok().map(|i| (i, v.as_str())))
            .collect();
        if parsed.len() < 3 || !recovery::verify_answers(phrase, &parsed) {
            return Ok(json!({ "ok": false }));
        }
        let mut h = st.store.load(&c.id)?;
        keyslot::set_recovery(&mut h, &c.key, phrase)?;
        commit(app, &h)?;
        c.pending_recovery = None;
        applog::log(&format!("recovery phrase replaced for {}", c.id));
        Ok(json!({ "ok": true }))
    })
}

// ---------------------------------------------------------------- recovery phrase / new Mac

/// Re-authenticate with the 24-word recovery phrase (e.g. on a new Mac,
/// where a TOTP vault's Secure Enclave key does not exist).
pub fn auth_recovery(app: &AppHandle, id: &str, phrase: Zeroizing<String>) -> CmdResult<Value> {
    let st = state::get(app);
    let header = st.store.load(id)?;
    let key = keyslot::unlock_with_recovery(&header, &phrase)?;
    drop(phrase);
    if !key.header_intact {
        return Err(CmdError::new("header_modified"));
    }
    let token = new_token();
    let mode = mode_of(&header);
    let keys: Vec<String> = fido2::keys(&header).into_iter().map(|k| k.label).collect();
    lock(&st.actions).insert(
        token.clone(),
        ActionCtx {
            id: id.to_string(),
            key,
            password: Zeroizing::new(String::new()),
            created: Instant::now(),
            pending_totp: None,
            pending_recovery: None,
            pw_change: None,
            via_recovery: true,
            reset_password: None,
        },
    );
    applog::log(&format!("action auth (recovery phrase) ok for {id}"));
    Ok(json!({ "token": token, "mode": mode, "keys": keys }))
}

/// TOTP vault reset, step 1: remember the new password, start a new
/// authenticator bound to THIS Mac. (YubiKey vaults use
/// `change_password` + `fido_rewrap`, which only need the VMK.)
pub fn reset_begin(
    app: &AppHandle,
    token: &str,
    new_password: Zeroizing<String>,
) -> CmdResult<Value> {
    let st = state::get(app);
    keyslot::validate_password(&new_password).map_err(|_| CmdError::invalid())?;
    with_ctx(app, token, |c| {
        let h = st.store.load(&c.id)?;
        if mode_of(&h) != "totp" {
            return Err(CmdError::invalid());
        }
        let (setup, pending) = totp::replace_begin(&h, st.se.as_ref())?;
        c.pending_totp = Some(pending);
        c.reset_password = Some(new_password);
        Ok(json!({ "secret": setup.secret.as_str(), "qrSvg": setup.qr_svg.as_str() }))
    })
}

/// Step 2: the first code from the new app confirms; new password + new
/// authenticator are written together.
pub fn reset_confirm(app: &AppHandle, token: &str, code: Zeroizing<String>) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        let mut h = st.store.load(&c.id)?;
        let pending = c.pending_totp.as_ref().ok_or(CmdError::invalid())?;
        let pw = c.reset_password.as_ref().ok_or(CmdError::invalid())?;
        match totp::reset_with_recovery(
            &mut h,
            &c.key,
            pw,
            pending,
            &code,
            vault_core::store::now_unix(),
        ) {
            Ok(()) => {}
            Err(vault_core::Error::UnlockFailed) => return Ok(json!({ "ok": false })),
            Err(e) => return Err(e.into()),
        }
        commit(app, &h)?;
        c.pending_totp = None;
        c.reset_password = None;
        applog::log(&format!("password + authenticator reset for {}", c.id));
        Ok(json!({ "ok": true }))
    })
}

// ---------------------------------------------------------------- portable Brave logins

/// Convert an existing Brave vault's logins to the portable key (vault must
/// be locked). macOS asks once for access to "Brave Safe Storage".
pub fn make_portable(app: &AppHandle, token: &str) -> CmdResult<Value> {
    let st = state::get(app);
    with_ctx(app, token, |c| {
        let stats = st.store.make_portable(&c.id, &c.key).map_err(|e| match e {
            vault_core::Error::Invalid(m) if m == vault_core::store::ERR_LOCK_FIRST => {
                CmdError::new("lock_first")
            }
            vault_core::Error::Invalid(m) if m == vault_core::portable::ERR_KEYCHAIN => {
                CmdError::new("keychain_denied")
            }
            other => other.into(),
        })?;
        if let Some(s) = lock(&st.sessions).get_mut(&c.id) {
            s.unlocked.header.settings.portable_keys = true;
        }
        lockctl::vaults_changed(app);
        applog::log(&format!(
            "logins made portable for {}: {} converted, {} unreadable",
            c.id, stats.converted, stats.failed
        ));
        Ok(json!({ "converted": stats.converted, "failed": stats.failed }))
    })
}
