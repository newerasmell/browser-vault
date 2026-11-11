//! `#[tauri::command]`s — the contract in docs/UI.md.
//!
//! Secrets (password, PIN, code, recovery phrase) arrive as `String`, are
//! moved into `Zeroizing` immediately and dropped when the command returns.
//! They are never logged, stored in state or echoed in errors.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};
use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use vault_core::events::Event;
use vault_core::header::{Header, OriginalState, Slot, VaultSettings};
use vault_core::keyslot::{Draft, KdfCost};
use vault_core::profiles::Roots;
use vault_core::store::{CreateOptions, Devices, ImportRequest};
use vault_core::{browser, Browser, Credential};
use zeroize::Zeroizing;

use crate::error::{CmdError, CmdResult};
use crate::lockctl::{self, Reason};
use crate::original::{self, Pending};
use crate::settings::{Patch, Settings};
use crate::state::{self, lock, AppState, Session};
use crate::texts::{tr, T};
use crate::{tray, triggers, windows};

/// Run blocking work (Argon2 256 MiB, hdiutil, browser shutdown) off the
/// main thread and off the async executor.
async fn blocking<R: Send + 'static>(
    f: impl FnOnce() -> CmdResult<R> + Send + 'static,
) -> CmdResult<R> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| CmdError::new("io"))?
}

fn parse_browser(s: &str) -> CmdResult<Browser> {
    Browser::parse(s).ok_or(CmdError::invalid())
}

#[derive(Serialize)]
struct Ok_ {
    ok: bool,
}
const OK: Ok_ = Ok_ { ok: true };

// ---------------------------------------------------------------- vaults

#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OriginalInfo {
    profile_name: String,
    size_mb: u64,
    reviewed: bool,
    state: &'static str,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    id: String,
    name: String,
    browser: &'static str,
    mode: &'static str,
    status: &'static str,
    size_gb: u32,
    original: Option<OriginalInfo>,
    /// Brave logins use the Mac-independent key (vault works on any Mac).
    portable: bool,
}

/// `fido2` if the vault has a YubiKey slot, else `totp`.
pub fn mode_of(h: &Header) -> &'static str {
    if h.slots.iter().any(|s| matches!(s, Slot::Fido2 { .. })) {
        "fido2"
    } else {
        "totp"
    }
}

pub fn bytes_to_mb(b: u64) -> u64 {
    (b + 512 * 1024) / (1024 * 1024)
}

fn original_info(h: &Header) -> Option<OriginalInfo> {
    h.original.as_ref().map(|o| OriginalInfo {
        profile_name: o.profile_name.clone(),
        size_mb: bytes_to_mb(o.size_bytes),
        reviewed: o.reviewed,
        state: match o.state {
            OriginalState::Pending => "pending",
            OriginalState::Kept => "kept",
            OriginalState::Deleted => "deleted",
        },
    })
}

/// Maximum size of the sparsebundle from its `Info.plist` (`<key>size</key>`,
/// bytes), in GiB as passed to `hdiutil create -size <N>g`. 0 if unreadable.
pub fn sparsebundle_size_gb(image: &Path) -> u32 {
    let Ok(xml) = std::fs::read_to_string(image.join("Info.plist")) else {
        return 0;
    };
    plist_size_gb(&xml)
}

fn plist_size_gb(xml: &str) -> u32 {
    let Some(i) = xml.find("<key>size</key>") else {
        return 0;
    };
    let rest = xml[i + "<key>size</key>".len()..].trim_start();
    let Some(body) = rest.strip_prefix("<integer>") else {
        return 0;
    };
    let Some(end) = body.find("</integer>") else {
        return 0;
    };
    body[..end]
        .trim()
        .parse::<u64>()
        .map(|b| ((b + (1 << 29)) >> 30) as u32)
        .unwrap_or(0)
}

fn vault_info(st: &AppState, h: &Header) -> VaultInfo {
    let id = h.vault_id.clone();
    let status = if lock(&st.errors).contains(&id) {
        "error"
    } else if lock(&st.sessions).contains_key(&id) || lock(&st.locking).contains(&id) {
        // Open, or being locked right now: don't touch a volume mid-detach.
        "unlocked"
    } else if st.store.is_unlocked(&id) {
        "unlocked"
    } else {
        "locked"
    };
    VaultInfo {
        size_gb: sparsebundle_size_gb(&st.store.image_path(&id)),
        name: h.name.clone(),
        browser: h.browser.as_str(),
        mode: mode_of(h),
        status,
        // Added from a backup: the original is on the other Mac (backup.rs).
        original: if vault_core::backup::restored_from_backup(&st.store, &id) {
            None
        } else {
            original_info(h)
        },
        portable: h.browser != Browser::Brave || h.settings.portable_keys,
        id,
    }
}

#[tauri::command]
pub async fn list_vaults(app: AppHandle) -> CmdResult<Vec<VaultInfo>> {
    let st = state::get(&app);
    Ok(st
        .store
        .list()?
        .iter()
        .map(|h| vault_info(&st, h))
        .collect())
}

// ---------------------------------------------------------------- browsers

/// The `.app` bundle that contains `binary`.
fn app_bundle_of(binary: &Path) -> Option<PathBuf> {
    binary
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .map(Path::to_path_buf)
}

/// Binary to launch: manual path from settings if valid, else auto-detect.
fn browser_binary(st: &AppState, b: Browser) -> Option<PathBuf> {
    let manual = st
        .settings()
        .browser_paths
        .get(b.as_str())
        .map(|app| browser::binary_in_app(b, Path::new(app)))
        .filter(|p| p.is_file());
    manual.or_else(|| browser::detect(b))
}

#[tauri::command]
pub async fn detect_browsers(app: AppHandle) -> Value {
    let st = state::get(&app);
    let one = |b: Browser| {
        let path = browser_binary(&st, b).and_then(|bin| app_bundle_of(&bin));
        json!({ "found": path.is_some(), "path": path.map(|p| p.to_string_lossy().into_owned()) })
    };
    json!({ "brave": one(Browser::Brave), "firefox": one(Browser::Firefox) })
}

#[tauri::command]
pub async fn pick_browser_path(app: AppHandle, browser: String) -> CmdResult<Option<String>> {
    let b = parse_browser(&browser)?;
    blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("App", &["app"])
            .set_directory("/Applications")
            .blocking_pick_file();
        let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        if !browser::binary_in_app(b, &path).is_file() {
            return Err(CmdError::new("browser_missing"));
        }
        let st = state::get(&app);
        let s = {
            let mut s = lock(&st.settings);
            s.browser_paths
                .insert(b.as_str().into(), path.to_string_lossy().into_owned());
            s.clone()
        };
        s.save(st.store.root())?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}

#[tauri::command]
pub async fn browser_running(browser: String) -> CmdResult<Value> {
    let b = parse_browser(&browser)?;
    Ok(json!({ "running": vault_core::profiles::regular_browser_running(b) }))
}

#[tauri::command]
pub async fn detect_profiles(browser: String) -> CmdResult<Value> {
    let b = parse_browser(&browser)?;
    match vault_core::profiles::detect_profiles(b) {
        Ok(list) => Ok(Value::Array(
            list.into_iter()
                .map(|p| json!({ "id": p.id, "name": p.name, "sizeMb": bytes_to_mb(p.size_bytes) }))
                .collect(),
        )),
        // Not implemented yet (M7b): the wizard simply shows no profiles.
        Err(vault_core::Error::Unsupported(_)) => Ok(json!([])),
        Err(e) => Err(e.into()),
    }
}

#[tauri::command]
pub fn focus_browser(app: AppHandle, id: String) -> CmdResult<()> {
    let st = state::get(&app);
    let pid = lock(&st.sessions)
        .get(&id)
        .and_then(|s| s.browser_pid)
        .ok_or(CmdError::not_found())?;
    activate_pid(pid);
    Ok(())
}

#[cfg(target_os = "macos")]
fn activate_pid(pid: u32) {
    use objc2_app_kit::{NSApplicationActivationOptions, NSRunningApplication};
    if let Some(app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid as i32) {
        app.activateWithOptions(NSApplicationActivationOptions::ActivateAllWindows);
    }
}

#[cfg(not(target_os = "macos"))]
fn activate_pid(_pid: u32) {}

// ---------------------------------------------------------------- windows / app

#[tauri::command]
pub fn open_window(
    app: AppHandle,
    view: String,
    params: Option<BTreeMap<String, String>>,
) -> CmdResult<()> {
    if view != windows::TRAY {
        if let Some(t) = app.get_webview_window(windows::TRAY) {
            let _ = t.hide();
        }
    }
    let params = params.unwrap_or_default();
    if view == "cleanup" {
        // Deleting the original needs the open session (SPEC §5.1).
        let id = params.get("id").ok_or(CmdError::invalid())?;
        return original::open_cleanup(&app, id);
    }
    windows::open(&app, &view, &params)
}

#[tauri::command]
pub fn close_window(window: WebviewWindow) -> CmdResult<()> {
    if window.label() == windows::TRAY {
        window.hide()?;
    } else {
        window.close()?;
    }
    Ok(())
}

/// Internal (not in docs/UI.md): sizes the tray popover to its content.
#[tauri::command]
pub fn tray_fit(app: AppHandle, height: f64) -> CmdResult<()> {
    windows::fit_tray(&app, height)
}

#[tauri::command]
pub async fn quit_app(app: AppHandle) -> CmdResult<()> {
    blocking(move || {
        let _ = lockctl::lock_all(&app, Reason::Quit);
        app.exit(0);
        Ok(())
    })
    .await
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> Value {
    json!({
        "version": app.package_info().version.to_string(),
        // Set by the CI build ("<run number>-<commit>"); "dev" locally.
        "build": option_env!("BV_BUILD").unwrap_or("dev"),
    })
}

// ---------------------------------------------------------------- unlock / lock

fn emit_touch(app: &AppHandle, id: Option<&str>, e: Event) {
    let name = match e {
        Event::FidoTouchNeeded => "fido_touch_needed",
        Event::FidoTouchDone => "fido_touch_done",
        _ => return,
    };
    let _ = app.emit(name, json!({ "id": id }));
}

enum Secret {
    Factors {
        password: Zeroizing<String>,
        pin: Zeroizing<String>,
        code: Zeroizing<String>,
    },
    Recovery(Zeroizing<String>),
}

fn do_unlock(app: &AppHandle, id: &str, secret: Secret) -> CmdResult<Value> {
    let st = state::get(app);
    // Already unlocked: bring its browser to the front, or start it again
    // if it was closed while the vault stayed open.
    {
        let mut sessions = lock(&st.sessions);
        if let Some(s) = sessions.get_mut(id) {
            if let Some(pid) = s.browser_pid.filter(|p| browser::is_alive(*p as i32)) {
                drop(sessions);
                activate_pid(pid);
                return Ok(json!(OK));
            }
            let bin = browser_binary(&st, s.unlocked.header.browser);
            let child = st.store.launch(&s.unlocked, bin.as_deref())?;
            let pid = child.id();
            s.browser_pid = Some(pid);
            let generation = s.generation;
            drop(sessions);
            crate::applog::log(&format!("browser for {id} reopened as pid {pid}"));
            if let Err(e) = vault_core::lock::spawn_crash_guard(
                std::process::id(),
                pid,
                &st.store.mountpoint(id),
            ) {
                crate::applog::log(&format!("crash guard not started: {e}"));
            }
            triggers::watch_browser(app.clone(), id.to_string(), generation, child);
            return Ok(json!(OK));
        }
    }
    if lock(&st.locking).contains(id) {
        return Err(CmdError::new("io"));
    }
    let header = st.store.load(id)?;
    let cred = match &secret {
        Secret::Recovery(p) => Credential::Recovery(p),
        Secret::Factors {
            password,
            pin,
            code,
        } => {
            if mode_of(&header) == "fido2" {
                Credential::Fido2 { password, pin }
            } else {
                Credential::Totp { password, code }
            }
        }
    };
    let (app2, vid) = (app.clone(), id.to_string());
    let notify = move |e: Event| emit_touch(&app2, Some(&vid), e);
    let dev = Devices {
        se: st.se.as_ref(),
        fido: st.fido.as_ref(),
        notify: &notify,
    };
    let result = st.store.unlock(id, cred, &dev);
    drop(secret);
    let unlocked = result?;
    if !unlocked.header_intact {
        lockctl::notify(app, tr(st.is_bg(), T::HeaderModified));
    }
    let bin = browser_binary(&st, unlocked.header.browser);
    let child = match st.store.launch(&unlocked, bin.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            drop(unlocked);
            let _ = vault_core::lock::lock_vault(&st.store, id);
            lockctl::vaults_changed(app);
            return Err(e.into());
        }
    };
    let generation = st.next_generation();
    let pid = child.id();
    lock(&st.sessions).insert(
        id.to_string(),
        Session {
            unlocked,
            generation,
            browser_pid: Some(pid),
        },
    );
    lock(&st.errors).remove(id);
    // If this app ever dies while the vault is open, a detached guard
    // stops the vault's browser and detaches the volume (SPEC §6).
    if let Err(e) =
        vault_core::lock::spawn_crash_guard(std::process::id(), pid, &st.store.mountpoint(id))
    {
        crate::applog::log(&format!("crash guard not started: {e}"));
    }
    triggers::watch_browser(app.clone(), id.to_string(), generation, child);
    lockctl::vaults_changed(app);
    // An action that asked for this unlock (cleanup, keep, delete) resumes
    // now, on its own thread so the unlock window can close.
    let (app2, vid) = (app.clone(), id.to_string());
    std::thread::spawn(move || original::resume(&app2, &vid));
    Ok(json!(OK))
}

#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    id: String,
    password: String,
    pin: Option<String>,
    code: Option<String>,
) -> CmdResult<Value> {
    let secret = Secret::Factors {
        password: Zeroizing::new(password),
        pin: Zeroizing::new(pin.unwrap_or_default()),
        code: Zeroizing::new(code.unwrap_or_default()),
    };
    blocking(move || do_unlock(&app, &id, secret)).await
}

#[tauri::command]
pub async fn unlock_with_recovery(app: AppHandle, id: String, phrase: String) -> CmdResult<Value> {
    let secret = Secret::Recovery(Zeroizing::new(phrase));
    blocking(move || do_unlock(&app, &id, secret)).await
}

#[tauri::command]
pub async fn lock_vault(app: AppHandle, id: String) -> CmdResult<()> {
    blocking(move || lockctl::lock_one(&app, &id, Reason::Manual)).await
}

#[tauri::command]
pub async fn lock_all(app: AppHandle) -> CmdResult<()> {
    blocking(move || lockctl::lock_all(&app, Reason::Manual)).await
}

// ---------------------------------------------------------------- wizard

fn new_draft_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Take the draft out of the map for the duration of `f` (which may block),
/// then put it back.
fn with_draft<R>(
    st: &AppState,
    draft_id: &str,
    f: impl FnOnce(&mut Draft) -> CmdResult<R>,
) -> CmdResult<R> {
    let mut d = lock(&st.drafts)
        .remove(draft_id)
        .ok_or(CmdError::not_found())?;
    let r = f(&mut d);
    lock(&st.drafts).insert(draft_id.to_string(), d);
    r
}

#[tauri::command]
pub fn wizard_begin(app: AppHandle, name: String, browser: String) -> CmdResult<Value> {
    let b = parse_browser(&browser)?;
    let draft = Draft::new(&name, b, KdfCost::DEFAULT)?;
    let id = new_draft_id();
    lock(&state::get(&app).drafts).insert(id.clone(), draft);
    Ok(json!({ "draftId": id }))
}

#[tauri::command]
pub async fn wizard_set_password(
    app: AppHandle,
    draft_id: String,
    password: String,
) -> CmdResult<Value> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let st = state::get(&app);
        with_draft(&st, &draft_id, |d| Ok(d.set_password(&password)?))?;
        Ok(json!(OK))
    })
    .await
}

#[tauri::command]
pub async fn fido_register(
    app: AppHandle,
    draft_id: String,
    pin: String,
    label: String,
) -> CmdResult<Value> {
    let pin = Zeroizing::new(pin);
    blocking(move || {
        let st = state::get(&app);
        let app2 = app.clone();
        let notify = move |e: Event| emit_touch(&app2, None, e);
        let label = with_draft(&st, &draft_id, |d| {
            vault_core::fido2::register(d, st.fido.as_ref(), &pin, label.trim(), &notify)
                .map_err(crate::error::fido_setup_error)
        });
        // Make sure the overlay goes away whatever happened.
        emit_touch(&app, None, Event::FidoTouchDone);
        Ok(json!({ "label": label? }))
    })
    .await
}

#[tauri::command]
pub async fn totp_begin(app: AppHandle, draft_id: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        let setup = with_draft(&st, &draft_id, |d| {
            Ok(vault_core::totp::begin(d, st.se.as_ref())?)
        })?;
        Ok(json!({ "secret": setup.secret.as_str(), "qrSvg": setup.qr_svg.as_str() }))
    })
    .await
}

#[tauri::command]
pub async fn totp_confirm(app: AppHandle, draft_id: String, code: String) -> CmdResult<Value> {
    let code = Zeroizing::new(code);
    blocking(move || {
        let st = state::get(&app);
        let r = with_draft(&st, &draft_id, |d| {
            Ok(vault_core::totp::confirm(
                d,
                &code,
                st.se.as_ref(),
                vault_core::store::now_unix(),
            ))
        })?;
        match r {
            Ok(()) => Ok(json!({ "ok": true })),
            Err(vault_core::Error::UnlockFailed | vault_core::Error::Invalid(_)) => {
                Ok(json!({ "ok": false }))
            }
            Err(e) => Err(e.into()),
        }
    })
    .await
}

#[tauri::command]
pub async fn recovery_generate(app: AppHandle, draft_id: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        let words = with_draft(&st, &draft_id, |d| Ok(d.generate_recovery()?))?;
        let list: Vec<&str> = words.iter().map(|w| w.as_str()).collect();
        Ok(json!({ "words": list }))
    })
    .await
}

#[tauri::command]
pub async fn recovery_verify(
    app: AppHandle,
    draft_id: String,
    answers: BTreeMap<String, String>,
) -> CmdResult<Value> {
    let answers: Vec<(usize, Zeroizing<String>)> = answers
        .into_iter()
        .map(|(k, v)| {
            k.parse::<usize>()
                .map(|i| (i, Zeroizing::new(v.trim().to_lowercase())))
                .map_err(|_| CmdError::invalid())
        })
        .collect::<CmdResult<_>>()?;
    blocking(move || {
        let st = state::get(&app);
        let refs: Vec<(usize, &str)> = answers.iter().map(|(i, w)| (*i, w.as_str())).collect();
        let ok = with_draft(&st, &draft_id, |d| Ok(d.verify_recovery(&refs)))?;
        Ok(json!({ "ok": ok }))
    })
    .await
}

#[derive(Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct FinishOptions {
    idle_minutes: Option<u32>,
    lock_on_screen_lock: Option<bool>,
    lock_on_key_removal: Option<bool>,
    disable_fxa: bool,
    import_profile: bool,
    import_profile_id: Option<String>,
}

fn vault_settings(o: &FinishOptions) -> VaultSettings {
    let d = VaultSettings::default();
    VaultSettings {
        idle_minutes: o.idle_minutes.unwrap_or(d.idle_minutes),
        lock_on_screen_lock: o.lock_on_screen_lock.unwrap_or(d.lock_on_screen_lock),
        lock_on_key_removal: o.lock_on_key_removal.unwrap_or(d.lock_on_key_removal),
        // Decided by Store::create_with (fresh Brave vaults / converted imports).
        portable_keys: false,
    }
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn wizard_finish(
    app: AppHandle,
    draft_id: String,
    name: String,
    browser: String,
    mode: String,
    size_gb: u32,
    options: FinishOptions,
) -> CmdResult<Value> {
    let b = parse_browser(&browser)?;
    if !(1..=4096).contains(&size_gb) || !matches!(mode.as_str(), "fido2" | "totp") {
        return Err(CmdError::invalid());
    }
    let st = state::get(&app);
    // Validate while the draft stays in the map, so a fixable error does not
    // lose the wizard's state.
    with_draft(&st, &draft_id, |d| {
        d.set_name(&name, b)?;
        if !d.has_second_factor() || !d.recovery_verified() {
            return Err(CmdError::invalid());
        }
        Ok(())
    })?;
    let draft = lock(&st.drafts)
        .remove(&draft_id)
        .ok_or(CmdError::not_found())?;
    let settings = vault_settings(&options);
    blocking(move || {
        let st = state::get(&app);
        let app2 = app.clone();
        let progress = move |e: Event| {
            if let Event::CreateProgress { stage, pct } = e {
                let _ = app2.emit(
                    "create_progress",
                    json!({ "stage": stage.as_str(), "pct": pct }),
                );
            }
        };
        let import = match (options.import_profile, options.import_profile_id) {
            (true, Some(profile_id)) => Some(ImportRequest {
                roots: Roots::system()?,
                profile_id,
            }),
            _ => None,
        };
        let opts = CreateOptions {
            disable_fxa: options.disable_fxa,
            import,
        };
        let created = st
            .store
            .create_with(draft, size_gb, settings, &opts, &progress)?;
        let id = created.header.vault_id.clone();
        let _ = app.emit("create_progress", json!({ "stage": "done", "pct": 100 }));
        lockctl::vaults_changed(&app);
        // The vault exists and works; only the import was refused.
        let import_error = created.import_error.map(|e| CmdError::from(e).code);
        if let Some(code) = import_error {
            let bg = st.is_bg();
            let text = match code {
                "browser_running" => tr(bg, T::ImportBrowserRunning),
                _ => tr(bg, T::ImportFailed),
            };
            let app2 = app.clone();
            std::thread::spawn(move || message(&app2, text));
        }
        Ok(json!({ "vaultId": id, "importError": import_error }))
    })
    .await
}

#[tauri::command]
pub fn wizard_cancel(app: AppHandle, draft_id: String) {
    // Dropping the draft zeroizes its secrets.
    lock(&state::get(&app).drafts).remove(&draft_id);
}

// ---------------------------------------------------------------- settings

#[tauri::command]
pub fn get_settings(app: AppHandle) -> Settings {
    state::get(&app).settings()
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub fn save_settings(
    app: AppHandle,
    language: Option<String>,
    launch_at_login: Option<bool>,
    idle_minutes: Option<u32>,
    lock_on_screen_lock: Option<bool>,
    lock_on_key_removal: Option<bool>,
    panic_hotkey: Option<String>,
    ghost_mode: Option<bool>,
    reveal_hotkey: Option<String>,
) -> CmdResult<Settings> {
    let st = state::get(&app);
    let (before, after) = {
        let mut s = lock(&st.settings);
        let before = s.clone();
        s.apply(Patch {
            language,
            launch_at_login,
            idle_minutes,
            lock_on_screen_lock,
            lock_on_key_removal,
            panic_hotkey,
            ghost_mode,
            reveal_hotkey,
        })
        .map_err(|e| {
            CmdError::new(if e == "hotkey clash" {
                "hotkey_clash"
            } else {
                "invalid"
            })
        })?;
        (before, s.clone())
    };
    after.save(st.store.root())?;
    if before.panic_hotkey != after.panic_hotkey
        || before.reveal_hotkey != after.reveal_hotkey
        || before.ghost_mode != after.ghost_mode
    {
        triggers::register_hotkey(&app);
    }
    if before.ghost_mode != after.ghost_mode {
        tray::apply_ghost(&app);
    }
    if before.language != after.language {
        tray::rebuild_menu(&app);
        // Every open window re-renders in the new language.
        let _ = app.emit("settings_changed", ());
    }
    if before.launch_at_login != after.launch_at_login {
        let al = app.autolaunch();
        let _ = if after.launch_at_login {
            al.enable()
        } else {
            al.disable()
        };
    }
    Ok(after)
}

// ---------------------------------------------------------------- factors / actions

pub fn factors(h: &Header) -> Vec<Value> {
    h.slots
        .iter()
        .filter_map(|s| match s {
            Slot::Fido2 { label, .. } => Some(json!({ "type": "fido2", "label": label })),
            Slot::Totp { .. } => Some(json!({ "type": "totp", "label": "Authenticator" })),
            Slot::Recovery { .. } => {
                Some(json!({ "type": "recovery", "label": "Recovery phrase" }))
            }
            Slot::Password { .. } => None,
        })
        .collect()
}

#[tauri::command]
pub async fn list_factors(app: AppHandle, id: String) -> CmdResult<Vec<Value>> {
    Ok(factors(&state::get(&app).store.load(&id)?))
}

fn message(app: &AppHandle, text: &str) {
    app.dialog()
        .message(text)
        .title("Browser Vault")
        .kind(MessageDialogKind::Info)
        .blocking_show();
}

/// Delete a vault the user has just proven they can open (it must be
/// unlocked), after a native confirmation.
pub fn delete_unlocked_vault(app: &AppHandle, id: &str) -> CmdResult<Value> {
    let st = state::get(app);
    let bg = st.is_bg();
    if !original::is_open(app, id) {
        original::require_unlock(app, id, Pending::Delete)?;
        return Ok(json!({ "ok": false, "pending": "unlock" }));
    }
    let confirmed = app
        .dialog()
        .message(tr(bg, T::DeleteConfirm))
        .title("Browser Vault")
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            tr(bg, T::DeleteButton).into(),
            tr(bg, T::Cancel).into(),
        ))
        .blocking_show();
    if !confirmed {
        return Ok(json!({ "ok": false }));
    }
    let header = st.store.load(id)?;
    lockctl::lock_one(app, id, Reason::Manual)?;
    // Best effort: the TOTP Secure Enclave key is useless without the vault.
    for s in &header.slots {
        if let Slot::Totp {
            se_key_tag,
            se_key_blob,
            ..
        } = s
        {
            let _ = st.se.delete_key(&vault_core::se::SeKeyRef {
                tag: se_key_tag.clone(),
                blob: se_key_blob.as_ref().map(|b| b.0.clone()),
            });
        }
    }
    std::fs::remove_dir_all(st.store.vault_dir(id))?;
    let _ = std::fs::remove_dir(st.store.mountpoint(id));
    lockctl::vaults_changed(app);
    if let Some(w) = app.get_webview_window("settings") {
        let _ = w.eval("location.reload()");
    }
    Ok(json!({ "ok": true }))
}

#[tauri::command]
pub async fn request_vault_action(app: AppHandle, id: String, action: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        st.store.load(&id)?; // validates the id
        match action.as_str() {
            "delete" => delete_unlocked_vault(&app, &id),
            // The other actions run in the settings window itself
            // (action_auth → action_* commands below).
            "change_password" | "add_fido2" | "replace_totp" | "new_recovery" => {
                Ok(json!({ "inline": true }))
            }
            _ => Err(CmdError::invalid()),
        }
    })
    .await
}

#[tauri::command]
pub async fn action_auth(
    app: AppHandle,
    id: String,
    password: String,
    code: Option<String>,
    pin: Option<String>,
) -> CmdResult<Value> {
    let (pw, code, pin) = (
        Zeroizing::new(password),
        Zeroizing::new(code.unwrap_or_default()),
        Zeroizing::new(pin.unwrap_or_default()),
    );
    blocking(move || crate::actions::auth(&app, &id, pw, code, pin)).await
}

#[tauri::command]
pub async fn action_change_password(
    app: AppHandle,
    token: String,
    new_password: String,
) -> CmdResult<Value> {
    let pw = Zeroizing::new(new_password);
    blocking(move || crate::actions::change_password(&app, &token, pw)).await
}

#[tauri::command]
pub async fn action_fido_rewrap(app: AppHandle, token: String, pin: String) -> CmdResult<Value> {
    let pin = Zeroizing::new(pin);
    blocking(move || crate::actions::fido_rewrap(&app, &token, pin)).await
}

#[tauri::command]
pub async fn action_totp_begin(app: AppHandle, token: String) -> CmdResult<Value> {
    blocking(move || crate::actions::totp_begin(&app, &token)).await
}

#[tauri::command]
pub async fn action_totp_confirm(app: AppHandle, token: String, code: String) -> CmdResult<Value> {
    let code = Zeroizing::new(code);
    blocking(move || crate::actions::totp_confirm(&app, &token, code)).await
}

#[tauri::command]
pub async fn action_add_fido2(
    app: AppHandle,
    token: String,
    pin: String,
    label: String,
) -> CmdResult<Value> {
    let pin = Zeroizing::new(pin);
    blocking(move || crate::actions::add_fido2(&app, &token, pin, label)).await
}

#[tauri::command]
pub async fn action_recovery_generate(app: AppHandle, token: String) -> CmdResult<Value> {
    blocking(move || crate::actions::recovery_generate(&app, &token)).await
}

#[tauri::command]
pub async fn action_recovery_confirm(
    app: AppHandle,
    token: String,
    answers: std::collections::HashMap<String, String>,
) -> CmdResult<Value> {
    blocking(move || crate::actions::recovery_confirm(&app, &token, answers)).await
}

#[tauri::command]
pub async fn action_auth_recovery(app: AppHandle, id: String, phrase: String) -> CmdResult<Value> {
    let phrase = Zeroizing::new(phrase);
    blocking(move || crate::actions::auth_recovery(&app, &id, phrase)).await
}

#[tauri::command]
pub async fn action_reset_begin(
    app: AppHandle,
    token: String,
    new_password: String,
) -> CmdResult<Value> {
    let pw = Zeroizing::new(new_password);
    blocking(move || crate::actions::reset_begin(&app, &token, pw)).await
}

#[tauri::command]
pub async fn action_reset_confirm(app: AppHandle, token: String, code: String) -> CmdResult<Value> {
    let code = Zeroizing::new(code);
    blocking(move || crate::actions::reset_confirm(&app, &token, code)).await
}

#[tauri::command]
pub async fn action_make_portable(app: AppHandle, token: String) -> CmdResult<Value> {
    blocking(move || crate::actions::make_portable(&app, &token)).await
}

#[tauri::command]
pub async fn action_end(app: AppHandle, token: String) -> CmdResult<()> {
    crate::actions::end(&app, &token);
    Ok(())
}

// ---------------------------------------------------------------- original profile (M7b)

#[tauri::command]
pub async fn cleanup_preview(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || original::preview(&app, &id)).await
}

#[tauri::command]
pub async fn cleanup_original(app: AppHandle, id: String, password: String) -> CmdResult<Value> {
    let password = Zeroizing::new(password);
    blocking(move || {
        original::cleanup(&app, &id, &password)?;
        Ok(json!(OK))
    })
    .await
}

#[tauri::command]
pub async fn keep_original(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || original::set_kept(&app, &id, true)).await
}

#[tauri::command]
pub async fn restore_original_notice(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || original::set_kept(&app, &id, false)).await
}

// ---------------------------------------------------------------- backup to / add from a drive

/// Specific codes for backup / import refusals (UI texts `err_backup_*`).
fn backup_error(e: vault_core::Error) -> CmdError {
    use vault_core::backup::*;
    use vault_core::Error::{Format, Invalid, NotFound};
    let code = match &e {
        Invalid(m) => match *m {
            ERR_UNLOCKED => "backup_unlocked",
            ERR_OTHER_VAULT => "backup_other_vault",
            ERR_DEST_IN_STORE => "backup_dest_in_store",
            ERR_NOT_A_VAULT => "backup_not_a_vault",
            ERR_INCOMPLETE => "backup_incomplete",
            ERR_ALREADY_ADDED => "backup_already_added",
            ERR_VERIFY => "backup_verify_failed",
            _ => return e.into(),
        },
        Format(_) => "backup_not_a_vault",
        NotFound => "not_found",
        _ => "backup_io",
    };
    CmdError::new(code)
}

fn backup_notify(app: &AppHandle, id: Option<String>) -> impl Fn(Event) + Sync {
    let app = app.clone();
    move |e: Event| {
        if let Event::BackupProgress { pct } = e {
            let _ = app.emit("backup_progress", json!({ "id": id, "pct": pct }));
        }
    }
}

fn pick_folder(app: &AppHandle) -> Option<PathBuf> {
    app.dialog()
        .file()
        .set_directory("/Volumes")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
}

/// `backup_vault { id }`: folder picker, then copy the LOCKED vault there
/// (incremental). Emits `backup_progress { id, pct }`.
/// Returns `{ path, copiedFiles, unchangedFiles }` or `{ cancelled: true }`.
#[tauri::command]
pub async fn backup_vault(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        st.store.load(&id)?;
        let busy = |st: &AppState| {
            lock(&st.sessions).contains_key(&id)
                || lock(&st.locking).contains(&id)
                || st.store.is_unlocked(&id)
        };
        if busy(&st) {
            return Err(CmdError::new("backup_unlocked"));
        }
        let Some(dest) = pick_folder(&app) else {
            return Ok(json!({ "cancelled": true }));
        };
        // Unlocked while the picker was open.
        if busy(&st) {
            return Err(CmdError::new("backup_unlocked"));
        }
        crate::applog::log(&format!("backup {id}: begin"));
        let notify = backup_notify(&app, Some(id.clone()));
        match vault_core::backup::export(&st.store, &id, &dest, &notify) {
            Ok(out) => {
                crate::applog::log(&format!(
                    "backup {id}: done ({} copied, {} unchanged, {} removed)",
                    out.stats.copied_files, out.stats.unchanged_files, out.stats.removed
                ));
                Ok(json!({
                    "path": out.path.to_string_lossy(),
                    "copiedFiles": out.stats.copied_files,
                    "unchangedFiles": out.stats.unchanged_files,
                }))
            }
            Err(e) => {
                crate::applog::log(&format!("backup {id}: error {e}"));
                Err(backup_error(e))
            }
        }
    })
    .await
}

/// `add_vault_from_drive {}`: folder picker (the `.bvault` folder or the
/// folder that holds it), then copy the vault into the local store.
/// Returns `{ id, name, mode }` or `{ cancelled: true }`.
#[tauri::command]
pub async fn add_vault_from_drive(app: AppHandle) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        let Some(src) = pick_folder(&app) else {
            return Ok(json!({ "cancelled": true }));
        };
        crate::applog::log("add from drive: begin");
        let notify = backup_notify(&app, None);
        match vault_core::backup::import(&st.store, &src, &notify) {
            Ok(h) => {
                crate::applog::log(&format!("add from drive {}: done", h.vault_id));
                lockctl::vaults_changed(&app);
                Ok(json!({ "id": h.vault_id, "name": h.name, "mode": mode_of(&h) }))
            }
            Err(e) => {
                crate::applog::log(&format!("add from drive: error {e}"));
                Err(backup_error(e))
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_size() {
        let xml = "<plist><dict><key>band-size</key><integer>8388608</integer>\
                   <key>size</key>\n\t<integer>21474836480</integer></dict></plist>";
        assert_eq!(plist_size_gb(xml), 20);
        assert_eq!(plist_size_gb("<plist/>"), 0);
        assert_eq!(sparsebundle_size_gb(Path::new("/nonexistent")), 0);
    }

    #[test]
    fn bundle_of_binary() {
        assert_eq!(
            app_bundle_of(Path::new(
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
            )),
            Some(PathBuf::from("/Applications/Brave Browser.app"))
        );
        assert_eq!(app_bundle_of(Path::new("/usr/bin/true")), None);
    }

    #[test]
    fn draft_ids_are_random_hex() {
        let a = new_draft_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, new_draft_id());
    }

    #[test]
    fn finish_options_from_ui() {
        let o: FinishOptions = serde_json::from_str(
            r#"{"idleMinutes":5,"lockOnScreenLock":false,"lockOnKeyRemoval":true,
                "disableFxa":false,"importProfile":false,"importProfileId":null}"#,
        )
        .unwrap();
        let s = vault_settings(&o);
        assert_eq!(s.idle_minutes, 5);
        assert!(!s.lock_on_screen_lock);
        assert!(s.lock_on_key_removal);
        assert_eq!(
            vault_settings(&FinishOptions::default()),
            VaultSettings::default()
        );
    }

    #[test]
    fn backup_error_codes() {
        use vault_core::backup::{ERR_ALREADY_ADDED, ERR_UNLOCKED};
        use vault_core::Error;
        assert_eq!(
            backup_error(Error::Invalid(ERR_UNLOCKED)).code,
            "backup_unlocked"
        );
        assert_eq!(
            backup_error(Error::Invalid(ERR_ALREADY_ADDED)).code,
            "backup_already_added"
        );
        assert_eq!(
            backup_error(Error::Format("x".into())).code,
            "backup_not_a_vault"
        );
        assert_eq!(
            backup_error(Error::Io(std::io::Error::other("x"))).code,
            "backup_io"
        );
        assert_eq!(backup_error(Error::Invalid("other")).code, "invalid");
    }

    #[test]
    fn mb_rounding() {
        assert_eq!(bytes_to_mb(0), 0);
        assert_eq!(bytes_to_mb(1024 * 1024), 1);
        assert_eq!(bytes_to_mb(1024 * 1024 * 3 / 2), 2);
    }
}

// ---------------------------------------------------------------- disguise (Settings → Privacy)

/// `{ current, supported, items: [{ id, name }] }`. `supported` is false
/// outside a macOS app bundle (dev builds, Linux).
#[tauri::command]
pub fn list_disguises() -> Value {
    let supported = cfg!(target_os = "macos") && crate::disguise::current_bundle().is_some();
    json!({
        "current": crate::disguise::current().id,
        "supported": supported,
        "items": crate::disguise::DISGUISES
            .iter()
            .map(|d| json!({ "id": d.id, "name": d.name }))
            .collect::<Vec<_>>(),
    })
}

/// Switch to another disguise (or back to "none"). All vaults must be
/// locked (`disguise_unlocked`). On success the app quits and the renamed
/// copy starts; returns `{ name }` first. Other codes: `disguise_same`,
/// `disguise_target_exists`, `disguise_data_exists`, `disguise_failed`,
/// `disguise_unsupported`.
#[tauri::command]
pub async fn apply_disguise(app: AppHandle, disguise: String) -> CmdResult<Value> {
    let d = crate::disguise::by_id(&disguise).ok_or(CmdError::invalid())?;
    blocking(move || {
        crate::disguise::apply(&app, d)
            .map(|name| json!({ "name": name }))
            .map_err(CmdError::new)
    })
    .await
}
