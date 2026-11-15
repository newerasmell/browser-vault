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
use vault_core::index;
use vault_core::keyslot::{Draft, KdfCost};
use vault_core::profiles::Roots;
use vault_core::store::Listed;
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

/// `name` / `browser` are `null` for a vault whose v2 header keeps them
/// encrypted and that this Mac has no index entry for ("Locked vault").
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    id: String,
    name: Option<String>,
    browser: Option<&'static str>,
    mode: &'static str,
    status: &'static str,
    size_gb: u32,
    original: Option<OriginalInfo>,
    /// Brave logins use the Mac-independent key (vault works on any Mac).
    portable: bool,
    /// Only known while unlocked: the vault has its own copy of the app.
    app_in_vault: Option<bool>,
    /// The installed app outside the vault (/Applications), if any.
    app_outside: Option<String>,
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

fn original_info(e: &index::Entry) -> Option<OriginalInfo> {
    e.original.as_ref().map(|o| OriginalInfo {
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

fn vault_info(st: &AppState, l: &Listed) -> VaultInfo {
    let h = &l.header;
    let label = l.label.as_ref();
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
        name: label.map(|e| e.name.clone()),
        browser: label.map(|e| e.browser.as_str()),
        mode: mode_of(h),
        status,
        // Added from a backup: the original is on the other Mac (backup.rs).
        original: if vault_core::backup::restored_from_backup(&st.store, &id) {
            None
        } else {
            label.and_then(original_info)
        },
        // Unknown browser: nothing to offer until the first unlock.
        portable: label.is_none_or(|e| e.browser != Browser::Brave || e.portable_keys),
        app_in_vault: (status == "unlocked")
            .then(|| {
                label.map(|e| browser::vault_binary(e.browser, &st.store.mountpoint(&id)).is_some())
            })
            .flatten(),
        app_outside: label
            .and_then(|e| browser_binary(st, e.browser))
            .and_then(|b| app_bundle_of(&b))
            .map(|p| p.to_string_lossy().into_owned()),
        id,
    }
}

/// The open vault's app kind and mountpoint (`vault_locked` otherwise).
fn open_vault(st: &AppState, id: &str) -> CmdResult<(Browser, PathBuf)> {
    let sessions = lock(&st.sessions);
    let s = sessions.get(id).ok_or(CmdError::new("vault_locked"))?;
    Ok((
        s.unlocked.header.meta()?.browser,
        s.unlocked.mountpoint.clone(),
    ))
}

/// Copy the installed app into the open vault, so the vault runs its own
/// copy from now on (`app_copy_failed`, `browser_missing`).
#[tauri::command]
pub async fn move_app_into_vault(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        let (b, mnt) = open_vault(&st, &id)?;
        // WhatsApp runs in the shared Brave; a VM vault holds the VM, not
        // Parallels itself.
        if b.engine() != b || b == Browser::Vm {
            return Err(CmdError::invalid());
        }
        let src = browser_binary(&st, b)
            .and_then(|bin| app_bundle_of(&bin))
            .ok_or(CmdError::new("browser_missing"))?;
        browser::copy_app_into(b, &src, &mnt).map_err(|e| {
            crate::applog::log(&format!("app copy into {id} failed: {e}"));
            CmdError::new("app_copy_failed")
        })?;
        crate::applog::log(&format!("app copied into vault {id}"));
        lockctl::vaults_changed(&app);
        Ok(json!(OK))
    })
    .await
}

/// Show the installed app (outside the vault) selected in the Finder, once
/// this open vault has its own copy, so the user drags it to the Trash.
/// The app never moves another developer's app itself: macOS blocks that
/// unless the app is allowed under Privacy & Security → App Management
/// (and lists it there), while the Finder may. Refused while that app runs
/// outside a vault (`browser_running`) or before the copy exists
/// (`app_not_in_vault`).
#[tauri::command]
pub async fn remove_app_outside(app: AppHandle, id: String) -> CmdResult<Value> {
    blocking(move || {
        let st = state::get(&app);
        let (b, mnt) = open_vault(&st, &id)?;
        // WhatsApp runs in the shared Brave; a VM vault holds the VM, not
        // Parallels itself.
        if b.engine() != b || b == Browser::Vm {
            return Err(CmdError::invalid());
        }
        if browser::vault_binary(b, &mnt).is_none() {
            return Err(CmdError::new("app_not_in_vault"));
        }
        if vault_core::profiles::regular_browser_running(b) {
            return Err(CmdError::new("browser_running"));
        }
        let src = browser_binary(&st, b)
            .and_then(|bin| app_bundle_of(&bin))
            .filter(|p| !p.starts_with(st.store.root()))
            .ok_or(CmdError::new("browser_missing"))?;
        let shown = std::process::Command::new("/usr/bin/open")
            .arg("-R")
            .arg(&src)
            .status()
            .is_ok_and(|s| s.success());
        if !shown {
            return Err(CmdError::new("app_remove_failed"));
        }
        Ok(json!({ "ok": true, "path": src.to_string_lossy() }))
    })
    .await
}

#[tauri::command]
pub async fn list_vaults(app: AppHandle) -> CmdResult<Vec<VaultInfo>> {
    let st = state::get(&app);
    Ok(st
        .store
        .list_labeled()?
        .iter()
        .map(|l| vault_info(&st, l))
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
        .get(b.engine().as_str())
        .filter(|app| browser::app_is_usable(b, Path::new(app)))
        .map(|app| browser::binary_in_app(b, Path::new(app)));
    manual.or_else(|| browser::detect(b))
}

#[tauri::command]
pub async fn detect_browsers(app: AppHandle) -> Value {
    let st = state::get(&app);
    let one = |b: Browser| {
        let path = browser_binary(&st, b).and_then(|bin| app_bundle_of(&bin));
        json!({ "found": path.is_some(), "path": path.map(|p| p.to_string_lossy().into_owned()) })
    };
    json!({
        "brave": one(Browser::Brave),
        "firefox": one(Browser::Firefox),
        "telegram": one(Browser::Telegram),
        "whatsapp": one(Browser::WhatsApp),
        "slack": one(Browser::Slack),
        "vm": one(Browser::Vm),
        "obsidian": one(Browser::Obsidian),
    })
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
        if !browser::app_is_usable(b, &path) {
            return Err(CmdError::new("browser_missing"));
        }
        let st = state::get(&app);
        let s = {
            let mut s = lock(&st.settings);
            s.browser_paths.insert(
                b.engine().as_str().into(),
                path.to_string_lossy().into_owned(),
            );
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

/// Pick a Parallels VM bundle anywhere (e.g. an external drive) for a VM
/// vault import. `null` when cancelled.
#[tauri::command]
pub async fn pick_vm(app: AppHandle) -> CmdResult<Option<Value>> {
    blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("Parallels VM", &["pvm"])
            .set_directory("/Volumes")
            .blocking_pick_file();
        let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        let p = vault_core::profiles::describe_vm(&path).map_err(|_| CmdError::new("not_a_vm"))?;
        Ok(Some(
            json!({ "id": p.id, "name": p.name, "sizeMb": bytes_to_mb(p.size_bytes) }),
        ))
    })
    .await
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
            if st.store.focus_running_vm(id) {
                return Ok(json!(OK));
            }
            let bin = browser_binary(&st, s.unlocked.header.meta()?.browser);
            let child = st.store.launch(&s.unlocked, bin.as_deref())?;
            let pid = child.id();
            s.browser_pid = (pid > 0).then_some(pid);
            let generation = s.generation;
            drop(sessions);
            crate::applog::log(&format!("browser for {id} reopened as pid {pid}"));
            if let Err(e) = vault_core::lock::spawn_crash_guard_with(
                std::process::id(),
                pid,
                &st.store.mountpoint(id),
                child.vm(),
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
    let bin = match unlocked.header.meta() {
        Ok(m) => browser_binary(&st, m.browser),
        Err(_) => None,
    };
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
            // A VM has no process of ours (`Launched::Vm`).
            browser_pid: (pid > 0).then_some(pid),
        },
    );
    lock(&st.errors).remove(id);
    // If this app ever dies while the vault is open, a detached guard
    // stops the vault's browser (suspends its VM) and detaches the volume
    // (SPEC §6).
    if let Err(e) = vault_core::lock::spawn_crash_guard_with(
        std::process::id(),
        pid,
        &st.store.mountpoint(id),
        child.vm(),
    ) {
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

/// Which vaults "Unlock group" opens (YubiKey vaults only, unknown or
/// authenticator vaults are dropped). Order is kept.
#[tauri::command]
pub fn set_unlock_group(app: AppHandle, ids: Vec<String>) -> CmdResult<Settings> {
    let st = state::get(&app);
    let mut group: Vec<String> = Vec::new();
    for id in ids {
        if group.contains(&id) {
            continue;
        }
        if let Ok(h) = st.store.load(&id) {
            if mode_of(&h) == "fido2" {
                group.push(id);
            }
        }
    }
    let s = {
        let mut s = lock(&st.settings);
        s.unlock_group = group;
        s.clone()
    };
    s.save(st.store.root())?;
    Ok(s)
}

/// Open every locked vault of the unlock group with one password + PIN.
/// Each vault still needs its own touch of the key (its own credential on
/// it). Emits `group_progress { id, index, total }` before each one.
/// Stops if the first vault fails (most likely a typo, and every further
/// try would ask for another touch); later failures don't stop the rest.
/// Returns `{ results: [{ id, ok, code }] }`; codes are the usual generic
/// ones.
#[tauri::command]
pub async fn unlock_group(app: AppHandle, password: String, pin: String) -> CmdResult<Value> {
    let password = Zeroizing::new(password);
    let pin = Zeroizing::new(pin);
    blocking(move || {
        let st = state::get(&app);
        let ids: Vec<String> = st
            .settings()
            .unlock_group
            .into_iter()
            .filter(|id| {
                !lock(&st.sessions).contains_key(id)
                    && st.store.load(id).is_ok_and(|h| mode_of(&h) == "fido2")
            })
            .collect();
        let total = ids.len();
        let mut results = Vec::new();
        for (index, id) in ids.iter().enumerate() {
            let _ = app.emit(
                "group_progress",
                json!({ "id": id, "index": index, "total": total }),
            );
            let secret = Secret::Factors {
                password: Zeroizing::new(password.to_string()),
                pin: Zeroizing::new(pin.to_string()),
                code: Zeroizing::new(String::new()),
            };
            let r = do_unlock(&app, id, secret);
            let failed = r.is_err();
            results.push(json!({
                "id": id,
                "ok": !failed,
                "code": r.err().map(|e| e.code),
            }));
            if failed && index == 0 {
                break;
            }
        }
        Ok(json!({ "results": results, "total": total }))
    })
    .await
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
    diagnostic_log: Option<bool>,
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
            diagnostic_log,
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
    if before.log_enabled() != after.log_enabled() {
        crate::applog::set_enabled(after.log_enabled());
    }
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
    // Key labels: the real ones once the metadata is open, else "YubiKey N"
    // (a v2 header keeps them sealed).
    let mut keys = vault_core::fido2::keys(h).into_iter();
    h.slots
        .iter()
        .filter_map(|s| match s {
            Slot::Fido2 { .. } => keys
                .next()
                .map(|k| json!({ "type": "fido2", "label": k.label })),
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
    let st = state::get(&app);
    // An open vault has its metadata (and so the key labels) decrypted.
    if let Some(s) = lock(&st.sessions).get(&id) {
        return Ok(factors(&s.unlocked.header));
    }
    Ok(factors(&st.store.load(&id)?))
}

fn message(app: &AppHandle, text: &str) {
    app.dialog()
        .message(text)
        .title(vault_core::identity::display_name())
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
        .title(vault_core::identity::display_name())
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
    st.store.remove_vault(id)?;
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
                // v2: the name is encrypted; `null` until the first unlock here.
                let name = st.store.label(&h).map(|e| e.name);
                Ok(json!({ "id": h.vault_id, "name": name, "mode": mode_of(&h) }))
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

/// Pick a downloaded update (`.dmg` or `.app`) and install it over this
/// bundle, keeping the current disguise. `null` when the picker was
/// cancelled; on success the app restarts and `{ name }` is returned first.
/// Codes: `disguise_unlocked`, `disguise_install_first`, `update_not_ours`,
/// `update_failed`, `disguise_unsupported`.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> CmdResult<Option<Value>> {
    blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("Update", &["dmg", "app"])
            .set_directory(
                std::env::var_os("HOME")
                    .map(|h| Path::new(&h).join("Downloads"))
                    .unwrap_or_default(),
            )
            .blocking_pick_file();
        let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
            return Ok(None);
        };
        crate::disguise::install_update(&app, &path)
            .map(|name| Some(json!({ "name": name })))
            .map_err(CmdError::new)
    })
    .await
}

/// Frontend errors (uncaught exceptions, rejected promises) go to the app
/// log so a blank window can be diagnosed. Messages are truncated; the UI
/// never puts secrets in errors (command errors are bare codes).
#[tauri::command]
pub fn ui_log(view: String, msg: String) {
    let clip = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    crate::applog::log(&format!("ui[{}]: {}", clip(&view, 24), clip(&msg, 300)));
}
