//! Browser Vault — macOS menu bar app (Tauri 2). UI contract: docs/UI.md.

mod actions;
mod applog;
mod commands;
mod disguise;
mod error;
mod hotkey;
mod launcher;
mod lockctl;
mod original;
mod settings;
mod state;
mod texts;
mod tray;
mod triggers;
mod updates;
mod windows;

use std::sync::Arc;

use tauri::RunEvent;
use tauri_plugin_global_shortcut::ShortcutState;
use vault_core::Store;

use crate::lockctl::Reason;
use crate::state::AppState;

/// Recovery when the reveal hotkey is forgotten:
/// `open -n -a "<app name>" --args --reveal` (docs/NOTES.md).
const REVEAL_ARG: &str = "--reveal";

static APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

fn main() {
    // An interrupted disguise switch may have left the data under the
    // previous name; adopt it before anything opens the store or the log.
    disguise::adopt_on_start();
    applog::install();
    let store = Store::default_location().expect("HOME must be set");
    let app_state = Arc::new(AppState::new(store));
    applog::set_enabled(app_state.settings().log_enabled());
    // Best effort, off the startup path: drop macOS's record of where this
    // app's download came from.
    std::thread::spawn(vault_core::traces::scrub_download_records);

    let app = tauri::Builder::default()
        // First: a second launch hands over its arguments and exits before
        // it creates anything (no icon flash). In ghost mode that is all —
        // nothing visible happens unless it asked for `--reveal`.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            let ghost = state::get(app).settings().ghost_mode;
            if args.iter().any(|a| a == REVEAL_ARG) || !ghost {
                windows::reveal_tray(app);
            }
        }))
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if event.state() != ShortcutState::Pressed {
                        return;
                    }
                    let s = state::get(app).settings();
                    let reveal = triggers::active_reveal_hotkey(&s);
                    match hotkey::dispatch(shortcut, reveal.as_deref()) {
                        hotkey::Action::LockAll => {
                            applog::log("hotkey pressed: lock all");
                            lockctl::spawn_lock_all(app, Reason::Hotkey);
                        }
                        hotkey::Action::Reveal => windows::reveal_tray(app),
                    }
                })
                .build(),
        )
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        // Named after the running bundle, so a disguised copy's LaunchAgent
        // is `~/Library/LaunchAgents/<disguise name>.plist` (LaunchAgent is
        // the builder default on macOS).
        .plugin(
            tauri_plugin_autostart::Builder::new()
                .app_name(vault_core::identity::display_name())
                .build(),
        )
        .manage(app_state.clone())
        .invoke_handler(tauri::generate_handler![
            commands::list_vaults,
            commands::detect_browsers,
            commands::open_window,
            commands::close_window,
            commands::focus_browser,
            commands::quit_app,
            commands::unlock_vault,
            commands::unlock_with_recovery,
            commands::lock_vault,
            commands::lock_all,
            commands::wizard_begin,
            commands::wizard_set_password,
            commands::fido_register,
            commands::totp_begin,
            commands::totp_confirm,
            commands::recovery_generate,
            commands::recovery_verify,
            commands::wizard_finish,
            commands::wizard_cancel,
            commands::get_settings,
            commands::save_settings,
            commands::list_factors,
            commands::request_vault_action,
            commands::action_auth,
            commands::action_change_password,
            commands::action_fido_rewrap,
            commands::action_totp_begin,
            commands::action_totp_confirm,
            commands::action_add_fido2,
            commands::action_recovery_generate,
            commands::action_recovery_confirm,
            commands::action_auth_recovery,
            commands::action_reset_begin,
            commands::action_reset_confirm,
            commands::action_make_portable,
            commands::action_repair_logins,
            commands::action_end,
            commands::ui_log,
            commands::install_update,
            commands::pick_vm,
            commands::set_unlock_group,
            commands::unlock_group,
            commands::app_version_status,
            commands::open_vault_app,
            commands::move_app_into_vault,
            commands::remove_app_outside,
            commands::detect_profiles,
            commands::browser_running,
            commands::cleanup_preview,
            commands::cleanup_original,
            commands::keep_original,
            commands::restore_original_notice,
            commands::pick_browser_path,
            commands::app_info,
            commands::tray_fit,
            commands::backup_vault,
            commands::add_vault_from_drive,
            commands::list_disguises,
            commands::apply_disguise,
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let handle = app.handle().clone();
            // Vault names arrive from the Keychain on a background thread;
            // refresh every list when they do (see index::keychain).
            let _ = APP.set(handle.clone());
            #[cfg(target_os = "macos")]
            vault_core::browser::set_launcher(launcher::launch);
            vault_core::index::set_on_ready(|| {
                if let Some(h) = APP.get() {
                    lockctl::vaults_changed(h);
                }
            });
            let st = state::get(&handle);

            // SPEC §6: leftovers from a crash are detached before anything else.
            match vault_core::lock::recover_after_crash(&st.store) {
                Ok(ids) if !ids.is_empty() => {
                    lockctl::notify(
                        &handle,
                        texts::tr(st.is_bg(), texts::T::RecoveredAfterCrash),
                    );
                }
                Ok(_) => {}
                Err(_) => {
                    // Still mounted: show as error until the user locks it.
                    for h in st.store.list().unwrap_or_default() {
                        if st.store.is_unlocked(&h.vault_id) {
                            state::lock(&st.errors).insert(h.vault_id);
                        }
                    }
                }
            }

            windows::create_tray_window(&handle)?;
            tray::create(&handle)?;
            triggers::start(&handle);
            updates::start(&handle);
            triggers::register_hotkey(&handle);

            // Keep `disguise` in settings in step with the bundle we run as.
            if disguise::current_bundle().is_some() {
                let cur = disguise::current().id;
                let mut s = state::lock(&st.settings);
                if s.disguise != cur {
                    s.disguise = cur.into();
                    let _ = s.save(st.store.root());
                }
            }
            // Re-register login start with this bundle's name and path
            // (after a disguise switch the old entry was removed).
            if st.settings().launch_at_login {
                use tauri_plugin_autostart::ManagerExt as _;
                let _ = handle.autolaunch().enable();
            }
            if std::env::args().any(|a| a == REVEAL_ARG) {
                windows::reveal_tray(&handle);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application");

    app.run(move |handle, event| match event {
        // Double-click on the already running app in Finder / Launchpad.
        // Ghost mode: nothing visible happens.
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => {
            if !state::get(handle).settings().ghost_mode {
                windows::reveal_tray(handle);
            }
        }
        // Switching to a disguise: everything is locked and the store has
        // already moved; hand over without touching it.
        RunEvent::Exit
            if state::get(handle)
                .relaunching
                .load(std::sync::atomic::Ordering::SeqCst) => {}
        // A menu bar app keeps running when its last window closes.
        RunEvent::ExitRequested {
            code: None, api, ..
        } => api.prevent_exit(),
        // Logout / shutdown / quit: never leave a vault mounted.
        RunEvent::Exit => {
            applog::log("exit: locking all vaults");
            state::get(handle)
                .quitting
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = lockctl::lock_all(handle, Reason::Quit);
            applog::log("exit: done");
        }
        _ => {}
    });
}
