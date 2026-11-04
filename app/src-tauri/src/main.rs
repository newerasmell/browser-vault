//! Browser Vault — macOS menu bar app (Tauri 2). UI contract: docs/UI.md.

mod actions;
mod applog;
mod commands;
mod error;
mod hotkey;
mod lockctl;
mod original;
mod settings;
mod state;
mod texts;
mod tray;
mod triggers;
mod windows;

use std::sync::Arc;

use tauri::RunEvent;
use tauri_plugin_autostart::MacosLauncher;
use tauri_plugin_global_shortcut::ShortcutState;
use vault_core::Store;

use crate::lockctl::Reason;
use crate::state::AppState;

fn main() {
    applog::install();
    let store = Store::default_location().expect("HOME must be set");
    let app_state = Arc::new(AppState::new(store));

    let app = tauri::Builder::default()
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    // The panic hotkey is the only registered shortcut.
                    if event.state() == ShortcutState::Pressed {
                        applog::log("hotkey pressed: lock all");
                        lockctl::spawn_lock_all(app, Reason::Hotkey);
                    }
                })
                .build(),
        )
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            None,
        ))
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
            commands::action_end,
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
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let handle = app.handle().clone();
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
            triggers::register_hotkey(&handle);
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application");

    app.run(move |handle, event| match event {
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
