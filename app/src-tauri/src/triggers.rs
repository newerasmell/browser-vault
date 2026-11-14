//! Lock triggers (SPEC §6, milestone M7):
//! 1. browser exit — a watcher thread per session waits on the `Child`;
//! 2. idle — `vault_core::lock::idle_seconds()` polled every 10 s;
//! 3. screen lock / sleep — macOS notifications (see `macos` below);
//! 4. YubiKey removal — `fido2::key_present` polled every 2 s per fido2
//!    vault; only a present → absent transition locks;
//! 5. manual / panic hotkey — tray menu, `lock_all`, global shortcut.

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use tauri::AppHandle;
use tauri_plugin_global_shortcut::GlobalShortcutExt;
use vault_core::header::{Header, Slot};
use vault_core::store::Unlocked;

use crate::hotkey;
use crate::lockctl::{self, Reason};
use crate::settings::effective_idle_minutes;
use crate::state::{self, lock};

const IDLE_POLL: Duration = Duration::from_secs(10);
const KEY_POLL: Duration = Duration::from_secs(2);

pub fn is_fido2(u: &Unlocked) -> bool {
    u.header
        .slots
        .iter()
        .any(|s| matches!(s, Slot::Fido2 { .. }))
}

/// Trigger 1: lock when the vault's browser exits. Owning the `Child` and
/// waiting on it also reaps the process (no zombie that `kill(pid, 0)` would
/// still report as alive).
pub fn watch_browser(
    app: AppHandle,
    id: String,
    generation: u64,
    child: vault_core::browser::Launched,
) {
    thread::spawn(move || {
        child.wait();
        let st = state::get(&app);
        let mnt = st.store.mountpoint(&id);
        // A browser may quit and relaunch itself under a new PID (Firefox
        // after installing an update). Keep the vault open while any process
        // still uses it; lock only when none appears within a few seconds.
        loop {
            let current = || {
                lock(&st.sessions)
                    .get(&id)
                    .is_some_and(|s| s.generation == generation)
            };
            if !current() {
                return; // locked meanwhile by another trigger
            }
            let mut next = None;
            for _ in 0..12 {
                if let Some(pid) = vault_core::lock::browser_pids_in(&mnt).first() {
                    next = Some(*pid);
                    break;
                }
                thread::sleep(Duration::from_millis(500));
            }
            let Some(pid) = next else { break };
            crate::applog::log(&format!(
                "browser for {id} relaunched as pid {pid}; still watching"
            ));
            let _ = st.store.set_browser_pid(&id, pid);
            if let Some(s) = lock(&st.sessions).get_mut(&id) {
                s.browser_pid = Some(pid as u32);
            }
            while vault_core::browser::is_alive(pid) {
                thread::sleep(Duration::from_secs(1));
            }
        }
        if lock(&st.sessions)
            .get(&id)
            .is_some_and(|s| s.generation == generation)
        {
            let _ = lockctl::lock_one(&app, &id, Reason::BrowserExit);
        }
    });
}

/// Whether the idle trigger fires for a vault.
pub fn idle_expired(idle_secs: f64, global_minutes: u32, vault_minutes: u32) -> bool {
    effective_idle_minutes(global_minutes, vault_minutes)
        .is_some_and(|m| idle_secs >= f64::from(m) * 60.0)
}

/// Trigger 4 edge detector: only a key that was seen and then vanished counts.
pub fn key_removed(previous: Option<bool>, now: bool) -> bool {
    previous == Some(true) && !now
}

fn idle_loop(app: AppHandle) {
    loop {
        thread::sleep(IDLE_POLL);
        let st = state::get(&app);
        if lock(&st.sessions).is_empty() {
            continue;
        }
        let Some(idle) = vault_core::lock::idle_seconds() else {
            continue;
        };
        let global = lock(&st.settings).idle_minutes;
        let _ = lockctl::lock_matching(&app, Reason::Idle, |s| {
            idle_expired(
                idle,
                global,
                s.unlocked.header.settings_or_default().idle_minutes,
            )
        });
    }
}

fn key_loop(app: AppHandle) {
    // Last observed presence per (vault id, session generation).
    let mut previous: HashMap<(String, u64), bool> = HashMap::new();
    loop {
        thread::sleep(KEY_POLL);
        let st = state::get(&app);
        // Snapshot the fido2 sessions' headers; probe without holding the lock.
        let open: Vec<(String, u64, Header, bool)> = lock(&st.sessions)
            .iter()
            .filter(|(_, s)| is_fido2(&s.unlocked))
            .map(|(id, s)| {
                let h = &s.unlocked.header;
                (
                    id.clone(),
                    s.generation,
                    h.clone(),
                    h.settings_or_default().lock_on_key_removal,
                )
            })
            .collect();
        previous.retain(|(id, g), _| open.iter().any(|(i, gg, ..)| i == id && gg == g));
        let global = lock(&st.settings).lock_on_key_removal;
        for (id, generation, header, vault_enabled) in open {
            // IOKit registry only — never open the HID device while polling
            // (pulling the key out mid-probe crashed the app via hidapi).
            let _ = &header;
            let now = vault_core::fido2::fido_hid_present();
            let prev = previous.insert((id.clone(), generation), now);
            if key_removed(prev, now) && global && vault_enabled {
                let app = app.clone();
                thread::spawn(move || {
                    let _ = lockctl::lock_one(&app, &id, Reason::KeyRemoved);
                });
            }
        }
    }
}

/// Trigger 3 handler (screen locked or system going to sleep).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn on_screen_lock(app: &AppHandle) {
    let st = state::get(app);
    if !lock(&st.settings).lock_on_screen_lock {
        return;
    }
    let app = app.clone();
    thread::spawn(move || {
        let _ = lockctl::lock_matching(&app, Reason::ScreenLock, |s| {
            s.unlocked.header.settings_or_default().lock_on_screen_lock
        });
    });
}

/// The reveal hotkey, if it should be registered (ghost mode only).
pub fn active_reveal_hotkey(s: &crate::settings::Settings) -> Option<String> {
    s.ghost_mode.then(|| s.reveal_hotkey.clone())
}

/// (Re-)register the panic hotkey and, in ghost mode, the reveal hotkey
/// from settings. Returns false if the OS refused the panic hotkey (e.g.
/// taken by another app). The handler in main.rs tells them apart with
/// `hotkey::dispatch`.
pub fn register_hotkey(app: &AppHandle) -> bool {
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    let s = state::get(app).settings();
    let shortcut = hotkey::parse(&s.panic_hotkey).or_else(|| hotkey::parse(hotkey::DEFAULT));
    let ok = shortcut.is_some_and(|sc| gs.register(sc).is_ok());
    if let Some(reveal) = active_reveal_hotkey(&s).and_then(|r| hotkey::parse(&r)) {
        if shortcut != Some(reveal) && gs.register(reveal).is_err() {
            crate::applog::log("reveal hotkey: refused by the system");
        }
    }
    ok
}

/// Called from `setup` on the main thread.
pub fn start(app: &AppHandle) {
    let a = app.clone();
    thread::spawn(move || idle_loop(a));
    let a = app.clone();
    thread::spawn(move || key_loop(a));
    #[cfg(target_os = "macos")]
    macos::observe_screen_lock_and_sleep(app.clone());
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ptr::NonNull;

    use block2::RcBlock;
    use objc2_app_kit::{NSWorkspace, NSWorkspaceWillSleepNotification};
    use objc2_foundation::{NSDistributedNotificationCenter, NSNotification, NSString};
    use tauri::AppHandle;

    /// `com.apple.screenIsLocked` (distributed) and
    /// `NSWorkspaceWillSleepNotification`. Observers live for the whole
    /// process, so their tokens are intentionally leaked.
    pub fn observe_screen_lock_and_sleep(app: AppHandle) {
        let block = RcBlock::new(move |_n: NonNull<NSNotification>| {
            super::on_screen_lock(&app);
        });
        let screen_locked = NSString::from_str("com.apple.screenIsLocked");
        let distributed = NSDistributedNotificationCenter::defaultCenter();
        let workspace_center = NSWorkspace::sharedWorkspace().notificationCenter();
        // SAFETY: no `object` filter; `queue` nil delivers on the posting
        // thread; the block only clones an AppHandle and spawns a thread.
        unsafe {
            let t1 = distributed.addObserverForName_object_queue_usingBlock(
                Some(&screen_locked),
                None,
                None,
                &block,
            );
            let t2 = workspace_center.addObserverForName_object_queue_usingBlock(
                Some(NSWorkspaceWillSleepNotification),
                None,
                None,
                &block,
            );
            std::mem::forget(t1);
            std::mem::forget(t2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_rules() {
        assert!(!idle_expired(14.0 * 60.0, 15, 15));
        assert!(idle_expired(15.0 * 60.0, 15, 15));
        assert!(idle_expired(5.0 * 60.0, 15, 5));
        assert!(!idle_expired(1e9, 0, 15));
        assert!(!idle_expired(1e9, 15, 0));
    }

    #[test]
    fn key_edges() {
        // Stub backend says "absent" from the start: never locks.
        assert!(!key_removed(None, false));
        assert!(!key_removed(Some(false), false));
        assert!(!key_removed(Some(true), true));
        assert!(!key_removed(Some(false), true));
        assert!(key_removed(Some(true), false));
    }
}
