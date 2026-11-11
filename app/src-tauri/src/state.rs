//! Process-wide app state, managed by Tauri as `Arc<AppState>`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use tauri::{AppHandle, Manager};
use vault_core::fido2::Authenticator;
use vault_core::keyslot::Draft;
use vault_core::se::SecureEnclave;
use vault_core::store::Unlocked;
use vault_core::Store;

use crate::settings::Settings;

/// One open vault. Dropping it wipes the VMK (`UnlockedKey` is zeroizing).
pub struct Session {
    pub unlocked: Unlocked,
    /// Generation, so a late "browser exited" from an earlier session of the
    /// same vault cannot lock a newer one.
    pub generation: u64,
    pub browser_pid: Option<u32>,
}

pub struct AppState {
    pub store: Store,
    pub sessions: Mutex<HashMap<String, Session>>,
    /// Wizard drafts by opaque random id. Secrets inside are zeroized on drop.
    pub drafts: Mutex<HashMap<String, Draft>>,
    pub settings: Mutex<Settings>,
    /// Vaults whose last detach failed (red icon, status `error`).
    pub errors: Mutex<HashSet<String>>,
    /// Vaults with a lock in progress (dedupes concurrent triggers).
    pub locking: Mutex<HashSet<String>>,
    pub se: Box<dyn SecureEnclave>,
    pub fido: Box<dyn Authenticator>,
    generation: AtomicU64,
    /// Set while the process exits. The final lock then runs ON the main
    /// thread, so it must not touch anything that needs the main thread
    /// (tray icon, events) or it deadlocks (seen on ⌘Q via the app menu).
    pub quitting: AtomicBool,
    /// Set by `disguise::apply` right before this process hands over to
    /// the renamed copy: the store and log directories have already moved,
    /// so the exit path must not touch them.
    pub relaunching: AtomicBool,
    /// Actions waiting for an unlock of that vault (see original.rs).
    pub pending: Mutex<HashMap<String, crate::original::Pending>>,
    /// Settings → vault actions in progress (see actions.rs), by token.
    pub actions: Mutex<crate::actions::Actions>,
    /// When the tray popover was last hidden by losing focus (see tray.rs).
    pub tray_blurred_at: Mutex<Option<Instant>>,
}

/// Poison-tolerant lock: a panic in one command must not wedge the app.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AppState {
    pub fn new(store: Store) -> Self {
        let settings = Settings::load(store.root());
        AppState {
            store,
            sessions: Mutex::default(),
            drafts: Mutex::default(),
            settings: Mutex::new(settings),
            errors: Mutex::default(),
            locking: Mutex::default(),
            se: vault_core::se::system(),
            fido: vault_core::fido2::system(),
            generation: AtomicU64::new(1),
            quitting: AtomicBool::new(false),
            relaunching: AtomicBool::new(false),
            pending: Mutex::default(),
            tray_blurred_at: Mutex::new(None),
            actions: Mutex::default(),
        }
    }

    pub fn is_quitting(&self) -> bool {
        self.quitting.load(Ordering::SeqCst)
    }

    pub fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::Relaxed)
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    pub fn is_bg(&self) -> bool {
        lock(&self.settings).is_bg()
    }
}

pub fn get(app: &AppHandle) -> Arc<AppState> {
    app.state::<Arc<AppState>>().inner().clone()
}
