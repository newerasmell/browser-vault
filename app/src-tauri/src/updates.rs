//! Watch the apps vaults run with (Brave, Firefox, Telegram, …) for
//! updates. A new major version can change how an app stores its data —
//! Brave 158 dropped every login it could no longer read — so the user is
//! told as soon as it happens, and each vault asks before opening with the
//! new version (`Store::launch_guarded`).

use std::time::Duration;

use tauri::AppHandle;
use vault_core::browser::{self, Browser};

use crate::state::{self, lock};

/// Every app kind, each installed app once (WhatsApp runs in Brave).
const KINDS: [Browser; 6] = [
    Browser::Brave,
    Browser::Firefox,
    Browser::Telegram,
    Browser::Slack,
    Browser::Obsidian,
    Browser::Vm,
];

fn display(b: Browser) -> &'static str {
    match b {
        Browser::Brave | Browser::WhatsApp => "Brave",
        Browser::Firefox => "Firefox",
        Browser::Telegram => "Telegram",
        Browser::Slack => "Slack",
        Browser::Obsidian => "Obsidian",
        Browser::Vm => "Parallels Desktop",
    }
}

/// Compare installed versions with the ones seen last time; notify on a
/// changed major version and remember the new ones.
pub fn check(app: &AppHandle) {
    let st = state::get(app);
    let mut changed: Vec<(Browser, String)> = Vec::new();
    {
        let mut s = lock(&st.settings);
        for b in KINDS {
            let Some(v) =
                crate::commands::installed_app(&s, b).and_then(|a| browser::app_version(&a))
            else {
                continue;
            };
            let key = b.as_str().to_string();
            match s.seen_versions.get(&key) {
                Some(old) if browser::major_version(old) != browser::major_version(&v) => {
                    changed.push((b, v.clone()));
                }
                _ => {}
            }
            s.seen_versions.insert(key, v);
        }
        let _ = s.save(st.store.root());
    }
    let bg = st.is_bg();
    for (b, v) in changed {
        let app_name = display(b);
        crate::applog::log(&format!("{app_name} updated to {v}"));
        let body = if bg {
            format!("{app_name} е обновен до {v}. Сейфовете, които го ползват, ще питат преди отваряне.")
        } else {
            format!("{app_name} was updated to {v}. Vaults that use it will ask before opening.")
        };
        crate::lockctl::notify(app, &body);
    }
}

/// Check now and every few hours.
pub fn start(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || loop {
        check(&app);
        std::thread::sleep(Duration::from_secs(3 * 60 * 60));
    });
}
