//! App-wide settings (`get_settings` / `save_settings`, docs/UI.md).
//! Persisted as `<store root>/settings.json`. Holds no secrets.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::hotkey;

pub const FILE_NAME: &str = "settings.json";
pub const LANGUAGES: [&str; 2] = ["bg", "en"];
pub const MAX_IDLE_MINUTES: u32 = 24 * 60;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    pub language: String,
    pub launch_at_login: bool,
    /// Global idle lock in minutes; 0 = off (SPEC §6 trigger 2).
    pub idle_minutes: u32,
    pub lock_on_screen_lock: bool,
    pub lock_on_key_removal: bool,
    /// Display form as recorded by the UI, e.g. `⌃⌥⌘L`.
    pub panic_hotkey: String,
    /// Manual browser locations (`.app` bundle path) by browser id.
    pub browser_paths: BTreeMap<String, String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            language: "bg".into(),
            launch_at_login: false,
            idle_minutes: 15,
            lock_on_screen_lock: true,
            lock_on_key_removal: true,
            panic_hotkey: hotkey::DEFAULT.into(),
            browser_paths: BTreeMap::new(),
        }
    }
}

/// Partial update from the UI (`save_settings` takes any subset).
#[derive(Debug, Default, Clone)]
pub struct Patch {
    pub language: Option<String>,
    pub launch_at_login: Option<bool>,
    pub idle_minutes: Option<u32>,
    pub lock_on_screen_lock: Option<bool>,
    pub lock_on_key_removal: Option<bool>,
    pub panic_hotkey: Option<String>,
}

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        fs::read(dir.join(FILE_NAME))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Atomic write (temp → fsync → rename), mode 600.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!("{FILE_NAME}.tmp"));
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(FILE_NAME))
    }

    /// Validate and apply a patch; on error nothing changes.
    pub fn apply(&mut self, p: Patch) -> Result<(), &'static str> {
        let mut next = self.clone();
        if let Some(l) = p.language {
            if !LANGUAGES.contains(&l.as_str()) {
                return Err("unknown language");
            }
            next.language = l;
        }
        if let Some(v) = p.launch_at_login {
            next.launch_at_login = v;
        }
        if let Some(m) = p.idle_minutes {
            if m > MAX_IDLE_MINUTES {
                return Err("idle timeout too long");
            }
            next.idle_minutes = m;
        }
        if let Some(v) = p.lock_on_screen_lock {
            next.lock_on_screen_lock = v;
        }
        if let Some(v) = p.lock_on_key_removal {
            next.lock_on_key_removal = v;
        }
        if let Some(h) = p.panic_hotkey {
            hotkey::parse(&h).ok_or("invalid hotkey")?;
            next.panic_hotkey = h;
        }
        *self = next;
        Ok(())
    }

    pub fn is_bg(&self) -> bool {
        self.language == "bg"
    }
}

/// Effective idle limit in minutes for one vault: the global setting is a
/// master switch and the per-vault value (chosen in the wizard) can only make
/// it stricter. 0 on either side = off for that vault.
pub fn effective_idle_minutes(global: u32, vault: u32) -> Option<u32> {
    if global == 0 || vault == 0 {
        None
    } else {
        Some(global.min(vault))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(d.path()), Settings::default());
        let mut s = Settings::default();
        s.apply(Patch {
            language: Some("en".into()),
            idle_minutes: Some(5),
            ..Patch::default()
        })
        .unwrap();
        s.save(d.path()).unwrap();
        assert_eq!(Settings::load(d.path()), s);
        let json = fs::read_to_string(d.path().join(FILE_NAME)).unwrap();
        assert!(json.contains("\"idleMinutes\": 5"));
        assert!(json.contains("\"panicHotkey\""));
    }

    #[test]
    fn corrupt_or_partial_file_falls_back() {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join(FILE_NAME), b"{not json").unwrap();
        assert_eq!(Settings::load(d.path()), Settings::default());
        fs::write(d.path().join(FILE_NAME), br#"{"idleMinutes":3}"#).unwrap();
        let s = Settings::load(d.path());
        assert_eq!(s.idle_minutes, 3);
        assert!(s.lock_on_screen_lock);
    }

    #[test]
    fn invalid_patch_changes_nothing() {
        let mut s = Settings::default();
        let before = s.clone();
        assert!(s
            .apply(Patch {
                idle_minutes: Some(1),
                panic_hotkey: Some("L".into()),
                ..Patch::default()
            })
            .is_err());
        assert_eq!(s, before);
        assert!(s
            .apply(Patch {
                language: Some("de".into()),
                ..Patch::default()
            })
            .is_err());
        assert!(s
            .apply(Patch {
                idle_minutes: Some(MAX_IDLE_MINUTES + 1),
                ..Patch::default()
            })
            .is_err());
        s.apply(Patch {
            panic_hotkey: Some("⌃⇧F5".into()),
            ..Patch::default()
        })
        .unwrap();
        assert_eq!(s.panic_hotkey, "⌃⇧F5");
    }

    #[test]
    fn idle_rule() {
        assert_eq!(effective_idle_minutes(15, 15), Some(15));
        assert_eq!(effective_idle_minutes(15, 5), Some(5));
        assert_eq!(effective_idle_minutes(5, 30), Some(5));
        assert_eq!(effective_idle_minutes(0, 5), None);
        assert_eq!(effective_idle_minutes(5, 0), None);
    }
}
