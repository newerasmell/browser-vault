//! The app's visible identity, read from the running bundle's `Info.plist`.
//!
//! A disguised copy of the app (see the app's `disguise.rs`) carries a
//! neutral `CFBundleName` and a custom key [`STORE_NAME_KEY`] naming the
//! data / log directories, so nothing a casual look would see says
//! "Browser Vault". Outside a bundle (CLI, `tauri dev`, Linux) every value
//! falls back to the defaults.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Custom `Info.plist` key: directory name under `~/Library/Application
/// Support` and `~/Library/Logs`.
pub const STORE_NAME_KEY: &str = "BVStoreName";
pub const DEFAULT_STORE_NAME: &str = "BrowserVault";
pub const DEFAULT_DISPLAY_NAME: &str = "Browser Vault";

/// `$0` of the crash guard shell (lock.rs). Neutral on purpose: it shows in
/// Activity Monitor / `ps` while a vault is open.
pub const GUARD_NAME: &str = "idle-watch";

/// A directory name we accept from `Info.plist`: one path component of
/// letters, digits, `.`, `-`, `_` and spaces, not starting with a dot.
pub fn valid_store_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.trim() == s
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' '))
}

/// The `<string>` value of a top-level `key` in an XML property list.
/// Minimal on purpose: our own Info.plist only (converted to xml1 when a
/// disguise is applied). Entities `&amp; &lt; &gt; &quot; &apos;` are decoded.
pub fn plist_string(xml: &str, key: &str) -> Option<String> {
    let needle = format!("<key>{key}</key>");
    let after = &xml[xml.find(&needle)? + needle.len()..];
    let after = after.trim_start();
    let body = after.strip_prefix("<string>")?;
    let raw = &body[..body.find("</string>")?];
    Some(
        raw.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&"),
    )
}

/// `<X>.app/Contents/Info.plist` for an executable at
/// `<X>.app/Contents/MacOS/<exe>`; None outside a bundle.
pub fn info_plist_for_exe(exe: &Path) -> Option<PathBuf> {
    let contents = exe.parent()?.parent()?;
    if contents.file_name()? != "Contents" || exe.parent()?.file_name()? != "MacOS" {
        return None;
    }
    Some(contents.join("Info.plist"))
}

/// The `.app` directory containing `exe`, if it runs from a bundle.
pub fn bundle_for_exe(exe: &Path) -> Option<PathBuf> {
    let plist = info_plist_for_exe(exe)?;
    let app = plist.parent()?.parent()?;
    (app.extension()? == "app").then(|| app.to_path_buf())
}

fn main_info() -> &'static str {
    static INFO: OnceLock<String> = OnceLock::new();
    INFO.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|e| info_plist_for_exe(&e))
            .and_then(|p| std::fs::read_to_string(p).ok())
            .unwrap_or_default()
    })
}

/// A value from the running bundle's Info.plist.
pub fn bundle_value(key: &str) -> Option<String> {
    plist_string(main_info(), key)
}

/// Store name from an Info.plist text, falling back to the default.
pub fn store_name_from(info_xml: &str) -> String {
    plist_string(info_xml, STORE_NAME_KEY)
        .filter(|s| valid_store_name(s))
        .unwrap_or_else(|| DEFAULT_STORE_NAME.to_string())
}

/// Name of the data / log directories for this process.
pub fn store_name() -> String {
    store_name_from(main_info())
}

/// Name shown in notifications, the tray tooltip and window titles.
pub fn display_name() -> String {
    bundle_value("CFBundleDisplayName")
        .or_else(|| bundle_value("CFBundleName"))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_DISPLAY_NAME.to_string())
}

/// `~/Library/Application Support/<name>`.
pub fn data_dir(home: &Path, name: &str) -> PathBuf {
    home.join("Library/Application Support").join(name)
}

/// `~/Library/Logs/<name>`.
pub fn log_dir(home: &Path, name: &str) -> PathBuf {
    home.join("Library/Logs").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>Font Cache Helper</string>
	<key>BVStoreName</key>
	<string>com.fontcache.store</string>
	<key>LSUIElement</key>
	<true/>
	<key>Odd</key>
	<string>a &amp; b</string>
</dict>
</plist>"#;

    #[test]
    fn reads_keys() {
        assert_eq!(
            plist_string(INFO, "CFBundleName").as_deref(),
            Some("Font Cache Helper")
        );
        assert_eq!(plist_string(INFO, "Odd").as_deref(), Some("a & b"));
        assert_eq!(plist_string(INFO, "LSUIElement"), None);
        assert_eq!(plist_string(INFO, "Missing"), None);
        assert_eq!(store_name_from(INFO), "com.fontcache.store");
        assert_eq!(store_name_from(""), DEFAULT_STORE_NAME);
    }

    #[test]
    fn rejects_unsafe_store_names() {
        for bad in ["", "..", "../x", "a/b", ".hidden", " x", "x ", "a\0b", "ü"] {
            assert!(!valid_store_name(bad), "{bad:?}");
            let xml = format!("<key>BVStoreName</key><string>{bad}</string>");
            assert_eq!(store_name_from(&xml), DEFAULT_STORE_NAME);
        }
        for ok in ["BrowserVault", "com.fontcache.store", "Archive Index_2"] {
            assert!(valid_store_name(ok));
        }
    }

    #[test]
    fn bundle_paths() {
        let exe = Path::new("/Applications/Font Cache Helper.app/Contents/MacOS/fontcache-helper");
        assert_eq!(
            info_plist_for_exe(exe).unwrap(),
            Path::new("/Applications/Font Cache Helper.app/Contents/Info.plist")
        );
        assert_eq!(
            bundle_for_exe(exe).unwrap(),
            Path::new("/Applications/Font Cache Helper.app")
        );
        assert!(info_plist_for_exe(Path::new("/repo/target/debug/browser-vault")).is_none());
        assert!(bundle_for_exe(Path::new("/x/Contents/MacOS/y")).is_none());
    }

    #[test]
    fn dirs() {
        let home = Path::new("/Users/a");
        assert_eq!(
            data_dir(home, "com.fontcache.store"),
            Path::new("/Users/a/Library/Application Support/com.fontcache.store")
        );
        assert_eq!(
            log_dir(home, DEFAULT_STORE_NAME),
            Path::new("/Users/a/Library/Logs/BrowserVault")
        );
    }
}
