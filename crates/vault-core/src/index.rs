//! Local encrypted index of vault labels (this Mac only).
//!
//! v2 headers keep a vault's name, browser, settings and imported-profile
//! data encrypted under the VMK, so the menu could not show them before
//! unlocking. `<store root>/index.bin` remembers them for vaults this Mac has
//! opened: `nonce (24) ‖ XChaCha20-Poly1305(index key, AAD "bv-index-v1",
//! JSON { "vaults": { <vault_id>: Entry } })`.
//!
//! The index key is 32 random bytes (OsRng) in the login Keychain as a
//! generic password (service [`KEYCHAIN_SERVICE`], account
//! [`KEYCHAIN_ACCOUNT`]), created on first use. The provider is injectable
//! ([`KeyProvider`]) so tests and Linux never touch a Keychain.
//!
//! The index is only a display cache: it never decides anything about
//! security. If the key or the file is missing or unreadable (vault copied
//! to another Mac, restored from a backup, Keychain reset), the vault shows
//! as "Locked vault" until its next unlock writes a fresh entry.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::browser::Browser;
use crate::crypto::{self, Key, NONCE_LEN};
use crate::error::Result;
use crate::header::{Meta, OriginalState};

pub const INDEX_FILE: &str = "index.bin";
const INDEX_TMP_FILE: &str = ".index.bin.tmp";
/// Deliberately neutral, so the Keychain does not advertise the app.
pub const KEYCHAIN_SERVICE: &str = "com.local.cacheindex";
pub const KEYCHAIN_ACCOUNT: &str = "index";
const AAD: &[u8] = b"bv-index-v1";

/// Returns the index key. `create`: make (and store) one if there is none.
/// `Ok(None)` = no key (reads show every v2 vault as locked).
pub type KeyProvider = fn(create: bool) -> Result<Option<Key>>;

/// No index at all (Linux, tests, unknown environments).
pub fn no_key(_create: bool) -> Result<Option<Key>> {
    Ok(None)
}

/// The provider used by [`crate::Store::new`]: the login Keychain in macOS
/// builds, none in tests and elsewhere.
pub fn default_provider() -> KeyProvider {
    #[cfg(all(target_os = "macos", not(test)))]
    {
        keychain
    }
    #[cfg(not(all(target_os = "macos", not(test))))]
    {
        no_key
    }
}

/// What this process learned from the Keychain so far.
#[cfg(target_os = "macos")]
enum Cached {
    Unknown,
    /// A background read is running (macOS may be showing an access prompt).
    Pending,
    Key(Key),
    /// No item yet (first run): created on the first write.
    Missing,
    /// Access failed (e.g. the user clicked Deny after an app update): don't
    /// ask again in this process; names show as "Locked vault".
    Failed,
}

/// Called once the background Keychain read finishes, so the app can
/// refresh lists that showed "Locked vault" meanwhile.
static ON_READY: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

pub fn set_on_ready(f: fn()) {
    let _ = ON_READY.set(f);
}

/// The key from the login Keychain, read once per process on a background
/// thread. Never blocks a caller for long: if macOS is still waiting for
/// the user to answer an access prompt (an updated or disguised app has a
/// new signature), callers get `Ok(None)` after ~1.5 s and the names fill
/// in when the read completes ([`set_on_ready`]). Holding a lock across the
/// prompt froze every window that lists vaults.
#[cfg(target_os = "macos")]
pub fn keychain(create: bool) -> Result<Option<Key>> {
    use crate::error::Error;
    use security_framework::passwords::{get_generic_password, set_generic_password};
    use std::sync::Condvar;
    use std::time::Duration;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR: Error = Error::Unsupported("Keychain index key");
    static STATE: (Mutex<Cached>, Condvar) = (Mutex::new(Cached::Unknown), Condvar::new());

    let lock = || STATE.0.lock().unwrap_or_else(|e| e.into_inner());
    let mut st = lock();
    if matches!(*st, Cached::Unknown) {
        *st = Cached::Pending;
        std::thread::spawn(move || {
            let r = match get_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT) {
                Ok(v) => match from_hex(&Zeroizing::new(v)) {
                    Some(k) => Cached::Key(k),
                    None => Cached::Failed,
                },
                Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Cached::Missing,
                Err(_) => Cached::Failed,
            };
            *STATE.0.lock().unwrap_or_else(|e| e.into_inner()) = r;
            STATE.1.notify_all();
            if let Some(f) = ON_READY.get() {
                f();
            }
        });
    }
    if matches!(*st, Cached::Pending) {
        st = STATE
            .1
            .wait_timeout_while(st, Duration::from_millis(1500), |c| {
                matches!(c, Cached::Pending)
            })
            .map(|(g, _)| g)
            .unwrap_or_else(|e| e.into_inner().0);
    }
    match &*st {
        Cached::Key(k) => Ok(Some(k.clone())),
        Cached::Failed => Err(ERR),
        Cached::Pending | Cached::Unknown => Ok(None),
        Cached::Missing if !create => Ok(None),
        Cached::Missing => {
            // Our own new item: creating it never prompts.
            let k = crypto::random_key();
            let hex = to_hex(&k);
            match set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, hex.as_bytes()) {
                Ok(()) => {
                    *st = Cached::Key(k.clone());
                    Ok(Some(k))
                }
                Err(_) => {
                    *st = Cached::Failed;
                    Err(ERR)
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn keychain(_create: bool) -> Result<Option<Key>> {
    Ok(None)
}

/// [`keychain`] that never creates the item. For the CLI: an item created
/// by another binary would make macOS ask the app for access later.
pub fn keychain_read_only(_create: bool) -> Result<Option<Key>> {
    keychain(false)
}

/// TEST ONLY: a process-wide in-memory key, created on first `create`.
#[cfg(any(test, feature = "test-mocks"))]
pub fn memory_key(create: bool) -> Result<Option<Key>> {
    static KEY: Mutex<Option<Key>> = Mutex::new(None);
    let mut k = KEY.lock().unwrap_or_else(|e| e.into_inner());
    if k.is_none() && create {
        *k = Some(crypto::random_key());
    }
    Ok(k.clone())
}

/// TEST ONLY: another Mac's key (always present, differs from [`memory_key`]).
#[cfg(any(test, feature = "test-mocks"))]
pub fn other_memory_key(_create: bool) -> Result<Option<Key>> {
    static KEY: std::sync::OnceLock<Key> = std::sync::OnceLock::new();
    Ok(Some(KEY.get_or_init(crypto::random_key).clone()))
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn to_hex(k: &Key) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(64));
    for b in k.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn from_hex(s: &[u8]) -> Option<Key> {
    if s.len() != 64 {
        return None;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    for (i, pair) in s.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        k[i] = (hi * 16 + lo) as u8;
    }
    Some(k)
}

/// What the menu shows for a vault before it is unlocked.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub browser: Browser,
    pub created_at: String,
    #[serde(default)]
    pub portable_keys: bool,
    /// The imported original's notice (no paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<OriginalNote>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OriginalNote {
    pub profile_name: String,
    pub size_bytes: u64,
    pub reviewed: bool,
    pub state: OriginalState,
}

impl Entry {
    pub fn from_meta(m: &Meta) -> Entry {
        Entry {
            name: m.name.clone(),
            browser: m.browser,
            created_at: m.created_at.clone(),
            portable_keys: m.settings.portable_keys,
            original: m.original.as_ref().map(|o| OriginalNote {
                profile_name: o.profile_name.clone(),
                size_bytes: o.size_bytes,
                reviewed: o.reviewed,
                state: o.state,
            }),
        }
    }
}

pub type Entries = BTreeMap<String, Entry>;

#[derive(Serialize, Deserialize, Default)]
struct Data {
    #[serde(default)]
    vaults: Entries,
}

/// Serializes read-modify-write cycles within this process.
static WRITE: Mutex<()> = Mutex::new(());

fn path(root: &Path) -> PathBuf {
    root.join(INDEX_FILE)
}

fn decode(key: &Key, bytes: &[u8]) -> Option<Entries> {
    if bytes.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = bytes.split_at(NONCE_LEN);
    let pt = crypto::open(key, AAD, nonce, ct).ok()?;
    serde_json::from_slice::<Data>(&pt).ok().map(|d| d.vaults)
}

/// Every entry this Mac knows; empty if there is no key or no readable index.
pub fn read(root: &Path, provider: KeyProvider) -> Entries {
    let Ok(Some(key)) = provider(false) else {
        return Entries::new();
    };
    let Ok(bytes) = fs::read(path(root)) else {
        return Entries::new();
    };
    decode(&key, &bytes).unwrap_or_default()
}

/// Change the index with `f` and write it back atomically (temp → fsync →
/// rename, 600). Creates the key if needed. An unreadable index (other key,
/// damaged) starts over empty.
pub fn update(
    root: &Path,
    provider: KeyProvider,
    f: impl FnOnce(&mut Entries) -> bool,
) -> Result<()> {
    let _g = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(key) = provider(true)? else {
        return Ok(());
    };
    let mut entries = fs::read(path(root))
        .ok()
        .and_then(|b| decode(&key, &b))
        .unwrap_or_default();
    if !f(&mut entries) {
        return Ok(());
    }
    let pt = Zeroizing::new(serde_json::to_vec(&Data { vaults: entries })?);
    let (nonce, ct) = crypto::seal(&key, AAD, &pt)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    fs::create_dir_all(root)?;
    crate::header::write_atomic(&path(root), &root.join(INDEX_TMP_FILE), &out)
}

/// Record (or refresh) `id`'s entry. Writes only when it changed.
pub fn put(root: &Path, provider: KeyProvider, id: &str, entry: Entry) -> Result<()> {
    update(root, provider, |e| {
        if e.get(id) == Some(&entry) {
            return false;
        }
        e.insert(id.to_string(), entry);
        true
    })
}

pub fn remove(root: &Path, provider: KeyProvider, id: &str) -> Result<()> {
    // Without a key there is nothing to remove; don't create one for this.
    if !matches!(provider(false), Ok(Some(_))) {
        return Ok(());
    }
    update(root, provider, |e| e.remove(id).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Original, VaultSettings};

    fn meta(name: &str) -> Meta {
        Meta {
            name: name.into(),
            browser: Browser::Firefox,
            created_at: "2026-11-05T10:00:00Z".into(),
            settings: VaultSettings::default(),
            original: Some(Original {
                browser: Browser::Firefox,
                profile_id: "abc.default".into(),
                profile_name: "Private".into(),
                paths: vec!["/Users/x/Library/Application Support/Firefox/Profiles/abc".into()],
                size_bytes: 42,
                imported_at: "2026-11-05T10:00:00Z".into(),
                reviewed: true,
                state: OriginalState::Pending,
                deleted_at: None,
            }),
            key_labels: Default::default(),
        }
    }

    #[test]
    fn roundtrip_put_remove() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        assert!(read(root, memory_key).is_empty());
        put(root, memory_key, "a", Entry::from_meta(&meta("Alpha"))).unwrap();
        put(root, memory_key, "b", Entry::from_meta(&meta("Beta"))).unwrap();
        let e = read(root, memory_key);
        assert_eq!(e.len(), 2);
        assert_eq!(e["a"].name, "Alpha");
        assert_eq!(e["a"].browser, Browser::Firefox);
        assert_eq!(e["a"].original.as_ref().unwrap().profile_name, "Private");
        remove(root, memory_key, "a").unwrap();
        assert_eq!(read(root, memory_key).keys().collect::<Vec<_>>(), ["b"]);

        // Nothing readable on disk; no paths are kept at all.
        let raw = fs::read(root.join(INDEX_FILE)).unwrap();
        let text = String::from_utf8_lossy(&raw);
        for needle in ["Alpha", "Beta", "Private", "Firefox", "firefox", "Users"] {
            assert!(!text.contains(needle));
        }
        let json = serde_json::to_string(&Entry::from_meta(&meta("x"))).unwrap();
        assert!(!json.contains("Users"));

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(root.join(INDEX_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!root.join(INDEX_TMP_FILE).exists());
    }

    #[test]
    fn missing_or_other_key_reads_empty() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        put(root, memory_key, "a", Entry::from_meta(&meta("Alpha"))).unwrap();
        assert!(read(root, no_key).is_empty());
        assert!(read(root, other_memory_key).is_empty());
        // Without a key nothing is written.
        put(root, no_key, "z", Entry::from_meta(&meta("Zed"))).unwrap();
        remove(root, no_key, "a").unwrap();
        assert_eq!(read(root, memory_key).len(), 1);
        // Another Mac's key starts a fresh index.
        put(root, other_memory_key, "c", Entry::from_meta(&meta("C"))).unwrap();
        assert_eq!(read(root, other_memory_key).len(), 1);
        assert!(read(root, memory_key).is_empty());
    }

    #[test]
    fn damaged_index_reads_empty_and_is_rebuilt() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        fs::write(root.join(INDEX_FILE), b"garbage").unwrap();
        assert!(read(root, memory_key).is_empty());
        put(root, memory_key, "a", Entry::from_meta(&meta("Alpha"))).unwrap();
        assert_eq!(read(root, memory_key)["a"].name, "Alpha");
        let mut raw = fs::read(root.join(INDEX_FILE)).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        fs::write(root.join(INDEX_FILE), raw).unwrap();
        assert!(read(root, memory_key).is_empty());
    }

    #[test]
    fn hex_roundtrip() {
        let k = crypto::random_key();
        assert_eq!(*from_hex(to_hex(&k).as_bytes()).unwrap(), *k);
        assert!(from_hex(b"zz").is_none());
        assert!(from_hex(&[b'g'; 64]).is_none());
    }
}
