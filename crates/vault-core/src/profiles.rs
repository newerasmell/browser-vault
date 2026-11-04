//! Existing browser profiles: detection, import into a vault and deletion of
//! the original (SPEC §5.1). Milestone M7b.
//!
//! RULE: the user's existing profiles are read-only everywhere except
//! [`cleanup_original`], which re-checks in Rust (never trusting the UI or
//! CLI) that the copy was reviewed, the regular browser is closed and the
//! vault password is correct.
//!
//! All locations are derived from [`Roots`], so tests run against a fake home
//! in a temp dir.
//!
//! ## Password check for cleanup
//! A vault needs password + second factor; the password alone cannot unwrap
//! the VMK, and storing any password hash on disk would be an offline
//! password oracle. So cleanup requires an unlocked session ([`Unlocked`]):
//! when a vault whose header records an original profile is unlocked with a
//! password-bearing credential, `Store::unlock` keeps a [`PasswordVerifier`]
//! in memory = HMAC(HKDF(VMK, "bv-cleanup-pw-v1"), Argon2id(password)).
//! It lives (zeroized on drop) only as long as the session; nothing new is
//! written to disk. A recovery-phrase session has no verifier, so cleanup
//! from it fails with `UnlockFailed`.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::browser::{self, Browser};
use crate::crypto::{self, Key};
use crate::error::{Error, Redacted, Result};
use crate::events::{CreateStage, Event, Notify};
use crate::header::{write_atomic_with_backup, Header, Kdf, Original, OriginalState};
use crate::keyslot::now_rfc3339;
use crate::store::{now_unix, Store, Unlocked};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProfile {
    /// `Default` / `Profile 1` (Brave) or the profiles.ini `Path` (Firefox).
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    pub path: PathBuf,
}

/// `profile_id` meaning "every Brave profile into one vault" (Brave only).
/// Each profile keeps its directory name inside the vault, and a reduced
/// `Local State` is written so Brave's profile switcher knows them all.
pub const ALL_PROFILES: &str = "*";

/// `original.profile_name` for an import of all profiles. The UI recognises
/// this exact form to show a translated label.
pub fn all_profiles_name(n: usize) -> String {
    format!("All profiles ({n})")
}

/// Where the regular browsers keep their data, plus the live probes. The
/// app uses [`Roots::system`]; tests point `home` at a temp dir and replace
/// the probes.
#[derive(Clone, Debug)]
pub struct Roots {
    pub home: PathBuf,
    /// Is the regular (non-vault) browser running? Default: [`regular_browser_running`].
    pub browser_running: fn(Browser) -> bool,
    /// FileVault on? `None` = unknown. Default: [`file_vault_enabled`].
    pub file_vault: fn() -> Option<bool>,
}

impl Roots {
    pub fn for_home(home: impl Into<PathBuf>) -> Roots {
        Roots {
            home: home.into(),
            browser_running: regular_browser_running,
            file_vault: file_vault_enabled,
        }
    }

    /// The real home (`$HOME`).
    pub fn system() -> Result<Roots> {
        let home = std::env::var_os("HOME").ok_or(Error::Invalid("HOME is not set"))?;
        Ok(Roots::for_home(home))
    }

    pub fn brave_data(&self) -> PathBuf {
        self.home
            .join("Library/Application Support/BraveSoftware/Brave-Browser")
    }

    pub fn brave_cache(&self) -> PathBuf {
        self.home.join("Library/Caches/BraveSoftware/Brave-Browser")
    }

    pub fn firefox_data(&self) -> PathBuf {
        self.home.join("Library/Application Support/Firefox")
    }

    pub fn firefox_cache(&self) -> PathBuf {
        self.home.join("Library/Caches/Firefox")
    }

    pub fn saved_state(&self, browser: Browser) -> PathBuf {
        let bundle = match browser {
            Browser::Brave => "com.brave.Browser.savedState",
            Browser::Firefox => "org.mozilla.firefox.savedState",
        };
        self.home
            .join("Library/Saved Application State")
            .join(bundle)
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Profiles of the regular browser installation, from `Local State` / `profiles.ini`.
pub fn detect_profiles(browser: Browser) -> Result<Vec<DetectedProfile>> {
    detect_profiles_in(&Roots::system()?, browser)
}

pub fn detect_profiles_in(roots: &Roots, browser: Browser) -> Result<Vec<DetectedProfile>> {
    let mut out = vec![];
    match browser {
        Browser::Brave => {
            let Some(ls) = read_json(&roots.brave_data().join("Local State"))? else {
                return Ok(out);
            };
            if let Some(cache) = ls
                .pointer("/profile/info_cache")
                .and_then(|v| v.as_object())
            {
                for (id, info) in cache {
                    if check_brave_id(id).is_err() {
                        continue;
                    }
                    let path = roots.brave_data().join(id);
                    if !is_real_dir(&path) {
                        continue;
                    }
                    let name = info
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or(id)
                        .to_string();
                    out.push(DetectedProfile {
                        id: id.clone(),
                        name,
                        size_bytes: dir_size(&path),
                        path,
                    });
                }
            }
        }
        Browser::Firefox => {
            let Some(ini) = Ini::load(&roots.firefox_data().join("profiles.ini"))? else {
                return Ok(out);
            };
            for (sect, kv) in &ini.sections {
                if !is_profile_section(sect) {
                    continue;
                }
                let Some(id) = get(kv, "Path") else { continue };
                let Ok(path) = firefox_profile_dir(roots, id, get(kv, "IsRelative")) else {
                    continue;
                };
                if !is_real_dir(&path) {
                    continue;
                }
                out.push(DetectedProfile {
                    id: id.to_string(),
                    name: get(kv, "Name").unwrap_or(id).to_string(),
                    size_bytes: dir_size(&path),
                    path,
                });
            }
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

fn find_profile(roots: &Roots, browser: Browser, id: &str) -> Result<DetectedProfile> {
    detect_profiles_in(roots, browser)?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or(Error::NotFound)
}

fn check_brave_id(id: &str) -> Result<()> {
    let mut c = Path::new(id).components();
    match (c.next(), c.next()) {
        (Some(Component::Normal(_)), None) if !id.starts_with('.') && id != ALL_PROFILES => Ok(()),
        _ => Err(Error::Invalid("bad profile id")),
    }
}

/// Resolve a profiles.ini `Path`, refusing `..` and anything that would
/// point at (or above) the home directory.
fn firefox_profile_dir(roots: &Roots, id: &str, is_relative: Option<&str>) -> Result<PathBuf> {
    let p = Path::new(id);
    if id.is_empty()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(Error::Invalid("bad profile path"));
    }
    let relative = is_relative.map(str::trim) != Some("0");
    let dir = if relative {
        if p.is_absolute() {
            return Err(Error::Invalid("bad profile path"));
        }
        roots.firefox_data().join(p)
    } else {
        if !p.is_absolute() {
            return Err(Error::Invalid("bad profile path"));
        }
        p.to_path_buf()
    };
    if roots.home.starts_with(&dir) || dir.components().count() < 3 {
        return Err(Error::Invalid("bad profile path"));
    }
    Ok(dir)
}

fn firefox_is_relative(roots: &Roots, id: &str) -> Result<Option<String>> {
    let Some(ini) = Ini::load(&roots.firefox_data().join("profiles.ini"))? else {
        return Ok(None);
    };
    Ok(ini
        .sections
        .iter()
        .find(|(s, kv)| is_profile_section(s) && get(kv, "Path") == Some(id))
        .and_then(|(_, kv)| get(kv, "IsRelative").map(str::to_string)))
}

// ---------------------------------------------------------------------------
// Regular-browser detection / FileVault
// ---------------------------------------------------------------------------

/// Whether the regular (non-vault) browser instance is running.
///
/// Reads `ps -axo command=` (full command lines) and looks for the browser's
/// main executable (`…/Contents/MacOS/Brave Browser`, `…/Contents/MacOS/firefox`,
/// not helpers) whose arguments do not point at a vault profile
/// (`…/mnt/<uuid>/profile`, see [`is_vault_command`]). If `ps` cannot be run
/// the answer is `true` (fail safe: blocks import/cleanup rather than racing
/// a live browser).
pub fn regular_browser_running(browser: Browser) -> bool {
    match Command::new("ps").args(["-axo", "command="]).output() {
        Ok(out) if out.status.success() => {
            regular_running_in(browser, &String::from_utf8_lossy(&out.stdout))
        }
        _ => true,
    }
}

/// [`regular_browser_running`] on a given `ps` listing (one command per line).
pub fn regular_running_in(browser: Browser, ps: &str) -> bool {
    let exe = match browser {
        Browser::Brave => "/Contents/MacOS/Brave Browser",
        Browser::Firefox => "/Contents/MacOS/firefox",
    };
    ps.lines().any(|line| {
        let line = line.trim();
        let Some(i) = line.find(exe) else {
            return false;
        };
        let rest = &line[i + exe.len()..];
        // `Brave Browser Helper …` shares the prefix; require end or a space
        // (the path itself contains spaces, so exclude the helper explicitly).
        let main = rest.is_empty() || (rest.starts_with(' ') && !rest.starts_with(" Helper"));
        main && !is_vault_command(line)
    })
}

/// A vault instance runs with `--user-data-dir=<…>/mnt/<uuid>/profile`
/// (Brave) or `-profile <…>/mnt/<uuid>/profile` (Firefox).
pub fn is_vault_command(cmd: &str) -> bool {
    cmd.match_indices("/mnt/").any(|(i, m)| {
        let rest = &cmd[i + m.len()..];
        rest.len() >= 36
            && rest.is_char_boundary(36)
            && uuid::Uuid::parse_str(&rest[..36]).is_ok()
            && rest[36..].starts_with("/profile")
    })
}

/// `fdesetup status` → `Some(true)` for "FileVault is On.", `None` if unknown.
pub fn file_vault_enabled() -> Option<bool> {
    let out = Command::new("/usr/bin/fdesetup")
        .arg("status")
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    if s.contains("FileVault is On") {
        Some(true)
    } else if s.contains("FileVault is Off") {
        Some(false)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// SPEC §5.1 step 2: files whose SHA-256 must match after the copy.
fn key_files(browser: Browser) -> &'static [&'static str] {
    match browser {
        // Chromium ≥ 96 keeps cookies in `Network/Cookies`.
        Browser::Brave => &[
            "Cookies",
            "Network/Cookies",
            "Login Data",
            "Bookmarks",
            "Preferences",
        ],
        Browser::Firefox => &["cookies.sqlite", "logins.json", "key4.db", "places.sqlite"],
    }
}

/// Where an imported profile goes inside the mounted vault: Brave's vault
/// instance uses `<mnt>/profile` as user-data-dir, so the copy becomes its
/// `Default`; Firefox uses `<mnt>/profile` as the profile itself.
pub fn import_destination(browser: Browser, mnt: &Path) -> PathBuf {
    match browser {
        Browser::Brave => browser::profile_dir(mnt).join("Default"),
        Browser::Firefox => browser::profile_dir(mnt),
    }
}

/// Copy the regular profile `profile_id` into the mounted vault at `mnt`
/// and verify it (file list + sizes, SHA-256 of key files). The original is
/// only read. On mismatch the copy is removed, the vault stays empty and
/// usable, and an error is returned. Returns the `original` record (state
/// `pending`, `reviewed: false`) for the caller to put into the header.
pub fn import_profile(
    roots: &Roots,
    browser: Browser,
    profile_id: &str,
    mnt: &Path,
    notify: Notify<'_>,
) -> Result<Original> {
    import_with_hook(roots, browser, profile_id, mnt, notify, &|_| {})
}

pub(crate) fn import_with_hook(
    roots: &Roots,
    browser: Browser,
    profile_id: &str,
    mnt: &Path,
    notify: Notify<'_>,
    after_copy: &dyn Fn(&Path),
) -> Result<Original> {
    if profile_id == ALL_PROFILES && browser != Browser::Brave {
        return Err(Error::Invalid("only Brave can import all profiles"));
    }
    if (roots.browser_running)(browser) {
        return Err(Error::BrowserRunning);
    }
    if profile_id == ALL_PROFILES {
        return import_all_brave(roots, mnt, notify, after_copy);
    }
    let src = find_profile(roots, browser, profile_id)?;
    let dst = import_destination(browser, mnt);
    if fs::read_dir(&dst)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
    {
        return Err(Error::Invalid("the vault profile is not empty"));
    }
    let keys = key_files(browser);
    let want = Manifest::of(&src.path, keys)?;
    let total = want.size.max(1);
    let mut copied = 0u64;
    let result = (|| {
        copy_tree(&src.path, &dst, &mut |n| {
            copied += n;
            notify(Event::CreateProgress {
                stage: CreateStage::Import,
                pct: 80 + (copied.min(total) * 15 / total) as u8,
            });
        })?;
        after_copy(&dst);
        let got = Manifest::of(&dst, keys)?;
        if got != want {
            return Err(Error::Invalid("imported copy does not match the original"));
        }
        Ok(())
    })();
    if let Err(e) = result {
        clear_dir(&dst)?;
        return Err(e);
    }
    let targets = targets(roots, browser, profile_id)?;
    Ok(pending_original(browser, profile_id, src.name, &targets))
}

fn pending_original(
    browser: Browser,
    profile_id: &str,
    profile_name: String,
    targets: &CleanupTargets,
) -> Original {
    Original {
        browser,
        profile_id: profile_id.to_string(),
        profile_name,
        paths: targets
            .items()
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        size_bytes: targets.size(),
        imported_at: now_rfc3339(),
        reviewed: false,
        state: OriginalState::Pending,
        deleted_at: None,
    }
}

/// [`ALL_PROFILES`]: copy every Brave profile listed in `Local State` (and
/// present on disk) to `<mnt>/profile/<same dir name>`, verify each copy like
/// a single import, and write a reduced vault `Local State` (see
/// [`vault_local_state`]). Any mismatch aborts the whole import and empties
/// the vault profile again.
fn import_all_brave(
    roots: &Roots,
    mnt: &Path,
    notify: Notify<'_>,
    after_copy: &dyn Fn(&Path),
) -> Result<Original> {
    let found = detect_profiles_in(roots, Browser::Brave)?;
    if found.is_empty() {
        return Err(Error::NotFound);
    }
    let root = browser::profile_dir(mnt);
    if fs::read_dir(&root)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
    {
        return Err(Error::Invalid("the vault profile is not empty"));
    }
    let keys = key_files(Browser::Brave);
    let want = found
        .iter()
        .map(|p| Manifest::of(&p.path, keys))
        .collect::<Result<Vec<_>>>()?;
    let total = want.iter().map(|m| m.size).sum::<u64>().max(1);
    let ids: Vec<String> = found.iter().map(|p| p.id.clone()).collect();
    let mut copied = 0u64;
    let result = (|| {
        for p in &found {
            copy_tree(&p.path, &root.join(&p.id), &mut |n| {
                copied += n;
                notify(Event::CreateProgress {
                    stage: CreateStage::Import,
                    pct: 80 + (copied.min(total) * 15 / total) as u8,
                });
            })?;
        }
        after_copy(&root);
        for (p, w) in found.iter().zip(&want) {
            if Manifest::of(&root.join(&p.id), keys)? != *w {
                return Err(Error::Invalid("imported copy does not match the original"));
            }
        }
        let ls = read_json(&roots.brave_data().join("Local State"))?.ok_or(Error::NotFound)?;
        write_private(
            &root.join("Local State"),
            &serde_json::to_vec_pretty(&vault_local_state(&ls, &ids))?,
        )
    })();
    if let Err(e) = result {
        clear_dir(&root)?;
        return Err(e);
    }
    let targets = brave_targets(roots, &ids)?;
    Ok(pending_original(
        Browser::Brave,
        ALL_PROFILES,
        all_profiles_name(ids.len()),
        &targets,
    ))
}

/// `Local State` for a vault that holds several Brave profiles: only the
/// `profile` keys the profile switcher needs, restricted to `ids`:
/// `info_cache` (names, avatars …), `profiles_order`, `last_used`,
/// `last_active_profiles` and `profiles_created` (so a profile added later
/// in the vault gets a fresh `Profile N`). Everything else is dropped on
/// purpose: `os_crypt` (on macOS the key is in the Keychain anyway),
/// `variations_*` seeds, `user_experience_metrics` / `uninstall_metrics`
/// client ids, `brave.stats` / referral / P3A ids, hardware and
/// install-specific state, flags (`browser.enabled_labs_experiments`).
/// Brave recreates whatever it needs with fresh values.
fn vault_local_state(ls: &serde_json::Value, ids: &[String]) -> serde_json::Value {
    use serde_json::{Map, Value};
    let kept = |id: &str| ids.iter().any(|i| i == id);
    let src = ls.get("profile").and_then(Value::as_object);
    let get = |k: &str| src.and_then(|p| p.get(k));
    let mut profile = Map::new();
    let cache: Map<String, Value> = get("info_cache")
        .and_then(Value::as_object)
        .map(|c| {
            c.iter()
                .filter(|(k, _)| kept(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    profile.insert("info_cache".into(), Value::Object(cache));
    for k in ["profiles_order", "last_active_profiles"] {
        if let Some(a) = get(k).and_then(Value::as_array) {
            let a: Vec<Value> = a
                .iter()
                .filter(|v| v.as_str().is_some_and(kept))
                .cloned()
                .collect();
            profile.insert(k.into(), Value::Array(a));
        }
    }
    let last_used = get("last_used")
        .and_then(Value::as_str)
        .filter(|s| kept(s))
        .map(str::to_string)
        .or_else(|| ids.iter().find(|i| *i == "Default").cloned())
        .or_else(|| ids.first().cloned());
    if let Some(l) = last_used {
        profile.insert("last_used".into(), l.into());
    }
    let highest = ids
        .iter()
        .filter_map(|i| i.strip_prefix("Profile ")?.parse::<u64>().ok())
        .map(|n| n + 1)
        .max()
        .unwrap_or(1);
    let created = get("profiles_created")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .max(highest)
        .max(ids.len() as u64);
    profile.insert("profiles_created".into(), created.into());
    serde_json::json!({ "profile": profile })
}

/// Write a new file readable only by the user (inside the vault).
fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Relative path → size of every regular file, plus SHA-256 of key files.
#[derive(Debug, PartialEq, Eq)]
struct Manifest {
    files: BTreeMap<PathBuf, u64>,
    size: u64,
    hashes: BTreeMap<&'static str, [u8; 32]>,
}

impl Manifest {
    fn of(root: &Path, keys: &[&'static str]) -> Result<Manifest> {
        let mut files = BTreeMap::new();
        walk(root, &mut |p, len| {
            if let Ok(rel) = p.strip_prefix(root) {
                files.insert(rel.to_path_buf(), len);
            }
        })?;
        let size = files.values().sum();
        let mut hashes = BTreeMap::new();
        for k in keys {
            let p = root.join(k);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
                hashes.insert(*k, sha256_file(&p)?);
            }
        }
        Ok(Manifest {
            files,
            size,
            hashes,
        })
    }
}

fn sha256_file(p: &Path) -> Result<[u8; 32]> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Visit regular files (no symlinks followed, sockets/symlinks skipped).
fn walk(dir: &Path, f: &mut dyn FnMut(&Path, u64)) -> Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let p = e.path();
        let md = fs::symlink_metadata(&p)?;
        if md.is_dir() {
            walk(&p, f)?;
        } else if md.is_file() {
            f(&p, md.len());
        }
    }
    Ok(())
}

/// Copy regular files and directories; symlinks, sockets (e.g. lock files)
/// are skipped. Directories are created private (700).
fn copy_tree(src: &Path, dst: &Path, progress: &mut dyn FnMut(u64)) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dst)?;
    for e in fs::read_dir(src)? {
        let e = e?;
        let p = e.path();
        let to = dst.join(e.file_name());
        let md = fs::symlink_metadata(&p)?;
        if md.is_dir() {
            copy_tree(&p, &to, progress)?;
        } else if md.is_file() {
            fs::copy(&p, &to)?;
            progress(md.len());
        }
    }
    Ok(())
}

/// Remove everything inside `dir` (inside the vault only).
fn clear_dir(dir: &Path) -> Result<()> {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for e in rd {
        remove_path(&e?.path())?;
    }
    Ok(())
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

/// Total size of regular files under `p` (0 if missing). Symlinks not followed.
pub fn dir_size(p: &Path) -> u64 {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_file() => m.len(),
        Ok(m) if m.is_dir() => {
            let mut n = 0;
            let _ = walk(p, &mut |_, l| n += l);
            n
        }
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Review / keep
// ---------------------------------------------------------------------------

/// In-memory proof of the vault password for the current unlocked session
/// (see module docs). Never persisted.
pub struct PasswordVerifier {
    kdf: Kdf,
    key: Key,
    tag: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PasswordVerifier").field(&Redacted).finish()
    }
}

const VERIFIER_INFO: &[u8] = b"bv-cleanup-pw-v1";

impl PasswordVerifier {
    /// `password` must be the one that just unlocked the vault with `vmk`.
    pub fn new(kdf: &Kdf, vmk: &Key, password: &str) -> Result<PasswordVerifier> {
        let pw = kdf.derive(password.as_bytes())?;
        let key = crypto::hkdf(vmk.as_ref(), VERIFIER_INFO);
        let tag = Zeroizing::new(crypto::hmac_sha256(&key, pw.as_ref()));
        Ok(PasswordVerifier {
            kdf: kdf.clone(),
            key,
            tag,
        })
    }

    /// Constant-time check; any failure is `false`.
    pub fn verify(&self, password: &str) -> bool {
        match self.kdf.derive(password.as_bytes()) {
            Ok(pw) => crypto::hmac_sha256_verify(&self.key, pw.as_ref(), self.tag.as_ref()),
            Err(_) => false,
        }
    }
}

/// Fresh header from disk, refused if its MAC does not verify under the
/// session's VMK (a tampered header must not steer deletion or get blessed
/// by a re-seal).
fn load_verified(store: &Store, session: &Unlocked) -> Result<Header> {
    let h = store.load(&session.header.vault_id)?;
    if !h.verify_mac(session.key.vmk()) {
        return Err(Error::Format("header integrity check failed".into()));
    }
    Ok(h)
}

fn save_sealed(store: &Store, session: &mut Unlocked, mut h: Header) -> Result<()> {
    h.seal_mac(session.key.vmk())?;
    store.save_header(&h)?;
    session.header = h;
    Ok(())
}

/// SPEC §5.1 step 3: `reviewed = true` at the first close of an unlocked
/// session after the import. Called by `Store::close`. Returns whether the
/// header changed.
pub fn mark_reviewed(store: &Store, session: &mut Unlocked) -> Result<bool> {
    let mut h = load_verified(store, session)?;
    match &mut h.original {
        Some(o) if o.state == OriginalState::Pending && !o.reviewed => o.reviewed = true,
        _ => return Ok(false),
    }
    save_sealed(store, session, h)?;
    Ok(true)
}

fn set_state(
    store: &Store,
    session: &mut Unlocked,
    from: OriginalState,
    to: OriginalState,
) -> Result<()> {
    let mut h = load_verified(store, session)?;
    match &mut h.original {
        Some(o) if o.state == from => o.state = to,
        Some(o) if o.state == to => return Ok(()),
        _ => return Err(Error::Invalid("no imported profile in this state")),
    }
    save_sealed(store, session, h)
}

/// "Keep original": `state = kept`, the notice disappears. Needs the
/// unlocked session to re-seal the header MAC.
pub fn keep_original(store: &Store, session: &mut Unlocked) -> Result<()> {
    set_state(store, session, OriginalState::Pending, OriginalState::Kept)
}

/// Undo [`keep_original`] (Settings): back to `pending`.
pub fn undo_keep_original(store: &Store, session: &mut Unlocked) -> Result<()> {
    set_state(store, session, OriginalState::Kept, OriginalState::Pending)
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

/// Exactly what [`cleanup_original`] deletes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupTargets {
    /// Each profile dir with its cache dir (when the cache lives outside it).
    /// One entry, or every imported profile for [`ALL_PROFILES`].
    pub profiles: Vec<(PathBuf, Option<PathBuf>)>,
    pub saved_state: PathBuf,
}

impl CleanupTargets {
    /// Paths that currently exist and will be deleted.
    pub fn items(&self) -> Vec<PathBuf> {
        self.profiles
            .iter()
            .flat_map(|(p, c)| [Some(p), c.as_ref()])
            .chain([Some(&self.saved_state)])
            .flatten()
            .filter(|p| fs::symlink_metadata(p).is_ok())
            .cloned()
            .collect()
    }

    pub fn size(&self) -> u64 {
        self.items().iter().map(|p| dir_size(p)).sum()
    }
}

/// Recomputed from the browser's own config + `profile_id` every time (not
/// from `original.paths`), with the id validated. For [`ALL_PROFILES`] see
/// [`targets_of`]: the ids are the dir names recorded in `paths`.
pub fn targets(roots: &Roots, browser: Browser, profile_id: &str) -> Result<CleanupTargets> {
    let saved_state = roots.saved_state(browser);
    match browser {
        Browser::Brave => brave_targets(roots, &[profile_id.to_string()]),
        Browser::Firefox => {
            if profile_id == ALL_PROFILES {
                return Err(Error::Invalid("bad profile path"));
            }
            let rel = firefox_is_relative(roots, profile_id)?;
            let profile_dir = firefox_profile_dir(roots, profile_id, rel.as_deref())?;
            // Relative profiles keep their cache under Caches/Firefox/<Path>;
            // an absolute profile keeps it inside itself.
            let cache_dir = (rel.as_deref().map(str::trim) != Some("0"))
                .then(|| roots.firefox_cache().join(profile_id));
            Ok(CleanupTargets {
                profiles: vec![(profile_dir, cache_dir)],
                saved_state,
            })
        }
    }
}

/// The vault was added from a backup: its imported original lives on
/// another Mac; nothing on this Mac may be deleted for it.
pub const ERR_ORIGINAL_ELSEWHERE: &str = "the original profile is on another Mac";

/// Brave profile dirs + their caches for validated ids.
fn brave_targets(roots: &Roots, ids: &[String]) -> Result<CleanupTargets> {
    let profiles = ids
        .iter()
        .map(|id| {
            check_brave_id(id)?;
            Ok((
                roots.brave_data().join(id),
                Some(roots.brave_cache().join(id)),
            ))
        })
        .collect::<Result<_>>()?;
    Ok(CleanupTargets {
        profiles,
        saved_state: roots.saved_state(Browser::Brave),
    })
}

/// Brave profile ids an [`ALL_PROFILES`] import copied: the dir names of the
/// recorded `paths` that sit directly in the Brave data dir (caches and
/// Saved Application State are elsewhere and ignored). Each id is validated
/// like a single one, and an entry that exists but is not a directory (e.g.
/// `Local State`) is refused. Profiles created after the import are not in
/// `paths`, so they are never targets.
fn imported_brave_ids(roots: &Roots, o: &Original) -> Result<Vec<String>> {
    let data = roots.brave_data();
    let mut ids: Vec<String> = vec![];
    for p in &o.paths {
        let p = Path::new(p);
        if p.parent() != Some(data.as_path()) {
            continue;
        }
        let Some(id) = p.file_name().and_then(|n| n.to_str()) else {
            return Err(Error::Invalid("bad profile id"));
        };
        check_brave_id(id)?;
        if fs::symlink_metadata(p).is_ok() && !is_real_dir(p) {
            return Err(Error::Invalid("bad profile id"));
        }
        if !ids.iter().any(|i| i == id) {
            ids.push(id.to_string());
        }
    }
    if ids.is_empty() {
        return Err(Error::Invalid("no imported profiles recorded"));
    }
    Ok(ids)
}

/// Profile ids an original record covers (one, or all imported ones).
fn original_ids(roots: &Roots, o: &Original) -> Result<Vec<String>> {
    match (o.browser, o.profile_id.as_str()) {
        (Browser::Brave, ALL_PROFILES) => imported_brave_ids(roots, o),
        (Browser::Firefox, ALL_PROFILES) => Err(Error::Invalid("bad profile path")),
        _ => Ok(vec![o.profile_id.clone()]),
    }
}

/// [`targets`] for an original record, including [`ALL_PROFILES`].
pub fn targets_of(roots: &Roots, o: &Original) -> Result<CleanupTargets> {
    if o.profile_id == ALL_PROFILES {
        return brave_targets(roots, &original_ids(roots, o)?);
    }
    targets(roots, o.browser, &o.profile_id)
}

/// `cleanup_preview` (UI.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPreview {
    pub items: Vec<PathBuf>,
    pub size_bytes: u64,
    pub reviewed: bool,
    pub state: OriginalState,
    /// `fdesetup status`; `None` = unknown.
    pub file_vault: Option<bool>,
    pub profile_name: String,
    pub browser: Browser,
}

pub fn cleanup_preview(store: &Store, roots: &Roots, id: &str) -> Result<CleanupPreview> {
    let h = store.load(id)?;
    // Added from a backup: `original` names a profile on the other Mac.
    if crate::backup::restored_from_backup(store, id) {
        return Err(Error::Invalid(ERR_ORIGINAL_ELSEWHERE));
    }
    let o = h
        .original
        .ok_or(Error::Invalid("this vault has no imported profile"))?;
    let t = targets_of(roots, &o)?;
    Ok(CleanupPreview {
        items: t.items(),
        size_bytes: t.size(),
        reviewed: o.reviewed,
        state: o.state,
        file_vault: (roots.file_vault)(),
        profile_name: o.profile_name,
        browser: o.browser,
    })
}

/// SPEC §5.1 steps 4–5. The ONLY function that deletes user profile data.
///
/// Re-checks, in this order: the header MAC (under the session VMK),
/// `reviewed` (`NotReviewed`), regular browser closed (`BrowserRunning`),
/// vault password via the session's [`PasswordVerifier`] (`UnlockFailed`).
/// Then backs up and edits `Local State` / `profiles.ini` + `installs.ini`,
/// deletes the profile dir(s) (every imported one for [`ALL_PROFILES`],
/// never a profile created after the import), their caches and the
/// browser's Saved Application State permanently, and records
/// `state: deleted`, `deleted_at`.
pub fn cleanup_original(
    store: &Store,
    roots: &Roots,
    session: &mut Unlocked,
    password: &str,
    notify: Notify<'_>,
) -> Result<()> {
    let mut h = load_verified(store, session)?;
    if crate::backup::restored_from_backup(store, &h.vault_id) {
        return Err(Error::Invalid(ERR_ORIGINAL_ELSEWHERE));
    }
    let o = h
        .original
        .clone()
        .ok_or(Error::Invalid("this vault has no imported profile"))?;
    if o.state == OriginalState::Deleted {
        return Err(Error::Invalid("the original profile is already deleted"));
    }
    if !o.reviewed {
        return Err(Error::NotReviewed);
    }
    if (roots.browser_running)(o.browser) {
        return Err(Error::BrowserRunning);
    }
    match &session.cleanup_verifier {
        Some(v) if v.verify(password) => {}
        _ => return Err(Error::UnlockFailed),
    }
    let ids = original_ids(roots, &o)?;
    let t = targets_of(roots, &o)?;
    notify(Event::CleanupProgress { pct: 5 });
    match o.browser {
        Browser::Brave => brave_forget_profiles(roots, &ids)?,
        Browser::Firefox => firefox_forget_profile(roots, &o.profile_id)?,
    }
    notify(Event::CleanupProgress { pct: 20 });
    let n = t.profiles.len().max(1);
    for (i, (dir, cache)) in t.profiles.iter().enumerate() {
        remove_path(dir)?;
        if let Some(c) = cache {
            remove_path(c)?;
        }
        notify(Event::CleanupProgress {
            pct: 20 + (65 * (i + 1) / n) as u8,
        });
    }
    remove_path(&t.saved_state)?;
    notify(Event::CleanupProgress { pct: 95 });
    if let Some(orig) = &mut h.original {
        orig.state = OriginalState::Deleted;
        orig.deleted_at = Some(now_rfc3339());
    }
    save_sealed(store, session, h)?;
    notify(Event::CleanupProgress { pct: 100 });
    Ok(())
}

/// Permanent delete (not Trash). Does not follow symlinks.
fn remove_path(p: &Path) -> Result<()> {
    let r = match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) => Err(e),
    };
    match r {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn backup_name(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bvault-{}.bak", now_unix()));
    path.with_file_name(name)
}

/// Back up `path` (to `<name>.bvault-<unix>.bak`) and replace it atomically.
fn rewrite_with_backup(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = path.file_name().unwrap_or_default().to_os_string();
    tmp.push(".bvault.tmp");
    write_atomic_with_backup(path, &backup_name(path), &path.with_file_name(tmp), data)
}

fn read_json(p: &Path) -> Result<Option<serde_json::Value>> {
    match fs::read(p) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Remove `ids` from `Local State` (one backup): `profile.info_cache`,
/// `profile.last_used` (moved to a remaining profile, `Default` preferred;
/// dropped if none remains, Brave then recreates `Default`),
/// `profile.last_active_profiles` and `profile.profiles_order`. Other
/// profiles and keys are untouched.
fn brave_forget_profiles(roots: &Roots, ids: &[String]) -> Result<()> {
    let path = roots.brave_data().join("Local State");
    let Some(mut ls) = read_json(&path)? else {
        return Ok(());
    };
    let Some(profile) = ls.get_mut("profile").and_then(|p| p.as_object_mut()) else {
        return Ok(());
    };
    let gone = |v: &serde_json::Value| v.as_str().is_some_and(|s| ids.iter().any(|i| i == s));
    let mut remaining: Vec<String> = vec![];
    if let Some(cache) = profile
        .get_mut("info_cache")
        .and_then(|c| c.as_object_mut())
    {
        for id in ids {
            cache.remove(id);
        }
        remaining = cache.keys().cloned().collect();
    }
    if profile.get("last_used").is_some_and(gone) {
        let next = remaining
            .iter()
            .find(|k| *k == "Default")
            .or(remaining.first())
            .cloned();
        match next {
            Some(n) => {
                profile.insert("last_used".into(), n.into());
            }
            None => {
                profile.remove("last_used");
            }
        }
    }
    for k in ["last_active_profiles", "profiles_order"] {
        if let Some(a) = profile.get_mut(k).and_then(|a| a.as_array_mut()) {
            a.retain(|v| !gone(v));
        }
    }
    rewrite_with_backup(&path, &serde_json::to_vec(&ls)?)
}

/// Remove the `[ProfileN]` section with `Path=id` from profiles.ini
/// (renumbering the rest — Firefox stops at the first missing `ProfileN`),
/// and fix `Default` in `[Install…]` sections of profiles.ini and in
/// installs.ini: moved to the first remaining profile, or the install
/// section dropped if none remains.
fn firefox_forget_profile(roots: &Roots, id: &str) -> Result<()> {
    let pi_path = roots.firefox_data().join("profiles.ini");
    let mut new_default: Option<String> = None;
    if let Some(mut ini) = Ini::load(&pi_path)? {
        let before = ini.clone();
        let mut was_default = false;
        ini.sections.retain(|(s, kv)| {
            let hit = is_profile_section(s) && get(kv, "Path") == Some(id);
            if hit && get(kv, "Default") == Some("1") {
                was_default = true;
            }
            !hit
        });
        let mut n = 0;
        for (s, _) in ini.sections.iter_mut() {
            if is_profile_section(s) {
                *s = format!("Profile{n}");
                n += 1;
            }
        }
        new_default = ini
            .sections
            .iter()
            .find(|(s, _)| is_profile_section(s))
            .and_then(|(_, kv)| get(kv, "Path").map(str::to_string));
        let any_default = ini
            .sections
            .iter()
            .any(|(s, kv)| is_profile_section(s) && get(kv, "Default") == Some("1"));
        if was_default && !any_default {
            if let Some((_, kv)) = ini.sections.iter_mut().find(|(s, _)| is_profile_section(s)) {
                set(kv, "Default", "1");
            }
        }
        fix_install_defaults(&mut ini, id, new_default.as_deref(), |s| {
            s.starts_with("Install")
        });
        if ini != before {
            rewrite_with_backup(&pi_path, ini.render().as_bytes())?;
        }
    }
    let ii_path = roots.firefox_data().join("installs.ini");
    if let Some(mut ini) = Ini::load(&ii_path)? {
        let before = ini.clone();
        fix_install_defaults(&mut ini, id, new_default.as_deref(), |_| true);
        if ini != before {
            rewrite_with_backup(&ii_path, ini.render().as_bytes())?;
        }
    }
    Ok(())
}

fn fix_install_defaults(
    ini: &mut Ini,
    id: &str,
    new_default: Option<&str>,
    is_install: impl Fn(&str) -> bool,
) {
    ini.sections.retain_mut(|(s, kv)| {
        if !is_install(s) || get(kv, "Default") != Some(id) {
            return true;
        }
        match new_default {
            Some(d) => {
                set(kv, "Default", d);
                true
            }
            None => false,
        }
    });
}

fn is_profile_section(s: &str) -> bool {
    s.strip_prefix("Profile")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

// ---------------------------------------------------------------------------
// Minimal INI (Firefox profiles.ini / installs.ini)
// ---------------------------------------------------------------------------

type Entries = Vec<(String, String)>;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Ini {
    pub(crate) sections: Vec<(String, Entries)>,
}

fn get<'a>(kv: &'a Entries, k: &str) -> Option<&'a str> {
    kv.iter().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
}

fn set(kv: &mut Entries, k: &str, v: &str) {
    match kv.iter_mut().find(|(a, _)| a == k) {
        Some(e) => e.1 = v.to_string(),
        None => kv.push((k.to_string(), v.to_string())),
    }
}

impl Ini {
    pub(crate) fn parse(text: &str) -> Ini {
        let mut ini = Ini::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                ini.sections.push((name.to_string(), vec![]));
            } else if let (Some((k, v)), Some((_, kv))) =
                (line.split_once('='), ini.sections.last_mut())
            {
                kv.push((k.to_string(), v.to_string()));
            }
        }
        ini
    }

    fn load(p: &Path) -> Result<Option<Ini>> {
        match fs::read(p) {
            Ok(b) => Ok(Some(Ini::parse(&String::from_utf8_lossy(&b)))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        for (name, kv) in &self.sections {
            out.push_str(&format!("[{name}]\n"));
            for (k, v) in kv {
                out.push_str(&format!("{k}={v}\n"));
            }
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
#[path = "profiles_tests.rs"]
mod tests;
