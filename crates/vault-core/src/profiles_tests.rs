//! Unit tests for `profiles` against a fake home in a temp dir.

use super::*;
use crate::events::ignore;
use crate::keyslot::{new_vault, KdfCost};
use std::os::unix::fs::DirBuilderExt;

const PW: &str = "correct horse battery";

fn write(p: &Path, data: &[u8]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, data).unwrap();
}

fn not_running(_: Browser) -> bool {
    false
}

fn running(_: Browser) -> bool {
    true
}

fn fv_on() -> Option<bool> {
    Some(true)
}

const LOCAL_STATE: &str = r#"{
  "browser": {"enabled_labs_experiments": []},
  "profile": {
    "info_cache": {
      "Default": {"name": "Person 1", "active_time": 1.0},
      "Profile 1": {"name": "Work", "active_time": 2.0}
    },
    "last_used": "Profile 1",
    "last_active_profiles": ["Default", "Profile 1"],
    "profiles_created": 2
  }
}"#;

const PROFILES_INI: &str = "[Install4F96D1932A9F858E]
Default=Profiles/bbb.work
Locked=1

[Profile1]
Name=work
IsRelative=1
Path=Profiles/bbb.work
Default=1

[Profile0]
Name=default
IsRelative=1
Path=Profiles/aaa.default

[General]
StartWithLastProfile=1
Version=2
";

const INSTALLS_INI: &str = "[4F96D1932A9F858E]
Default=Profiles/bbb.work
Locked=1
";

/// Fake home: Brave `Default` + `Profile 1`, Firefox `aaa.default` + `bbb.work`.
fn fake_home() -> (tempfile::TempDir, Roots) {
    let d = tempfile::tempdir().unwrap();
    let mut roots = Roots::for_home(d.path().join("home"));
    roots.browser_running = not_running;
    roots.file_vault = fv_on;

    let b = roots.brave_data();
    write(&b.join("Local State"), LOCAL_STATE.as_bytes());
    for (p, body) in [
        ("Default/Preferences", "{\"d\":1}"),
        ("Default/Bookmarks", "default bookmarks"),
        ("Profile 1/Preferences", "{\"p\":1}"),
        ("Profile 1/Bookmarks", "work bookmarks"),
        ("Profile 1/Login Data", "logins"),
        ("Profile 1/Network/Cookies", "cookies"),
        ("Profile 1/Local Storage/leveldb/000003.log", "ls"),
    ] {
        write(&b.join(p), body.as_bytes());
    }
    // A socket/symlink-like entry that must be skipped, not followed.
    std::os::unix::fs::symlink("/etc", b.join("Profile 1/link")).unwrap();
    write(&roots.brave_cache().join("Profile 1/Cache/data_0"), b"c1");
    write(&roots.brave_cache().join("Default/Cache/data_0"), b"c0");
    write(&roots.saved_state(Browser::Brave).join("data.data"), b"s");

    let f = roots.firefox_data();
    write(&f.join("profiles.ini"), PROFILES_INI.as_bytes());
    write(&f.join("installs.ini"), INSTALLS_INI.as_bytes());
    for (p, body) in [
        ("Profiles/aaa.default/prefs.js", "a"),
        ("Profiles/aaa.default/places.sqlite", "aplaces"),
        ("Profiles/bbb.work/prefs.js", "b"),
        ("Profiles/bbb.work/places.sqlite", "bplaces"),
        ("Profiles/bbb.work/cookies.sqlite", "bcookies"),
        ("Profiles/bbb.work/key4.db", "bkey"),
        ("Profiles/bbb.work/logins.json", "{}"),
    ] {
        write(&f.join(p), body.as_bytes());
    }
    write(
        &roots.firefox_cache().join("Profiles/bbb.work/cache2/x"),
        b"fc",
    );
    write(
        &roots.firefox_cache().join("Profiles/aaa.default/cache2/x"),
        b"fc",
    );
    write(&roots.saved_state(Browser::Firefox).join("data.data"), b"s");
    (d, roots)
}

fn mnt(d: &tempfile::TempDir) -> PathBuf {
    let m = d.path().join("mnt");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(m.join("profile"))
        .unwrap();
    m
}

#[test]
fn detects_brave_and_firefox_profiles() {
    let (_d, roots) = fake_home();
    let b = detect_profiles_in(&roots, Browser::Brave).unwrap();
    assert_eq!(
        b.iter()
            .map(|p| (p.id.as_str(), p.name.as_str()))
            .collect::<Vec<_>>(),
        [("Default", "Person 1"), ("Profile 1", "Work")]
    );
    assert_eq!(b[1].size_bytes, 7 + 14 + 6 + 7 + 2);
    assert_eq!(b[1].path, roots.brave_data().join("Profile 1"));

    let f = detect_profiles_in(&roots, Browser::Firefox).unwrap();
    assert_eq!(
        f.iter()
            .map(|p| (p.id.as_str(), p.name.as_str()))
            .collect::<Vec<_>>(),
        [
            ("Profiles/aaa.default", "default"),
            ("Profiles/bbb.work", "work")
        ]
    );
    assert_eq!(f[0].size_bytes, 1 + 7);

    // No browser data at all → empty list, not an error.
    let empty = Roots::for_home(_d.path().join("nobody"));
    assert!(detect_profiles_in(&empty, Browser::Brave)
        .unwrap()
        .is_empty());
    assert!(detect_profiles_in(&empty, Browser::Firefox)
        .unwrap()
        .is_empty());
}

#[test]
fn rejects_bad_ids() {
    let (_d, roots) = fake_home();
    for id in ["..", "../x", "a/b", "", ".hidden", "/abs"] {
        assert!(targets(&roots, Browser::Brave, id).is_err(), "{id}");
    }
    for id in ["../x", "Profiles/../..", ""] {
        assert!(targets(&roots, Browser::Firefox, id).is_err(), "{id}");
    }
}

#[test]
fn import_brave_copies_and_verifies() {
    let (d, roots) = fake_home();
    let m = mnt(&d);
    let o = import_profile(&roots, Browser::Brave, "Profile 1", &m, &ignore).unwrap();
    let dst = m.join("profile/Default");
    assert_eq!(fs::read(dst.join("Network/Cookies")).unwrap(), b"cookies");
    assert_eq!(
        fs::read(dst.join("Local Storage/leveldb/000003.log")).unwrap(),
        b"ls"
    );
    assert!(!dst.join("link").exists(), "symlinks are not copied");
    assert_eq!(o.profile_id, "Profile 1");
    assert_eq!(o.profile_name, "Work");
    assert_eq!(o.state, OriginalState::Pending);
    assert!(!o.reviewed);
    assert_eq!(
        o.paths,
        [
            roots.brave_data().join("Profile 1"),
            roots.brave_cache().join("Profile 1"),
            roots.saved_state(Browser::Brave),
        ]
        .map(|p| p.to_string_lossy().into_owned())
    );
    // Original untouched.
    assert!(roots.brave_data().join("Profile 1/Bookmarks").is_file());
}

#[test]
fn import_firefox_into_profile_root() {
    let (d, roots) = fake_home();
    let m = mnt(&d);
    let o = import_profile(&roots, Browser::Firefox, "Profiles/bbb.work", &m, &ignore).unwrap();
    assert_eq!(fs::read(m.join("profile/key4.db")).unwrap(), b"bkey");
    assert_eq!(o.profile_name, "work");
    assert!(o.paths[1].ends_with("Caches/Firefox/Profiles/bbb.work"));
}

#[test]
fn corrupted_copy_aborts_and_leaves_vault_empty() {
    let (d, roots) = fake_home();
    for (b, id, key) in [
        (Browser::Brave, "Profile 1", "Bookmarks"),
        (Browser::Firefox, "Profiles/bbb.work", "places.sqlite"),
        // Same size, different content: only the SHA-256 catches it.
        (Browser::Brave, "Profile 1", "Login Data"),
    ] {
        let m = mnt(&d);
        let r = import_with_hook(&roots, b, id, &m, &ignore, &|dst| {
            let p = dst.join(key);
            let mut v = fs::read(&p).unwrap();
            v[0] ^= 1;
            fs::write(&p, v).unwrap();
        });
        assert!(matches!(r, Err(Error::Invalid(_))), "{key}");
        let left: Vec<_> = fs::read_dir(m.join("profile"))
            .unwrap()
            .flatten()
            .filter(|e| e.path() != import_destination(b, &m))
            .collect();
        assert!(left.is_empty());
        assert_eq!(
            fs::read_dir(import_destination(b, &m))
                .map(|d| d.count())
                .unwrap_or(0),
            0
        );
        fs::remove_dir_all(&m).unwrap();
    }
    // A missing file (count mismatch) is caught as well.
    let m = mnt(&d);
    let r = import_with_hook(&roots, Browser::Brave, "Profile 1", &m, &ignore, &|dst| {
        fs::remove_file(dst.join("Local Storage/leveldb/000003.log")).unwrap();
    });
    assert!(matches!(r, Err(Error::Invalid(_))));
    // The original is never modified.
    assert_eq!(
        fs::read(roots.brave_data().join("Profile 1/Bookmarks")).unwrap(),
        b"work bookmarks"
    );
}

#[test]
fn import_refused_while_browser_runs_or_unknown_profile() {
    let (d, mut roots) = fake_home();
    let m = mnt(&d);
    assert!(matches!(
        import_profile(&roots, Browser::Brave, "Profile 9", &m, &ignore),
        Err(Error::NotFound)
    ));
    roots.browser_running = running;
    assert!(matches!(
        import_profile(&roots, Browser::Brave, "Profile 1", &m, &ignore),
        Err(Error::BrowserRunning)
    ));
    assert_eq!(fs::read_dir(m.join("profile")).unwrap().count(), 0);
}

// --- cleanup ---------------------------------------------------------------

struct Fixture {
    _d: tempfile::TempDir,
    roots: Roots,
    store: Store,
    session: Unlocked,
    /// Copy of the VMK, to read the encrypted metadata after `close`.
    vmk: crate::crypto::Key,
}

/// A store with one vault whose header records an import of `profile_id`,
/// plus an unlocked session for it (as `Store::unlock` would build it).
fn fixture(browser: Browser, profile_id: &str, reviewed: bool) -> Fixture {
    fixture_with(browser, profile_id, reviewed, |_| {})
}

fn fixture_with(
    browser: Browser,
    profile_id: &str,
    reviewed: bool,
    setup: impl Fn(&Roots),
) -> Fixture {
    let (d, roots) = fake_home();
    setup(&roots);
    let store = Store::new(d.path().join("BrowserVault"));
    let nv = new_vault("V", browser, PW, KdfCost::FAST).unwrap().0;
    let m = mnt(&d);
    let mut o = import_profile(&roots, browser, profile_id, &m, &ignore).unwrap();
    o.reviewed = reviewed;
    let mut h = nv.header;
    h.meta_mut().unwrap().original = Some(o);
    h.seal_mac(nv.key.vmk()).unwrap();
    fs::create_dir_all(store.vault_dir(&h.vault_id)).unwrap();
    store.save_header(&h).unwrap();
    let verifier = PasswordVerifier::new(&h.kdf, nv.key.vmk(), PW).unwrap();
    let vmk = nv.key.vmk().clone();
    let session = Unlocked {
        header: h,
        mountpoint: m,
        header_intact: true,
        key: nv.key,
        cleanup_verifier: Some(verifier),
    };
    Fixture {
        _d: d,
        roots,
        store,
        session,
        vmk,
    }
}

fn state(f: &Fixture) -> Original {
    load_open(f, &f.session.header.vault_id)
        .meta()
        .unwrap()
        .original
        .clone()
        .unwrap()
}

fn load_open(f: &Fixture, id: &str) -> Header {
    let mut h = f.store.load(id).unwrap();
    h.open_meta(&f.vmk).unwrap();
    h
}

fn brave_originals_exist(f: &Fixture) -> bool {
    f.roots.brave_data().join("Profile 1").is_dir()
        && f.roots.brave_cache().join("Profile 1").is_dir()
        && f.roots.saved_state(Browser::Brave).is_dir()
}

#[test]
fn cleanup_refused_when_not_reviewed() {
    // The check lives in core: no caller (UI, CLI) can skip it.
    let mut f = fixture(Browser::Brave, "Profile 1", false);
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::NotReviewed)));
    assert!(brave_originals_exist(&f));
    assert_eq!(state(&f).state, OriginalState::Pending);
    assert_eq!(
        fs::read_to_string(f.roots.brave_data().join("Local State")).unwrap(),
        LOCAL_STATE
    );
}

#[test]
fn cleanup_refused_when_browser_running() {
    let mut f = fixture(Browser::Brave, "Profile 1", true);
    f.roots.browser_running = running;
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::BrowserRunning)));
    assert!(brave_originals_exist(&f));
}

#[test]
fn cleanup_refused_with_wrong_password_or_no_verifier() {
    let mut f = fixture(Browser::Brave, "Profile 1", true);
    let r = cleanup_original(
        &f.store,
        &f.roots,
        &mut f.session,
        "wrong password!!",
        &ignore,
    );
    assert!(matches!(r, Err(Error::UnlockFailed)));
    assert!(brave_originals_exist(&f));
    // e.g. unlocked with the recovery phrase: no password proof in memory.
    f.session.cleanup_verifier = None;
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::UnlockFailed)));
    assert!(brave_originals_exist(&f));
}

#[test]
fn cleanup_refused_on_tampered_header() {
    let mut f = fixture(Browser::Brave, "Profile 1", false);
    // Someone changes the encrypted metadata on disk without the VMK.
    let mut h = f.store.load(&f.session.header.vault_id).unwrap();
    h.tamper_sealed_meta();
    f.store.save_header(&h).unwrap();
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::Format(_))));
    assert!(brave_originals_exist(&f));

    // v1 header: someone flips `reviewed` (or the paths) in the plain JSON.
    let mut f = fixture(Browser::Brave, "Profile 1", false);
    let mut h = load_open(&f, &f.session.header.vault_id);
    h.downgrade_to_v1(&f.vmk);
    h.meta_mut().unwrap().original.as_mut().unwrap().reviewed = true;
    f.store.save_header(&h).unwrap();
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::Format(_))));
    assert!(brave_originals_exist(&f));
}

#[test]
fn brave_cleanup_removes_only_that_profile() {
    let mut f = fixture(Browser::Brave, "Profile 1", true);
    let preview = cleanup_preview(&f.store, &f.roots, &f.session).unwrap();
    assert_eq!(
        preview.items,
        [
            f.roots.brave_data().join("Profile 1"),
            f.roots.brave_cache().join("Profile 1"),
            f.roots.saved_state(Browser::Brave),
        ]
    );
    assert_eq!(preview.size_bytes, 36 + 2 + 1);
    assert!(preview.reviewed);
    assert_eq!(preview.file_vault, Some(true));
    assert_eq!(preview.profile_name, "Work");

    let pcts = std::sync::Mutex::new(vec![]);
    let notify = |e: Event| {
        if let Event::CleanupProgress { pct } = e {
            pcts.lock().unwrap().push(pct);
        }
    };
    cleanup_original(&f.store, &f.roots, &mut f.session, PW, &notify).unwrap();
    assert_eq!(pcts.lock().unwrap().last(), Some(&100));

    let b = f.roots.brave_data();
    assert!(!b.join("Profile 1").exists());
    assert!(!f.roots.brave_cache().join("Profile 1").exists());
    assert!(!f.roots.saved_state(Browser::Brave).exists());
    // Default and its cache untouched.
    assert_eq!(
        fs::read(b.join("Default/Bookmarks")).unwrap(),
        b"default bookmarks"
    );
    assert!(f.roots.brave_cache().join("Default/Cache/data_0").is_file());

    let ls: serde_json::Value =
        serde_json::from_slice(&fs::read(b.join("Local State")).unwrap()).unwrap();
    let p = &ls["profile"];
    assert!(p["info_cache"].get("Profile 1").is_none());
    assert_eq!(p["info_cache"]["Default"]["name"], "Person 1");
    assert_eq!(p["info_cache"]["Default"]["active_time"], 1.0);
    assert_eq!(p["last_used"], "Default");
    assert_eq!(p["last_active_profiles"], serde_json::json!(["Default"]));
    assert_eq!(p["profiles_created"], 2);
    assert_eq!(
        ls["browser"]["enabled_labs_experiments"],
        serde_json::json!([])
    );

    let backups: Vec<_> = fs::read_dir(&b)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("Local State.bvault-") && n.ends_with(".bak"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        fs::read_to_string(b.join(&backups[0])).unwrap(),
        LOCAL_STATE
    );
    assert!(!b.join("Local State.bvault.tmp").exists());

    let o = state(&f);
    assert_eq!(o.state, OriginalState::Deleted);
    assert!(o.deleted_at.is_some());
    let h = f.store.load(&f.session.header.vault_id).unwrap();
    assert!(h.verify_mac(f.session.key.vmk()));
    // Second attempt: nothing left to delete.
    assert!(cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore).is_err());
}

#[test]
fn firefox_cleanup_moves_default_and_keeps_ini_valid() {
    let mut f = fixture(Browser::Firefox, "Profiles/bbb.work", true);
    cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore).unwrap();
    let fx = f.roots.firefox_data();
    assert!(!fx.join("Profiles/bbb.work").exists());
    assert!(!f.roots.firefox_cache().join("Profiles/bbb.work").exists());
    assert!(fx.join("Profiles/aaa.default/places.sqlite").is_file());
    assert!(f
        .roots
        .firefox_cache()
        .join("Profiles/aaa.default/cache2/x")
        .is_file());

    let ini = Ini::parse(&fs::read_to_string(fx.join("profiles.ini")).unwrap());
    let names: Vec<&str> = ini.sections.iter().map(|(s, _)| s.as_str()).collect();
    assert_eq!(names, ["Install4F96D1932A9F858E", "Profile0", "General"]);
    let p0 = &ini.sections[1].1;
    assert_eq!(get(p0, "Path"), Some("Profiles/aaa.default"));
    assert_eq!(get(p0, "Default"), Some("1"));
    assert_eq!(
        get(&ini.sections[0].1, "Default"),
        Some("Profiles/aaa.default")
    );
    assert_eq!(get(&ini.sections[0].1, "Locked"), Some("1"));
    assert_eq!(get(&ini.sections[2].1, "Version"), Some("2"));

    let inst = Ini::parse(&fs::read_to_string(fx.join("installs.ini")).unwrap());
    assert_eq!(
        get(&inst.sections[0].1, "Default"),
        Some("Profiles/aaa.default")
    );

    for (name, orig) in [
        ("profiles.ini", PROFILES_INI),
        ("installs.ini", INSTALLS_INI),
    ] {
        let bak: Vec<_> = fs::read_dir(&fx)
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(&format!("{name}.bvault-")) && n.ends_with(".bak")
            })
            .collect();
        assert_eq!(bak.len(), 1, "{name}");
        assert_eq!(fs::read_to_string(bak[0].path()).unwrap(), orig);
    }
    assert_eq!(state(&f).state, OriginalState::Deleted);
}

#[test]
fn firefox_removing_last_profile_drops_install_default() {
    let mut ini = Ini::parse(
        "[Install1]\nDefault=Profiles/x\nLocked=1\n\n[Profile0]\nName=x\nIsRelative=1\nPath=Profiles/x\nDefault=1\n\n[General]\nVersion=2\n",
    );
    ini.sections.retain(|(s, _)| s != "Profile0");
    fix_install_defaults(&mut ini, "Profiles/x", None, |s| s.starts_with("Install"));
    assert_eq!(ini.render(), "[General]\nVersion=2\n\n");
}

#[test]
fn ini_roundtrip() {
    let ini = Ini::parse(PROFILES_INI);
    assert_eq!(Ini::parse(&ini.render()), ini);
    assert_eq!(ini.sections.len(), 4);
}

#[test]
fn close_marks_reviewed_once_and_keep_toggles() {
    let f = fixture(Browser::Brave, "Profile 1", false);
    let id = f.session.header.vault_id.clone();
    let vmk = f.vmk.clone();
    // Not mounted here, so lock is a no-op; close then marks reviewed.
    f.store.close(f.session).unwrap();
    let mut h = f.store.load(&id).unwrap();
    h.open_meta(&vmk).unwrap();
    let o = h.meta().unwrap().original.clone().unwrap();
    assert!(o.reviewed);
    assert_eq!(o.state, OriginalState::Pending);

    let mut f = fixture(Browser::Brave, "Profile 1", true);
    assert!(!mark_reviewed(&f.store, &mut f.session).unwrap());
    keep_original(&f.store, &mut f.session).unwrap();
    assert_eq!(state(&f).state, OriginalState::Kept);
    assert!(f
        .store
        .load(&f.session.header.vault_id)
        .unwrap()
        .verify_mac(f.session.key.vmk()));
    undo_keep_original(&f.store, &mut f.session).unwrap();
    assert_eq!(state(&f).state, OriginalState::Pending);
}

#[test]
fn verifier_checks_password() {
    let nv = new_vault("V", Browser::Brave, PW, KdfCost::FAST).unwrap().0;
    let v = PasswordVerifier::new(&nv.header.kdf, nv.key.vmk(), PW).unwrap();
    assert!(v.verify(PW));
    assert!(!v.verify("correct horse batterY"));
    assert_eq!(format!("{v:?}"), "PasswordVerifier(<redacted>)");
}

#[test]
fn ps_parsing_ignores_vault_instances_and_helpers() {
    let vault = "/Users/a/Library/Application Support/BrowserVault/mnt/8b4c7f0e-7a63-4d55-9a1e-2f0d9d3b6a11/profile";
    let brave = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
    let helper = "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Versions/1/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper --type=renderer";
    let ff = "/Applications/Firefox.app/Contents/MacOS/firefox";

    assert!(regular_running_in(Browser::Brave, brave));
    assert!(regular_running_in(
        Browser::Brave,
        &format!("{brave} --profile-directory=Default")
    ));
    assert!(!regular_running_in(Browser::Brave, helper));
    assert!(!regular_running_in(
        Browser::Brave,
        &format!("{brave} --user-data-dir={vault} --disk-cache-dir=x")
    ));
    assert!(!regular_running_in(Browser::Brave, ff));
    assert!(regular_running_in(
        Browser::Brave,
        &format!("{brave} --user-data-dir={vault}\n{brave}\n")
    ));

    assert!(regular_running_in(Browser::Firefox, ff));
    assert!(!regular_running_in(
        Browser::Firefox,
        &format!("{ff} --new-instance -profile {vault}")
    ));
    assert!(!regular_running_in(
        Browser::Firefox,
        "/Applications/Firefox.app/Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container"
    ));
    assert!(!regular_running_in(Browser::Firefox, "/usr/bin/firefoxish"));
    assert!(!is_vault_command("/mnt/not-a-uuid/profile"));
}

// --- all Brave profiles into one vault ----------------------------------------

fn read_ls(p: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

fn write_ls(roots: &Roots, ls: &serde_json::Value) {
    write(
        &roots.brave_data().join("Local State"),
        &serde_json::to_vec_pretty(ls).unwrap(),
    );
}

/// Add a regular Brave profile: its dir and its `Local State` entry.
fn add_brave_profile(roots: &Roots, id: &str, name: &str) {
    let b = roots.brave_data();
    write(
        &b.join(id).join("Preferences"),
        format!("{{\"{id}\":1}}").as_bytes(),
    );
    write(
        &b.join(id).join("Bookmarks"),
        format!("{name} bookmarks").as_bytes(),
    );
    write(&roots.brave_cache().join(id).join("Cache/data_0"), b"cx");
    let mut ls = read_ls(&b.join("Local State"));
    ls["profile"]["info_cache"][id] =
        serde_json::json!({ "name": name, "avatar_icon": "chrome://theme/IDR_PROFILE_AVATAR_26" });
    if let Some(a) = ls["profile"]["last_active_profiles"].as_array_mut() {
        a.push(id.into());
    }
    if let Some(a) = ls["profile"]["profiles_order"].as_array_mut() {
        a.push(id.into());
    }
    write_ls(roots, &ls);
}

/// Three profiles, plus machine-specific / sensitive keys that must not
/// reach the vault, and a stale `info_cache` entry without a directory.
fn three_profiles(roots: &Roots) {
    let mut ls = read_ls(&roots.brave_data().join("Local State"));
    ls["profile"]["profiles_order"] = serde_json::json!(["Default", "Profile 1"]);
    ls["profile"]["info_cache"]["Profile 7"] = serde_json::json!({ "name": "Gone" });
    ls["os_crypt"] = serde_json::json!({ "portal": { "prev_init_success": true } });
    ls["variations_compressed_seed"] = "c2VlZA==".into();
    ls["user_experience_metrics"] =
        serde_json::json!({ "client_id2": "1234-abcd", "low_entropy_source3": 42 });
    ls["brave"] = serde_json::json!({ "stats": { "week_of_installation": "2026-01-05" } });
    write_ls(roots, &ls);
    add_brave_profile(roots, "Profile 2", "Ads");
}

#[test]
fn import_all_brave_copies_every_profile_and_writes_local_state() {
    let (d, roots) = fake_home();
    three_profiles(&roots);
    let before = fs::read(roots.brave_data().join("Local State")).unwrap();
    let m = mnt(&d);
    let o = import_profile(&roots, Browser::Brave, ALL_PROFILES, &m, &ignore).unwrap();
    let p = m.join("profile");
    // Same dir names as in the regular install.
    assert_eq!(
        fs::read(p.join("Default/Bookmarks")).unwrap(),
        b"default bookmarks"
    );
    assert_eq!(
        fs::read(p.join("Profile 1/Network/Cookies")).unwrap(),
        b"cookies"
    );
    assert_eq!(
        fs::read(p.join("Profile 2/Bookmarks")).unwrap(),
        b"Ads bookmarks"
    );
    assert!(!p.join("Profile 7").exists());
    assert!(
        !p.join("Profile 1/link").exists(),
        "symlinks are not copied"
    );

    let ls = read_ls(&p.join("Local State"));
    let keys: Vec<&String> = ls.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["profile"], "only the profile switcher state");
    let pr = &ls["profile"];
    let ids: Vec<&String> = pr["info_cache"].as_object().unwrap().keys().collect();
    assert_eq!(ids, ["Default", "Profile 1", "Profile 2"]);
    assert_eq!(pr["info_cache"]["Profile 1"]["name"], "Work");
    assert_eq!(pr["info_cache"]["Profile 1"]["active_time"], 2.0);
    assert_eq!(
        pr["info_cache"]["Profile 2"]["avatar_icon"],
        "chrome://theme/IDR_PROFILE_AVATAR_26"
    );
    assert_eq!(pr["last_used"], "Profile 1");
    assert_eq!(
        pr["last_active_profiles"],
        serde_json::json!(["Default", "Profile 1", "Profile 2"])
    );
    assert_eq!(
        pr["profiles_order"],
        serde_json::json!(["Default", "Profile 1", "Profile 2"])
    );
    assert_eq!(pr["profiles_created"], 3);
    let text = String::from_utf8(fs::read(p.join("Local State")).unwrap()).unwrap();
    for secret in [
        "os_crypt",
        "variations",
        "client_id",
        "week_of_installation",
        "Gone",
    ] {
        assert!(!text.contains(secret), "{secret}");
    }

    assert_eq!(o.profile_id, ALL_PROFILES);
    assert_eq!(o.profile_name, "All profiles (3)");
    assert_eq!(o.state, OriginalState::Pending);
    assert!(!o.reviewed);
    let b = roots.brave_data();
    let c = roots.brave_cache();
    assert_eq!(
        o.paths,
        [
            b.join("Default"),
            c.join("Default"),
            b.join("Profile 1"),
            c.join("Profile 1"),
            b.join("Profile 2"),
            c.join("Profile 2"),
            roots.saved_state(Browser::Brave),
        ]
        .map(|p| p.to_string_lossy().into_owned())
    );
    assert_eq!(o.size_bytes, (7 + 17 + 2) + (36 + 2) + (15 + 13 + 2) + 1);
    // The regular install is only read.
    assert_eq!(fs::read(b.join("Local State")).unwrap(), before);
    assert!(b.join("Profile 2/Bookmarks").is_file());
}

#[test]
fn import_all_corrupted_profile_aborts_everything() {
    let (d, roots) = fake_home();
    three_profiles(&roots);
    let hooks: [&dyn Fn(&Path); 3] = [
        // Same size, different content: only the SHA-256 catches it.
        &|r| fs::write(r.join("Profile 2/Bookmarks"), b"Adz bookmarks").unwrap(),
        &|r| fs::remove_file(r.join("Profile 1/Local Storage/leveldb/000003.log")).unwrap(),
        &|r| fs::write(r.join("Default/extra"), b"x").unwrap(),
    ];
    for corrupt in hooks {
        let m = mnt(&d);
        let r = import_with_hook(&roots, Browser::Brave, ALL_PROFILES, &m, &ignore, corrupt);
        assert!(matches!(r, Err(Error::Invalid(_))));
        assert_eq!(
            fs::read_dir(m.join("profile")).unwrap().count(),
            0,
            "vault left empty"
        );
        fs::remove_dir_all(&m).unwrap();
    }
    assert_eq!(
        fs::read(roots.brave_data().join("Profile 2/Bookmarks")).unwrap(),
        b"Ads bookmarks"
    );
    // A non-empty vault profile is refused before anything is copied.
    let m = mnt(&d);
    write(&m.join("profile/x"), b"x");
    assert!(matches!(
        import_profile(&roots, Browser::Brave, ALL_PROFILES, &m, &ignore),
        Err(Error::Invalid(_))
    ));
    assert!(!m.join("profile/Default").exists());
}

#[test]
fn import_all_refused_for_firefox_and_while_brave_runs() {
    let (d, mut roots) = fake_home();
    let m = mnt(&d);
    assert!(matches!(
        import_profile(&roots, Browser::Firefox, ALL_PROFILES, &m, &ignore),
        Err(Error::Invalid(_))
    ));
    assert!(targets(&roots, Browser::Firefox, ALL_PROFILES).is_err());
    assert!(targets(&roots, Browser::Brave, ALL_PROFILES).is_err());
    roots.browser_running = running;
    assert!(matches!(
        import_profile(&roots, Browser::Brave, ALL_PROFILES, &m, &ignore),
        Err(Error::BrowserRunning)
    ));
    assert_eq!(fs::read_dir(m.join("profile")).unwrap().count(), 0);
    // No profiles at all.
    roots.browser_running = not_running;
    let empty = Roots {
        home: d.path().join("nobody"),
        ..roots
    };
    assert!(matches!(
        import_profile(&empty, Browser::Brave, ALL_PROFILES, &m, &ignore),
        Err(Error::NotFound)
    ));
}

fn all_originals_exist(f: &Fixture) -> bool {
    ["Default", "Profile 1", "Profile 2"]
        .iter()
        .all(|id| f.roots.brave_data().join(id).is_dir() && f.roots.brave_cache().join(id).is_dir())
}

#[test]
fn cleanup_all_refused_when_not_reviewed_running_or_wrong_password() {
    let mut f = fixture_with(Browser::Brave, ALL_PROFILES, false, three_profiles);
    let ls = fs::read(f.roots.brave_data().join("Local State")).unwrap();
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::NotReviewed)));

    let mut f2 = fixture_with(Browser::Brave, ALL_PROFILES, true, three_profiles);
    f2.roots.browser_running = running;
    let r = cleanup_original(&f2.store, &f2.roots, &mut f2.session, PW, &ignore);
    assert!(matches!(r, Err(Error::BrowserRunning)));
    f2.roots.browser_running = not_running;
    let r = cleanup_original(
        &f2.store,
        &f2.roots,
        &mut f2.session,
        "wrong password!!",
        &ignore,
    );
    assert!(matches!(r, Err(Error::UnlockFailed)));

    for f in [&f, &f2] {
        assert!(all_originals_exist(f));
        assert!(f.roots.saved_state(Browser::Brave).is_dir());
        assert_eq!(
            fs::read(f.roots.brave_data().join("Local State")).unwrap(),
            ls
        );
        assert_eq!(state(f).state, OriginalState::Pending);
    }
}

#[test]
fn cleanup_all_removes_exactly_the_imported_profiles() {
    let mut f = fixture_with(Browser::Brave, ALL_PROFILES, true, three_profiles);
    // Created in regular Brave after the import: must survive.
    add_brave_profile(&f.roots, "Profile 3", "Later");
    let b = f.roots.brave_data();
    let c = f.roots.brave_cache();
    let ls_before = fs::read(b.join("Local State")).unwrap();

    let preview = cleanup_preview(&f.store, &f.roots, &f.session).unwrap();
    assert_eq!(
        preview.items,
        [
            b.join("Default"),
            c.join("Default"),
            b.join("Profile 1"),
            c.join("Profile 1"),
            b.join("Profile 2"),
            c.join("Profile 2"),
            f.roots.saved_state(Browser::Brave),
        ]
    );
    assert_eq!(preview.profile_name, "All profiles (3)");

    cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore).unwrap();
    for id in ["Default", "Profile 1", "Profile 2"] {
        assert!(!b.join(id).exists(), "{id}");
        assert!(!c.join(id).exists(), "{id}");
    }
    assert!(!f.roots.saved_state(Browser::Brave).exists());
    assert_eq!(
        fs::read(b.join("Profile 3/Bookmarks")).unwrap(),
        b"Later bookmarks"
    );
    assert!(c.join("Profile 3/Cache/data_0").is_file());

    let ls = read_ls(&b.join("Local State"));
    let p = &ls["profile"];
    let ids: Vec<&String> = p["info_cache"].as_object().unwrap().keys().collect();
    // The stale entry without a dir was never imported, so it stays as well.
    assert_eq!(ids, ["Profile 3", "Profile 7"]);
    assert_eq!(p["last_used"], "Profile 3");
    assert_eq!(p["last_active_profiles"], serde_json::json!(["Profile 3"]));
    assert_eq!(p["profiles_order"], serde_json::json!(["Profile 3"]));
    assert_eq!(
        ls["os_crypt"]["portal"]["prev_init_success"], true,
        "other keys kept"
    );

    let backups: Vec<_> = fs::read_dir(&b)
        .unwrap()
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with("Local State.bvault-") && n.ends_with(".bak")
        })
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path()).unwrap(), ls_before);

    let o = state(&f);
    assert_eq!(o.state, OriginalState::Deleted);
    assert!(o.deleted_at.is_some());
}

#[test]
fn forgetting_every_profile_leaves_local_state_brave_can_start_from() {
    let (_d, roots) = fake_home();
    let ids = ["Default".to_string(), "Profile 1".to_string()];
    brave_forget_profiles(&roots, &ids).unwrap();
    let ls = read_ls(&roots.brave_data().join("Local State"));
    let p = &ls["profile"];
    assert_eq!(p["info_cache"], serde_json::json!({}));
    assert!(
        p.get("last_used").is_none(),
        "Brave falls back to a new Default"
    );
    assert_eq!(p["last_active_profiles"], serde_json::json!([]));
    assert_eq!(p["profiles_created"], 2);
}

#[test]
fn all_profiles_ids_come_only_from_recorded_brave_dirs() {
    let (_d, roots) = fake_home();
    let b = roots.brave_data();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    let mut o = Original {
        browser: Browser::Brave,
        profile_id: ALL_PROFILES.into(),
        profile_name: all_profiles_name(1),
        paths: vec![
            s(b.join("Profile 1")),
            s(roots.brave_cache().join("Default")),
            s(roots.saved_state(Browser::Brave)),
        ],
        size_bytes: 0,
        imported_at: now_rfc3339(),
        reviewed: true,
        state: OriginalState::Pending,
        deleted_at: None,
    };
    let t = targets_of(&roots, &o).unwrap();
    assert_eq!(
        t.profiles,
        [(
            b.join("Profile 1"),
            Some(roots.brave_cache().join("Profile 1"))
        )]
    );
    for bad in [
        b.join("Local State"),
        b.join(".."),
        b.join("*"),
        b.join(".hidden"),
    ] {
        o.paths = vec![s(bad.clone())];
        assert!(targets_of(&roots, &o).is_err(), "{bad:?}");
    }
    // Nothing under the Brave data dir: refused, never "delete everything".
    o.paths = vec![s(roots.home.join("Documents"))];
    assert!(targets_of(&roots, &o).is_err());
    o.browser = Browser::Firefox;
    o.paths = vec![s(b.join("Profile 1"))];
    assert!(targets_of(&roots, &o).is_err());
}

#[test]
fn telegram_session_detect_import_and_targets() {
    let (d, roots) = fake_home();
    // Nothing there yet.
    assert!(detect_profiles_in(&roots, Browser::Telegram)
        .unwrap()
        .is_empty());

    let tg = roots.telegram_data();
    write(&tg.join("tdata/key_datas"), b"local key");
    write(&tg.join("tdata/D877F783D5D3EF8C/maps"), b"maps");
    write(&tg.join("log.txt"), b"log");
    let found = detect_profiles_in(&roots, Browser::Telegram).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, TELEGRAM_PROFILE);

    let m = mnt(&d);
    let o = import_profile(&roots, Browser::Telegram, TELEGRAM_PROFILE, &m, &ignore).unwrap();
    // Lands where `-workdir <mnt>/profile` looks for it.
    assert_eq!(
        fs::read(m.join("profile/tdata/key_datas")).unwrap(),
        b"local key"
    );
    assert_eq!(
        fs::read(m.join("profile/tdata/D877F783D5D3EF8C/maps")).unwrap(),
        b"maps"
    );
    assert_eq!(o.browser, Browser::Telegram);
    // The original is only read.
    assert!(tg.join("tdata/key_datas").exists());

    // Cleanup deletes the whole default working dir, nothing else.
    let t = targets(&roots, Browser::Telegram, TELEGRAM_PROFILE).unwrap();
    assert_eq!(t.profiles, vec![(tg.clone(), None)]);
    assert!(t
        .saved_state
        .ends_with("Saved Application State/com.tdesktop.Telegram.savedState"));
    assert!(targets(&roots, Browser::Telegram, "../x").is_err());
}

#[test]
fn telegram_vault_instance_is_not_the_regular_one() {
    let regular = "/Applications/Telegram.app/Contents/MacOS/Telegram";
    let vault = "/Applications/Telegram.app/Contents/MacOS/Telegram -workdir /Users/a/Library/Application Support/X/mnt/8b4c7f0e-7a63-4d55-9a1e-2f0d9d3b6a11/profile";
    assert!(regular_running_in(Browser::Telegram, regular));
    assert!(!regular_running_in(Browser::Telegram, vault));
    assert!(!regular_running_in(Browser::Brave, regular));
}

#[test]
fn parallels_vms_detect_import_and_targets() {
    let (d, roots) = fake_home();
    let par = roots.parallels_dir();
    write(
        &par.join("Windows 11 Work.pvm/config.pvs"),
        b"<VmUuid>{5681d811-e628-4c9b-9e4e-46a5cec0418a}</VmUuid>",
    );
    write(&par.join("Windows 11 Work.pvm/harddisk.hdd/data"), b"disk");
    write(&par.join("notes.txt"), b"not a vm");
    let found = detect_profiles_in(&roots, Browser::Vm).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "Windows 11 Work.pvm");
    assert_eq!(found[0].name, "Windows 11 Work");

    let m = mnt(&d);
    import_profile(&roots, Browser::Vm, "Windows 11 Work.pvm", &m, &ignore).unwrap();
    assert_eq!(
        fs::read(m.join("profile/Windows 11 Work.pvm/harddisk.hdd/data")).unwrap(),
        b"disk"
    );
    assert_eq!(
        crate::vm::find_pvm(&m),
        Some(m.join("profile/Windows 11 Work.pvm"))
    );
    let t = targets(&roots, Browser::Vm, "Windows 11 Work.pvm").unwrap();
    assert_eq!(t.profiles, vec![(par.join("Windows 11 Work.pvm"), None)]);
    for bad in ["../x.pvm", "x", ".pvm", "a/b.pvm"] {
        assert!(targets(&roots, Browser::Vm, bad).is_err(), "{bad}");
    }
}

#[test]
fn vm_from_another_location() {
    let (d, roots) = fake_home();
    let ext = d.path().join("Volumes/Ext/Windows 11 Personal.pvm");
    write(
        &ext.join("config.pvs"),
        b"<VmUuid>{a3761211-d92e-4f48-8528-6ddc68eee96c}</VmUuid>",
    );
    write(&ext.join("disk.hdd/data"), b"big");
    let id = ext.to_string_lossy().into_owned();
    let found = describe_vm(&ext).unwrap();
    assert_eq!(
        (found.id.as_str(), found.name.as_str()),
        (id.as_str(), "Windows 11 Personal")
    );

    let m = mnt(&d);
    import_profile(&roots, Browser::Vm, &id, &m, &ignore).unwrap();
    assert_eq!(
        fs::read(m.join("profile/Windows 11 Personal.pvm/disk.hdd/data")).unwrap(),
        b"big"
    );
    let t = targets(&roots, Browser::Vm, &id).unwrap();
    assert_eq!(t.profiles, vec![(ext.clone(), None)]);

    // Not a VM bundle, relative, `..`, or missing config: refused.
    let plain = d.path().join("Volumes/Ext/photos.pvm");
    fs::create_dir_all(&plain).unwrap();
    for bad in [
        plain.to_string_lossy().into_owned(),
        "Volumes/Ext/Windows 11 Personal.pvm".into(),
        format!(
            "{}/../Ext/Windows 11 Personal.pvm",
            d.path().join("Volumes/Ext").display()
        ),
        d.path().join("Volumes/Ext").to_string_lossy().into_owned(),
    ] {
        assert!(targets(&roots, Browser::Vm, &bad).is_err(), "{bad}");
    }
}

#[test]
fn obsidian_notes_detect_import_targets_and_forget() {
    let (d, roots) = fake_home();
    let notes = roots.home.join("Documents/Notes");
    write(&notes.join("Ideas.md"), b"# idea");
    write(&notes.join(".obsidian/app.json"), b"{}");
    let docs = roots.home.join("Documents");
    let cfg = roots.obsidian_config();
    write(
        &cfg,
        format!(
            r#"{{"vaults":{{"a":{{"path":"{}"}},"b":{{"path":"{}"}},"c":{{"path":"/nope/x/y"}}}}}}"#,
            notes.display(),
            docs.display()
        )
        .as_bytes(),
    );
    // ~/Documents itself is never offered (a top-level home folder).
    let found = detect_profiles_in(&roots, Browser::Obsidian).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].path, notes);
    assert_eq!(found[0].name, "Notes");

    let m = mnt(&d);
    let id = notes.to_string_lossy().into_owned();
    import_profile(&roots, Browser::Obsidian, &id, &m, &ignore).unwrap();
    assert_eq!(fs::read(m.join("notes/Ideas.md")).unwrap(), b"# idea");

    let t = targets(&roots, Browser::Obsidian, &id).unwrap();
    assert_eq!(t.profiles, vec![(notes.clone(), None)]);
    assert!(targets(&roots, Browser::Obsidian, &docs.to_string_lossy()).is_err());
    assert!(targets(&roots, Browser::Obsidian, "/Users/someone/else/Notes").is_err());

    crate::obsidian::forget_vault(&cfg, &notes).unwrap();
    assert!(!crate::obsidian::known_vaults(&cfg).contains(&notes));
}
