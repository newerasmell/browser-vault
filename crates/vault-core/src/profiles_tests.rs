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
}

/// A store with one vault whose header records an import of `profile_id`,
/// plus an unlocked session for it (as `Store::unlock` would build it).
fn fixture(browser: Browser, profile_id: &str, reviewed: bool) -> Fixture {
    let (d, roots) = fake_home();
    let store = Store::new(d.path().join("BrowserVault"));
    let nv = new_vault("V", browser, PW, KdfCost::FAST).unwrap().0;
    let m = mnt(&d);
    let mut o = import_profile(&roots, browser, profile_id, &m, &ignore).unwrap();
    o.reviewed = reviewed;
    let mut h = nv.header;
    h.original = Some(o);
    h.seal_mac(nv.key.vmk()).unwrap();
    fs::create_dir_all(store.vault_dir(&h.vault_id)).unwrap();
    store.save_header(&h).unwrap();
    let verifier = PasswordVerifier::new(&h.kdf, nv.key.vmk(), PW).unwrap();
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
    }
}

fn state(f: &Fixture) -> Original {
    f.store
        .load(&f.session.header.vault_id)
        .unwrap()
        .original
        .unwrap()
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
    // Someone flips `reviewed` (or the paths) on disk without the VMK.
    let mut h = f.store.load(&f.session.header.vault_id).unwrap();
    h.original.as_mut().unwrap().reviewed = true;
    f.store.save_header(&h).unwrap();
    let r = cleanup_original(&f.store, &f.roots, &mut f.session, PW, &ignore);
    assert!(matches!(r, Err(Error::Format(_))));
    assert!(brave_originals_exist(&f));
}

#[test]
fn brave_cleanup_removes_only_that_profile() {
    let mut f = fixture(Browser::Brave, "Profile 1", true);
    let preview = cleanup_preview(&f.store, &f.roots, &f.session.header.vault_id).unwrap();
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
    // Not mounted here, so lock is a no-op; close then marks reviewed.
    f.store.close(f.session).unwrap();
    let h = f.store.load(&id).unwrap();
    let o = h.original.clone().unwrap();
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
