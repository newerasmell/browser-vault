//! End-to-end tests that need a real Mac (hdiutil) and, for M1, Brave.
//!
//! Run manually on macOS:
//!   cargo test -p vault-core --test e2e_macos -- --ignored --nocapture --test-threads=1
//!
//! `m1_brave_acceptance` / `m5_firefox_acceptance` additionally need Brave /
//! Firefox in /Applications and open a
//! real browser window for ~10 s; do not touch it while the test runs.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use vault_core::header::VaultSettings;
use vault_core::keyslot::Draft;
use vault_core::store::{Credential, Devices};
use vault_core::{browser, events, fido2, hdiutil, se, Browser, Error, KdfCost, Store};

const PW: &str = "correct horse battery";

fn devs() -> Devices<'static> {
    Devices {
        se: Box::leak(se::system()),
        fido: Box::leak(fido2::system()),
        notify: &events::ignore,
    }
}

/// Password-only vault (test feature) → (header id, recovery phrase).
fn create(s: &Store, name: &str, browser: Browser) -> (String, String) {
    let mut d = Draft::new(name, browser, KdfCost::FAST).unwrap();
    d.set_password(PW).unwrap();
    d.add_password_only_slot().unwrap();
    d.generate_recovery().unwrap();
    let phrase = d.recovery_phrase().unwrap().to_string();
    let h = s
        .create(d, 1, VaultSettings::default(), &events::ignore)
        .unwrap();
    (h.vault_id, phrase)
}

fn store() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let s = Store::new(d.path().join("BrowserVault"));
    (d, s)
}

/// Create → unlock (mount) → write → lock → unmounted, data not readable,
/// wrong password refused, recovery phrase mounts too.
#[test]
#[ignore = "needs macOS hdiutil; run manually (see file header)"]
fn container_roundtrip() {
    let (_d, s) = store();
    let (id, phrase) = create(&s, "E2E", Browser::Brave);
    assert!(s.image_path(&id).is_dir(), "sparsebundle is a directory");

    let u = s.unlock(&id, Credential::Password(PW), &devs()).unwrap();
    assert!(u.header_intact);
    assert!(hdiutil::is_mounted(&u.mountpoint));
    let secret_file = u.mountpoint.join("profile/secret.txt");
    fs::write(&secret_file, b"top secret session cookie").unwrap();
    drop(u);

    s.lock(&id).unwrap();
    assert!(!hdiutil::is_mounted(&s.mountpoint(&id)));
    assert!(!secret_file.exists());
    // The plaintext must not appear anywhere in the image bands.
    assert!(!dir_contains(
        &s.image_path(&id),
        b"top secret session cookie"
    ));

    assert!(matches!(
        s.unlock(&id, Credential::Password("wrong password!!"), &devs()),
        Err(Error::UnlockFailed)
    ));
    assert!(!hdiutil::is_mounted(&s.mountpoint(&id)));

    let u = s
        .unlock(&id, Credential::Recovery(&phrase), &devs())
        .unwrap();
    assert_eq!(
        fs::read(u.mountpoint.join("profile/secret.txt")).unwrap(),
        b"top secret session cookie"
    );
    drop(u);
    s.lock(&id).unwrap();
    assert!(!hdiutil::is_mounted(&s.mountpoint(&id)));
}

/// SPEC §9 M1 acceptance: create → unlock → Brave writes into <mnt> → lock →
/// volume not mounted, and ~/Library has no new profile data.
#[test]
#[ignore = "needs macOS + Brave; opens a browser window (see file header)"]
fn m1_brave_acceptance() {
    let brave = browser::detect(Browser::Brave).expect("Brave must be installed");
    let (_d, s) = store();
    let (id, _phrase) = create(&s, "M1", Browser::Brave);

    let marker = SystemTime::now();
    std::thread::sleep(Duration::from_secs(1));

    let u = s.unlock(&id, Credential::Password(PW), &devs()).unwrap();
    let mut child = s.launch(&u, Some(&brave)).unwrap();
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        u.mountpoint.join("profile/Default").is_dir(),
        "Brave wrote its profile inside the vault"
    );
    assert!(fs::read_dir(u.mountpoint.join("cache")).is_ok());
    let mnt = u.mountpoint.clone();
    drop(u);

    s.lock(&id).unwrap();
    let _ = child.wait();
    assert!(!hdiutil::is_mounted(&mnt));
    assert!(!browser::is_alive(child.id() as i32));

    // Nothing new from the vault profile under the regular Brave locations.
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let watched = [
        home.join("Library/Application Support/BraveSoftware"),
        home.join("Library/Caches/BraveSoftware"),
    ];
    let mut leaked = vec![];
    for w in &watched {
        newer_files(w, marker, &mut leaked);
    }
    // Crashpad client metadata (client id, upload consent; no browsing
    // data) is touched by Brave even with --disable-crash-reporter.
    // Dumps (`Crashpad/pending`, `completed`, …) still fail the test.
    leaked.retain(|p| {
        let allowed = p.ends_with("Brave-Browser/Crashpad/settings.dat");
        if allowed {
            eprintln!("note: allow-listed {}", p.display());
        }
        !allowed
    });
    // Saved Application State cleanup is milestone M7; listed for manual review only.
    let mut saved_state = vec![];
    newer_files(
        &home.join("Library/Saved Application State/com.brave.Browser.savedState"),
        marker,
        &mut saved_state,
    );
    if !saved_state.is_empty() {
        eprintln!("note (M7 cleanup): {saved_state:#?}");
    }
    assert!(
        leaked.is_empty(),
        "files modified outside the vault (close regular Brave and retry): {leaked:#?}"
    );
}

/// SPEC §9 M5 acceptance: the M1 checks for Firefox, plus the cache lives
/// inside <mnt> (user.js `browser.cache.disk.parent_directory`).
#[test]
#[ignore = "needs macOS + Firefox; opens a browser window (see file header)"]
fn m5_firefox_acceptance() {
    let firefox = browser::detect(Browser::Firefox).expect("Firefox must be installed");
    let (_d, s) = store();
    let (id, _phrase) = create(&s, "M5", Browser::Firefox);

    let marker = SystemTime::now();
    std::thread::sleep(Duration::from_secs(1));

    let u = s.unlock(&id, Credential::Password(PW), &devs()).unwrap();
    let user_js = fs::read_to_string(u.mountpoint.join("profile/user.js")).unwrap();
    let cache = u.mountpoint.join("cache");
    assert!(
        user_js.contains(&format!(
            "user_pref(\"browser.cache.disk.parent_directory\", \"{}\");",
            cache.display()
        )),
        "{user_js}"
    );
    let mut child = s.launch(&u, Some(&firefox)).unwrap();
    std::thread::sleep(Duration::from_secs(15));
    assert!(
        u.mountpoint.join("profile/prefs.js").is_file(),
        "Firefox wrote its profile inside the vault"
    );
    let mut cached = vec![];
    newer_files(&cache, marker, &mut cached);
    eprintln!("cache files in <mnt>/cache: {}", cached.len());
    assert!(
        cache.join("cache2").is_dir(),
        "Firefox disk cache inside <mnt>/cache: {:#?}",
        fs::read_dir(&cache).map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())
    );
    let mnt = u.mountpoint.clone();
    drop(u);

    s.lock(&id).unwrap();
    let _ = child.wait();
    assert!(!hdiutil::is_mounted(&mnt));
    assert!(!browser::is_alive(child.id() as i32));
    let ps = Command::new("ps")
        .args(["-axo", "command="])
        .output()
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&ps.stdout).contains(&*mnt.to_string_lossy()),
        "no process left running against the vault"
    );

    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let mut leaked = vec![];
    for w in [
        home.join("Library/Application Support/Firefox"),
        home.join("Library/Caches/Firefox"),
        home.join("Library/Application Support/Mozilla"),
    ] {
        newer_files(&w, marker, &mut leaked);
    }
    let mut saved_state = vec![];
    newer_files(
        &home.join("Library/Saved Application State/org.mozilla.firefox.savedState"),
        marker,
        &mut saved_state,
    );
    if !saved_state.is_empty() {
        eprintln!("note (M7 cleanup): {saved_state:#?}");
    }
    assert!(
        leaked.is_empty(),
        "files modified outside the vault (close regular Firefox and retry): {leaked:#?}"
    );
}

fn newer_files(dir: &Path, since: SystemTime, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = fs::symlink_metadata(&p) else {
            continue;
        };
        if md.is_dir() {
            newer_files(&p, since, out);
        } else if md.modified().map(|m| m > since).unwrap_or(false) {
            out.push(p);
        }
    }
}

fn dir_contains(dir: &Path, needle: &[u8]) -> bool {
    let out = Command::new("grep")
        .args(["-r", "-l", "-a", "-F"])
        .arg(std::str::from_utf8(needle).unwrap())
        .arg(dir)
        .output()
        .unwrap();
    !out.stdout.is_empty()
}
