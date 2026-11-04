//! SPEC §9 M7b acceptance: import an existing profile, review it, delete the
//! original. Needs a real Mac (hdiutil) plus Brave and Firefox installed.
//!
//! The "existing" profiles are created by the real browsers inside a temp
//! dir used as a fake home (`--user-data-dir=<fake>/…/Brave-Browser`,
//! `-profile <fake>/…/Firefox/Profiles/…`), so the test never touches the
//! real profiles of whoever runs it. Quit regular Brave and Firefox first:
//! import and cleanup refuse to run while they are open.
//!
//! Run manually on macOS:
//!   cargo test -p vault-core --all-features --test e2e_import_macos -- --ignored --nocapture --test-threads=1
#![cfg(target_os = "macos")]

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use vault_core::header::{OriginalState, VaultSettings};
use vault_core::keyslot::Draft;
use vault_core::profiles::{self, Roots};
use vault_core::store::{CreateOptions, Credential, Devices, ImportRequest};
use vault_core::{browser, events, fido2, se, Browser, Error, KdfCost, Store};

const PW: &str = "correct horse battery";

fn devs() -> Devices<'static> {
    Devices {
        se: Box::leak(se::system()),
        fido: Box::leak(fido2::system()),
        notify: &events::ignore,
    }
}

fn spawn(bin: &Path, args: &[&std::ffi::OsStr], env: &[(&str, &str)]) -> Child {
    Command::new(bin)
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Wait until no regular instance is left (helpers may linger briefly).
fn wait_regular_gone(b: Browser) {
    let start = Instant::now();
    while profiles::regular_browser_running(b) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "regular {b:?} still running"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Run a browser for `secs`, check it stayed up, then stop it gracefully.
fn run_for(bin: &Path, args: &[&std::ffi::OsStr], env: &[(&str, &str)], b: Browser, secs: u64) {
    let mut c = spawn(bin, args, env);
    let pid = c.id() as i32;
    std::thread::sleep(Duration::from_secs(secs));
    assert!(browser::is_alive(pid), "{b:?} exited early");
    assert!(
        profiles::regular_browser_running(b),
        "a non-vault {b:?} counts as the regular instance"
    );
    browser::terminate(pid, Duration::from_secs(10));
    let _ = c.wait();
    // Firefox may relaunch itself on a fresh profile (new PID); stop every
    // process started against this test's profile path too.
    let needle = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .find(|a| a.contains("/home/Library/"))
        .expect("profile path argument under the fake home");
    let needle = needle.trim_start_matches("--user-data-dir=");
    for other in pids_with(needle) {
        eprintln!("note: stopping relaunched {b:?} pid {other}");
        browser::terminate(other, Duration::from_secs(10));
    }
    wait_regular_gone(b);
}

fn pids_with(needle: &str) -> Vec<i32> {
    let out = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(needle))
        .filter_map(|l| l.trim().split_once(' ')?.0.parse().ok())
        .collect()
}

fn create_with_import(s: &Store, roots: &Roots, b: Browser, profile_id: &str) -> String {
    let mut d = Draft::new("Import", b, KdfCost::FAST).unwrap();
    d.set_password(PW).unwrap();
    d.add_password_only_slot().unwrap();
    d.generate_recovery().unwrap();
    let opts = CreateOptions {
        disable_fxa: true,
        import: Some(ImportRequest {
            roots: roots.clone(),
            profile_id: profile_id.into(),
        }),
    };
    let c = s
        .create_with(d, 1, VaultSettings::default(), &opts, &events::ignore)
        .unwrap();
    assert!(c.import_error.is_none(), "{:?}", c.import_error);
    let o = c.header.original.clone().unwrap();
    assert_eq!(o.profile_id, profile_id);
    assert!(!o.reviewed);
    assert_eq!(o.state, OriginalState::Pending);
    c.header.vault_id
}

/// Import → open + close (review) → delete, with the in-core refusals.
fn review_and_delete(s: &Store, roots: &Roots, id: &str, bin: &Path, check: impl Fn(&Path)) {
    let mut u = s.unlock(id, Credential::Password(PW), &devs()).unwrap();
    check(&u.mountpoint);
    let mut child = s.launch(&u, Some(bin)).unwrap();
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        !profiles::regular_browser_running(u.header.browser),
        "the vault instance is not the regular one"
    );
    // Not reviewed yet: refused in core, whatever the caller.
    assert!(matches!(
        profiles::cleanup_original(s, roots, &mut u, PW, &events::ignore),
        Err(Error::NotReviewed)
    ));
    s.close(u).unwrap();
    let _ = child.wait();
    assert!(s.load(id).unwrap().original.unwrap().reviewed);

    let mut u = s.unlock(id, Credential::Password(PW), &devs()).unwrap();
    let preview = profiles::cleanup_preview(s, roots, id).unwrap();
    eprintln!("cleanup preview: {preview:#?}");
    assert!(preview.reviewed && !preview.items.is_empty());
    assert!(matches!(
        profiles::cleanup_original(s, roots, &mut u, "wrong password!!", &events::ignore),
        Err(Error::UnlockFailed)
    ));
    profiles::cleanup_original(s, roots, &mut u, PW, &events::ignore).unwrap();
    s.close(u).unwrap();
    let o = s.load(id).unwrap().original.unwrap();
    assert_eq!(o.state, OriginalState::Deleted);
    assert!(o.deleted_at.is_some());
}

#[test]
#[ignore = "needs macOS + Brave; opens browser windows (see file header)"]
fn m7b_brave_import_and_cleanup() {
    let brave = browser::detect(Browser::Brave).expect("Brave must be installed");
    assert!(
        !profiles::regular_browser_running(Browser::Brave),
        "quit Brave first"
    );
    let d = tempfile::tempdir().unwrap();
    let roots = Roots::for_home(d.path().join("home"));
    let udd = roots.brave_data();
    fs::create_dir_all(&udd).unwrap();
    let mut udd_arg = std::ffi::OsString::from("--user-data-dir=");
    udd_arg.push(&udd);
    for p in ["Default", "Profile 1"] {
        let pd = format!("--profile-directory={p}");
        run_for(
            &brave,
            &[
                udd_arg.as_os_str(),
                pd.as_ref(),
                "--no-first-run".as_ref(),
                "--no-default-browser-check".as_ref(),
                "--disable-crash-reporter".as_ref(),
            ],
            &[],
            Browser::Brave,
            8,
        );
    }
    let found = profiles::detect_profiles_in(&roots, Browser::Brave).unwrap();
    eprintln!("detected: {found:#?}");
    let ids: Vec<&str> = found.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["Default", "Profile 1"]);
    let default_prefs = fs::read(udd.join("Default/Preferences")).unwrap();

    let s = Store::new(d.path().join("BrowserVault"));
    let id = create_with_import(&s, &roots, Browser::Brave, "Profile 1");
    review_and_delete(&s, &roots, &id, &brave, |mnt| {
        assert!(mnt.join("profile/Default/Preferences").is_file());
    });

    assert!(!udd.join("Profile 1").exists());
    assert_eq!(
        fs::read(udd.join("Default/Preferences")).unwrap(),
        default_prefs
    );
    let ls: serde_json::Value =
        serde_json::from_slice(&fs::read(udd.join("Local State")).unwrap()).unwrap();
    assert!(ls["profile"]["info_cache"].get("Profile 1").is_none());
    assert!(ls["profile"]["info_cache"].get("Default").is_some());
    assert!(has_backup(&udd, "Local State"));

    // Brave still starts normally on the remaining profile.
    run_for(
        &brave,
        &[
            udd_arg.as_os_str(),
            "--no-first-run".as_ref(),
            "--no-default-browser-check".as_ref(),
            "--disable-crash-reporter".as_ref(),
        ],
        &[],
        Browser::Brave,
        8,
    );
    assert!(udd.join("Default/Preferences").is_file());
    let ls: serde_json::Value =
        serde_json::from_slice(&fs::read(udd.join("Local State")).unwrap()).unwrap();
    assert!(ls["profile"]["info_cache"].get("Default").is_some());
}

#[test]
#[ignore = "needs macOS + Brave; opens browser windows (see file header)"]
fn m7b_brave_import_all_profiles_and_cleanup() {
    let brave = browser::detect(Browser::Brave).expect("Brave must be installed");
    assert!(
        !profiles::regular_browser_running(Browser::Brave),
        "quit Brave first"
    );
    let d = tempfile::tempdir().unwrap();
    let roots = Roots::for_home(d.path().join("home"));
    let udd = roots.brave_data();
    fs::create_dir_all(&udd).unwrap();
    let mut udd_arg = std::ffi::OsString::from("--user-data-dir=");
    udd_arg.push(&udd);
    let run_profile = |p: &str| {
        let pd = format!("--profile-directory={p}");
        run_for(
            &brave,
            &[
                udd_arg.as_os_str(),
                pd.as_ref(),
                "--no-first-run".as_ref(),
                "--no-default-browser-check".as_ref(),
                "--disable-crash-reporter".as_ref(),
            ],
            &[],
            Browser::Brave,
            8,
        );
    };
    run_profile("Default");
    run_profile("Profile 1");
    let ids: Vec<String> = profiles::detect_profiles_in(&roots, Browser::Brave)
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(ids, ["Default", "Profile 1"]);

    let s = Store::new(d.path().join("BrowserVault"));
    let id = create_with_import(&s, &roots, Browser::Brave, profiles::ALL_PROFILES);
    assert_eq!(
        s.load(&id).unwrap().original.unwrap().profile_name,
        "All profiles (2)"
    );
    // Created in regular Brave after the import: cleanup must not touch it.
    run_profile("Profile 2");
    assert!(udd.join("Profile 2/Preferences").is_file());

    review_and_delete(&s, &roots, &id, &brave, |mnt| {
        for p in ["Default", "Profile 1"] {
            assert!(mnt.join("profile").join(p).join("Preferences").is_file());
        }
        let ls: serde_json::Value =
            serde_json::from_slice(&fs::read(mnt.join("profile/Local State")).unwrap()).unwrap();
        eprintln!("vault Local State: {ls:#}");
        let cache = ls["profile"]["info_cache"].as_object().unwrap();
        assert!(cache.contains_key("Default") && cache.contains_key("Profile 1"));
        assert!(ls.get("os_crypt").is_none());
    });

    assert!(!udd.join("Default").exists());
    assert!(!udd.join("Profile 1").exists());
    assert!(udd.join("Profile 2/Preferences").is_file());
    let ls: serde_json::Value =
        serde_json::from_slice(&fs::read(udd.join("Local State")).unwrap()).unwrap();
    let cache = ls["profile"]["info_cache"].as_object().unwrap();
    assert_eq!(cache.keys().collect::<Vec<_>>(), ["Profile 2"]);
    assert_eq!(ls["profile"]["last_used"], "Profile 2");
    assert!(has_backup(&udd, "Local State"));

    // Brave still starts on the regular install, with the remaining profile.
    run_for(
        &brave,
        &[
            udd_arg.as_os_str(),
            "--no-first-run".as_ref(),
            "--no-default-browser-check".as_ref(),
            "--disable-crash-reporter".as_ref(),
        ],
        &[],
        Browser::Brave,
        8,
    );
    let ls: serde_json::Value =
        serde_json::from_slice(&fs::read(udd.join("Local State")).unwrap()).unwrap();
    assert!(ls["profile"]["info_cache"].get("Profile 2").is_some());
}

#[test]
#[ignore = "needs macOS + Firefox; opens browser windows (see file header)"]
fn m7b_firefox_import_and_cleanup() {
    let firefox = browser::detect(Browser::Firefox).expect("Firefox must be installed");
    assert!(
        !profiles::regular_browser_running(Browser::Firefox),
        "quit Firefox first"
    );
    let d = tempfile::tempdir().unwrap();
    let roots = Roots::for_home(d.path().join("home"));
    let fx = roots.firefox_data();
    let env = [("MOZ_CRASHREPORTER_DISABLE", "1")];
    for p in ["aaa.default", "bbb.work"] {
        let dir = fx.join("Profiles").join(p);
        fs::create_dir_all(&dir).unwrap();
        run_for(
            &firefox,
            &[
                "--headless".as_ref(),
                "--new-instance".as_ref(),
                "-profile".as_ref(),
                dir.as_os_str(),
            ],
            &env,
            Browser::Firefox,
            8,
        );
        assert!(dir.join("prefs.js").is_file() || dir.join("times.json").is_file());
    }
    fs::write(
        fx.join("profiles.ini"),
        "[Install4F96D1932A9F858E]\nDefault=Profiles/bbb.work\nLocked=1\n\n\
         [Profile1]\nName=work\nIsRelative=1\nPath=Profiles/bbb.work\nDefault=1\n\n\
         [Profile0]\nName=default\nIsRelative=1\nPath=Profiles/aaa.default\n\n\
         [General]\nStartWithLastProfile=1\nVersion=2\n",
    )
    .unwrap();
    fs::write(
        fx.join("installs.ini"),
        "[4F96D1932A9F858E]\nDefault=Profiles/bbb.work\nLocked=1\n",
    )
    .unwrap();

    let s = Store::new(d.path().join("BrowserVault"));
    let id = create_with_import(&s, &roots, Browser::Firefox, "Profiles/bbb.work");
    review_and_delete(&s, &roots, &id, &firefox, |mnt| {
        let uj = fs::read_to_string(mnt.join("profile/user.js")).unwrap();
        assert!(uj.contains("\"identity.fxaccounts.enabled\", false"));
        assert!(mnt.join("profile/prefs.js").is_file());
    });

    assert!(!fx.join("Profiles/bbb.work").exists());
    assert!(fx.join("Profiles/aaa.default/prefs.js").is_file());
    let left = profiles::detect_profiles_in(&roots, Browser::Firefox).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, "Profiles/aaa.default");
    let ini = fs::read_to_string(fx.join("profiles.ini")).unwrap();
    eprintln!("profiles.ini after cleanup:\n{ini}");
    assert!(ini.contains(
        "[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/aaa.default\nDefault=1\n"
    ));
    assert!(ini.contains("[Install4F96D1932A9F858E]\nDefault=Profiles/aaa.default\n"));
    assert!(!ini.contains("bbb.work") && !ini.contains("[Profile1]"));
    let installs = fs::read_to_string(fx.join("installs.ini")).unwrap();
    assert!(installs.contains("Default=Profiles/aaa.default"));
    assert!(has_backup(&fx, "profiles.ini") && has_backup(&fx, "installs.ini"));

    // Firefox still starts on the remaining profile.
    let dir = fx.join("Profiles/aaa.default");
    run_for(
        &firefox,
        &[
            "--headless".as_ref(),
            "--new-instance".as_ref(),
            "-profile".as_ref(),
            dir.as_os_str(),
        ],
        &env,
        Browser::Firefox,
        8,
    );
}

fn has_backup(dir: &Path, name: &str) -> bool {
    fs::read_dir(dir).unwrap().flatten().any(|e| {
        let n = e.file_name().to_string_lossy().into_owned();
        n.starts_with(&format!("{name}.bvault-")) && n.ends_with(".bak")
    })
}
