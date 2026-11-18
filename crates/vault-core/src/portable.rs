//! Portable Brave logins: make a vault's Brave profile(s) independent of
//! this Mac's Keychain, so the vault works with its logins on another Mac.
//!
//! Brave in a portable vault runs with `--use-mock-keychain` and encrypts
//! cookies / saved passwords with a fixed key ([`ChromiumKey::mock`]). The
//! real protection is the encrypted vault around the profile. An imported
//! profile is still encrypted with this Mac's "Brave Safe Storage" key, so
//! [`convert_mount`] re-encrypts every "v10" value IN THE VAULT COPY from
//! that key to the portable one. The user's original profile is never
//! touched (CLAUDE.md: originals are read-only).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::browser;
use crate::chromium::{self, ChromiumKey};
use crate::error::{Error, Result};

/// Brave's databases that hold `v10` values (relative to a profile dir).
const DATABASES: &[&str] = &[
    "Cookies",
    "Network/Cookies",
    "Extension Cookies",
    "Login Data",
    "Login Data For Account",
    "Web Data",
    "Account Web Data",
];

/// Brave launch flag for portable vaults.
pub const MOCK_KEYCHAIN_FLAG: &str = "--use-mock-keychain";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Values re-encrypted with the portable key.
    pub converted: u64,
    /// `v10` values the source key could not open (left untouched).
    pub failed: u64,
    /// Databases scanned.
    pub databases: u64,
}

impl std::ops::AddAssign for Stats {
    fn add_assign(&mut self, o: Stats) {
        self.converted += o.converted;
        self.failed += o.failed;
        self.databases += o.databases;
    }
}

/// This Mac's "Brave Safe Storage" key from the login Keychain. macOS asks
/// the user once to allow Browser Vault to read it.
#[cfg(target_os = "macos")]
pub fn brave_keychain_key() -> Result<ChromiumKey> {
    use security_framework::passwords::get_generic_password;
    let pw = zeroize::Zeroizing::new(
        get_generic_password("Brave Safe Storage", "Brave")
            .map_err(|_| Error::Invalid(ERR_KEYCHAIN))?,
    );
    Ok(ChromiumKey::from_password(&pw))
}

#[cfg(not(target_os = "macos"))]
pub fn brave_keychain_key() -> Result<ChromiumKey> {
    Err(Error::Unsupported("Keychain"))
}

/// The Keychain item could not be read (missing, or the user clicked Deny).
pub const ERR_KEYCHAIN: &str = "could not read Brave's key from the Keychain";

/// This Mac's "Brave Safe Storage" password, as Brave keeps it.
pub enum MacKey {
    Present(zeroize::Zeroizing<Vec<u8>>),
    /// Brave never ran on this Mac: no item yet.
    Missing,
    /// There, but not readable (the user clicked Deny).
    Unreadable,
}

pub type MacKeySource = fn() -> MacKey;
pub type MacKeySet = fn(&[u8]) -> Result<()>;

#[cfg(target_os = "macos")]
pub fn system_mac_key() -> MacKey {
    use security_framework::passwords::get_generic_password;
    match get_generic_password("Brave Safe Storage", "Brave") {
        Ok(v) => MacKey::Present(zeroize::Zeroizing::new(v)),
        // errSecItemNotFound
        Err(e) if e.code() == -25300 => MacKey::Missing,
        Err(_) => MacKey::Unreadable,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn system_mac_key() -> MacKey {
    MacKey::Unreadable
}

/// Create this Mac's "Brave Safe Storage" item with `password` (only when it
/// does not exist yet). Brave asks once to use it.
#[cfg(target_os = "macos")]
pub fn system_set_mac_key(password: &[u8]) -> Result<()> {
    security_framework::passwords::set_generic_password("Brave Safe Storage", "Brave", password)
        .map_err(|_| Error::Invalid(ERR_KEYCHAIN))
}

#[cfg(not(target_os = "macos"))]
pub fn system_set_mac_key(_password: &[u8]) -> Result<()> {
    Err(Error::Unsupported("Keychain"))
}

/// Where a vault keeps the "Brave Safe Storage" password its logins are
/// encrypted with (inside the encrypted volume, mode 600).
pub fn key_file(mnt: &Path) -> PathBuf {
    mnt.join(".bv").join("brave-key")
}

/// What [`follow_mac_key`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Followed {
    /// First time: this Mac's key was recorded.
    Saved,
    /// Same Mac (same key): nothing to do.
    Same,
    /// Another Mac: logins re-encrypted to this Mac's key.
    Converted(Stats),
    /// Brave never ran here: this Mac got the vault's key, no conversion.
    Installed,
    /// This Mac's key could not be read; logins stay as they were.
    Unreadable,
}

/// Keep a Brave vault's logins readable on whichever Mac opens it (Brave
/// 158+ has no working Mac-independent mode). Runs after the vault is
/// mounted and before Brave starts.
pub fn follow_mac_key(mnt: &Path, current: MacKeySource, set: MacKeySet) -> Result<Followed> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let file = key_file(mnt);
    let write = |pw: &[u8]| -> Result<()> {
        let dir = file.parent().ok_or(Error::Invalid("bad key path"))?;
        std::fs::create_dir_all(dir)?;
        let tmp = file.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(pw)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &file)?;
        Ok(())
    };
    let stored = match std::fs::read(&file) {
        Ok(v) => Some(zeroize::Zeroizing::new(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    match (stored, current()) {
        (None, MacKey::Present(k)) => {
            write(&k)?;
            Ok(Followed::Saved)
        }
        (None, _) => Ok(Followed::Unreadable),
        (Some(s), MacKey::Present(k)) if *s == *k => Ok(Followed::Same),
        (Some(s), MacKey::Present(k)) => {
            let user_data = browser::profile_dir(mnt);
            backup_databases(&user_data, "pre-move")?;
            let stats = convert_user_data(
                &user_data,
                &ChromiumKey::from_password(&s),
                &ChromiumKey::from_password(&k),
            )?;
            write(&k)?;
            Ok(Followed::Converted(stats))
        }
        (Some(s), MacKey::Missing) => {
            set(&s)?;
            Ok(Followed::Installed)
        }
        (Some(_), MacKey::Unreadable) => Ok(Followed::Unreadable),
    }
}

/// Copy each Brave database to `<name>.<suffix>` (once) before rewriting it.
fn backup_databases(user_data: &Path, suffix: &str) -> Result<()> {
    for profile in profile_dirs(user_data) {
        for db in DATABASES {
            let path = profile.join(db);
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("db");
            let backup = path.with_file_name(format!("{name}.{suffix}"));
            if !backup.exists() {
                std::fs::copy(&path, &backup)?;
            }
        }
    }
    Ok(())
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// Re-encrypt every `v10` BLOB in one SQLite database. Runs in a single
/// transaction: either the whole database is converted or nothing changes.
pub fn convert_database(path: &Path, from: &ChromiumKey, to: &ChromiumKey) -> Result<Stats> {
    let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| Error::Format(format!("sqlite open: {e}")))?;
    let sql_err = |e: rusqlite::Error| Error::Format(format!("sqlite: {e}"));
    let tx = conn.transaction().map_err(sql_err)?;
    let mut stats = Stats {
        databases: 1,
        ..Stats::default()
    };
    let tables: Vec<String> = {
        let mut st = tx
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            )
            .map_err(sql_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sql_err)?;
        rows.filter_map(|r| r.ok()).collect()
    };
    for table in tables {
        let t = quote_ident(&table);
        // Tables WITHOUT ROWID can't be updated by rowid; Brave's encrypted
        // columns live in ordinary tables, so skipping those is safe.
        if tx
            .prepare(&format!("SELECT rowid FROM {t} LIMIT 1"))
            .is_err()
        {
            continue;
        }
        let columns: Vec<String> = {
            let mut st = tx
                .prepare(&format!("PRAGMA table_info({t})"))
                .map_err(sql_err)?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(sql_err)?;
            rows.filter_map(|r| r.ok()).collect()
        };
        for col in columns {
            let c = quote_ident(&col);
            let found: Vec<(i64, Vec<u8>)> = {
                let mut st = tx
                    .prepare(&format!(
                        "SELECT rowid, {c} FROM {t} WHERE typeof({c}) = 'blob' AND substr({c}, 1, 3) = X'763130'"
                    ))
                    .map_err(sql_err)?;
                let rows = st
                    .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
                    .map_err(sql_err)?;
                rows.filter_map(|r| r.ok()).collect()
            };
            for (rowid, blob) in found {
                match chromium::decrypt(from, &blob) {
                    Ok(pt) => {
                        let new = chromium::encrypt(to, &pt);
                        tx.execute(
                            &format!("UPDATE {t} SET {c} = ?1 WHERE rowid = ?2"),
                            rusqlite::params![new, rowid],
                        )
                        .map_err(sql_err)?;
                        stats.converted += 1;
                    }
                    Err(_) => stats.failed += 1,
                }
            }
        }
    }
    tx.commit().map_err(sql_err)?;
    // Fold the WAL back in so no old-key copies linger in -wal files.
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    Ok(stats)
}

/// Profile directories inside a Brave user-data dir: `Default`, `Profile N`
/// (and anything else that holds one of [`DATABASES`]).
pub fn profile_dirs(user_data: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(user_data) else {
        return vec![];
    };
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && DATABASES.iter().any(|d| p.join(d).is_file()))
        .collect();
    out.sort();
    out
}

/// Convert every profile of a Brave user-data dir from `from` to `to`.
pub fn convert_user_data(user_data: &Path, from: &ChromiumKey, to: &ChromiumKey) -> Result<Stats> {
    let mut total = Stats::default();
    for dir in profile_dirs(user_data) {
        for db in DATABASES {
            let p = dir.join(db);
            if p.is_file() {
                total += convert_database(&p, from, to)?;
            }
        }
    }
    Ok(total)
}

/// Convert the Brave profile(s) of a MOUNTED vault from this Mac's Keychain
/// key to the portable key. The vault's browser must not be running.
pub fn convert_mount(mnt: &Path) -> Result<Stats> {
    convert_mount_with(mnt, brave_keychain_key)
}

/// Brave 158 changed what `--use-mock-keychain` does: it writes a new value
/// format ("v11") and no longer reads the portable "v10" values, so a
/// portable vault looked logged out everywhere. This moves a vault back to
/// Brave's standard storage: every portable `v10` value is re-encrypted with
/// this Mac's "Brave Safe Storage" key, and the vault then runs without the
/// mock keychain. Each database is first copied to `<name>.pre-repair`
/// inside the vault. Values in the new format are left untouched.
pub fn unportable_mount(mnt: &Path, keychain_key: fn() -> Result<ChromiumKey>) -> Result<Stats> {
    let to = keychain_key()?;
    let user_data = browser::profile_dir(mnt);
    backup_databases(&user_data, "pre-repair")?;
    convert_user_data(&user_data, &ChromiumKey::mock(), &to)
}

/// [`convert_mount`] with an explicit source-key provider (see `Roots::brave_key`).
pub fn convert_mount_with(mnt: &Path, source_key: fn() -> Result<ChromiumKey>) -> Result<Stats> {
    let from = source_key()?;
    let to = ChromiumKey::mock();
    if from.same_as(&to) {
        return Ok(Stats::default());
    }
    convert_user_data(&browser::profile_dir(mnt), &from, &to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db(path: &Path, key: &ChromiumKey) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = Connection::open(path).unwrap();
        c.execute_batch(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB);
             CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
             INSERT INTO meta VALUES ('version', '24');",
        )
        .unwrap();
        for (i, v) in ["alpha", "beta", ""].iter().enumerate() {
            c.execute(
                "INSERT INTO cookies VALUES (?1, ?2, '', ?3)",
                rusqlite::params![
                    format!("site{i}.example"),
                    "sid",
                    chromium::encrypt(key, v.as_bytes())
                ],
            )
            .unwrap();
        }
        // A plain (unencrypted) blob and a non-v10 blob must be left alone.
        c.execute(
            "INSERT INTO cookies VALUES ('x', 'plain', 'v', X'00010203')",
            [],
        )
        .unwrap();
    }

    fn values(path: &Path) -> Vec<Vec<u8>> {
        let c = Connection::open(path).unwrap();
        let mut st = c
            .prepare("SELECT encrypted_value FROM cookies ORDER BY rowid")
            .unwrap();
        let rows = st.query_map([], |r| r.get::<_, Vec<u8>>(0)).unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    fn test_mac_key() -> Result<ChromiumKey> {
        Ok(ChromiumKey::from_password(b"this-mac"))
    }

    use std::sync::Mutex;
    static KEYCHAIN: Mutex<Option<Vec<u8>>> = Mutex::new(None);
    fn fake_get() -> MacKey {
        match KEYCHAIN.lock().unwrap().clone() {
            Some(v) => MacKey::Present(zeroize::Zeroizing::new(v)),
            None => MacKey::Missing,
        }
    }
    fn fake_set(pw: &[u8]) -> Result<()> {
        *KEYCHAIN.lock().unwrap() = Some(pw.to_vec());
        Ok(())
    }

    #[test]
    fn logins_follow_the_mac_that_opens_the_vault() {
        let d = tempfile::tempdir().unwrap();
        let mnt = d.path();
        let db = browser::profile_dir(mnt).join("Default/Network/Cookies");
        let mac_a = ChromiumKey::from_password(b"mac-a");
        make_db(&db, &mac_a);

        // Mac A, first unlock: its key is recorded; again: nothing to do.
        *KEYCHAIN.lock().unwrap() = Some(b"mac-a".to_vec());
        assert_eq!(
            follow_mac_key(mnt, fake_get, fake_set).unwrap(),
            Followed::Saved
        );
        assert_eq!(
            follow_mac_key(mnt, fake_get, fake_set).unwrap(),
            Followed::Same
        );
        assert_eq!(std::fs::read(key_file(mnt)).unwrap(), b"mac-a");

        // Mac B with its own Brave key: logins move to it.
        *KEYCHAIN.lock().unwrap() = Some(b"mac-b".to_vec());
        match follow_mac_key(mnt, fake_get, fake_set).unwrap() {
            Followed::Converted(st) => assert_eq!(st.converted, 3),
            other => panic!("{other:?}"),
        }
        let v = values(&db);
        let mac_b = ChromiumKey::from_password(b"mac-b");
        assert_eq!(&*chromium::decrypt(&mac_b, &v[0]).unwrap(), b"alpha");
        assert!(db.with_file_name("Cookies.pre-move").is_file());
        assert_eq!(std::fs::read(key_file(mnt)).unwrap(), b"mac-b");

        // Mac C where Brave never ran: it gets the vault's key as is.
        *KEYCHAIN.lock().unwrap() = None;
        assert_eq!(
            follow_mac_key(mnt, fake_get, fake_set).unwrap(),
            Followed::Installed
        );
        assert_eq!(KEYCHAIN.lock().unwrap().as_deref(), Some(&b"mac-b"[..]));
        assert_eq!(
            &*chromium::decrypt(&mac_b, &values(&db)[0]).unwrap(),
            b"alpha"
        );
    }

    #[test]
    fn repair_moves_portable_values_to_the_keychain_key() {
        let d = tempfile::tempdir().unwrap();
        let mnt = d.path();
        let db = browser::profile_dir(mnt).join("Default/Network/Cookies");
        make_db(&db, &ChromiumKey::mock());
        let stats = unportable_mount(mnt, test_mac_key).unwrap();
        assert_eq!(stats.converted, 3);
        let mac = test_mac_key().unwrap();
        let v = values(&db);
        assert_eq!(&*chromium::decrypt(&mac, &v[0]).unwrap(), b"alpha");
        assert!(chromium::decrypt(&ChromiumKey::mock(), &v[0]).is_err());
        // A copy of the database as it was stays in the vault.
        let backup = db.with_file_name("Cookies.pre-repair");
        assert_eq!(
            &*chromium::decrypt(&ChromiumKey::mock(), &values(&backup)[0]).unwrap(),
            b"alpha"
        );
        // Running it again changes nothing and keeps the first backup.
        let again = unportable_mount(mnt, test_mac_key).unwrap();
        assert_eq!(again.converted, 0);
        assert!(chromium::decrypt(&ChromiumKey::mock(), &values(&backup)[0]).is_ok());
    }

    #[test]
    fn converts_every_profile_database() {
        let d = tempfile::tempdir().unwrap();
        let mac = ChromiumKey::from_password(b"this-mac-keychain-secret");
        let portable = ChromiumKey::mock();
        for prof in ["Default", "Profile 1"] {
            make_db(&d.path().join(prof).join("Network/Cookies"), &mac);
            make_db(&d.path().join(prof).join("Login Data"), &mac);
        }
        // A non-profile dir is ignored.
        std::fs::create_dir_all(d.path().join("Crashpad")).unwrap();

        let s = convert_user_data(d.path(), &mac, &portable).unwrap();
        assert_eq!(s.databases, 4);
        assert_eq!(s.converted, 12);
        assert_eq!(s.failed, 0);

        let v = values(&d.path().join("Profile 1/Network/Cookies"));
        assert_eq!(&*chromium::decrypt(&portable, &v[0]).unwrap(), b"alpha");
        assert_eq!(&*chromium::decrypt(&portable, &v[1]).unwrap(), b"beta");
        assert_eq!(&*chromium::decrypt(&portable, &v[2]).unwrap(), b"");
        assert_eq!(v[3], vec![0, 1, 2, 3]);

        // Converting twice is prevented by the vault's `portable_keys` flag
        // (a wrong key passes the padding check ~1/256 of the time and would
        // turn a value into garbage), so it is not exercised here.
    }

    #[test]
    fn wrong_source_key_changes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let mac = ChromiumKey::from_password(b"real");
        make_db(&d.path().join("Default/Login Data"), &mac);
        let before = values(&d.path().join("Default/Login Data"));
        let s = convert_user_data(
            d.path(),
            &ChromiumKey::from_password(b"wrong"),
            &ChromiumKey::mock(),
        )
        .unwrap();
        // Each value either fails (left untouched) or, rarely, passes the
        // padding check by chance; the count adds up either way.
        assert_eq!(s.converted + s.failed, 3);
        let after = values(&d.path().join("Default/Login Data"));
        assert_eq!(after[3], before[3], "non-v10 blob untouched");
    }
}
