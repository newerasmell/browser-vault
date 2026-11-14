//! Records macOS keeps about this app that say nothing about vault
//! contents but show it was downloaded or that a vault's own app copy ran.
//! Everything here is best effort and never fails an operation.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// LaunchServices' download record (`com.apple.quarantine` events):
/// URL, referrer and time of every quarantined download.
fn quarantine_db(home: &Path) -> PathBuf {
    home.join("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
}

/// URL fragment of this app's downloads (repository and build artifacts).
const DOWNLOAD_MARK: &str = "browser-vault";

/// Remove this app's download records (DMG / artifact zip) from the
/// quarantine events database. Other downloads are untouched.
pub fn scrub_download_records() {
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    match scrub_download_records_in(&quarantine_db(Path::new(&home))) {
        Ok(0) => {}
        Ok(n) => crate::trace::emit(&format!("download records removed: {n}")),
        Err(e) => crate::trace::emit(&format!("download records not cleaned: {e}")),
    }
}

fn scrub_download_records_in(db: &Path) -> rusqlite::Result<usize> {
    if !db.is_file() {
        return Ok(0);
    }
    let c = rusqlite::Connection::open(db)?;
    c.busy_timeout(std::time::Duration::from_secs(2))?;
    let like = format!("%{DOWNLOAD_MARK}%");
    c.execute(
        "DELETE FROM LSQuarantineEvent WHERE \
         LSQuarantineDataURLString LIKE ?1 OR LSQuarantineOriginURLString LIKE ?1",
        [like],
    )
}

const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/\
LaunchServices.framework/Support/lsregister";

/// Drop LaunchServices' registration of each `.app` directly in `dir`
/// (a vault's own app copies, or bundles about to be trashed), so its
/// database does not keep their paths.
pub fn unregister_apps_in(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for app in entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
    {
        unregister_app(&app);
    }
}

pub fn unregister_app(app: &Path) {
    if !Path::new(LSREGISTER).is_file() {
        return;
    }
    let _ = Command::new(LSREGISTER)
        .arg("-u")
        .arg(app)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_this_apps_download_records() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("q.db");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, \
             LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT);
             INSERT INTO LSQuarantineEvent VALUES ('1', 'https://x/blob/a.zip', \
             'https://github.com/someone/browser-vault/actions/runs/1');
             INSERT INTO LSQuarantineEvent VALUES ('2', 'https://brave.com/x.dmg', NULL);
             INSERT INTO LSQuarantineEvent VALUES ('3', 'https://h/browser-vault.dmg', NULL);",
        )
        .unwrap();
        drop(c);
        assert_eq!(scrub_download_records_in(&db).unwrap(), 2);
        let c = rusqlite::Connection::open(&db).unwrap();
        let left: Vec<String> = c
            .prepare("SELECT LSQuarantineEventIdentifier FROM LSQuarantineEvent")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(left, ["2"]);
        // No database: nothing to do.
        assert_eq!(
            scrub_download_records_in(&d.path().join("none")).unwrap(),
            0
        );
    }
}
