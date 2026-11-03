//! On-disk layout and vault lifecycle: create → unlock (mount) → launch → lock.
//!
//! ```text
//! ~/Library/Application Support/BrowserVault/
//!   vaults/<vault-id>/image.sparsebundle
//!   vaults/<vault-id>/header.json (+ .bak)
//!   mnt/<vault-id>/            (700, mountpoint while unlocked)
//!   run/<vault-id>.pid         (PID of the vault's browser while it runs)
//! ```

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Child;

use crate::browser::{self, Browser};
use crate::error::{Error, Result};
use crate::hdiutil;
use crate::header::Header;
use crate::keyslot::{self, KdfCost, UnlockedKey};

pub const DEFAULT_SIZE_GB: u32 = 20;
/// Overrides the base directory (tests / debugging). Holds a path, never a secret.
pub const HOME_ENV: &str = "BVAULT_HOME";

pub struct Store {
    root: PathBuf,
}

/// Credential presented to unlock a vault. M3/M4 add TOTP and FIDO2 variants.
pub enum Credential<'a> {
    Password(&'a str),
    Recovery(&'a str),
}

pub struct Created {
    pub header: Header,
    pub recovery_phrase: zeroize::Zeroizing<String>,
}

pub struct Unlocked {
    pub header: Header,
    pub mountpoint: PathBuf,
    /// SPEC §8: false → warn the user the header was modified.
    pub header_intact: bool,
    /// Held for header updates while unlocked; wiped on drop (lock).
    pub key: UnlockedKey,
}

fn mkdir_700(p: &Path) -> Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn check_id(id: &str) -> Result<()> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| Error::NotFound)
}

impl Store {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    /// `$BVAULT_HOME`, else `~/Library/Application Support/BrowserVault`.
    pub fn default_location() -> Result<Self> {
        if let Some(p) = std::env::var_os(HOME_ENV) {
            return Ok(Store::new(p));
        }
        let home = std::env::var_os("HOME").ok_or(Error::Invalid("HOME is not set"))?;
        Ok(Store::new(
            PathBuf::from(home).join("Library/Application Support/BrowserVault"),
        ))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn vaults_dir(&self) -> PathBuf {
        self.root.join("vaults")
    }

    pub fn vault_dir(&self, id: &str) -> PathBuf {
        self.vaults_dir().join(id)
    }

    pub fn image_path(&self, id: &str) -> PathBuf {
        self.vault_dir(id).join("image.sparsebundle")
    }

    pub fn mountpoint(&self, id: &str) -> PathBuf {
        self.root.join("mnt").join(id)
    }

    fn pid_path(&self, id: &str) -> PathBuf {
        self.root.join("run").join(format!("{id}.pid"))
    }

    pub fn load(&self, id: &str) -> Result<Header> {
        check_id(id)?;
        let h = Header::load(&self.vault_dir(id))?;
        if h.vault_id != id {
            return Err(Error::Format(
                "vault_id does not match its directory".into(),
            ));
        }
        Ok(h)
    }

    pub fn list(&self) -> Result<Vec<Header>> {
        let dir = self.vaults_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = vec![];
        for e in entries {
            let name = e?.file_name();
            if let Some(id) = name.to_str() {
                if let Ok(h) = self.load(id) {
                    out.push(h);
                }
            }
        }
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
        Ok(out)
    }

    /// Find a vault by exact id, or by unique case-insensitive name.
    pub fn resolve(&self, id_or_name: &str) -> Result<Header> {
        if let Ok(h) = self.load(id_or_name) {
            return Ok(h);
        }
        let wanted = id_or_name.trim().to_lowercase();
        let mut hits: Vec<Header> = self
            .list()?
            .into_iter()
            .filter(|h| h.name.to_lowercase() == wanted)
            .collect();
        match hits.len() {
            1 => Ok(hits.remove(0)),
            0 => Err(Error::NotFound),
            _ => Err(Error::Invalid("several vaults have that name; use the id")),
        }
    }

    pub fn save_header(&self, header: &Header) -> Result<()> {
        check_id(&header.vault_id)?;
        header.save(&self.vault_dir(&header.vault_id))
    }

    /// Create the header and the encrypted sparsebundle. The recovery phrase is
    /// returned once and never stored.
    pub fn create(
        &self,
        name: &str,
        browser: Browser,
        password: &str,
        size_gb: u32,
        cost: KdfCost,
    ) -> Result<Created> {
        if browser == Browser::Firefox {
            return Err(Error::Unsupported("Firefox vaults arrive in milestone M5"));
        }
        let nv = keyslot::new_vault(name, browser, password, cost)?;
        let id = nv.header.vault_id.clone();
        mkdir_700(&self.root)?;
        mkdir_700(&self.vaults_dir())?;
        let dir = self.vault_dir(&id);
        mkdir_700(&dir)?;

        let result = (|| {
            hdiutil::create(&self.image_path(&id), size_gb, &id, &nv.key.disk_key_hex())?;
            self.save_header(&nv.header)
        })();
        if let Err(e) = result {
            let _ = fs::remove_dir_all(&dir);
            return Err(e);
        }
        Ok(Created {
            header: nv.header,
            recovery_phrase: nv.recovery_phrase,
        })
    }

    pub fn is_unlocked(&self, id: &str) -> bool {
        hdiutil::is_mounted(&self.mountpoint(id))
    }

    /// Derive the VMK and attach the image at `mnt/<id>`.
    pub fn unlock(&self, id: &str, cred: Credential<'_>) -> Result<Unlocked> {
        let header = self.load(id)?;
        let key = match cred {
            Credential::Password(p) => keyslot::unlock_with_password(&header, p)?,
            Credential::Recovery(p) => keyslot::unlock_with_recovery(&header, p)?,
        };
        let mnt = self.mountpoint(id);
        if !hdiutil::is_mounted(&mnt) {
            mkdir_700(&self.root.join("mnt"))?;
            mkdir_700(&mnt)?;
            hdiutil::attach(&self.image_path(id), &mnt, &key.disk_key_hex())?;
            // Best effort: indexing off is a hardening step, not a blocker.
            let _ = hdiutil::disable_spotlight(&mnt);
        }
        mkdir_700(&browser::profile_dir(&mnt))?;
        mkdir_700(&browser::cache_dir(&mnt))?;
        Ok(Unlocked {
            header_intact: key.header_intact,
            header,
            mountpoint: mnt,
            key,
        })
    }

    /// Launch the vault's browser against the mounted volume and record its PID.
    pub fn launch(&self, unlocked: &Unlocked, binary: Option<&Path>) -> Result<Child> {
        let browser = unlocked.header.browser;
        let bin = match binary {
            Some(b) => b.to_path_buf(),
            None => browser::detect(browser).ok_or(Error::BrowserMissing)?,
        };
        let child = browser::launch(browser, &bin, &unlocked.mountpoint)?;
        mkdir_700(&self.root.join("run"))?;
        fs::write(
            self.pid_path(&unlocked.header.vault_id),
            child.id().to_string(),
        )?;
        Ok(child)
    }

    pub fn browser_pid(&self, id: &str) -> Option<i32> {
        fs::read_to_string(self.pid_path(id))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// SPEC §6: stop the browser (SIGTERM → 8 s → SIGKILL), detach (force, 3
    /// tries). Idempotent. Keys are wiped when the caller drops its `Unlocked`.
    pub fn lock(&self, id: &str) -> Result<()> {
        check_id(id)?;
        if let Some(pid) = self.browser_pid(id) {
            browser::terminate(pid, browser::TERMINATE_GRACE);
            let _ = fs::remove_file(self.pid_path(id));
        }
        hdiutil::detach_with_retries(&self.mountpoint(id))
    }

    pub fn lock_all(&self) -> Result<()> {
        let mut first_err = None;
        for h in self.list()? {
            if let Err(e) = self.lock(&h.vault_id) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyslot::new_vault;

    const PW: &str = "correct horse battery";

    fn store_with_vault(name: &str) -> (tempfile::TempDir, Store, Header) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path());
        let nv = new_vault(name, Browser::Brave, PW, KdfCost::FAST).unwrap();
        mkdir_700(&s.vault_dir(&nv.header.vault_id)).unwrap();
        s.save_header(&nv.header).unwrap();
        (d, s, nv.header)
    }

    #[test]
    fn list_load_resolve() {
        let (_d, s, h) = store_with_vault("Work");
        assert_eq!(s.list().unwrap().len(), 1);
        assert_eq!(s.load(&h.vault_id).unwrap(), h);
        assert_eq!(s.resolve("work").unwrap().vault_id, h.vault_id);
        assert_eq!(s.resolve(&h.vault_id).unwrap().vault_id, h.vault_id);
        assert!(matches!(s.resolve("nope"), Err(Error::NotFound)));
    }

    #[test]
    fn ambiguous_name_needs_id() {
        let (_d, s, _h) = store_with_vault("Work");
        let nv = new_vault("work", Browser::Brave, PW, KdfCost::FAST).unwrap();
        mkdir_700(&s.vault_dir(&nv.header.vault_id)).unwrap();
        s.save_header(&nv.header).unwrap();
        assert!(matches!(s.resolve("WORK"), Err(Error::Invalid(_))));
    }

    #[test]
    fn rejects_path_traversal_ids() {
        let (_d, s, _h) = store_with_vault("Work");
        assert!(matches!(s.load("../../etc"), Err(Error::NotFound)));
        assert!(s.lock("../x").is_err());
    }

    #[test]
    fn header_in_wrong_directory_is_rejected() {
        let (_d, s, h) = store_with_vault("Work");
        let other = "11111111-1111-4111-8111-111111111111";
        mkdir_700(&s.vault_dir(other)).unwrap();
        h.save(&s.vault_dir(other)).unwrap();
        assert!(matches!(s.load(other), Err(Error::Format(_))));
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn wrong_password_fails_before_touching_disk() {
        let (_d, s, h) = store_with_vault("Work");
        let r = s.unlock(&h.vault_id, Credential::Password("wrong password!!"));
        assert!(matches!(r, Err(Error::UnlockFailed)));
        assert!(!s.mountpoint(&h.vault_id).exists());
    }

    #[test]
    fn create_rejects_firefox_until_m5() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path());
        assert!(matches!(
            s.create("F", Browser::Firefox, PW, 1, KdfCost::FAST),
            Err(Error::Unsupported(_))
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn failed_create_leaves_no_vault_behind() {
        // Off macOS there is no hdiutil, so create must fail and clean up.
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path());
        assert!(s.create("W", Browser::Brave, PW, 1, KdfCost::FAST).is_err());
        assert!(s.list().unwrap().is_empty());
        assert_eq!(fs::read_dir(s.vaults_dir()).unwrap().count(), 0);
    }

    #[test]
    fn lock_is_idempotent_when_not_mounted() {
        let (_d, s, h) = store_with_vault("Work");
        s.lock(&h.vault_id).unwrap();
        s.lock_all().unwrap();
    }

    #[test]
    fn dirs_are_private() {
        let (_d, s, h) = store_with_vault("Work");
        for p in [s.vaults_dir(), s.vault_dir(&h.vault_id)] {
            let mode = fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", p.display());
        }
    }
}
