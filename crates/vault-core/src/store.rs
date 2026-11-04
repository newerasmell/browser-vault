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
use crate::events::{CreateStage, Event, Notify};
use crate::fido2::Authenticator;
use crate::hdiutil;
use crate::header::{Header, VaultSettings};
use crate::keyslot::{self, Draft, UnlockedKey};
use crate::profiles::{self, PasswordVerifier, Roots};
use crate::se::SecureEnclave;

pub const DEFAULT_SIZE_GB: u32 = 20;
/// The action needs the vault closed (its volume is mounted right now).
pub const ERR_LOCK_FIRST: &str = "lock the vault first";
/// Overrides the base directory (tests / debugging). Holds a path, never a secret.
pub const HOME_ENV: &str = "BVAULT_HOME";

pub struct Store {
    root: PathBuf,
}

/// Credential presented to unlock a vault.
pub enum Credential<'a> {
    /// Password + 6-digit code from the authenticator app (SPEC §4.1).
    Totp { password: &'a str, code: &'a str },
    /// Password + YubiKey PIN (+ touch) (SPEC §4.2).
    Fido2 { password: &'a str, pin: &'a str },
    /// The 24-word recovery phrase alone.
    Recovery(&'a str),
    /// TEST ONLY: temporary password-only slot.
    #[cfg(any(test, feature = "test-password-slot"))]
    Password(&'a str),
}

/// Hardware backends used for unlocking. Tests pass mocks.
pub struct Devices<'a> {
    pub se: &'a dyn SecureEnclave,
    pub fido: &'a dyn Authenticator,
    pub notify: Notify<'a>,
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub struct Unlocked {
    pub header: Header,
    pub mountpoint: PathBuf,
    /// SPEC §8: false → warn the user the header was modified.
    pub header_intact: bool,
    /// Held for header updates while unlocked; wiped on drop (lock).
    pub key: UnlockedKey,
    /// In-memory password proof for `profiles::cleanup_original`; only set
    /// when the header records an imported original and the credential had
    /// a password. Wiped on drop.
    pub(crate) cleanup_verifier: Option<PasswordVerifier>,
}

/// Extra choices for [`Store::create_with`] (wizard options).
#[derive(Default)]
pub struct CreateOptions {
    /// Firefox only: `identity.fxaccounts.enabled = false` in user.js.
    pub disable_fxa: bool,
    /// SPEC §5.1: copy this regular profile into the new vault.
    pub import: Option<ImportRequest>,
}

pub struct ImportRequest {
    pub roots: Roots,
    pub profile_id: String,
}

pub struct Created {
    pub header: Header,
    /// The vault was created, but the import was refused (browser running,
    /// verification mismatch …); the vault is empty and usable.
    pub import_error: Option<Error>,
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

    /// Finish a [`Draft`]: build the sealed header, create the encrypted
    /// sparsebundle and save the header. On failure nothing is left behind.
    pub fn create(
        &self,
        draft: Draft,
        size_gb: u32,
        settings: VaultSettings,
        notify: Notify<'_>,
    ) -> Result<Header> {
        self.create_with(draft, size_gb, settings, &CreateOptions::default(), notify)
            .map(|c| c.header)
    }

    /// [`Store::create`] plus wizard options. Firefox vaults and imports
    /// mount the new image once to write `user.js` / copy the profile.
    pub fn create_with(
        &self,
        draft: Draft,
        size_gb: u32,
        settings: VaultSettings,
        opts: &CreateOptions,
        notify: Notify<'_>,
    ) -> Result<Created> {
        notify(Event::CreateProgress {
            stage: CreateStage::Keys,
            pct: 10,
        });
        let mut settings = settings;
        // Fresh Brave vaults start portable (logins work on any Mac). An
        // imported profile becomes portable only if its logins can be
        // converted below.
        settings.portable_keys = draft.browser() == Browser::Brave && opts.import.is_none();
        let nv = draft.finish(settings)?;
        let id = nv.header.vault_id.clone();
        mkdir_700(&self.root)?;
        mkdir_700(&self.vaults_dir())?;
        let dir = self.vault_dir(&id);
        mkdir_700(&dir)?;

        let result = (|| {
            notify(Event::CreateProgress {
                stage: CreateStage::Disk,
                pct: 30,
            });
            hdiutil::create(&self.image_path(&id), size_gb, &id, &nv.key.disk_key_hex())?;
            self.save_header(&nv.header)?;
            notify(Event::CreateProgress {
                stage: CreateStage::Profile,
                pct: 80,
            });
            if nv.header.browser == Browser::Firefox || opts.import.is_some() {
                self.init_profile(&nv.header, &nv.key, opts, notify)
            } else {
                Ok(None)
            }
        })();
        let import_result = match result {
            Ok(r) => r,
            Err(e) => {
                let _ = hdiutil::detach_with_retries(&self.mountpoint(&id));
                let _ = fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let mut header = nv.header;
        let import_error = match import_result {
            None => None,
            Some(Ok((original, portable))) => {
                header.original = Some(original);
                header.settings.portable_keys = portable;
                header.seal_mac(nv.key.vmk())?;
                self.save_header(&header)?;
                None
            }
            Some(Err(e)) => Some(e),
        };
        notify(Event::CreateProgress {
            stage: CreateStage::Done,
            pct: 100,
        });
        Ok(Created {
            header,
            import_error,
        })
    }

    /// Mount the new image, import (if asked) and write Firefox's user.js,
    /// then detach. Returns the import outcome.
    fn init_profile(
        &self,
        header: &Header,
        key: &UnlockedKey,
        opts: &CreateOptions,
        notify: Notify<'_>,
    ) -> Result<Option<Result<(crate::header::Original, bool)>>> {
        let id = &header.vault_id;
        let mnt = self.mountpoint(id);
        mkdir_700(&self.root.join("mnt"))?;
        mkdir_700(&mnt)?;
        hdiutil::attach(&self.image_path(id), &mnt, &key.disk_key_hex())?;
        let _ = hdiutil::disable_spotlight(&mnt);
        let r = (|| -> Result<_> {
            mkdir_700(&browser::profile_dir(&mnt))?;
            mkdir_700(&browser::cache_dir(&mnt))?;
            let imported = opts.import.as_ref().map(|req| {
                profiles::import_profile(&req.roots, header.browser, &req.profile_id, &mnt, notify)
                    .map(|original| {
                        // Re-encrypt the COPY's logins for other Macs. If the
                        // Keychain can't be read (user clicked Deny), the
                        // vault stays tied to this Mac and still works here.
                        let portable = header.browser == Browser::Brave
                            && match crate::portable::convert_mount_with(&mnt, req.roots.brave_key)
                            {
                                Ok(st) => {
                                    crate::trace::emit(&format!(
                                        "portable: converted {} values ({} unreadable) in {} dbs",
                                        st.converted, st.failed, st.databases
                                    ));
                                    true
                                }
                                Err(e) => {
                                    crate::trace::emit(&format!("portable: skipped: {e}"));
                                    false
                                }
                            };
                        (original, portable)
                    })
            });
            // After the import, so our managed block wins over an imported user.js.
            if header.browser == Browser::Firefox {
                browser::write_firefox_user_js(&mnt, Some(opts.disable_fxa))?;
            }
            Ok(imported)
        })();
        let detached = hdiutil::detach_with_retries(&mnt);
        let imported = r?;
        detached?;
        Ok(imported)
    }

    /// Settings → "make logins portable" for an existing (locked) Brave
    /// vault: mount without launching, convert the profile copy from this
    /// Mac's Keychain key to the portable key, detach, set the flag.
    pub fn make_portable(&self, id: &str, key: &UnlockedKey) -> Result<crate::portable::Stats> {
        let mut header = self.load(id)?;
        if header.browser != Browser::Brave {
            return Err(Error::Invalid("only Brave vaults need this"));
        }
        if header.settings.portable_keys {
            return Ok(crate::portable::Stats::default());
        }
        if !header.verify_mac(key.vmk()) {
            return Err(Error::Invalid("header was modified outside the app"));
        }
        let mnt = self.mountpoint(id);
        if hdiutil::is_mounted(&mnt) {
            return Err(Error::Invalid(ERR_LOCK_FIRST));
        }
        mkdir_700(&self.root.join("mnt"))?;
        mkdir_700(&mnt)?;
        hdiutil::attach(&self.image_path(id), &mnt, &key.disk_key_hex())?;
        let r = crate::portable::convert_mount(&mnt);
        let detached = hdiutil::detach_with_retries(&mnt);
        let stats = r?;
        detached?;
        header.settings.portable_keys = true;
        header.seal_mac(key.vmk())?;
        self.save_header(&header)?;
        Ok(stats)
    }

    pub fn is_unlocked(&self, id: &str) -> bool {
        hdiutil::is_mounted(&self.mountpoint(id))
    }

    /// Derive the VMK and attach the image at `mnt/<id>`.
    pub fn unlock(&self, id: &str, cred: Credential<'_>, dev: &Devices<'_>) -> Result<Unlocked> {
        let mut header = self.load(id)?;
        let password: Option<&str> = match &cred {
            Credential::Totp { password, .. } | Credential::Fido2 { password, .. } => {
                Some(password)
            }
            Credential::Recovery(_) => None,
            #[cfg(any(test, feature = "test-password-slot"))]
            Credential::Password(p) => Some(p),
        };
        let key = match cred {
            Credential::Totp { password, code } => {
                let r = crate::totp::unlock(&mut header, password, code, dev.se, now_unix());
                // Counters (anti-replay, rate limit) change on success and failure.
                self.save_header(&header)?;
                r?
            }
            Credential::Fido2 { password, pin } => {
                crate::fido2::unlock(&header, dev.fido, password, pin, dev.notify)?
            }
            Credential::Recovery(p) => keyslot::unlock_with_recovery(&header, p)?,
            #[cfg(any(test, feature = "test-password-slot"))]
            Credential::Password(p) => keyslot::unlock_with_password(&header, p)?,
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
        if header.browser == Browser::Firefox {
            browser::write_firefox_user_js(&mnt, None)?;
        }
        // Only vaults with an original still on disk pay the extra Argon2id.
        let cleanup_verifier = match (&header.original, password) {
            (Some(o), Some(pw)) if o.state != crate::header::OriginalState::Deleted => {
                Some(PasswordVerifier::new(&header.kdf, key.vmk(), pw)?)
            }
            _ => None,
        };
        Ok(Unlocked {
            header_intact: key.header_intact,
            header,
            mountpoint: mnt,
            key,
            cleanup_verifier,
        })
    }

    /// Lock an unlocked session and, if this was the first close after an
    /// import, mark the copy as reviewed (SPEC §5.1 step 3). Keys are wiped
    /// when `session` drops at the end.
    pub fn close(&self, mut session: Unlocked) -> Result<()> {
        self.lock(&session.header.vault_id)?;
        profiles::mark_reviewed(self, &mut session)?;
        Ok(())
    }

    /// Launch the vault's browser against the mounted volume and record its PID.
    pub fn launch(&self, unlocked: &Unlocked, binary: Option<&Path>) -> Result<Child> {
        let browser = unlocked.header.browser;
        let bin = match binary {
            Some(b) => b.to_path_buf(),
            None => browser::detect(browser).ok_or(Error::BrowserMissing)?,
        };
        let child = browser::launch_with(
            browser,
            &bin,
            &unlocked.mountpoint,
            unlocked.header.settings.portable_keys,
        )?;
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
        crate::trace::emit(&format!("lock {id}: start"));
        if let Some(pid) = self.browser_pid(id) {
            crate::trace::emit(&format!("lock {id}: terminate pid {pid}"));
            let killed = browser::terminate(pid, browser::TERMINATE_GRACE);
            crate::trace::emit(&format!("lock {id}: browser stopped (forced: {killed})"));
            let _ = fs::remove_file(self.pid_path(id));
        }
        let r = hdiutil::detach_with_retries(&self.mountpoint(id));
        crate::trace::emit(&format!(
            "lock {id}: detach {}",
            if r.is_ok() { "ok" } else { "FAILED" }
        ));
        r
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
    use crate::keyslot::{new_vault, KdfCost};

    fn devs() -> Devices<'static> {
        Devices {
            se: Box::leak(crate::se::system()),
            fido: Box::leak(crate::fido2::system()),
            notify: &crate::events::ignore,
        }
    }

    const PW: &str = "correct horse battery";

    fn store_with_vault(name: &str) -> (tempfile::TempDir, Store, Header) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path());
        let nv = new_vault(name, Browser::Brave, PW, KdfCost::FAST)
            .unwrap()
            .0;
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
        let nv = new_vault("work", Browser::Brave, PW, KdfCost::FAST)
            .unwrap()
            .0;
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
        let r = s.unlock(
            &h.vault_id,
            Credential::Password("wrong password!!"),
            &devs(),
        );
        assert!(matches!(r, Err(Error::UnlockFailed)));
        assert!(!s.mountpoint(&h.vault_id).exists());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn failed_create_leaves_no_vault_behind() {
        // Off macOS there is no hdiutil, so create must fail and clean up.
        // Firefox is no longer rejected up front (M5).
        for b in [Browser::Brave, Browser::Firefox] {
            let d = tempfile::tempdir().unwrap();
            let s = Store::new(d.path());
            let mut d = Draft::new("W", b, KdfCost::FAST).unwrap();
            d.set_password(PW).unwrap();
            d.add_password_only_slot().unwrap();
            d.generate_recovery().unwrap();
            let r = s.create(d, 1, VaultSettings::default(), &crate::events::ignore);
            assert!(matches!(r, Err(Error::Command { .. })));
            assert!(s.list().unwrap().is_empty());
            assert_eq!(fs::read_dir(s.vaults_dir()).unwrap().count(), 0);
        }
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
