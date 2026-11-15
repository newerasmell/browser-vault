//! On-disk layout and vault lifecycle: create → unlock (mount) → launch → lock.
//!
//! ```text
//! ~/Library/Application Support/BrowserVault/
//!   vaults/<vault-id>/image.sparsebundle
//!   vaults/<vault-id>/header.json (+ .bak)
//!   index.bin                  (this Mac's encrypted name index, see `index`)
//!   mnt/<vault-id>/            (700, mountpoint while unlocked)
//!   run/<vault-id>.pid         (PID of the vault's browser while it runs)
//! ```

use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::browser::{self, Browser};
use crate::error::{Error, Result};
use crate::events::{CreateStage, Event, Notify};
use crate::fido2::Authenticator;
use crate::hdiutil;
use crate::header::{Header, VaultSettings};
use crate::index::{self, KeyProvider};
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
    /// Key for the local name index (`index.bin`); see [`Store::with_index_key`].
    index_key: KeyProvider,
}

/// A vault in [`Store::list_labeled`]: its header plus what this Mac knows
/// about it before unlocking (`None` = "Locked vault").
pub struct Listed {
    pub header: Header,
    pub label: Option<index::Entry>,
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
    /// A store at `root`. The name index uses [`index::default_provider`]
    /// (login Keychain in macOS builds, nothing in tests / elsewhere).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Store {
            root: root.into(),
            index_key: index::default_provider(),
        }
    }

    /// Use another index key provider (tests: [`index::no_key`],
    /// `index::memory_key`).
    pub fn with_index_key(mut self, provider: KeyProvider) -> Self {
        self.index_key = provider;
        self
    }

    /// `$BVAULT_HOME`, else `~/Library/Application Support/<name>`, where
    /// `<name>` is the running bundle's `BVStoreName` (a disguised copy,
    /// see `identity`) or `BrowserVault`.
    pub fn default_location() -> Result<Self> {
        if let Some(p) = std::env::var_os(HOME_ENV) {
            return Ok(Store::new(p));
        }
        let home = std::env::var_os("HOME").ok_or(Error::Invalid("HOME is not set"))?;
        Ok(Store::new(crate::identity::data_dir(
            Path::new(&home),
            &crate::identity::store_name(),
        )))
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

    /// Every vault, ordered by creation date then name (as far as known:
    /// locked vaults without an index entry come last, by id).
    pub fn list(&self) -> Result<Vec<Header>> {
        Ok(self.list_labeled()?.into_iter().map(|l| l.header).collect())
    }

    /// [`Store::list`] with each vault's display label: the decrypted (or
    /// v1 plain) metadata if the header has it, else this Mac's index entry.
    pub fn list_labeled(&self) -> Result<Vec<Listed>> {
        let index = index::read(&self.root, self.index_key);
        let mut out: Vec<Listed> = self
            .list_headers()?
            .into_iter()
            .map(|h| {
                let label = match h.try_meta() {
                    Some(m) => Some(index::Entry::from_meta(m)),
                    None => index.get(&h.vault_id).cloned(),
                };
                Listed { header: h, label }
            })
            .collect();
        out.sort_by(|a, b| {
            let key = |l: &Listed| match &l.label {
                Some(e) => (0, e.created_at.clone(), e.name.clone()),
                None => (1, String::new(), String::new()),
            };
            key(a)
                .cmp(&key(b))
                .then_with(|| a.header.vault_id.cmp(&b.header.vault_id))
        });
        Ok(out)
    }

    /// The display label of one vault (see [`Store::list_labeled`]).
    pub fn label(&self, h: &Header) -> Option<index::Entry> {
        match h.try_meta() {
            Some(m) => Some(index::Entry::from_meta(m)),
            None => index::read(&self.root, self.index_key).remove(&h.vault_id),
        }
    }

    /// Best effort: remember `h`'s label on this Mac (needs open metadata).
    pub fn index_put(&self, h: &Header) {
        if let Some(m) = h.try_meta() {
            if let Err(e) = index::put(
                &self.root,
                self.index_key,
                &h.vault_id,
                index::Entry::from_meta(m),
            ) {
                crate::trace::emit(&format!("index: not updated: {e}"));
            }
        }
    }

    /// Best effort: forget `id` in this Mac's index (vault deleted).
    pub fn index_remove(&self, id: &str) {
        if let Err(e) = index::remove(&self.root, self.index_key, id) {
            crate::trace::emit(&format!("index: not updated: {e}"));
        }
    }

    /// Delete a vault's files (image, header) and its index entry. The
    /// caller makes sure it is locked and the user confirmed.
    pub fn remove_vault(&self, id: &str) -> Result<()> {
        check_id(id)?;
        fs::remove_dir_all(self.vault_dir(id))?;
        let _ = fs::remove_dir(self.mountpoint(id));
        self.index_remove(id);
        Ok(())
    }

    fn list_headers(&self) -> Result<Vec<Header>> {
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
        Ok(out)
    }

    /// Find a vault by exact id, or by unique case-insensitive name.
    pub fn resolve(&self, id_or_name: &str) -> Result<Header> {
        if let Ok(h) = self.load(id_or_name) {
            return Ok(h);
        }
        let wanted = id_or_name.trim().to_lowercase();
        let mut hits: Vec<Header> = self
            .list_labeled()?
            .into_iter()
            .filter(|l| {
                l.label
                    .as_ref()
                    .is_some_and(|e| e.name.to_lowercase() == wanted)
            })
            .map(|l| l.header)
            .collect();
        match hits.len() {
            1 => Ok(hits.remove(0)),
            0 => Err(Error::NotFound),
            _ => Err(Error::Invalid("several vaults have that name; use the id")),
        }
    }

    /// Save atomically (+ `.bak`). A header with known metadata also
    /// refreshes this Mac's index entry.
    pub fn save_header(&self, header: &Header) -> Result<()> {
        check_id(&header.vault_id)?;
        header.save(&self.vault_dir(&header.vault_id))?;
        self.index_put(header);
        Ok(())
    }

    /// [`Store::load`] with the v2 metadata decrypted under the vault's key.
    pub fn load_open(&self, id: &str, key: &UnlockedKey) -> Result<Header> {
        let mut h = self.load(id)?;
        h.open_meta(key.vmk())?;
        Ok(h)
    }

    /// Convert `id`'s header to v2 (encrypted metadata) if it is still v1,
    /// and refresh this Mac's index entry. Returns the header with its
    /// metadata open. Refuses a header whose MAC does not verify under
    /// `key` (re-sealing would bless the tampering). After the conversion
    /// `header.json.bak` is the v2 header too, so no plain copy of the
    /// metadata stays in the vault folder.
    pub fn upgrade_header(&self, id: &str, key: &UnlockedKey) -> Result<Header> {
        let mut h = self.load(id)?;
        if !h.verify_mac(key.vmk()) {
            return Err(Error::Invalid("header was modified outside the app"));
        }
        // v2 written before the YubiKey labels were sealed: re-seal so the
        // labels leave the file.
        let clear_labels = h.has_clear_labels();
        h.open_meta(key.vmk())?;
        if clear_labels {
            h.seal_mac(key.vmk())?;
        }
        if h.upgrade(key.vmk())? || clear_labels {
            let dir = self.vault_dir(id);
            h.save(&dir)?;
            // Second save: the .bak (the old v1 file) becomes v2 as well.
            h.save(&dir)?;
            crate::trace::emit(&format!("header {id}: upgraded"));
        }
        self.index_put(&h);
        Ok(h)
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
        let browser = draft.browser();
        // Fresh Brave vaults start portable (logins work on any Mac). An
        // imported profile becomes portable only if its logins can be
        // converted below.
        settings.portable_keys = browser.is_chromium() && opts.import.is_none();
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
            hdiutil::create(&self.image_path(&id), size_gb, &nv.key.disk_key_hex())?;
            self.save_header(&nv.header)?;
            notify(Event::CreateProgress {
                stage: CreateStage::Profile,
                pct: 80,
            });
            if browser == Browser::Firefox || opts.import.is_some() {
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
                let m = header.meta_mut()?;
                m.original = Some(original);
                m.settings.portable_keys = portable;
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
        let browser = header.meta()?.browser;
        let mnt = self.mountpoint(id);
        mkdir_700(&self.root.join("mnt"))?;
        mkdir_700(&mnt)?;
        hdiutil::attach(&self.image_path(id), &mnt, &key.disk_key_hex())?;
        let _ = hdiutil::disable_spotlight(&mnt);
        let _ = hdiutil::neutralize_volume_name(&mnt);
        let r = (|| -> Result<_> {
            mkdir_700(&browser::profile_dir(&mnt))?;
            mkdir_700(&browser::cache_dir(&mnt))?;
            let imported = opts.import.as_ref().map(|req| {
                // A VM must be down (suspended/shut down) while it is copied.
                let vm = if browser == Browser::Vm {
                    Some(vm_import_check(&req.roots, &req.profile_id)?)
                } else {
                    None
                };
                let r =
                    profiles::import_profile(&req.roots, browser, &req.profile_id, &mnt, notify)
                        .map(|original| {
                            // Re-encrypt the COPY's logins for other Macs. If the
                            // Keychain can't be read (user clicked Deny), the
                            // vault stays tied to this Mac and still works here.
                            let portable = browser == Browser::Brave
                                && match crate::portable::convert_mount_with(
                                    &mnt,
                                    req.roots.brave_key,
                                ) {
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
                        });
                // Moved, not copied: the original leaves Parallels' list so
                // the vault copy can be registered under the same UUID. Its
                // files stay until the user deletes the original.
                if let (Ok(_), Some((prlctl, uuid))) = (&r, vm) {
                    crate::vm::unregister(&prlctl, &uuid);
                    crate::trace::emit("vm: original unregistered after the copy");
                }
                r
            });
            // After the import, so our managed block wins over an imported user.js.
            if browser == Browser::Firefox {
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
        if !header.verify_mac(key.vmk()) {
            return Err(Error::Invalid("header was modified outside the app"));
        }
        header.open_meta(key.vmk())?;
        if header.meta()?.browser != Browser::Brave {
            return Err(Error::Invalid("only Brave vaults need this"));
        }
        if header.meta()?.settings.portable_keys {
            return Ok(crate::portable::Stats::default());
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
        header.upgrade(key.vmk())?;
        header.meta_mut()?.settings.portable_keys = true;
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
        // v1 → v2 now that the VMK is known (never for a tampered header).
        if key.header_intact {
            match self.upgrade_header(id, &key) {
                Ok(h) => header = h,
                Err(e) => crate::trace::emit(&format!("header {id}: not upgraded: {e}")),
            }
        }
        header.open_meta(key.vmk())?;
        self.index_put(&header);
        let browser = header.meta()?.browser;
        let mnt = self.mountpoint(id);
        if !hdiutil::is_mounted(&mnt) {
            mkdir_700(&self.root.join("mnt"))?;
            mkdir_700(&mnt)?;
            hdiutil::attach(&self.image_path(id), &mnt, &key.disk_key_hex())?;
            // Best effort: indexing off is a hardening step, not a blocker.
            let _ = hdiutil::disable_spotlight(&mnt);
            let _ = hdiutil::neutralize_volume_name(&mnt);
        }
        mkdir_700(&browser::profile_dir(&mnt))?;
        mkdir_700(&browser::cache_dir(&mnt))?;
        if browser == Browser::Firefox {
            browser::write_firefox_user_js(&mnt, None)?;
        }
        // Only vaults with an original still on disk pay the extra Argon2id.
        let cleanup_verifier = match (&header.meta()?.original, password) {
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
    pub fn launch(&self, unlocked: &Unlocked, binary: Option<&Path>) -> Result<browser::Launched> {
        let meta = unlocked.header.meta()?;
        let browser = meta.browser;
        if browser == Browser::Vm {
            return self.launch_vm(unlocked, binary);
        }
        // The vault's own copy of the app wins over the installed one.
        let bin = match (browser::vault_binary(browser, &unlocked.mountpoint), binary) {
            (Some(own), _) => own,
            (None, Some(b)) => b.to_path_buf(),
            (None, None) => browser::detect(browser).ok_or(Error::BrowserMissing)?,
        };
        let child = browser::launch_with(
            browser,
            &bin,
            &unlocked.mountpoint,
            meta.settings.portable_keys,
        )?;
        mkdir_700(&self.root.join("run"))?;
        fs::write(
            self.pid_path(&unlocked.header.vault_id),
            child.id().to_string(),
        )?;
        Ok(child)
    }

    fn vm_marker(&self, id: &str) -> PathBuf {
        self.root.join("run").join(format!("{id}.vm"))
    }

    /// An open VM vault whose VM is up: bring Parallels to the front and
    /// return `true` (nothing to start).
    pub fn focus_running_vm(&self, id: &str) -> bool {
        let Some((prlctl, uuid)) = fs::read_to_string(self.vm_marker(id))
            .ok()
            .and_then(|m| crate::vm::parse_marker(&m))
        else {
            return false;
        };
        if !crate::vm::status(&prlctl, &uuid).is_some_and(|s| crate::vm::is_active(&s)) {
            return false;
        }
        if let Some(app) = prlctl
            .ancestors()
            .find(|p| p.extension().is_some_and(|e| e == "app"))
        {
            let _ = std::process::Command::new("/usr/bin/open")
                .arg("-a")
                .arg(app)
                .status();
        }
        true
    }

    /// VM vault: register the bundle in the vault (keeping its UUID), start
    /// or resume it and show Parallels. The marker tells a later lock (or
    /// the crash guard's caller) how to suspend it.
    fn launch_vm(&self, unlocked: &Unlocked, binary: Option<&Path>) -> Result<browser::Launched> {
        let bin = match binary {
            Some(b) => b.to_path_buf(),
            None => browser::detect(Browser::Vm).ok_or(Error::BrowserMissing)?,
        };
        let app = bin
            .ancestors()
            .find(|p| p.extension().is_some_and(|e| e == "app"))
            .ok_or(Error::BrowserMissing)?;
        let prlctl = crate::vm::prlctl_for(app).ok_or(Error::BrowserMissing)?;
        let pvm = crate::vm::find_pvm(&unlocked.mountpoint)
            .ok_or(Error::Invalid("no virtual machine in this vault"))?;
        let uuid =
            crate::vm::vm_uuid(&pvm).ok_or(Error::Invalid("no virtual machine in this vault"))?;
        mkdir_700(&self.root.join("run"))?;
        fs::write(
            self.vm_marker(&unlocked.header.vault_id),
            crate::vm::marker_text(&prlctl, &uuid),
        )?;
        crate::vm::register(&prlctl, &pvm)?;
        crate::vm::start(&prlctl, &uuid)?;
        let _ = std::process::Command::new("/usr/bin/open")
            .arg("-a")
            .arg(app)
            .status();
        crate::trace::emit("vm: started");
        Ok(browser::Launched::Vm { prlctl, uuid })
    }

    /// Record a new browser PID for an open vault (the browser relaunched
    /// itself, e.g. Firefox after an update), so locking stops the right one.
    pub fn set_browser_pid(&self, id: &str, pid: i32) -> Result<()> {
        check_id(id)?;
        fs::write(self.pid_path(id), pid.to_string())?;
        Ok(())
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
        // A VM is suspended (memory into the vault), never killed; if that
        // fails the vault stays open rather than pulling the plug on it.
        if let Some((prlctl, uuid)) = fs::read_to_string(self.vm_marker(id))
            .ok()
            .and_then(|m| crate::vm::parse_marker(&m))
        {
            crate::trace::emit(&format!("lock {id}: suspending the VM"));
            crate::vm::suspend(&prlctl, &uuid)?;
            crate::vm::unregister(&prlctl, &uuid);
            let _ = fs::remove_file(self.vm_marker(id));
            crate::trace::emit(&format!("lock {id}: VM suspended and unregistered"));
        }
        if let Some(pid) = self.browser_pid(id) {
            crate::trace::emit(&format!("lock {id}: terminate pid {pid}"));
            let killed = browser::terminate(pid, browser::TERMINATE_GRACE);
            crate::trace::emit(&format!("lock {id}: browser stopped (forced: {killed})"));
            let _ = fs::remove_file(self.pid_path(id));
        }
        // The vault's own app copies leave LaunchServices' database before
        // their volume goes away.
        crate::traces::unregister_apps_in(&self.mountpoint(id).join("app"));
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

/// `(prlctl, uuid)` of the VM about to be imported, refusing while it runs.
fn vm_import_check(roots: &profiles::Roots, profile_id: &str) -> Result<(PathBuf, String)> {
    let app = browser::detect(Browser::Vm)
        .and_then(|b| {
            b.ancestors()
                .find(|p| p.extension().is_some_and(|e| e == "app"))
                .map(Path::to_path_buf)
        })
        .ok_or(Error::BrowserMissing)?;
    let prlctl = crate::vm::prlctl_for(&app).ok_or(Error::BrowserMissing)?;
    let uuid = crate::vm::vm_uuid(&profiles::vm_source(roots, profile_id)?)
        .ok_or(Error::Invalid("not a Parallels virtual machine"))?;
    if crate::vm::status(&prlctl, &uuid).is_some_and(|s| crate::vm::is_active(&s)) {
        return Err(Error::BrowserRunning);
    }
    Ok((prlctl, uuid))
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

    /// A store with this Mac's (in-memory) index key and one saved vault.
    fn store_with_vault(name: &str) -> (tempfile::TempDir, Store, Header) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path()).with_index_key(index::memory_key);
        let h = add_vault(&s, name).0;
        (d, s, h)
    }

    fn add_vault(s: &Store, name: &str) -> (Header, UnlockedKey) {
        let nv = new_vault(name, Browser::Brave, PW, KdfCost::FAST)
            .unwrap()
            .0;
        mkdir_700(&s.vault_dir(&nv.header.vault_id)).unwrap();
        s.save_header(&nv.header).unwrap();
        (nv.header, nv.key)
    }

    #[test]
    fn list_load_resolve() {
        let (_d, s, h) = store_with_vault("Work");
        assert_eq!(s.list().unwrap().len(), 1);
        let loaded = s.load(&h.vault_id).unwrap();
        assert!(loaded.meta_locked());
        assert_eq!(loaded.mac, h.mac);
        assert_eq!(loaded.slots, h.slots);
        assert_eq!(s.resolve("work").unwrap().vault_id, h.vault_id);
        assert_eq!(s.resolve(&h.vault_id).unwrap().vault_id, h.vault_id);
        assert!(matches!(s.resolve("nope"), Err(Error::NotFound)));
    }

    #[test]
    fn ambiguous_name_needs_id() {
        let (_d, s, _h) = store_with_vault("Work");
        add_vault(&s, "work");
        assert!(matches!(s.resolve("WORK"), Err(Error::Invalid(_))));
    }

    #[test]
    fn new_vault_header_on_disk_reveals_no_metadata() {
        let (_d, s, h) = store_with_vault("Very Secret Name");
        for f in ["header.json", "header.json.bak"] {
            let p = s.vault_dir(&h.vault_id).join(f);
            if !p.exists() {
                continue;
            }
            let text = fs::read_to_string(p).unwrap();
            for needle in ["Very Secret", "brave", "created_at", "settings", "202"] {
                assert!(!text.contains(needle), "{f}: {needle}");
            }
        }
    }

    #[test]
    fn labels_come_from_the_local_index() {
        let (_d, s, h) = store_with_vault("Work");
        let (h2, k2) = add_vault(&s, "Private");
        let listed = s.list_labeled().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|l| l.header.meta_locked()));
        let names: Vec<_> = listed
            .iter()
            .map(|l| l.label.as_ref().unwrap().name.as_str())
            .collect();
        assert!(names.contains(&"Work") && names.contains(&"Private"));
        assert_eq!(
            s.label(&s.load(&h.vault_id).unwrap()).unwrap().browser,
            Browser::Brave
        );

        // The same store seen without the key (another Mac, Keychain reset):
        // no names, generic "Locked vault"; resolve by name is impossible.
        let blind = Store::new(s.root()).with_index_key(index::no_key);
        let listed = blind.list_labeled().unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().all(|l| l.label.is_none()));
        assert!(matches!(blind.resolve("work"), Err(Error::NotFound)));
        assert_eq!(blind.resolve(&h.vault_id).unwrap().vault_id, h.vault_id);
        // Unlocking (upgrade_header) on a Mac with a key restores the label.
        let other = Store::new(s.root()).with_index_key(index::other_memory_key);
        assert!(other.label(&other.load(&h2.vault_id).unwrap()).is_none());
        other.upgrade_header(&h2.vault_id, &k2).unwrap();
        assert_eq!(
            other
                .label(&other.load(&h2.vault_id).unwrap())
                .unwrap()
                .name,
            "Private"
        );

        // Deleting a vault drops its entry.
        s.remove_vault(&h2.vault_id).unwrap();
        assert!(!index::read(s.root(), index::memory_key).contains_key(&h2.vault_id));
        assert_eq!(s.list().unwrap().len(), 1);
    }

    #[test]
    fn upgrade_refuses_tampered_header() {
        let (_d, s, mut h) = store_with_vault("Work");
        let nv = new_vault("X", Browser::Brave, PW, KdfCost::FAST).unwrap().0;
        // A key that isn't this vault's: MAC does not verify.
        assert!(s.upgrade_header(&h.vault_id, &nv.key).is_err());
        h.tamper_sealed_meta();
        h.save(&s.vault_dir(&h.vault_id)).unwrap();
        let k = keyslot::unlock_with_password(&s.load(&h.vault_id).unwrap(), PW).unwrap();
        assert!(!k.header_intact);
        assert!(s.upgrade_header(&h.vault_id, &k).is_err());
    }

    /// `Store::unlock` converts a v1 header before mounting. Off macOS the
    /// mount itself fails, but the conversion has happened by then.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unlock_converts_v1_header_before_mounting() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::new(d.path()).with_index_key(index::memory_key);
        let nv = new_vault("Legacy", Browser::Firefox, PW, KdfCost::FAST)
            .unwrap()
            .0;
        let mut h = nv.header;
        h.downgrade_to_v1(nv.key.vmk());
        let id = h.vault_id.clone();
        mkdir_700(&s.vault_dir(&id)).unwrap();
        h.save(&s.vault_dir(&id)).unwrap();
        h.save(&s.vault_dir(&id)).unwrap();
        assert!(fs::read_to_string(s.vault_dir(&id).join("header.json.bak"))
            .unwrap()
            .contains("Legacy"));
        let blind = Store::new(d.path()).with_index_key(index::no_key);
        // v1: the plain name is still listed, even without an index.
        assert_eq!(
            blind.list_labeled().unwrap()[0]
                .label
                .as_ref()
                .unwrap()
                .name,
            "Legacy"
        );

        let r = s.unlock(&id, Credential::Password(PW), &devs());
        assert!(matches!(r, Err(Error::Command { .. })), "no hdiutil here");
        let on_disk = s.load(&id).unwrap();
        assert_eq!(on_disk.version, crate::header::HEADER_VERSION);
        assert!(on_disk.meta_locked());
        for f in ["header.json", "header.json.bak"] {
            let text = fs::read_to_string(s.vault_dir(&id).join(f)).unwrap();
            assert!(!text.contains("Legacy") && !text.contains("firefox"), "{f}");
        }
        assert_eq!(s.label(&on_disk).unwrap().name, "Legacy");
        assert_eq!(s.label(&on_disk).unwrap().browser, Browser::Firefox);
        assert!(blind.list_labeled().unwrap()[0].label.is_none());
        // Still opens with every factor it had.
        let k = keyslot::unlock_with_password(&on_disk, PW).unwrap();
        assert!(k.header_intact);
        assert_eq!(s.load_open(&id, &k).unwrap().meta().unwrap().name, "Legacy");
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
