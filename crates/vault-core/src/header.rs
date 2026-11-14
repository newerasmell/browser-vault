//! `header.json` format (SPEC §8) and its atomic persistence.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::browser::Browser;
use crate::crypto::{self, Key};
use crate::error::{Error, Result};

/// Current header format (encrypted metadata). New vaults are created as v2.
pub const HEADER_VERSION: u32 = 2;
/// Legacy format with plain-JSON metadata; still read, upgraded on unlock.
pub const HEADER_VERSION_V1: u32 = 1;
pub const HEADER_FILE: &str = "header.json";
pub const HEADER_BACKUP_FILE: &str = "header.json.bak";
const HEADER_TMP_FILE: &str = "header.json.tmp";
const MAC_INFO: &[u8] = b"bv-header-mac-v1";
const META_INFO: &[u8] = b"bv-meta-v1";
/// Sealed metadata plaintext is padded to a multiple of this many bytes.
pub const META_PAD: usize = 512;
/// The vault's name/browser/settings are encrypted and the vault is locked.
pub const ERR_META_LOCKED: &str = "vault metadata is encrypted; unlock first";

/// Bytes serialized as standard base64.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl std::fmt::Debug for B64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        B64(v)
    }
}

impl<const N: usize> From<[u8; N]> for B64 {
    fn from(v: [u8; N]) -> Self {
        B64(v.to_vec())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Kdf {
    pub alg: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub salt: B64,
}

impl Kdf {
    pub fn derive(&self, secret: &[u8]) -> Result<Key> {
        if self.alg != "argon2id" {
            return Err(Error::Format(format!("unsupported kdf {}", self.alg)));
        }
        self.derive_with_salt(secret, &self.salt.0)
    }

    /// Same cost parameters, different salt (used by the recovery slot).
    pub fn derive_with_salt(&self, secret: &[u8], salt: &[u8]) -> Result<Key> {
        crypto::argon2id(secret, salt, self.m_kib, self.t, self.p)
    }
}

/// One keyslot: the VMK wrapped under a slot-specific KEK (SPEC §4).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Slot {
    /// TEMPORARY (M1/M2): KEK = HKDF(PW). Exists only until the real second
    /// factors land in M3 (TOTP) and M4 (FIDO2); must not ship in a release.
    Password { nonce: B64, wrapped_vmk: B64 },
    /// KEK = HKDF(PW ‖ hmac-secret(YubiKey, salt)). Implemented in M4.
    Fido2 {
        label: String,
        credential_id: B64,
        salt: B64,
        nonce: B64,
        wrapped_vmk: B64,
    },
    /// KEK = HKDF(PW ‖ SE_secret) (SPEC §4.1, see `totp`).
    ///
    /// `last_counter`, `failures`, `locked_until` and `state_mac` are the
    /// mutable anti-replay / rate-limit state. They change on every attempt,
    /// including failed ones where the VMK is unknown, so they are excluded
    /// from the VMK header MAC and protected by `state_mac` instead (keyed
    /// from the TOTP seed, which the Secure Enclave unwraps without a code).
    Totp {
        se_key_tag: String,
        /// Opaque Secure Enclave token object id used to re-open the key
        /// (see `se`). Absent only for a keychain-resident key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        se_key_blob: Option<B64>,
        wrapped_se_secret: B64,
        wrapped_seed: B64,
        last_counter: u64,
        #[serde(default)]
        failures: u32,
        /// Unix time (s) before which no attempt is evaluated; 0 = none.
        #[serde(default)]
        locked_until: u64,
        #[serde(default)]
        state_mac: B64,
        nonce: B64,
        wrapped_vmk: B64,
    },
    /// KEK = HKDF(Argon2id(24-word BIP39 phrase, salt)).
    Recovery {
        salt: B64,
        nonce: B64,
        wrapped_vmk: B64,
    },
}

impl Slot {
    pub fn kind(&self) -> &'static str {
        match self {
            Slot::Password { .. } => "password",
            Slot::Fido2 { .. } => "fido2",
            Slot::Totp { .. } => "totp",
            Slot::Recovery { .. } => "recovery",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VaultSettings {
    pub idle_minutes: u32,
    pub lock_on_screen_lock: bool,
    pub lock_on_key_removal: bool,
    /// Brave runs with a Mac-independent key (see `portable.rs`), so the
    /// vault's logins work on another Mac. Omitted when false, so headers
    /// written before this field existed keep a valid MAC.
    #[serde(default, skip_serializing_if = "is_false")]
    pub portable_keys: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Default for VaultSettings {
    fn default() -> Self {
        VaultSettings {
            idle_minutes: 15,
            lock_on_screen_lock: true,
            lock_on_key_removal: true,
            portable_keys: false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OriginalState {
    Pending,
    Kept,
    Deleted,
}

/// Imported original profile bookkeeping (SPEC §5.1, milestone M7b).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Original {
    pub browser: Browser,
    pub profile_id: String,
    pub profile_name: String,
    pub paths: Vec<String>,
    pub size_bytes: u64,
    pub imported_at: String,
    pub reviewed: bool,
    pub state: OriginalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// The metadata that a v2 header keeps encrypted on disk (SPEC §8, header
/// v2): everything that says *what* the vault is, nothing that unlocking needs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub name: String,
    pub browser: Browser,
    pub created_at: String,
    pub settings: VaultSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<Original>,
    /// YubiKey slot labels by credential id (base64). In a v2 header the
    /// labels on disk are blank and live here, encrypted; the in-memory
    /// slots get them back when the metadata is opened.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub key_labels: std::collections::BTreeMap<String, String>,
}

fn b64_key(b: &B64) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b.0)
}

/// `meta` as stored in a v2 header: XChaCha20-Poly1305 under
/// `HKDF(VMK, "bv-meta-v1")`, AAD `bv-meta-v1|<vault_id>`, plaintext = the
/// JSON of [`Meta`] padded with spaces to a multiple of [`META_PAD`] bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealedMeta {
    pub nonce: B64,
    pub ct: B64,
}

/// A vault header (SPEC §8) in memory.
///
/// v1 headers (plain JSON metadata) always have their [`Meta`]. A v2 header
/// loaded from disk has only the sealed metadata until [`Header::open_meta`]
/// is called with the VMK, so code that needs the name, browser, settings or
/// original before unlocking has to handle "unknown" ([`Header::try_meta`])
/// or gets [`ERR_META_LOCKED`] from [`Header::meta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub vault_id: String,
    pub kdf: Kdf,
    pub slots: Vec<Slot>,
    /// Decrypted (or v1 plain) metadata; `None` = v2, not opened yet.
    meta: Option<Meta>,
    /// v2 only: the metadata as stored (refreshed by [`Header::seal_mac`]).
    sealed: Option<SealedMeta>,
    pub mac: B64,
}

/// On-disk v1 layout. Field order is the historical one: the MAC of
/// existing v1 headers is computed over exactly this serialization.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskV1 {
    version: u32,
    vault_id: String,
    name: String,
    browser: Browser,
    created_at: String,
    kdf: Kdf,
    slots: Vec<Slot>,
    settings: VaultSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<Original>,
    #[serde(default)]
    mac: B64,
}

/// On-disk v2 layout: only what unlocking needs stays in the clear.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskV2 {
    version: u32,
    vault_id: String,
    kdf: Kdf,
    slots: Vec<Slot>,
    meta: SealedMeta,
    #[serde(default)]
    mac: B64,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Disk {
    V1(DiskV1),
    V2(DiskV2),
}

#[derive(Deserialize)]
struct VersionOnly {
    version: u32,
}

fn meta_key(vmk: &Key) -> Key {
    crypto::hkdf(vmk.as_ref(), META_INFO)
}

fn meta_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = META_INFO.to_vec();
    aad.push(b'|');
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

impl Header {
    /// A new v2 header. Call [`Header::seal_mac`] before saving it.
    pub fn new(vault_id: String, kdf: Kdf, slots: Vec<Slot>, meta: Meta) -> Header {
        Header {
            version: HEADER_VERSION,
            vault_id,
            kdf,
            slots,
            meta: Some(meta),
            sealed: None,
            mac: B64::default(),
        }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Header> {
        let v: VersionOnly = serde_json::from_slice(bytes)?;
        match v.version {
            HEADER_VERSION_V1 => {
                let d: DiskV1 = serde_json::from_slice(bytes)?;
                Ok(Header {
                    version: d.version,
                    vault_id: d.vault_id,
                    kdf: d.kdf,
                    slots: d.slots,
                    meta: Some(Meta {
                        name: d.name,
                        browser: d.browser,
                        created_at: d.created_at,
                        settings: d.settings,
                        original: d.original,
                        key_labels: Default::default(),
                    }),
                    sealed: None,
                    mac: d.mac,
                })
            }
            HEADER_VERSION => {
                let d: DiskV2 = serde_json::from_slice(bytes)?;
                Ok(Header {
                    version: d.version,
                    vault_id: d.vault_id,
                    kdf: d.kdf,
                    slots: d.slots,
                    meta: None,
                    sealed: Some(d.meta),
                    mac: d.mac,
                })
            }
            other => Err(Error::Format(format!("unsupported version {other}"))),
        }
    }

    fn to_disk(&self) -> Result<Disk> {
        self.to_disk_with(true)
    }

    /// `blank_labels: false` is the v2 form written by versions before the
    /// YubiKey labels moved into the sealed metadata (only used to verify
    /// the MAC of such a header).
    fn to_disk_with(&self, blank_labels: bool) -> Result<Disk> {
        match self.version {
            HEADER_VERSION_V1 => {
                let m = self
                    .meta
                    .clone()
                    .ok_or(Error::Invalid("v1 header without metadata"))?;
                Ok(Disk::V1(DiskV1 {
                    version: self.version,
                    vault_id: self.vault_id.clone(),
                    name: m.name,
                    browser: m.browser,
                    created_at: m.created_at,
                    kdf: self.kdf.clone(),
                    slots: self.slots.clone(),
                    settings: m.settings,
                    original: m.original,
                    mac: self.mac.clone(),
                }))
            }
            HEADER_VERSION => Ok(Disk::V2(DiskV2 {
                version: self.version,
                vault_id: self.vault_id.clone(),
                kdf: self.kdf.clone(),
                // Labels are user text ("YubiKey main"): kept in the sealed
                // metadata, never on disk in the clear.
                slots: self
                    .slots
                    .iter()
                    .cloned()
                    .map(|mut s| {
                        if let Slot::Fido2 { label, .. } = &mut s {
                            if blank_labels {
                                label.clear();
                            }
                        }
                        s
                    })
                    .collect(),
                meta: self
                    .sealed
                    .clone()
                    .ok_or(Error::Invalid("metadata not sealed yet"))?,
                mac: self.mac.clone(),
            })),
            other => Err(Error::Format(format!("unsupported version {other}"))),
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut v = serde_json::to_vec_pretty(&self.to_disk()?)?;
        v.push(b'\n');
        Ok(v)
    }

    /// The metadata, or [`ERR_META_LOCKED`] for a v2 header that was not
    /// opened with the VMK.
    pub fn meta(&self) -> Result<&Meta> {
        self.meta.as_ref().ok_or(Error::Invalid(ERR_META_LOCKED))
    }

    pub fn meta_mut(&mut self) -> Result<&mut Meta> {
        self.meta.as_mut().ok_or(Error::Invalid(ERR_META_LOCKED))
    }

    /// The metadata if known (v1, or v2 after [`Header::open_meta`]).
    pub fn try_meta(&self) -> Option<&Meta> {
        self.meta.as_ref()
    }

    /// The vault's own lock settings; the strict defaults (all triggers on)
    /// while the metadata is unknown.
    pub fn settings_or_default(&self) -> VaultSettings {
        self.meta
            .as_ref()
            .map(|m| m.settings.clone())
            .unwrap_or_default()
    }

    /// True for a v2 header whose metadata has not been decrypted.
    pub fn meta_locked(&self) -> bool {
        self.meta.is_none()
    }

    /// Decrypt the v2 metadata with the VMK (no-op if already known). Fails
    /// if `vmk` is not this vault's or the sealed metadata was modified.
    pub fn open_meta(&mut self, vmk: &Key) -> Result<()> {
        if self.meta.is_some() {
            return Ok(());
        }
        let s = self
            .sealed
            .as_ref()
            .ok_or(Error::Invalid("header has no metadata"))?;
        let pt = crypto::open(
            &meta_key(vmk),
            &meta_aad(&self.vault_id),
            &s.nonce.0,
            &s.ct.0,
        )
        .map_err(|_| Error::Format("vault metadata could not be decrypted".into()))?;
        let meta: Meta = serde_json::from_slice(&pt)
            .map_err(|_| Error::Format("vault metadata is malformed".into()))?;
        for slot in &mut self.slots {
            if let Slot::Fido2 {
                label,
                credential_id,
                ..
            } = slot
            {
                if let Some(l) = meta.key_labels.get(&b64_key(credential_id)) {
                    *label = l.clone();
                }
            }
        }
        self.meta = Some(meta);
        Ok(())
    }

    /// Encrypt the current metadata into `sealed` (fresh nonce).
    fn seal_meta(&mut self, vmk: &Key) -> Result<()> {
        let labels: std::collections::BTreeMap<String, String> = self
            .slots
            .iter()
            .filter_map(|s| match s {
                Slot::Fido2 {
                    label,
                    credential_id,
                    ..
                } if !label.is_empty() => Some((b64_key(credential_id), label.clone())),
                _ => None,
            })
            .collect();
        if !labels.is_empty() {
            let m = self.meta_mut()?;
            m.key_labels.extend(labels);
        }
        // Drop labels of keys that were removed.
        let ids: Vec<String> = self
            .slots
            .iter()
            .filter_map(|s| match s {
                Slot::Fido2 { credential_id, .. } => Some(b64_key(credential_id)),
                _ => None,
            })
            .collect();
        self.meta_mut()?.key_labels.retain(|k, _| ids.contains(k));
        let meta = self.meta()?;
        let mut pt = Zeroizing::new(serde_json::to_vec(meta)?);
        // Pad so the ciphertext length says little about the name or paths.
        let padded = pt.len().div_ceil(META_PAD).max(1) * META_PAD;
        pt.resize(padded, b' ');
        let (nonce, ct) = crypto::seal(&meta_key(vmk), &meta_aad(&self.vault_id), &pt)?;
        self.sealed = Some(SealedMeta {
            nonce: nonce.into(),
            ct: ct.into(),
        });
        Ok(())
    }

    /// v1 → v2 in memory: the metadata gets sealed and the MAC recomputed.
    /// Returns whether anything changed. The caller saves.
    pub fn upgrade(&mut self, vmk: &Key) -> Result<bool> {
        if self.version != HEADER_VERSION_V1 {
            return Ok(false);
        }
        self.meta()?;
        self.version = HEADER_VERSION;
        self.seal_mac(vmk)?;
        Ok(true)
    }

    /// The bytes the MAC covers: the whole header as stored, with `mac`
    /// emptied and the TOTP slot's mutable counter state zeroed (that state
    /// has its own MAC, see [`Slot::Totp`]), so failed unlock attempts keep
    /// the header intact. For v2 that includes the sealed metadata.
    fn mac_input(&self) -> Result<Vec<u8>> {
        self.mac_input_with(true)
    }

    fn mac_input_with(&self, blank_labels: bool) -> Result<Vec<u8>> {
        let mut h = self.clone();
        h.mac = B64::default();
        for slot in &mut h.slots {
            if let Slot::Totp {
                last_counter,
                failures,
                locked_until,
                state_mac,
                ..
            } = slot
            {
                *last_counter = 0;
                *failures = 0;
                *locked_until = 0;
                *state_mac = B64::default();
            }
        }
        Ok(serde_json::to_vec(&h.to_disk_with(blank_labels)?)?)
    }

    fn mac_key(vmk: &Key) -> Key {
        crypto::hkdf(vmk.as_ref(), MAC_INFO)
    }

    /// Recompute `mac` = HMAC-SHA256(HKDF(VMK, "bv-header-mac-v1"), header).
    /// For v2 with known metadata, the metadata is re-sealed first; a v2
    /// header that was never opened keeps its sealed metadata as it is.
    /// Must be called after every change, before saving.
    pub fn seal_mac(&mut self, vmk: &Key) -> Result<()> {
        if self.version == HEADER_VERSION && self.meta.is_some() {
            self.seal_meta(vmk)?;
        }
        let tag = crypto::hmac_sha256(&Self::mac_key(vmk), &self.mac_input()?);
        self.mac = B64(tag.to_vec());
        Ok(())
    }

    /// SPEC §8: checked after unlock; `false` means the header was tampered with.
    pub fn verify_mac(&self, vmk: &Key) -> bool {
        let key = Self::mac_key(vmk);
        let ok = |blank| match self.mac_input_with(blank) {
            Ok(input) => crypto::hmac_sha256_verify(&key, &input, &self.mac.0),
            Err(_) => false,
        };
        // A v2 header from before the labels were sealed was MACed with the
        // labels in the clear. Both forms are bound to the VMK; the next
        // save writes the current one.
        ok(true) || (self.has_clear_labels() && ok(false))
    }

    /// A v2 header as written before YubiKey labels moved into the sealed
    /// metadata (labels still in the clear). Only meaningful on a header
    /// fresh from disk, before [`Header::open_meta`].
    pub fn has_clear_labels(&self) -> bool {
        self.version == HEADER_VERSION
            && self
                .slots
                .iter()
                .any(|s| matches!(s, Slot::Fido2 { label, .. } if !label.is_empty()))
    }

    pub fn load(dir: &Path) -> Result<Header> {
        let path = dir.join(HEADER_FILE);
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Error::NotFound,
            _ => Error::Io(e),
        })?;
        Header::from_json(&bytes)
    }

    /// Atomic save (SPEC §8): temp file → fsync → rename, keeping the previous
    /// version as `header.json.bak`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_atomic_with_backup(
            &dir.join(HEADER_FILE),
            &dir.join(HEADER_BACKUP_FILE),
            &dir.join(HEADER_TMP_FILE),
            &self.to_json()?,
        )
    }

    /// TEST ONLY: turn this header into the v1 format (plain metadata), as
    /// written by older versions, and re-seal its MAC.
    #[cfg(test)]
    pub(crate) fn downgrade_to_v1(&mut self, vmk: &Key) {
        assert!(self.meta.is_some(), "open the metadata first");
        self.version = HEADER_VERSION_V1;
        self.sealed = None;
        self.seal_mac(vmk).unwrap();
    }

    /// TEST ONLY: flip a bit of the sealed metadata (on-disk tampering).
    #[cfg(test)]
    pub(crate) fn tamper_sealed_meta(&mut self) {
        let s = self.sealed.as_mut().expect("v2 header");
        s.ct.0[0] ^= 1;
        self.meta = None;
    }
}

fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// temp file → fsync → rename → fsync dir, without a backup copy.
pub(crate) fn write_atomic(path: &Path, tmp: &Path, data: &[u8]) -> Result<()> {
    let dir: PathBuf = path
        .parent()
        .map(Path::to_path_buf)
        .ok_or(Error::Invalid("path has no parent"))?;
    write_synced(tmp, data)?;
    fs::rename(tmp, path)?;
    sync_dir(&dir)?;
    Ok(())
}

pub(crate) fn write_atomic_with_backup(
    path: &Path,
    backup: &Path,
    tmp: &Path,
    data: &[u8],
) -> Result<()> {
    let dir: PathBuf = path
        .parent()
        .map(Path::to_path_buf)
        .ok_or(Error::Invalid("header path has no parent"))?;
    write_synced(tmp, data)?;
    if path.exists() {
        // Backup is also written atomically so a crash never leaves a torn .bak.
        let current = fs::read(path)?;
        let bak_tmp = backup.with_extension("bak.tmp");
        write_synced(&bak_tmp, &current)?;
        fs::rename(&bak_tmp, backup)?;
    }
    fs::rename(tmp, path)?;
    sync_dir(&dir)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "8b4c7f0e-7a63-4d55-9a1e-2f0d9d3b6a11";

    fn sample_meta() -> Meta {
        Meta {
            name: "Work – Brave".into(),
            browser: Browser::Brave,
            created_at: "2026-11-03T10:00:00Z".into(),
            settings: VaultSettings::default(),
            original: None,
            key_labels: Default::default(),
        }
    }

    fn sample_slots() -> Vec<Slot> {
        vec![
            Slot::Fido2 {
                label: "YubiKey main".into(),
                credential_id: B64(vec![2; 64]),
                salt: B64(vec![3; 32]),
                nonce: B64(vec![4; 24]),
                wrapped_vmk: B64(vec![5; 48]),
            },
            Slot::Totp {
                se_key_tag: "com.browservault.x".into(),
                wrapped_se_secret: B64(vec![6; 80]),
                se_key_blob: Some(B64(vec![13; 40])),
                wrapped_seed: B64(vec![7; 80]),
                last_counter: 0,
                failures: 0,
                locked_until: 0,
                state_mac: B64(vec![14; 32]),
                nonce: B64(vec![8; 24]),
                wrapped_vmk: B64(vec![9; 48]),
            },
            Slot::Recovery {
                salt: B64(vec![10; 16]),
                nonce: B64(vec![11; 24]),
                wrapped_vmk: B64(vec![12; 48]),
            },
        ]
    }

    fn kdf() -> Kdf {
        Kdf {
            alg: "argon2id".into(),
            m_kib: 262144,
            t: 3,
            p: 1,
            salt: B64(vec![1; 16]),
        }
    }

    /// v2 header with its metadata open, sealed under `vmk`.
    fn sample_v2(vmk: &Key) -> Header {
        let mut h = Header::new(ID.into(), kdf(), sample_slots(), sample_meta());
        h.seal_mac(vmk).unwrap();
        h
    }

    /// v1 header (the historical format).
    fn sample() -> Header {
        Header {
            version: HEADER_VERSION_V1,
            vault_id: ID.into(),
            kdf: kdf(),
            slots: sample_slots(),
            meta: Some(sample_meta()),
            sealed: None,
            mac: B64::default(),
        }
    }

    fn sample_original() -> Original {
        Original {
            browser: Browser::Brave,
            profile_id: "Profile 1".into(),
            profile_name: "Secret profile".into(),
            paths: vec!["/Users/someone/Library/Application Support/BraveSoftware/x".into()],
            size_bytes: 123456789,
            imported_at: "2026-11-04T10:00:00Z".into(),
            reviewed: false,
            state: OriginalState::Pending,
            deleted_at: None,
        }
    }

    #[test]
    fn v1_json_roundtrip_and_spec_field_names() {
        let h = sample();
        let json = h.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["kdf"]["m_kib"], 262144);
        assert_eq!(v["slots"][0]["type"], "fido2");
        assert_eq!(v["slots"][1]["type"], "totp");
        assert_eq!(v["slots"][2]["type"], "recovery");
        assert_eq!(v["browser"], "brave");
        assert_eq!(v["name"], "Work – Brave");
        assert_eq!(v["settings"]["idle_minutes"], 15);
        assert!(v.get("original").is_none());
        assert!(v.get("meta").is_none());
        assert_eq!(Header::from_json(&json).unwrap(), h);
    }

    /// Exactly what the old (v1-only) code wrote; its MAC must still verify.
    #[test]
    fn v1_mac_bytes_are_unchanged() {
        let vmk = crypto::random_key();
        let mut h = sample();
        h.seal_mac(&vmk).unwrap();
        let json = String::from_utf8(h.to_json().unwrap()).unwrap();
        let keys: Vec<&str> = json
            .lines()
            .filter(|l| l.starts_with("  \"") && !l.starts_with("   "))
            .map(|l| l.trim().split('"').nth(1).unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "version",
                "vault_id",
                "name",
                "browser",
                "created_at",
                "kdf",
                "slots",
                "settings",
                "mac"
            ]
        );
        let back = Header::from_json(json.as_bytes()).unwrap();
        assert!(back.verify_mac(&vmk));
        assert_eq!(back.meta().unwrap().name, "Work – Brave");
    }

    #[test]
    fn v2_json_hides_all_metadata() {
        let vmk = crypto::random_key();
        let mut h = Header::new(ID.into(), kdf(), sample_slots(), sample_meta());
        h.meta_mut().unwrap().original = Some(sample_original());
        h.meta_mut().unwrap().settings.idle_minutes = 37;
        h.seal_mac(&vmk).unwrap();
        let json = h.to_json().unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        for needle in [
            "Work",
            "Brave",
            "brave",
            "2026-11-03",
            "2026-11-04",
            "Secret profile",
            "Profile 1",
            "/Users/someone",
            "123456789",
            "idle_minutes",
            "original",
            "settings",
            "name",
            "pending",
        ] {
            assert!(!text.contains(needle), "{needle} visible in {text}");
        }
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        let mut keys: Vec<&str> = keys.iter().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["kdf", "mac", "meta", "slots", "vault_id", "version"]);
        assert_eq!(v["version"], 2);
        assert_eq!(v["slots"][1]["type"], "totp");
        assert_eq!(v["meta"]["nonce"].as_str().unwrap().len(), 32); // 24 bytes b64

        let mut back = Header::from_json(&json).unwrap();
        assert!(back.meta_locked());
        assert!(matches!(back.meta(), Err(Error::Invalid(ERR_META_LOCKED))));
        assert!(back.verify_mac(&vmk));
        back.open_meta(&vmk).unwrap();
        assert_eq!(back.meta().unwrap().original, Some(sample_original()));
        assert_eq!(back.meta().unwrap().settings.idle_minutes, 37);
        assert_eq!(back, h);
    }

    #[test]
    fn v2_ciphertext_length_is_padded() {
        let vmk = crypto::random_key();
        let mut a = sample_v2(&vmk);
        a.meta_mut().unwrap().name = "A".into();
        a.seal_mac(&vmk).unwrap();
        let mut b = sample_v2(&vmk);
        b.meta_mut().unwrap().name = "A much longer vault name, still short".into();
        b.seal_mac(&vmk).unwrap();
        let la = a.sealed.as_ref().unwrap().ct.0.len();
        assert_eq!(la, b.sealed.as_ref().unwrap().ct.0.len());
        assert_eq!((la - 16) % META_PAD, 0);
    }

    #[test]
    fn v2_wrong_vmk_cannot_open_meta() {
        let vmk = crypto::random_key();
        let mut h = Header::from_json(&sample_v2(&vmk).to_json().unwrap()).unwrap();
        let other = crypto::random_key();
        assert!(!h.verify_mac(&other));
        assert!(matches!(h.open_meta(&other), Err(Error::Format(_))));
        assert!(h.meta_locked());
        // The MAC key is not the metadata key and vice versa.
        let mac_key = Header::mac_key(&vmk);
        assert!(h.open_meta(&mac_key).is_err());
        h.open_meta(&vmk).unwrap();
    }

    #[test]
    fn v2_meta_bound_to_vault_id() {
        let vmk = crypto::random_key();
        let mut h = Header::from_json(&sample_v2(&vmk).to_json().unwrap()).unwrap();
        h.vault_id = "11111111-1111-4111-8111-111111111111".into();
        assert!(h.open_meta(&vmk).is_err());
    }

    #[test]
    fn v2_tampered_meta_fails_mac_and_aead() {
        let vmk = crypto::random_key();
        let mut h = Header::from_json(&sample_v2(&vmk).to_json().unwrap()).unwrap();
        h.tamper_sealed_meta();
        assert!(!h.verify_mac(&vmk));
        assert!(h.open_meta(&vmk).is_err());

        // Swapping in another (valid) ciphertext of the same vault is caught by the MAC.
        let a = sample_v2(&vmk);
        let mut b = sample_v2(&vmk);
        b.sealed = a.sealed.clone();
        assert!(!b.verify_mac(&vmk));
    }

    #[test]
    fn v2_seal_mac_on_locked_header_keeps_sealed_meta() {
        let vmk = crypto::random_key();
        let h = sample_v2(&vmk);
        let mut locked = Header::from_json(&h.to_json().unwrap()).unwrap();
        // E.g. TOTP counters: changed and re-sealed without opening the metadata.
        if let Slot::Totp { last_counter, .. } = &mut locked.slots[1] {
            *last_counter = 5;
        }
        locked.seal_mac(&vmk).unwrap();
        assert_eq!(locked.sealed, h.sealed);
        assert!(locked.meta_locked());
        assert!(locked.verify_mac(&vmk));
        locked.open_meta(&vmk).unwrap();
        assert_eq!(locked.meta().unwrap(), h.meta().unwrap());
    }

    #[test]
    fn v2_unsealed_header_cannot_be_written() {
        let h = Header::new(ID.into(), kdf(), sample_slots(), sample_meta());
        assert!(h.to_json().is_err());
    }

    #[test]
    fn upgrade_v1_to_v2_keeps_everything() {
        let vmk = crypto::random_key();
        let mut h = sample();
        h.meta_mut().unwrap().original = Some(sample_original());
        h.seal_mac(&vmk).unwrap();
        let before = h.clone();
        assert!(h.upgrade(&vmk).unwrap());
        assert!(!h.upgrade(&vmk).unwrap(), "second upgrade is a no-op");
        assert_eq!(h.version, HEADER_VERSION);
        assert!(h.verify_mac(&vmk));
        let mut back = Header::from_json(&h.to_json().unwrap()).unwrap();
        assert!(back.verify_mac(&vmk));
        back.open_meta(&vmk).unwrap();
        let mut m = back.meta().unwrap().clone();
        assert_eq!(m.key_labels.len(), 1, "labels moved into the sealed meta");
        m.key_labels.clear();
        assert_eq!(&m, before.meta().unwrap());
        assert_eq!(back.slots, before.slots);
        assert_eq!(back.kdf, before.kdf);
        assert_eq!(back.vault_id, before.vault_id);
    }

    #[test]
    fn v2_keeps_key_labels_out_of_the_file() {
        let vmk = crypto::random_key();
        let h = sample_v2(&vmk);
        let json = h.to_json().unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(!text.contains("YubiKey main"), "label must not be in clear");
        let mut back = Header::from_json(&json).unwrap();
        assert!(back.verify_mac(&vmk));
        let locked: Vec<_> = crate::fido2::keys(&back)
            .into_iter()
            .map(|k| k.label)
            .collect();
        assert!(locked.iter().all(|l| l.starts_with("YubiKey ")));
        back.open_meta(&vmk).unwrap();
        assert!(back.verify_mac(&vmk));
        assert_eq!(back.slots, h.slots, "labels restored on open");

        // A removed key's label is dropped from the metadata too.
        let mut fewer = back.clone();
        let idx = fewer
            .slots
            .iter()
            .position(|s| matches!(s, Slot::Fido2 { .. }))
            .unwrap();
        fewer.slots.remove(idx);
        fewer.seal_mac(&vmk).unwrap();
        let n = fewer
            .slots
            .iter()
            .filter(|s| matches!(s, Slot::Fido2 { .. }))
            .count();
        assert_eq!(fewer.meta().unwrap().key_labels.len(), n);
    }

    #[test]
    fn header_with_clear_labels_still_verifies_and_migrates() {
        let vmk = crypto::random_key();
        let mut h = sample_v2(&vmk);
        // Re-MAC in the old form: labels in the clear on disk.
        let tag = crypto::hmac_sha256(&Header::mac_key(&vmk), &h.mac_input_with(false).unwrap());
        h.mac = B64(tag.to_vec());
        let legacy = serde_json::to_vec(&h.to_disk_with(false).unwrap()).unwrap();
        assert!(String::from_utf8_lossy(&legacy).contains("YubiKey main"));

        let mut back = Header::from_json(&legacy).unwrap();
        assert!(back.has_clear_labels());
        assert!(back.verify_mac(&vmk), "old headers must keep working");
        assert!(!back.verify_mac(&crypto::random_key()));
        back.open_meta(&vmk).unwrap();
        assert!(back.verify_mac(&vmk));
        back.seal_mac(&vmk).unwrap();
        let json = back.to_json().unwrap();
        assert!(!String::from_utf8_lossy(&json).contains("YubiKey main"));
        let mut again = Header::from_json(&json).unwrap();
        assert!(!again.has_clear_labels());
        assert!(again.verify_mac(&vmk));
        again.open_meta(&vmk).unwrap();
        assert_eq!(again.slots, back.slots, "labels survive the migration");

        // Tampering with a clear label is still caught.
        let mut t: serde_json::Value = serde_json::from_slice(&legacy).unwrap();
        for slot in t["slots"].as_array_mut().unwrap() {
            if slot.get("label").is_some() {
                slot["label"] = serde_json::json!("evil");
            }
        }
        let t = Header::from_json(&serde_json::to_vec(&t).unwrap()).unwrap();
        assert!(!t.verify_mac(&vmk));
    }

    #[test]
    fn original_roundtrip() {
        let mut h = sample();
        h.meta_mut().unwrap().original = Some(Original {
            browser: Browser::Brave,
            profile_id: "Profile 1".into(),
            profile_name: "Work".into(),
            paths: vec!["/x".into()],
            size_bytes: 10,
            imported_at: "2026-11-03T10:00:00Z".into(),
            reviewed: false,
            state: OriginalState::Pending,
            deleted_at: None,
        });
        let json = h.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["original"]["state"], "pending");
        assert_eq!(Header::from_json(&json).unwrap(), h);
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        let vmk = crypto::random_key();
        for json in [
            sample().to_json().unwrap(),
            sample_v2(&vmk).to_json().unwrap(),
        ] {
            let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            v["extra"] = serde_json::json!(1);
            assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());

            let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            v["version"] = serde_json::json!(3);
            assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());

            let mut v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            v["slots"][0]["type"] = serde_json::json!("magic");
            assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
        }
        // A v2 header must not carry plain metadata (and v1 must not carry `meta`).
        let mut v: serde_json::Value =
            serde_json::from_slice(&sample_v2(&vmk).to_json().unwrap()).unwrap();
        v["name"] = serde_json::json!("x");
        assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
        let mut v: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        v["version"] = serde_json::json!(2);
        assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }

    #[test]
    fn rejects_bad_base64() {
        let mut v: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        v["kdf"]["salt"] = serde_json::json!("not base64!!");
        assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());
    }

    #[test]
    fn mac_detects_any_change() {
        let vmk = crypto::random_key();
        let mut h = sample();
        h.seal_mac(&vmk).unwrap();
        assert!(h.verify_mac(&vmk));
        assert_eq!(h.mac.0.len(), 32);
        assert!(!h.verify_mac(&crypto::random_key()));

        type Mutation = Box<dyn Fn(&mut Header)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|h| h.meta_mut().unwrap().name.push('!')),
            Box::new(|h| h.meta_mut().unwrap().browser = Browser::Firefox),
            Box::new(|h| h.kdf.m_kib = 1024),
            Box::new(|h| h.meta_mut().unwrap().settings.idle_minutes = 0),
            Box::new(|h| h.meta_mut().unwrap().settings.lock_on_key_removal = false),
            Box::new(|h| {
                h.slots.pop();
            }),
            Box::new(|h| {
                if let Slot::Totp { wrapped_seed, .. } = &mut h.slots[1] {
                    wrapped_seed.0[0] ^= 1;
                }
            }),
            Box::new(|h| {
                if let Slot::Totp { se_key_blob, .. } = &mut h.slots[1] {
                    *se_key_blob = None;
                }
            }),
            Box::new(|h| h.mac.0[0] ^= 1),
            Box::new(|h| h.version = HEADER_VERSION),
        ];
        for m in mutations {
            let mut t = h.clone();
            m(&mut t);
            assert!(!t.verify_mac(&vmk), "mutation not detected");
        }
    }

    #[test]
    fn v2_mac_detects_slot_changes() {
        let vmk = crypto::random_key();
        let h = sample_v2(&vmk);
        let mut t = h.clone();
        t.slots.pop();
        assert!(!t.verify_mac(&vmk));
        let mut t = h.clone();
        t.kdf.t = 1;
        assert!(!t.verify_mac(&vmk));
        let mut t = h.clone();
        t.version = HEADER_VERSION_V1;
        assert!(!t.verify_mac(&vmk));
    }

    #[test]
    fn mac_ignores_totp_counter_state() {
        let vmk = crypto::random_key();
        for mut h in [sample(), sample_v2(&vmk)] {
            h.seal_mac(&vmk).unwrap();
            if let Slot::Totp {
                last_counter,
                failures,
                locked_until,
                state_mac,
                ..
            } = &mut h.slots[1]
            {
                *last_counter = 99;
                *failures = 7;
                *locked_until = 12345;
                state_mac.0[0] ^= 1;
            }
            assert!(h.verify_mac(&vmk));
        }
    }

    #[test]
    fn totp_slot_fields() {
        let json = sample().to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        let t = &v["slots"][1];
        for f in [
            "se_key_tag",
            "se_key_blob",
            "wrapped_se_secret",
            "wrapped_seed",
            "last_counter",
            "failures",
            "locked_until",
            "state_mac",
            "nonce",
            "wrapped_vmk",
        ] {
            assert!(t.get(f).is_some(), "missing {f}");
        }
        // The added fields default when absent.
        let mut t = t.clone();
        for f in ["se_key_blob", "failures", "locked_until", "state_mac"] {
            t.as_object_mut().unwrap().remove(f);
        }
        let s: Slot = serde_json::from_value(t).unwrap();
        assert!(matches!(
            s,
            Slot::Totp {
                se_key_blob: None,
                failures: 0,
                locked_until: 0,
                ..
            }
        ));
    }

    #[test]
    fn mac_survives_json_roundtrip() {
        let vmk = crypto::random_key();
        let mut h = sample();
        h.seal_mac(&vmk).unwrap();
        let back = Header::from_json(&h.to_json().unwrap()).unwrap();
        assert!(back.verify_mac(&vmk));
        let back = Header::from_json(&sample_v2(&vmk).to_json().unwrap()).unwrap();
        assert!(back.verify_mac(&vmk));
    }

    #[test]
    fn atomic_save_keeps_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = sample();
        h.save(dir.path()).unwrap();
        assert!(dir.path().join(HEADER_FILE).exists());
        assert!(!dir.path().join(HEADER_BACKUP_FILE).exists());
        assert!(!dir.path().join(HEADER_TMP_FILE).exists());

        h.meta_mut().unwrap().name = "Renamed".into();
        h.save(dir.path()).unwrap();
        assert_eq!(
            Header::load(dir.path()).unwrap().meta().unwrap().name,
            "Renamed"
        );
        let bak =
            Header::from_json(&fs::read(dir.path().join(HEADER_BACKUP_FILE)).unwrap()).unwrap();
        assert_eq!(bak.meta().unwrap().name, "Work – Brave");
        assert!(!dir.path().join(HEADER_TMP_FILE).exists());
        assert!(!dir.path().join("header.json.bak.tmp").exists());

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.path().join(HEADER_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(Header::load(dir.path()), Err(Error::NotFound)));
    }
}
