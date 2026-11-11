//! `header.json` format (SPEC §8) and its atomic persistence.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::browser::Browser;
use crate::crypto::{self, Key};
use crate::error::{Error, Result};

pub const HEADER_VERSION: u32 = 1;
pub const HEADER_FILE: &str = "header.json";
pub const HEADER_BACKUP_FILE: &str = "header.json.bak";
const HEADER_TMP_FILE: &str = "header.json.tmp";
const MAC_INFO: &[u8] = b"bv-header-mac-v1";

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u32,
    pub vault_id: String,
    pub name: String,
    pub browser: Browser,
    pub created_at: String,
    pub kdf: Kdf,
    pub slots: Vec<Slot>,
    pub settings: VaultSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<Original>,
    #[serde(default)]
    pub mac: B64,
}

impl Header {
    pub fn from_json(bytes: &[u8]) -> Result<Header> {
        let h: Header = serde_json::from_slice(bytes)?;
        if h.version != HEADER_VERSION {
            return Err(Error::Format(format!("unsupported version {}", h.version)));
        }
        Ok(h)
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut v = serde_json::to_vec_pretty(self)?;
        v.push(b'\n');
        Ok(v)
    }

    /// The bytes the MAC covers: the whole header with `mac` emptied and the
    /// TOTP slot's mutable counter state zeroed (that state has its own MAC,
    /// see [`Slot::Totp`]), so failed unlock attempts keep the header intact.
    fn mac_input(&self) -> Result<Vec<u8>> {
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
        Ok(serde_json::to_vec(&h)?)
    }

    fn mac_key(vmk: &Key) -> Key {
        crypto::hkdf(vmk.as_ref(), MAC_INFO)
    }

    /// Recompute `mac` = HMAC-SHA256(HKDF(VMK, "bv-header-mac-v1"), header).
    /// Must be called after every change, before saving.
    pub fn seal_mac(&mut self, vmk: &Key) -> Result<()> {
        let tag = crypto::hmac_sha256(&Self::mac_key(vmk), &self.mac_input()?);
        self.mac = B64(tag.to_vec());
        Ok(())
    }

    /// SPEC §8: checked after unlock; `false` means the header was tampered with.
    pub fn verify_mac(&self, vmk: &Key) -> bool {
        match self.mac_input() {
            Ok(input) => crypto::hmac_sha256_verify(&Self::mac_key(vmk), &input, &self.mac.0),
            Err(_) => false,
        }
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

    fn sample() -> Header {
        Header {
            version: HEADER_VERSION,
            vault_id: "8b4c7f0e-7a63-4d55-9a1e-2f0d9d3b6a11".into(),
            name: "Work – Brave".into(),
            browser: Browser::Brave,
            created_at: "2026-11-03T10:00:00Z".into(),
            kdf: Kdf {
                alg: "argon2id".into(),
                m_kib: 262144,
                t: 3,
                p: 1,
                salt: B64(vec![1; 16]),
            },
            slots: vec![
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
            ],
            settings: VaultSettings::default(),
            original: None,
            mac: B64::default(),
        }
    }

    #[test]
    fn json_roundtrip_and_spec_field_names() {
        let h = sample();
        let json = h.to_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["kdf"]["m_kib"], 262144);
        assert_eq!(v["slots"][0]["type"], "fido2");
        assert_eq!(v["slots"][1]["type"], "totp");
        assert_eq!(v["slots"][2]["type"], "recovery");
        assert_eq!(v["browser"], "brave");
        assert_eq!(v["settings"]["idle_minutes"], 15);
        assert!(v.get("original").is_none());
        assert_eq!(Header::from_json(&json).unwrap(), h);
    }

    #[test]
    fn original_roundtrip() {
        let mut h = sample();
        h.original = Some(Original {
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
        let mut v: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        v["extra"] = serde_json::json!(1);
        assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());

        let mut v: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        v["version"] = serde_json::json!(2);
        assert!(Header::from_json(&serde_json::to_vec(&v).unwrap()).is_err());

        let mut v: serde_json::Value =
            serde_json::from_slice(&sample().to_json().unwrap()).unwrap();
        v["slots"][0]["type"] = serde_json::json!("magic");
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
            Box::new(|h| h.name.push('!')),
            Box::new(|h| h.browser = Browser::Firefox),
            Box::new(|h| h.kdf.m_kib = 1024),
            Box::new(|h| h.settings.idle_minutes = 0),
            Box::new(|h| h.settings.lock_on_key_removal = false),
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
        ];
        for m in mutations {
            let mut t = h.clone();
            m(&mut t);
            assert!(!t.verify_mac(&vmk), "mutation not detected");
        }
    }

    #[test]
    fn mac_ignores_totp_counter_state() {
        let vmk = crypto::random_key();
        let mut h = sample();
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
    }

    #[test]
    fn atomic_save_keeps_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = sample();
        h.save(dir.path()).unwrap();
        assert!(dir.path().join(HEADER_FILE).exists());
        assert!(!dir.path().join(HEADER_BACKUP_FILE).exists());
        assert!(!dir.path().join(HEADER_TMP_FILE).exists());

        h.name = "Renamed".into();
        h.save(dir.path()).unwrap();
        assert_eq!(Header::load(dir.path()).unwrap().name, "Renamed");
        let bak =
            Header::from_json(&fs::read(dir.path().join(HEADER_BACKUP_FILE)).unwrap()).unwrap();
        assert_eq!(bak.name, "Work – Brave");
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
