//! Obsidian (obsidian.md) in a vault.
//!
//! Obsidian is Electron: with `--user-data-dir=<mnt>/profile` its settings,
//! caches and its list of note folders (`obsidian.json`) live in the vault.
//! The notes themselves are plain files in `<mnt>/notes`. On every unlock
//! `obsidian.json` is rewritten so that folder is the one Obsidian opens
//! (the vault's path changes with the store location, e.g. a disguise).

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::error::{Error, Result};

/// The notes folder inside a mounted vault.
pub fn notes_dir(mnt: &Path) -> PathBuf {
    mnt.join("notes")
}

/// `obsidian.json` in a user-data dir (the vault's profile, or the regular
/// `~/Library/Application Support/obsidian`).
pub fn config_path(user_data: &Path) -> PathBuf {
    user_data.join("obsidian.json")
}

fn read_json(p: &Path) -> Result<Value> {
    match fs::read(p) {
        Ok(b) => Ok(serde_json::from_slice(&b).unwrap_or_else(|_| json!({}))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e.into()),
    }
}

fn write_json(p: &Path, v: &Value) -> Result<()> {
    let tmp = p.with_extension("json.bvtmp");
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(v)?)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, p)?;
    Ok(())
}

/// Random 16-hex-digit id, the form Obsidian uses for its vault entries.
fn new_vault_id() -> String {
    crate::crypto::random_bytes::<8>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Make `<mnt>/notes` the folder Obsidian opens, keeping its id (and so its
/// per-vault window state) across unlocks. Any other entry — a folder the
/// user added outside the vault — stays listed but not open.
pub fn write_config(mnt: &Path) -> Result<()> {
    let notes = notes_dir(mnt);
    fs::create_dir_all(&notes)?;
    let profile = crate::browser::profile_dir(mnt);
    fs::create_dir_all(&profile)?;
    let path = config_path(&profile);
    let mut cfg = read_json(&path)?;
    if !cfg.is_object() {
        cfg = json!({});
    }
    let obj = cfg.as_object_mut().ok_or(Error::Invalid("obsidian.json"))?;
    let mut vaults = obj
        .remove("vaults")
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    // Ours: the entry whose folder is called `notes` directly in a vault
    // mount (its absolute path moves with the store), else a new one.
    let ours = vaults
        .iter()
        .find(|(_, v)| {
            v.get("path")
                .and_then(Value::as_str)
                .is_some_and(|p| Path::new(p).ends_with("notes"))
        })
        .map(|(k, _)| k.clone())
        .unwrap_or_else(new_vault_id);
    for (k, v) in vaults.iter_mut() {
        if k != &ours {
            if let Some(o) = v.as_object_mut() {
                o.insert("open".into(), Value::Bool(false));
            }
        }
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut entry = Map::new();
    entry.insert(
        "path".into(),
        Value::String(notes.to_string_lossy().into_owned()),
    );
    entry.insert("ts".into(), Value::from(ts));
    entry.insert("open".into(), Value::Bool(true));
    vaults.insert(ours, Value::Object(entry));
    obj.insert("vaults".into(), Value::Object(vaults));
    write_json(&path, &cfg)?;
    keep_deleted_notes_inside(&notes)
}

/// Obsidian's default sends deleted notes to the macOS Trash (`~/.Trash`):
/// outside the vault, unencrypted. Force its own `.trash` folder inside the
/// notes instead, unless the user chose to delete permanently.
fn keep_deleted_notes_inside(notes: &Path) -> Result<()> {
    let dir = notes.join(".obsidian");
    fs::create_dir_all(&dir)?;
    let app = dir.join("app.json");
    let mut cfg = read_json(&app)?;
    if !cfg.is_object() {
        cfg = json!({});
    }
    let obj = cfg.as_object_mut().ok_or(Error::Invalid("app.json"))?;
    let current = obj.get("trashOption").and_then(Value::as_str);
    if matches!(current, Some("local") | Some("none")) {
        return Ok(());
    }
    obj.insert("trashOption".into(), Value::String("local".into()));
    write_json(&app, &cfg)
}

/// Note folders the regular Obsidian knows (`vaults.*.path`), as listed.
pub fn known_vaults(config: &Path) -> Vec<PathBuf> {
    read_json(config)
        .ok()
        .and_then(|v| v.get("vaults").and_then(Value::as_object).cloned())
        .map(|m| {
            m.values()
                .filter_map(|v| v.get("path").and_then(Value::as_str))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Remove `folder` from the regular Obsidian's list (after its notes were
/// moved into a vault and deleted), so its path is not left behind there.
pub fn forget_vault(config: &Path, folder: &Path) -> Result<()> {
    if !config.is_file() {
        return Ok(());
    }
    let mut cfg = read_json(config)?;
    let Some(vaults) = cfg.get_mut("vaults").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let before = vaults.len();
    vaults.retain(|_, v| v.get("path").and_then(Value::as_str) != Some(&*folder.to_string_lossy()));
    if vaults.len() != before {
        let _ = fs::copy(config, config.with_extension("json.bak"));
        write_json(config, &cfg)?;
        let _ = fs::remove_file(config.with_extension("json.bak"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_points_at_the_vault_notes_and_keeps_its_id() {
        let d = tempfile::tempdir().unwrap();
        let mnt = d.path().join("mnt/one");
        write_config(&mnt).unwrap();
        let cfg = read_json(&config_path(&mnt.join("profile"))).unwrap();
        let vaults = cfg["vaults"].as_object().unwrap();
        assert_eq!(vaults.len(), 1);
        let (id, v) = vaults.iter().next().unwrap();
        assert_eq!(id.len(), 16);
        assert_eq!(v["path"], mnt.join("notes").to_string_lossy().as_ref());
        assert_eq!(v["open"], true);
        assert!(mnt.join("notes").is_dir());
        let app = read_json(&mnt.join("notes/.obsidian/app.json")).unwrap();
        assert_eq!(
            app["trashOption"], "local",
            "deleted notes stay in the vault"
        );
        // The user's own "delete permanently" is kept; "system" is not.
        fs::write(
            mnt.join("notes/.obsidian/app.json"),
            r#"{"trashOption":"none","x":1}"#,
        )
        .unwrap();
        write_config(&mnt).unwrap();
        assert_eq!(
            read_json(&mnt.join("notes/.obsidian/app.json")).unwrap()["trashOption"],
            "none"
        );
        fs::write(
            mnt.join("notes/.obsidian/app.json"),
            r#"{"trashOption":"system","x":1}"#,
        )
        .unwrap();
        write_config(&mnt).unwrap();
        let app = read_json(&mnt.join("notes/.obsidian/app.json")).unwrap();
        assert_eq!(
            (app["trashOption"].as_str(), app["x"].as_i64()),
            (Some("local"), Some(1))
        );

        // The store moved (other disguise): same id, new path.
        let moved = d.path().join("other/mnt/one");
        fs::create_dir_all(moved.parent().unwrap()).unwrap();
        fs::rename(&mnt, &moved).unwrap();
        write_config(&moved).unwrap();
        let cfg = read_json(&config_path(&moved.join("profile"))).unwrap();
        let vaults = cfg["vaults"].as_object().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(
            vaults[id]["path"],
            moved.join("notes").to_string_lossy().as_ref()
        );
    }

    #[test]
    fn regular_list_is_read_and_one_entry_forgotten() {
        let d = tempfile::tempdir().unwrap();
        let cfg = d.path().join("obsidian.json");
        fs::write(
            &cfg,
            r#"{"vaults":{"a1":{"path":"/Users/x/Notes","ts":1,"open":true},"b2":{"path":"/Users/x/Work","ts":2}},"frame":"hidden"}"#,
        )
        .unwrap();
        let mut known = known_vaults(&cfg);
        known.sort();
        assert_eq!(
            known,
            [
                PathBuf::from("/Users/x/Notes"),
                PathBuf::from("/Users/x/Work")
            ]
        );
        forget_vault(&cfg, Path::new("/Users/x/Notes")).unwrap();
        assert_eq!(known_vaults(&cfg), [PathBuf::from("/Users/x/Work")]);
        let v = read_json(&cfg).unwrap();
        assert_eq!(v["frame"], "hidden", "other settings kept");
        assert!(!cfg.with_extension("json.bak").exists());
    }
}
