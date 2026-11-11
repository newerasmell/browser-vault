//! Backup of a LOCKED vault to an external drive, and "add vault from
//! drive" (import into the local store).
//!
//! A backup is a plain folder `<parent>/vault-<short id>.bvault/` with
//! `image.sparsebundle/` and `header.json` (+ `header.json.bak`). Both are
//! already encrypted / sealed, so nothing here touches key material. The
//! folder name carries no vault name (v2 headers keep the name encrypted);
//! backups made by older versions as `<name> (<short id>).bvault` are still
//! found and updated in place by their header's `vault_id`.
//!
//! Backups are incremental: an existing backup of the same vault is updated
//! by copying only files whose size or mtime differ and deleting files the
//! source no longer has (sparsebundle bands come and go). `header.json` is
//! written last. While a backup is being written, the folder holds an
//! `.incomplete` marker; [`import`] refuses such a folder.
//!
//! Only regular files and directories are copied; symlinks and special
//! files are skipped (never followed).

use std::collections::{HashMap, HashSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};
use crate::events::{Event, Notify};
use crate::header::{Header, HEADER_BACKUP_FILE, HEADER_FILE};
use crate::store::Store;
use crate::trace;

pub const ERR_UNLOCKED: &str = "lock the vault before backing it up";
pub const ERR_OTHER_VAULT: &str = "the destination holds a different vault";
pub const ERR_DEST_IN_STORE: &str = "choose a folder outside Browser Vault's own data";
pub const ERR_NOT_A_VAULT: &str = "the folder does not contain a vault backup";
pub const ERR_INCOMPLETE: &str = "the backup is incomplete; run the backup again";
pub const ERR_ALREADY_ADDED: &str = "this vault is already added";
pub const ERR_VERIFY: &str = "the copy does not match the original";

/// Extension of a backup folder.
pub const BACKUP_EXT: &str = "bvault";
pub const IMAGE_DIR: &str = "image.sparsebundle";
/// Present in a backup folder while it is being written.
pub const INCOMPLETE_MARKER: &str = ".incomplete";
/// Written into `<root>/vaults/<id>/` by [`import`]. The header's
/// `original` (imported-profile bookkeeping) then describes a profile on the
/// Mac the backup came from, so the app must not offer deleting anything
/// on this Mac for it (see `profiles::cleanup_preview`).
pub const RESTORED_MARKER: &str = "restored-from-backup";

/// mtime tolerance: HFS+ keeps whole seconds, FAT32 two seconds.
const MTIME_SLACK: Duration = Duration::from_secs(2);
const BUF: usize = 1024 * 1024;

/// What one export / import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyStats {
    pub copied_files: u64,
    pub copied_bytes: u64,
    /// Files already up to date in the destination.
    pub unchanged_files: u64,
    /// Destination entries removed because the source no longer has them.
    pub removed: u64,
}

#[derive(Debug, Clone)]
pub struct Exported {
    pub path: PathBuf,
    pub stats: CopyStats,
}

#[derive(Debug, Clone)]
struct Entry {
    rel: PathBuf,
    dir: bool,
    size: u64,
    mtime: SystemTime,
}

fn skip_name(name: &str) -> bool {
    // Finder / AppleDouble litter on non-APFS drives.
    name == ".DS_Store" || name.starts_with("._")
}

/// Pre-order walk (a directory comes before its children). Never follows
/// symlinks.
fn walk(base: &Path, rel: &Path, out: &mut Vec<Entry>) -> Result<()> {
    let mut names: Vec<_> = fs::read_dir(base.join(rel))?
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()?;
    names.sort();
    for name in names {
        let Some(s) = name.to_str() else {
            trace::emit("backup: skipped a non-UTF-8 name");
            continue;
        };
        if skip_name(s) {
            continue;
        }
        let r = rel.join(&name);
        let md = fs::symlink_metadata(base.join(&r))?;
        let ft = md.file_type();
        if ft.is_dir() {
            out.push(Entry {
                rel: r.clone(),
                dir: true,
                size: 0,
                mtime: md.modified()?,
            });
            walk(base, &r, out)?;
        } else if ft.is_file() {
            out.push(Entry {
                rel: r,
                dir: false,
                size: md.len(),
                mtime: md.modified()?,
            });
        } else {
            trace::emit(&format!("backup: skipped non-regular file {}", r.display()));
        }
    }
    Ok(())
}

/// The files that make up a vault in `dir`, header files LAST
/// (`header.json` is the very last entry).
fn vault_entries(dir: &Path) -> Result<Vec<Entry>> {
    let image = dir.join(IMAGE_DIR);
    let md = fs::symlink_metadata(&image).map_err(|_| Error::Invalid(ERR_NOT_A_VAULT))?;
    if !md.is_dir() || !image.join("Info.plist").is_file() {
        return Err(Error::Invalid(ERR_NOT_A_VAULT));
    }
    let mut out = vec![Entry {
        rel: PathBuf::from(IMAGE_DIR),
        dir: true,
        size: 0,
        mtime: md.modified()?,
    }];
    walk(dir, Path::new(IMAGE_DIR), &mut out)?;
    for name in [HEADER_BACKUP_FILE, HEADER_FILE] {
        match fs::symlink_metadata(dir.join(name)) {
            Ok(m) if m.is_file() => out.push(Entry {
                rel: PathBuf::from(name),
                dir: false,
                size: m.len(),
                mtime: m.modified()?,
            }),
            Ok(_) => trace::emit(&format!("backup: skipped non-regular {name}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    if out.last().map(|e| e.rel.as_path()) != Some(Path::new(HEADER_FILE)) {
        return Err(Error::Invalid(ERR_NOT_A_VAULT));
    }
    Ok(out)
}

fn mkdir(p: &Path, private: bool) -> Result<()> {
    let mut b = DirBuilder::new();
    b.recursive(true).mode(0o700);
    b.create(p)?;
    if private {
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn same_mtime(a: SystemTime, b: SystemTime) -> bool {
    let d = a.duration_since(b).or_else(|_| b.duration_since(a));
    d.map(|d| d < MTIME_SLACK).unwrap_or(false)
}

/// Byte-level progress, emitted only when the percentage changes.
struct Progress<'a> {
    total: u64,
    done: u64,
    last: Option<u8>,
    notify: Notify<'a>,
}

impl Progress<'_> {
    fn add(&mut self, n: u64) {
        self.done += n;
        // Leave 100 for "verified".
        let pct = (self.done.min(self.total) * 99)
            .checked_div(self.total)
            .unwrap_or(99) as u8;
        if self.last != Some(pct) {
            self.last = Some(pct);
            (self.notify)(Event::BackupProgress { pct });
        }
    }
}

/// Copy one file to `dst` via a temp name in the same directory: write,
/// set mtime, fsync, rename.
fn copy_file(src: &Path, dst: &Path, mtime: SystemTime, p: &mut Progress<'_>) -> Result<u64> {
    let name = dst
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::Invalid(ERR_NOT_A_VAULT))?;
    let tmp = dst.with_file_name(format!(".{name}.bvtmp"));
    let r = (|| -> Result<u64> {
        let mut input = File::open(src)?;
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        let mut buf = vec![0u8; BUF];
        let mut n = 0u64;
        loop {
            let k = input.read(&mut buf)?;
            if k == 0 {
                break;
            }
            out.write_all(&buf[..k])?;
            n += k as u64;
            p.add(k as u64);
        }
        out.set_modified(mtime)?;
        out.sync_all()?;
        Ok(n)
    })();
    match r {
        Ok(n) => {
            fs::rename(&tmp, dst)?;
            Ok(n)
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn remove_any(p: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn sync_dir(p: &Path) {
    // Best effort: not every filesystem supports fsync on a directory.
    if let Ok(f) = File::open(p) {
        let _ = f.sync_all();
    }
}

/// Copy `entries` from `src` into `dst`. With `incremental`, files whose
/// size and mtime already match are kept and destination entries under
/// `image.sparsebundle/` that the source lacks are deleted.
fn sync_tree(
    src: &Path,
    dst: &Path,
    entries: &[Entry],
    incremental: bool,
    private: bool,
    notify: Notify<'_>,
) -> Result<CopyStats> {
    let mut stats = CopyStats::default();
    let existing: HashMap<PathBuf, Entry> = if incremental && dst.join(IMAGE_DIR).is_dir() {
        let mut v = vec![];
        walk(dst, Path::new(IMAGE_DIR), &mut v)?;
        v.into_iter().map(|e| (e.rel.clone(), e)).collect()
    } else {
        HashMap::new()
    };
    let is_header =
        |e: &Entry| e.rel == Path::new(HEADER_FILE) || e.rel == Path::new(HEADER_BACKUP_FILE);

    // Decide what to copy first, so progress is by the bytes really copied.
    let todo: Vec<&Entry> = entries
        .iter()
        .filter(|e| !e.dir)
        .filter(|e| {
            // Header files are tiny and always rewritten.
            if is_header(e) {
                return true;
            }
            let unchanged = matches!(existing.get(&e.rel),
                Some(d) if !d.dir && d.size == e.size && same_mtime(d.mtime, e.mtime));
            !unchanged
        })
        .collect();
    stats.unchanged_files = entries.iter().filter(|e| !e.dir).count() as u64 - todo.len() as u64;
    let mut progress = Progress {
        total: todo.iter().map(|e| e.size).sum(),
        done: 0,
        last: None,
        notify,
    };
    progress.add(0);

    // Remove what the source no longer has (and kind changes file <-> dir),
    // deepest first is not needed: remove_dir_all takes whole subtrees.
    if incremental {
        let wanted: HashMap<&Path, bool> =
            entries.iter().map(|e| (e.rel.as_path(), e.dir)).collect();
        let mut gone: Vec<&Entry> = existing
            .values()
            .filter(|d| wanted.get(d.rel.as_path()) != Some(&d.dir))
            .collect();
        gone.sort_by(|a, b| a.rel.cmp(&b.rel));
        let mut removed_dirs: HashSet<&Path> = HashSet::new();
        for d in gone {
            if d.rel.ancestors().skip(1).any(|a| removed_dirs.contains(a)) {
                continue; // already removed with its parent
            }
            remove_any(&dst.join(&d.rel))?;
            stats.removed += 1;
            if d.dir {
                removed_dirs.insert(&d.rel);
            }
        }
        if !entries
            .iter()
            .any(|e| e.rel == Path::new(HEADER_BACKUP_FILE))
        {
            let bak = dst.join(HEADER_BACKUP_FILE);
            if bak.exists() {
                remove_any(&bak)?;
                stats.removed += 1;
            }
        }
    }

    let todo: HashSet<&Path> = todo.iter().map(|e| e.rel.as_path()).collect();
    for e in entries {
        let to = dst.join(&e.rel);
        if e.dir {
            mkdir(&to, private)?;
            if !private {
                let _ = fs::set_permissions(&to, fs::Permissions::from_mode(0o700));
            }
            continue;
        }
        if !todo.contains(e.rel.as_path()) {
            continue;
        }
        // header.json goes last: entries are ordered that way.
        let n = copy_file(&src.join(&e.rel), &to, e.mtime, &mut progress)?;
        if n != e.size {
            return Err(Error::Invalid(ERR_VERIFY)); // changed while copying
        }
        stats.copied_files += 1;
        stats.copied_bytes += n;
    }
    sync_dir(&dst.join(IMAGE_DIR));
    sync_dir(dst);
    Ok(stats)
}

/// Every source file exists in `dst` as a regular file of equal size, and
/// `dst/header.json` parses with the expected `vault_id`.
pub(crate) fn verify(src: &Path, dst: &Path, vault_id: &str) -> Result<()> {
    for e in vault_entries(src)? {
        let md = fs::symlink_metadata(dst.join(&e.rel)).map_err(|_| Error::Invalid(ERR_VERIFY))?;
        let ok = if e.dir {
            md.is_dir()
        } else {
            md.is_file() && md.len() == e.size
        };
        if !ok {
            trace::emit(&format!("backup: verify mismatch at {}", e.rel.display()));
            return Err(Error::Invalid(ERR_VERIFY));
        }
    }
    match Header::load(dst) {
        Ok(h) if h.vault_id == vault_id => Ok(()),
        _ => Err(Error::Invalid(ERR_VERIFY)),
    }
}

/// Folder name for a new backup: `vault-<first 8 of id>.bvault`. Never the
/// vault's name: the drive must not tell what the vault is.
pub fn backup_folder_name(id: &str) -> String {
    let short: String = id
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(8)
        .collect();
    format!("vault-{short}.{BACKUP_EXT}")
}

/// `vault_id` of the backup in `dir`, if `dir/header.json` parses.
fn backup_id(dir: &Path) -> Option<String> {
    Header::load(dir).ok().map(|h| h.vault_id)
}

fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

fn inside(p: &Path, root: &Path) -> bool {
    match (p.canonicalize(), root.canonicalize()) {
        (Ok(p), Ok(r)) => p.starts_with(r),
        _ => false,
    }
}

/// Where the backup of `id` goes under `dest_parent`: the user may pick
/// the `.bvault` folder itself, a parent with an earlier backup of this
/// vault (even under an older name), or any other folder.
fn destination(dest_parent: &Path, header: &Header) -> Result<PathBuf> {
    let id = &header.vault_id;
    if dest_parent.join(HEADER_FILE).exists() {
        return match backup_id(dest_parent) {
            Some(b) if &b == id => Ok(dest_parent.to_path_buf()),
            _ => Err(Error::Invalid(ERR_OTHER_VAULT)),
        };
    }
    for e in fs::read_dir(dest_parent)? {
        let p = e?.path();
        if p.extension().is_some_and(|x| x == BACKUP_EXT)
            && is_real_dir(&p)
            && backup_id(&p).as_deref() == Some(id.as_str())
        {
            return Ok(p);
        }
    }
    Ok(dest_parent.join(backup_folder_name(id)))
}

/// Back up the locked vault `id` into `dest_parent` (see module docs).
pub fn export(store: &Store, id: &str, dest_parent: &Path, notify: Notify<'_>) -> Result<Exported> {
    export_with(store, id, dest_parent, &|v| store.is_unlocked(v), notify)
}

/// [`export`] with the "is it mounted?" check injected (tests).
fn export_with(
    store: &Store,
    id: &str,
    dest_parent: &Path,
    is_unlocked: &dyn Fn(&str) -> bool,
    notify: Notify<'_>,
) -> Result<Exported> {
    let header = store.load(id)?;
    // A mounted sparsebundle changes underneath the copy.
    if is_unlocked(id) {
        return Err(Error::Invalid(ERR_UNLOCKED));
    }
    if !is_real_dir(dest_parent) {
        return Err(Error::NotFound);
    }
    if inside(dest_parent, store.root()) {
        return Err(Error::Invalid(ERR_DEST_IN_STORE));
    }
    let src = store.vault_dir(id);
    let entries = vault_entries(&src)?;
    let dest = destination(dest_parent, &header)?;
    trace::emit(&format!("backup {id}: start"));

    // First backup: write into a hidden partial folder (named by the full
    // id, so an interrupted run resumes there), rename at the end.
    let existing = dest.exists();
    if existing {
        if !is_real_dir(&dest) {
            return Err(Error::Invalid(ERR_OTHER_VAULT));
        }
        match backup_id(&dest) {
            Some(b) if b == id => {}
            Some(_) => return Err(Error::Invalid(ERR_OTHER_VAULT)),
            // No header: only an empty folder is ours to fill.
            None if fs::read_dir(&dest)?.next().is_none() => {}
            None => return Err(Error::Invalid(ERR_OTHER_VAULT)),
        }
    }
    let partial = dest_parent.join(format!(".{id}.{BACKUP_EXT}-partial"));
    let work = if existing {
        dest.clone()
    } else {
        partial.clone()
    };
    mkdir(&work, false)?;
    let marker = work.join(INCOMPLETE_MARKER);
    File::create(&marker)?.sync_all()?;

    let stats = sync_tree(&src, &work, &entries, true, false, notify)?;
    // Unlocked while we were copying: the copy may be torn. Keep the
    // marker so this copy cannot be imported; the next run repairs it.
    if is_unlocked(id) {
        return Err(Error::Invalid(ERR_UNLOCKED));
    }
    verify(&src, &work, id)?;
    fs::remove_file(&marker)?;
    sync_dir(&work);
    if !existing {
        fs::rename(&partial, &dest)?;
        sync_dir(dest_parent);
    }
    notify(Event::BackupProgress { pct: 100 });
    trace::emit(&format!(
        "backup {id}: done, {} copied, {} unchanged, {} removed",
        stats.copied_files, stats.unchanged_files, stats.removed
    ));
    Ok(Exported { path: dest, stats })
}

/// The backup folder for `src`: `src` itself if it holds `header.json`,
/// else its single `.bvault` child.
fn backup_root(src: &Path) -> Result<PathBuf> {
    if src.join(HEADER_FILE).is_file() {
        return Ok(src.to_path_buf());
    }
    let mut hits = vec![];
    if let Ok(rd) = fs::read_dir(src) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == BACKUP_EXT)
                && is_real_dir(&p)
                && p.join(HEADER_FILE).is_file()
            {
                hits.push(p);
            }
        }
    }
    match hits.len() {
        1 => Ok(hits.remove(0)),
        _ => Err(Error::Invalid(ERR_NOT_A_VAULT)),
    }
}

/// Add a vault from a backup folder: validate, copy into
/// `<root>/vaults/<id>/` via `<root>/vaults/.<id>.importing` + rename,
/// verify. The header is NOT modified (its MAC needs the VMK); the vault
/// dir gets a [`RESTORED_MARKER`] instead.
pub fn import(store: &Store, src: &Path, notify: Notify<'_>) -> Result<Header> {
    let src = backup_root(src)?;
    if src.join(INCOMPLETE_MARKER).exists() {
        return Err(Error::Invalid(ERR_INCOMPLETE));
    }
    let header = match Header::load(&src) {
        Ok(h) => h,
        Err(Error::NotFound) => return Err(Error::Invalid(ERR_NOT_A_VAULT)),
        Err(e) => return Err(e),
    };
    let id = header.vault_id.clone();
    if uuid::Uuid::parse_str(&id).is_err() {
        return Err(Error::Format("invalid vault_id".into()));
    }
    let entries = vault_entries(&src)?;
    let final_dir = store.vault_dir(&id);
    if fs::symlink_metadata(&final_dir).is_ok() {
        return Err(Error::Invalid(ERR_ALREADY_ADDED));
    }
    trace::emit(&format!("import {id}: start"));
    let vaults = final_dir
        .parent()
        .ok_or(Error::Invalid(ERR_NOT_A_VAULT))?
        .to_path_buf();
    mkdir(store.root(), true)?;
    mkdir(&vaults, true)?;
    let tmp = vaults.join(format!(".{id}.importing"));
    // Leftover of an interrupted import: ours, start over.
    remove_any(&tmp)?;
    mkdir(&tmp, true)?;
    let r = (|| -> Result<CopyStats> {
        let stats = sync_tree(&src, &tmp, &entries, false, true, notify)?;
        verify(&src, &tmp, &id)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(tmp.join(RESTORED_MARKER))?;
        f.write_all(format!("{}\n", crate::store::now_unix()).as_bytes())?;
        f.sync_all()?;
        sync_dir(&tmp);
        Ok(stats)
    })();
    let stats = match r {
        Ok(s) => s,
        Err(e) => {
            let _ = remove_any(&tmp);
            return Err(e);
        }
    };
    if fs::symlink_metadata(&final_dir).is_ok() {
        let _ = remove_any(&tmp);
        return Err(Error::Invalid(ERR_ALREADY_ADDED));
    }
    fs::rename(&tmp, &final_dir)?;
    sync_dir(&vaults);
    notify(Event::BackupProgress { pct: 100 });
    trace::emit(&format!("import {id}: done, {} files", stats.copied_files));
    store.load(&id)
}

/// True for a vault added from a backup ([`import`]): its `original`
/// refers to the other Mac's profile, never to anything on this Mac.
pub fn restored_from_backup(store: &Store, id: &str) -> bool {
    fs::symlink_metadata(store.vault_dir(id).join(RESTORED_MARKER)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyslot::{new_vault, KdfCost};
    use crate::Browser;
    use std::sync::Mutex;

    const PW: &str = "correct horse battery";

    fn fake_vault(s: &Store, name: &str) -> Header {
        fake_vault_k(s, name).0
    }

    /// A vault on disk; returns its header as loaded (metadata sealed) and key.
    fn fake_vault_k(s: &Store, name: &str) -> (Header, crate::keyslot::UnlockedKey) {
        let nv = new_vault(name, Browser::Brave, PW, KdfCost::FAST)
            .unwrap()
            .0;
        let h = nv.header;
        let dir = s.vault_dir(&h.vault_id);
        mkdir(&dir, true).unwrap();
        let img = dir.join(IMAGE_DIR);
        fs::create_dir_all(img.join("bands")).unwrap();
        fs::write(img.join("Info.plist"), "<plist/>").unwrap();
        fs::write(img.join("token"), [7u8; 100]).unwrap();
        for b in 0..4 {
            fs::write(
                img.join("bands").join(format!("{b:x}")),
                vec![b as u8; 4096],
            )
            .unwrap();
        }
        s.save_header(&h).unwrap();
        s.save_header(&h).unwrap(); // also writes header.json.bak
        (s.load(&h.vault_id).unwrap(), nv.key)
    }

    fn set_old_mtime(p: &Path) {
        let f = OpenOptions::new().write(true).open(p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
    }

    fn locked(_: &str) -> bool {
        false
    }

    struct Fx {
        _d: tempfile::TempDir,
        store: Store,
        drive: PathBuf,
        h: Header,
        key: crate::keyslot::UnlockedKey,
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let store = Store::new(d.path().join("store")).with_index_key(crate::index::memory_key);
        let drive = d.path().join("drive");
        fs::create_dir_all(&drive).unwrap();
        let (h, key) = fake_vault_k(&store, "Work: Brave/1");
        // Source files are "old", so a rewrite is detectable by mtime.
        for e in vault_entries(&store.vault_dir(&h.vault_id)).unwrap() {
            if !e.dir {
                set_old_mtime(&store.vault_dir(&h.vault_id).join(&e.rel));
            }
        }
        Fx {
            _d: d,
            store,
            drive,
            h,
            key,
        }
    }

    fn export_t(f: &Fx) -> Result<Exported> {
        export_with(
            &f.store,
            &f.h.vault_id,
            &f.drive,
            &locked,
            &crate::events::ignore,
        )
    }

    #[test]
    fn folder_name_has_no_vault_name() {
        let id = "8b4c7f0e-7a63-4d55-9a1e-2f0d9d3b6a11";
        assert_eq!(backup_folder_name(id), "vault-8b4c7f0e.bvault");
        assert_eq!(backup_folder_name("../x"), "vault-.bvault");
    }

    #[test]
    fn first_backup_copies_everything_and_verifies() {
        let f = fx();
        let pcts = Mutex::new(vec![]);
        let notify = |e: Event| {
            if let Event::BackupProgress { pct } = e {
                pcts.lock().unwrap().push(pct);
            }
        };
        let out = export_with(&f.store, &f.h.vault_id, &f.drive, &locked, &notify).unwrap();
        assert_eq!(out.path, f.drive.join(backup_folder_name(&f.h.vault_id)));
        // Info.plist, token, 4 bands, header.json.bak, header.json.
        assert_eq!(out.stats.copied_files, 8);
        assert_eq!(out.stats.unchanged_files, 0);
        assert!(!out.path.join(INCOMPLETE_MARKER).exists());
        assert!(!f
            .drive
            .join(format!(".{}.bvault-partial", f.h.vault_id))
            .exists());
        assert_eq!(Header::load(&out.path).unwrap(), f.h);
        verify(&f.store.vault_dir(&f.h.vault_id), &out.path, &f.h.vault_id).unwrap();
        let pcts = pcts.into_inner().unwrap();
        assert_eq!(pcts.last(), Some(&100));
        assert!(pcts.windows(2).all(|w| w[0] <= w[1]));
        // mtimes preserved
        let a = fs::metadata(f.store.image_path(&f.h.vault_id).join("bands/0")).unwrap();
        let b = fs::metadata(out.path.join(IMAGE_DIR).join("bands/0")).unwrap();
        assert!(same_mtime(a.modified().unwrap(), b.modified().unwrap()));
    }

    #[test]
    fn second_backup_copies_only_changes_and_removes_deleted_bands() {
        let f = fx();
        let first = export_t(&f).unwrap();
        let bands = f.store.image_path(&f.h.vault_id).join("bands");
        fs::write(bands.join("1"), vec![9u8; 4096]).unwrap(); // same size, new mtime
        fs::write(bands.join("4"), vec![1u8; 10]).unwrap(); // new band
        fs::remove_file(bands.join("3")).unwrap(); // band gone
        let second = export_t(&f).unwrap();
        assert_eq!(second.path, first.path);
        // band 1, band 4, header.json.bak, header.json
        assert_eq!(second.stats.copied_files, 4);
        assert_eq!(
            second.stats.copied_bytes,
            4096 + 10
                + 2 * fs::metadata(f.store.vault_dir(&f.h.vault_id).join(HEADER_FILE))
                    .unwrap()
                    .len()
        );
        assert_eq!(second.stats.unchanged_files, 4); // Info.plist, token, bands 0, 2
        assert_eq!(second.stats.removed, 1);
        let dst = second.path.join(IMAGE_DIR).join("bands");
        assert!(!dst.join("3").exists());
        assert_eq!(fs::read(dst.join("1")).unwrap(), vec![9u8; 4096]);
        assert!(dst.join("4").exists());
        // Nothing changed: nothing but the header files is copied.
        let third = export_t(&f).unwrap();
        assert_eq!(third.stats.copied_files, 2);
        assert_eq!(third.stats.removed, 0);
    }

    #[test]
    fn legacy_named_backup_folder_is_reused_and_picking_it_works() {
        let f = fx();
        let first = export_t(&f).unwrap();
        // A backup made by an older version, named after the vault.
        let legacy = f.drive.join("Work_ Brave_1 (8b4c7f0e).bvault");
        fs::rename(&first.path, &legacy).unwrap();
        assert_eq!(export_t(&f).unwrap().path, legacy);
        // The user picked the .bvault folder itself.
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            &legacy,
            &locked,
            &crate::events::ignore,
        )
        .unwrap();
        assert_eq!(r.path, legacy);
        assert!(!f.drive.join(backup_folder_name(&f.h.vault_id)).exists());
    }

    #[test]
    fn backup_on_drive_never_names_the_vault() {
        let f = fx();
        let out = export_t(&f).unwrap();
        let name = out.path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            name.starts_with("vault-") && name.ends_with(".bvault"),
            "{name}"
        );
        let mut all = vec![];
        walk(&f.drive, Path::new(""), &mut all).unwrap();
        for e in &all {
            let rel = e.rel.to_string_lossy();
            assert!(!rel.contains("Work") && !rel.contains("Brave"), "{rel}");
            if !e.dir {
                let bytes = fs::read(f.drive.join(&e.rel)).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("Work"), "{rel} names the vault");
            }
        }
    }

    #[test]
    fn imported_v2_backup_is_locked_until_first_unlock() {
        let f = fx();
        assert_eq!(f.store.label(&f.h).unwrap().name, "Work: Brave/1");
        export_t(&f).unwrap();
        let d = tempfile::tempdir().unwrap();
        // Another Mac: its own index key, nothing known about this vault.
        let other = Store::new(d.path().join("s")).with_index_key(crate::index::other_memory_key);
        let h = import(&other, &f.drive, &crate::events::ignore).unwrap();
        assert!(h.meta_locked());
        let listed = other.list_labeled().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].label.is_none(), "shown as 'Locked vault'");
        assert!(matches!(
            other.resolve("Work: Brave/1"),
            Err(Error::NotFound)
        ));
        // First unlock on the new Mac fills its index.
        let opened = other.upgrade_header(&h.vault_id, &f.key).unwrap();
        assert_eq!(opened.meta().unwrap().name, "Work: Brave/1");
        let label = other.list_labeled().unwrap().remove(0).label.unwrap();
        assert_eq!(label.name, "Work: Brave/1");
        assert_eq!(label.browser, Browser::Brave);
        assert_eq!(other.resolve("work: brave/1").unwrap().vault_id, h.vault_id);
    }

    #[test]
    fn destination_with_other_vault_is_refused() {
        let f = fx();
        let other = fake_vault(&f.store, "Other");
        let out = export_with(
            &f.store,
            &other.vault_id,
            &f.drive,
            &locked,
            &crate::events::ignore,
        )
        .unwrap();
        // Put the other vault's backup where this vault's would go.
        fs::rename(&out.path, f.drive.join(backup_folder_name(&f.h.vault_id))).unwrap();
        // The user picks that folder for this vault:
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            &f.drive.join(backup_folder_name(&f.h.vault_id)),
            &locked,
            &crate::events::ignore,
        );
        assert!(matches!(r, Err(Error::Invalid(ERR_OTHER_VAULT))));
        // A non-empty folder without a header at the target name is not ours.
        let d2 = f.drive.join("d2");
        fs::create_dir_all(d2.join(backup_folder_name(&f.h.vault_id)).join("x")).unwrap();
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            &d2,
            &locked,
            &crate::events::ignore,
        );
        assert!(matches!(r, Err(Error::Invalid(ERR_OTHER_VAULT))));
    }

    #[test]
    fn unlocked_vault_is_refused() {
        let f = fx();
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            &f.drive,
            &|_| true,
            &crate::events::ignore,
        );
        assert!(matches!(r, Err(Error::Invalid(ERR_UNLOCKED))));
        assert_eq!(fs::read_dir(&f.drive).unwrap().count(), 0);
        // Unlocked during the copy: refused, and the copy stays unimportable.
        let calls = Mutex::new(0);
        let flip = |_: &str| {
            let mut c = calls.lock().unwrap();
            *c += 1;
            *c > 1
        };
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            &f.drive,
            &flip,
            &crate::events::ignore,
        );
        assert!(matches!(r, Err(Error::Invalid(ERR_UNLOCKED))));
        let partial = f.drive.join(format!(".{}.bvault-partial", f.h.vault_id));
        assert!(partial.join(INCOMPLETE_MARKER).exists());
        let other = Store::new(f.drive.join("other-store"));
        assert!(matches!(
            import(&other, &partial, &crate::events::ignore),
            Err(Error::Invalid(ERR_INCOMPLETE))
        ));
        // The next run resumes and finishes.
        let ok = export_t(&f).unwrap();
        assert!(!partial.exists());
        assert!(!ok.path.join(INCOMPLETE_MARKER).exists());
    }

    #[test]
    fn destination_inside_store_is_refused() {
        let f = fx();
        let r = export_with(
            &f.store,
            &f.h.vault_id,
            f.store.root(),
            &locked,
            &crate::events::ignore,
        );
        assert!(matches!(r, Err(Error::Invalid(ERR_DEST_IN_STORE))));
    }

    #[test]
    fn symlinks_are_skipped() {
        let f = fx();
        let img = f.store.image_path(&f.h.vault_id);
        std::os::unix::fs::symlink("/etc/passwd", img.join("bands/link")).unwrap();
        let out = export_t(&f).unwrap();
        assert!(fs::symlink_metadata(out.path.join(IMAGE_DIR).join("bands/link")).is_err());
    }

    #[test]
    fn import_into_empty_store_and_duplicate_refused() {
        let f = fx();
        let out = export_t(&f).unwrap();
        let d = tempfile::tempdir().unwrap();
        let other = Store::new(d.path().join("store2"));
        // Picking the drive (parent of the single .bvault) works too.
        let h = import(&other, &f.drive, &crate::events::ignore).unwrap();
        assert_eq!(h, f.h);
        assert_eq!(other.list().unwrap().len(), 1);
        assert!(restored_from_backup(&other, &h.vault_id));
        assert!(!restored_from_backup(&f.store, &h.vault_id));
        let dir = other.vault_dir(&h.vault_id);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let band = dir.join(IMAGE_DIR).join("bands/0");
        assert_eq!(
            fs::metadata(&band).unwrap().permissions().mode() & 0o777,
            0o600
        );
        verify(&out.path, &dir, &h.vault_id).unwrap();
        assert!(!other
            .root()
            .join("vaults")
            .join(format!(".{}.importing", h.vault_id))
            .exists());
        assert!(matches!(
            import(&other, &out.path, &crate::events::ignore),
            Err(Error::Invalid(ERR_ALREADY_ADDED))
        ));
        // Into the store it came from: also "already added".
        assert!(matches!(
            import(&f.store, &out.path, &crate::events::ignore),
            Err(Error::Invalid(ERR_ALREADY_ADDED))
        ));
    }

    #[test]
    fn restored_vault_never_offers_deleting_local_paths() {
        let f = fx();
        export_t(&f).unwrap();
        let d = tempfile::tempdir().unwrap();
        let other = Store::new(d.path().join("s"));
        let h = import(&other, &f.drive, &crate::events::ignore).unwrap();
        let roots = crate::profiles::Roots::for_home(d.path());
        let mut header = h.clone();
        header.open_meta(f.key.vmk()).unwrap();
        let session = crate::store::Unlocked {
            header,
            mountpoint: d.path().join("mnt"),
            header_intact: true,
            key: crate::keyslot::unlocked(&h, f.key.vmk().clone()),
            cleanup_verifier: None,
        };
        assert!(matches!(
            crate::profiles::cleanup_preview(&other, &roots, &session),
            Err(Error::Invalid(crate::profiles::ERR_ORIGINAL_ELSEWHERE))
        ));
    }

    #[test]
    fn corrupted_or_missing_backup_is_refused() {
        let f = fx();
        let out = export_t(&f).unwrap();
        let d = tempfile::tempdir().unwrap();
        let other = Store::new(d.path().join("s"));
        fs::write(
            out.path.join(HEADER_FILE),
            b"{\"version\": 1, \"vault_id\": ",
        )
        .unwrap();
        assert!(matches!(
            import(&other, &out.path, &crate::events::ignore),
            Err(Error::Format(_))
        ));
        let mut h: serde_json::Value = serde_json::from_slice(&f.h.to_json().unwrap()).unwrap();
        h["version"] = serde_json::json!(99);
        fs::write(out.path.join(HEADER_FILE), serde_json::to_vec(&h).unwrap()).unwrap();
        assert!(matches!(
            import(&other, &out.path, &crate::events::ignore),
            Err(Error::Format(_))
        ));
        let mut h = f.h.clone();
        h.vault_id = "../../etc".into();
        fs::write(out.path.join(HEADER_FILE), h.to_json().unwrap()).unwrap();
        assert!(matches!(
            import(&other, &out.path, &crate::events::ignore),
            Err(Error::Format(_))
        ));
        // Header fine, image missing.
        f.h.save(&out.path).unwrap();
        fs::remove_dir_all(out.path.join(IMAGE_DIR)).unwrap();
        assert!(matches!(
            import(&other, &out.path, &crate::events::ignore),
            Err(Error::Invalid(ERR_NOT_A_VAULT))
        ));
        assert!(matches!(
            import(&other, d.path(), &crate::events::ignore),
            Err(Error::Invalid(ERR_NOT_A_VAULT))
        ));
        assert!(other.list().unwrap().is_empty());
    }

    #[test]
    fn verify_detects_size_mismatch() {
        let f = fx();
        let out = export_t(&f).unwrap();
        let src = f.store.vault_dir(&f.h.vault_id);
        verify(&src, &out.path, &f.h.vault_id).unwrap();
        fs::write(out.path.join(IMAGE_DIR).join("bands/2"), [0u8; 10]).unwrap();
        assert!(matches!(
            verify(&src, &out.path, &f.h.vault_id),
            Err(Error::Invalid(ERR_VERIFY))
        ));
        fs::remove_file(out.path.join(IMAGE_DIR).join("bands/2")).unwrap();
        assert!(verify(&src, &out.path, &f.h.vault_id).is_err());
        // The next backup repairs it.
        export_t(&f).unwrap();
        verify(&src, &out.path, &f.h.vault_id).unwrap();
    }
}
