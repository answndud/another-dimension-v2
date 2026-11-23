//! The private directory in which backup transfers are staged.

use super::*;

pub(crate) struct BackupTransferWorkspace {
    pub(crate) path: PathBuf,
    pub(crate) owner_id: String,
    pub(crate) _lock: File,
    pub(crate) manifest_lock: Mutex<()>,
}

pub(crate) fn backup_transfer_workspace(
    identity: &Identity,
) -> io::Result<Arc<BackupTransferWorkspace>> {
    let root = History::backup_transfer_base_directory(identity)?;
    let owners = BACKUP_TRANSFER_WORKSPACES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut owners = owners
        .lock()
        .map_err(|_| io::Error::other("backup transfer owner state unavailable"))?;
    if let Some(workspace) = owners.get(&root) {
        return Ok(Arc::clone(workspace));
    }
    if let Err(error) = cleanup_stale_transfer_workspaces(&root) {
        eprintln!("백업 전송 임시 파일 정리 실패: {error}");
    }
    let workspace = Arc::new(create_backup_transfer_workspace(&root)?);
    owners.insert(root, Arc::clone(&workspace));
    Ok(workspace)
}

pub(crate) fn create_backup_transfer_workspace(
    root: &std::path::Path,
) -> io::Result<BackupTransferWorkspace> {
    for _ in 0..8 {
        let owner_id = crate::hex::encode(&random_nonce()?);
        let path = root.join(format!(".process-{owner_id}"));
        match crate::fsutil::create_private_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
        if let Err(error) = set_private_directory(&path) {
            let _ = remove_dir(&path);
            return Err(error);
        }
        let lock_path = path.join("owner.lock");
        let lock = match crate::fsutil::private_options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) => {
                let _ = remove_dir(&path);
                return Err(error);
            }
        };
        if let Err(error) = set_private_file(&lock).and_then(|()| lock_transfer_owner(&lock)) {
            drop(lock);
            let _ = remove_file(&lock_path);
            let _ = remove_dir(&path);
            return Err(error);
        }
        let manifest_path = path.join("manifest");
        let mut manifest = match crate::fsutil::private_options()
            .write(true)
            .create_new(true)
            .open(&manifest_path)
        {
            Ok(file) => file,
            Err(error) => {
                drop(lock);
                let _ = remove_file(&lock_path);
                let _ = remove_dir(&path);
                return Err(error);
            }
        };
        if let Err(error) = set_private_file(&manifest) {
            drop(manifest);
            drop(lock);
            let _ = remove_file(&manifest_path);
            let _ = remove_file(&lock_path);
            let _ = remove_dir(&path);
            return Err(error);
        }
        if let Err(error) = manifest
            .write_all(b"ADBT1\n")
            .and_then(|()| manifest.sync_all())
        {
            drop(manifest);
            drop(lock);
            let _ = remove_file(&manifest_path);
            let _ = remove_file(&lock_path);
            let _ = remove_dir(&path);
            return Err(error);
        }
        return Ok(BackupTransferWorkspace {
            path,
            owner_id,
            _lock: lock,
            manifest_lock: Mutex::new(()),
        });
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate backup transfer owner directory",
    ))
}

pub(crate) fn register_backup_transfer_file(
    workspace: &BackupTransferWorkspace,
    name: &str,
    file: &File,
) -> io::Result<()> {
    if !is_backup_transfer_temp_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid backup transfer temporary filename",
        ));
    }
    let _guard = workspace
        .manifest_lock
        .lock()
        .map_err(|_| io::Error::other("backup transfer manifest unavailable"))?;
    let manifest_path = workspace.path.join("manifest");
    let mut manifest = open_manifest_append_nofollow(&manifest_path)?;
    ensure_single_link_owned_file(&manifest)?;
    let (device, inode) = backup_transfer_file_identity(&file.metadata()?)?;
    let line = format!("{name}\t{device}\t{inode}\n");
    manifest.write_all(line.as_bytes())?;
    manifest.sync_all()
}

pub(crate) fn cleanup_stale_transfer_workspaces(root: &std::path::Path) -> io::Result<usize> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_dir() {
        return Err(invalid_data(
            "backup transfer directory is not a real directory",
        ));
    }
    let mut removed = 0;
    for entry in read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(owner_id) = name.strip_prefix(".process-") else {
            continue;
        };
        if !is_hex_string(owner_id, NONCE_BYTES * 2) || !entry.file_type()?.is_dir() {
            continue;
        }
        match cleanup_stale_transfer_workspace(&entry.path()) {
            Ok(true) => removed += 1,
            Ok(false) => {}
            Err(error) => eprintln!("백업 전송 임시 파일 정리 실패: {error}"),
        }
    }
    Ok(removed)
}

pub(crate) fn cleanup_stale_transfer_workspace(path: &std::path::Path) -> io::Result<bool> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Ok(false);
    }
    let lock_path = path.join("owner.lock");
    let lock_metadata = match std::fs::symlink_metadata(&lock_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !lock_metadata.file_type().is_file() {
        return Ok(false);
    }
    let lock = match open_nofollow(&lock_path, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    ensure_single_link_owned_file(&lock)?;
    if !try_lock_transfer_owner(&lock)? {
        return Ok(false);
    }

    let manifest_path = path.join("manifest");
    let mut manifest = match open_nofollow(&manifest_path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    ensure_single_link_owned_file(&manifest)?;
    let mut contents = String::new();
    manifest.read_to_string(&mut contents)?;
    let mut lines = contents.lines();
    if lines.next() != Some("ADBT1") {
        return Err(invalid_data("invalid backup transfer ownership manifest"));
    }
    let mut entries = HashMap::new();
    for line in lines {
        let mut fields = line.split('\t');
        let (Some(name), Some(device), Some(inode), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(invalid_data("invalid backup transfer ownership manifest"));
        };
        if !is_backup_transfer_temp_name(name) {
            return Err(invalid_data("invalid backup transfer ownership manifest"));
        }
        let (Ok(device), Ok(inode)) = (device.parse::<u64>(), inode.parse::<u64>()) else {
            return Err(invalid_data("invalid backup transfer ownership manifest"));
        };
        if entries.insert(name.to_owned(), (device, inode)).is_some() {
            return Err(invalid_data("duplicate backup transfer manifest entry"));
        }
    }
    let mut owned_files = Vec::new();
    for (name, expected_identity) in entries {
        let file_path = path.join(name);
        let file_metadata = match std::fs::symlink_metadata(&file_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !file_metadata.file_type().is_file() || !is_single_link_owned_metadata(&file_metadata) {
            return Err(invalid_data(
                "backup transfer file ownership could not be verified",
            ));
        }
        if backup_transfer_file_identity(&file_metadata)? != expected_identity {
            return Err(invalid_data(
                "backup transfer file identity does not match its manifest",
            ));
        }
        owned_files.push(file_path);
    }
    for file_path in owned_files {
        remove_file(file_path)?;
    }
    remove_file(&lock_path)?;
    drop(manifest);
    remove_file(&manifest_path)?;
    if read_dir(path)?.next().is_none() {
        remove_dir(path)?;
    }
    Ok(true)
}

pub(crate) fn is_backup_transfer_temp_name(name: &str) -> bool {
    if let Some(id) = name.strip_suffix(".backup") {
        return is_hex_string(id, 64);
    }
    ["bundle-child-", "bundle-import-child-"]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .and_then(|suffix| suffix.strip_suffix(".tmp"))
                .is_some_and(|id| is_hex_string(id, NONCE_BYTES * 2))
        })
}

pub(crate) fn is_hex_string(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn open_nofollow(path: &std::path::Path, read_write: bool) -> io::Result<File> {
    let mut options = crate::fsutil::private_options();
    options.read(true).write(read_write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(crate) fn open_manifest_append_nofollow(path: &std::path::Path) -> io::Result<File> {
    let mut options = crate::fsutil::private_options();
    options.append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(crate) fn ensure_single_link_owned_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !is_single_link_owned_metadata(&metadata) {
        return Err(invalid_data(
            "backup transfer file ownership could not be verified",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn backup_transfer_file_identity(
    metadata: &std::fs::Metadata,
) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
pub(crate) fn backup_transfer_file_identity(
    _metadata: &std::fs::Metadata,
) -> io::Result<(u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "backup transfer cleanup ownership checks require Unix file identities",
    ))
}

#[cfg(unix)]
pub(crate) fn is_single_link_owned_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub(crate) fn is_single_link_owned_metadata(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_file()
}

pub(crate) fn lock_transfer_owner(file: &File) -> io::Result<()> {
    if try_lock_transfer_owner(file)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "backup transfer owner lock is already held",
        ))
    }
}

#[cfg(unix)]
pub(crate) fn try_lock_transfer_owner(file: &File) -> io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
pub(crate) fn try_lock_transfer_owner(_file: &File) -> io::Result<bool> {
    Ok(false)
}
