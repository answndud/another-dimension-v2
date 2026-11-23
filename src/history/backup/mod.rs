//! Backup export, import and verification, in every format the program has written.

mod bundle;
mod legacy;
mod stream;

use super::*;
pub(crate) use bundle::*;
pub(crate) use legacy::*;
pub(crate) use stream::*;

impl History {
    #[cfg(test)]
    pub fn export_backup(
        identity: &Identity,
        peer_id: &str,
        password: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let (_, messages, _) = Self::open(identity, peer_id)?;
        encode_backup(identity, peer_id, &messages, password)
    }

    /// Write a versioned, independently authenticated backup frame by frame.
    /// The largest plaintext buffer is one stored message plus its AEAD tag.
    pub(crate) fn export_backup_stream<W: Write>(
        identity: &Identity,
        peer_id: &str,
        password: Option<&str>,
        output: &mut W,
    ) -> io::Result<u64> {
        let links = backup_links_for(identity, peer_id)?;
        let mut reader = Self::reader_for_identity_copy(identity, peer_id)?;
        let mut writer = BackupStreamWriter::new(identity, peer_id, password, &links, output)?;
        let mut count = 0u64;
        while let Some(message) = reader.next_record()? {
            writer.write_message(&message)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("backup message count overflow"))?;
        }
        writer.finish(count, &links)?;
        Ok(count)
    }

    /// ADPACK2 stores independently authenticated ADBACK6 children. A child
    /// is first written to a private temporary file so its length can be
    /// emitted without buffering the backup in memory.
    pub(crate) fn export_backup_bundle_stream<W: Write>(
        identity: &Identity,
        peer_ids: &[String],
        output: &mut W,
    ) -> io::Result<()> {
        if peer_ids.is_empty() || peer_ids.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid conversation selection",
            ));
        }
        let mut unique = HashSet::new();
        for peer_id in peer_ids {
            validate_peer_id(peer_id)?;
            if !unique.insert(peer_id.to_ascii_lowercase()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate conversation",
                ));
            }
        }
        let directory = Self::backup_transfer_directory(identity)?;
        let mut active_child_path = None;
        let result = (|| {
            let mut bundle_id = [0; 16];
            crate::random::fill(&mut bundle_id)?;
            let mut header = Vec::with_capacity(8 + bundle_id.len() + 4);
            header.extend_from_slice(BACKUP_STREAM_BUNDLE_MAGIC);
            header.extend_from_slice(&bundle_id);
            header.extend_from_slice(&(peer_ids.len() as u32).to_be_bytes());
            output.write_all(&header)?;
            let bundle_key = derive_backup_bundle_key(identity, &bundle_id)?;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(bundle_key.as_ref())
                .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
            mac.update(&header);
            for peer_id in peer_ids {
                let suffix = crate::hex::encode(&random_nonce()?);
                let child_name = format!("bundle-child-{suffix}.tmp");
                let child_path = directory.join(&child_name);
                let (_, mut child) = Self::create_backup_transfer_file(identity, &child_name)?;
                active_child_path = Some(child_path.clone());
                Self::export_backup_stream(identity, peer_id, None, &mut child)?;
                child.flush()?;
                child.sync_all()?;
                let length = child.metadata()?.len();
                let length_bytes = length.to_be_bytes();
                output.write_all(&length_bytes)?;
                mac.update(&length_bytes);
                child.seek(SeekFrom::Start(0))?;
                let mut buffer = [0; 64 * 1024];
                loop {
                    let read = child.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    output.write_all(&buffer[..read])?;
                    mac.update(&buffer[..read]);
                }
                drop(child);
                std::fs::remove_file(&child_path)?;
                active_child_path = None;
            }
            output.write_all(&mac.finalize().into_bytes())?;
            output.flush()
        })();
        if result.is_err() {
            if let Some(child_path) = active_child_path {
                let _ = std::fs::remove_file(child_path);
            }
        }
        result
    }

    pub(crate) fn backup_transfer_directory(identity: &Identity) -> io::Result<PathBuf> {
        backup_transfer_workspace(identity).map(|workspace| workspace.path.clone())
    }

    pub(crate) fn create_backup_transfer_file(
        identity: &Identity,
        name: &str,
    ) -> io::Result<(PathBuf, File)> {
        if !is_backup_transfer_temp_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid backup transfer temporary filename",
            ));
        }
        let workspace = backup_transfer_workspace(identity)?;
        let path = workspace.path.join(name);
        let file = crate::fsutil::private_options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        if let Err(error) = set_private_file(&file)
            .and_then(|()| register_backup_transfer_file(&workspace, name, &file))
        {
            drop(file);
            let cleanup = remove_file(&path);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(io::Error::other(format!(
                    "backup transfer file setup failed ({error}); temporary cleanup failed ({cleanup_error})"
                ))),
            };
        }
        Ok((path, file))
    }

    /// Remove only transfer files whose owner lock proves that their process
    /// has exited and whose exact names were recorded in its private manifest.
    pub(crate) fn cleanup_abandoned_backup_transfers() -> io::Result<usize> {
        let root = data_directory()?;
        if !root.exists() {
            return Ok(0);
        }
        let mut removed = 0;
        for identity_entry in read_dir(&root)? {
            let identity_entry = identity_entry?;
            if !identity_entry.file_type()?.is_dir() {
                continue;
            }
            let transfer_root = identity_entry.path().join(".backup-transfer");
            match cleanup_stale_transfer_workspaces(&transfer_root) {
                Ok(count) => removed += count,
                Err(error) => eprintln!("백업 전송 임시 파일 정리 실패: {error}"),
            }
        }
        Ok(removed)
    }

    pub(crate) fn backup_transfer_base_directory(identity: &Identity) -> io::Result<PathBuf> {
        let directory = data_directory()?
            .join(identity.public_id())
            .join(".backup-transfer");
        crate::fsutil::create_private_dir_all(&directory)?;
        if !std::fs::symlink_metadata(&directory)?.file_type().is_dir() {
            return Err(invalid_data(
                "backup transfer directory is not a real directory",
            ));
        }
        set_private_directory(&directory)?;
        Ok(directory)
    }

    pub(crate) fn backup_transfer_workspace_id(identity: &Identity) -> io::Result<String> {
        backup_transfer_workspace(identity).map(|workspace| workspace.owner_id.clone())
    }

    /// Imports a backup file. Formats with weaker guarantees are rejected; use
    /// [`Self::import_backup_file_with_policy`] after the user has confirmed them.
    #[cfg(test)]
    pub(crate) fn import_backup_file(
        identity: &Identity,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> io::Result<Vec<(String, usize, bool)>> {
        Self::import_backup_file_with_policy(identity, path, password, LegacyBackupPolicy::Reject)
    }

    pub(crate) fn import_backup_file_with_policy(
        identity: &Identity,
        path: &std::path::Path,
        password: Option<&str>,
        policy: LegacyBackupPolicy,
    ) -> io::Result<Vec<(String, usize, bool)>> {
        let mut file = File::open(path)?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;
        require_legacy_opt_in(&magic, policy)?;
        if &magic == BACKUP_STREAM_MAGIC || &magic == BACKUP_STREAM_V6_MAGIC {
            let (peer_id, mut staging, links) = if &magic == BACKUP_STREAM_MAGIC {
                decode_backup_stream(identity, &mut file, password)?
            } else {
                decode_backup_stream_v6(identity, &mut file, password)?
            };
            ensure_stream_eof(&mut file)?;
            let count = staging.count();
            import_verified_staging(identity, &peer_id, &mut staging, &links)?;
            staging.cleanup()?;
            return Ok(vec![(
                peer_id,
                count as usize,
                !links.local.is_empty() || !links.peer.is_empty(),
            )]);
        }
        if &magic == BACKUP_STREAM_BUNDLE_MAGIC {
            return import_backup_bundle_stream(identity, &mut file);
        }
        if &magic == BACKUP_STREAM_BUNDLE_V2_MAGIC {
            return import_backup_bundle_stream_v2(identity, &mut file);
        }
        let bytes = read_legacy_backup(&mut file)?;
        if bytes.starts_with(BACKUP_BUNDLE_MAGIC) {
            return Self::import_backup_bundle_with_info(identity, &bytes);
        }
        Ok(vec![Self::import_backup_with_info(
            identity, &bytes, password,
        )?])
    }

    pub(crate) fn verify_backup_file(
        identity: &Identity,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> io::Result<(String, u64)> {
        let mut file = File::open(path)?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;
        if &magic == BACKUP_STREAM_MAGIC || &magic == BACKUP_STREAM_V6_MAGIC {
            let (peer_id, staging, _) = if &magic == BACKUP_STREAM_MAGIC {
                decode_backup_stream(identity, &mut file, password)?
            } else {
                decode_backup_stream_v6(identity, &mut file, password)?
            };
            ensure_stream_eof(&mut file)?;
            let result = (peer_id, staging.count());
            staging.cleanup()?;
            return Ok(result);
        }
        let bytes = read_legacy_backup(&mut file)?;
        let (peer_id, count) = Self::verify_backup(identity, &bytes, password)?;
        Ok((peer_id, count as u64))
    }

    /// Re-encrypts a backup under a new identity. Re-protecting would carry the
    /// content of a weak-format backup into a stronger container, so the same
    /// legacy confirmation applies as for importing.
    #[cfg(test)]
    pub(crate) fn reprotect_backup_file(
        previous_identity: &Identity,
        replacement_identity: &Identity,
        source: &std::path::Path,
        output: &mut File,
        previous_password: Option<&str>,
        replacement_password: Option<&str>,
    ) -> io::Result<u64> {
        Self::reprotect_backup_file_with_policy(
            previous_identity,
            replacement_identity,
            source,
            output,
            previous_password,
            replacement_password,
            LegacyBackupPolicy::Reject,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reprotect_backup_file_with_policy(
        previous_identity: &Identity,
        replacement_identity: &Identity,
        source: &std::path::Path,
        output: &mut File,
        previous_password: Option<&str>,
        replacement_password: Option<&str>,
        policy: LegacyBackupPolicy,
    ) -> io::Result<u64> {
        let mut input = File::open(source)?;
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        input.seek(SeekFrom::Start(0))?;
        require_legacy_opt_in(&magic, policy)?;
        if &magic != BACKUP_STREAM_MAGIC && &magic != BACKUP_STREAM_V6_MAGIC {
            let bytes = read_legacy_backup(&mut input)?;
            let bytes = Self::reprotect_backup(
                previous_identity,
                replacement_identity,
                &bytes,
                previous_password,
                replacement_password,
            )?;
            output.write_all(&bytes)?;
            return Ok(0);
        }
        let (peer_id, mut staging, mut links) = if &magic == BACKUP_STREAM_MAGIC {
            decode_backup_stream(previous_identity, &mut input, previous_password)?
        } else {
            decode_backup_stream_v6(previous_identity, &mut input, previous_password)?
        };
        ensure_stream_eof(&mut input)?;
        let previous_id = previous_identity.public_id();
        let replacement_id = replacement_identity.public_id();
        if previous_id != replacement_id {
            if !links.origins.contains(&previous_id) {
                links.origins.push(previous_id.clone());
            }
            links.local.insert(previous_id);
        }
        let count = staging.count();
        export_staging_stream(
            replacement_identity,
            &peer_id,
            replacement_password,
            &links,
            &mut staging,
            output,
        )?;
        staging.cleanup()?;
        Ok(count)
    }

    /// Bundle separately authenticated conversation backups. Each child stays
    /// encrypted with the existing backup format, preserving import compatibility.
    #[cfg(test)]
    pub fn export_backup_bundle(identity: &Identity, peer_ids: &[String]) -> io::Result<Vec<u8>> {
        if peer_ids.is_empty() || peer_ids.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid conversation selection",
            ));
        }
        let mut bundle = Vec::new();
        bundle.extend_from_slice(BACKUP_BUNDLE_MAGIC);
        bundle.extend_from_slice(&(peer_ids.len() as u32).to_be_bytes());
        let mut unique = HashSet::new();
        for peer_id in peer_ids {
            validate_peer_id(peer_id)?;
            if !unique.insert(peer_id.to_ascii_lowercase()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate conversation",
                ));
            }
            let backup = Self::export_backup(identity, peer_id, None)?;
            let backup_len = u32::try_from(backup.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "backup is too large"))?;
            if bundle.len().saturating_add(4 + backup.len()) > MAX_LEGACY_BACKUP_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "backup bundle is too large",
                ));
            }
            bundle.extend_from_slice(&backup_len.to_be_bytes());
            bundle.extend_from_slice(&backup);
        }
        Ok(bundle)
    }

    pub fn import_backup_bundle(
        identity: &Identity,
        bundle: &[u8],
    ) -> io::Result<Vec<(String, usize)>> {
        Ok(Self::import_backup_bundle_with_info(identity, bundle)?
            .into_iter()
            .map(|(peer, count, _)| (peer, count))
            .collect())
    }

    pub fn import_backup_bundle_with_info(
        identity: &Identity,
        bundle: &[u8],
    ) -> io::Result<Vec<(String, usize, bool)>> {
        if bundle.len() > MAX_LEGACY_BACKUP_BYTES
            || !bundle.starts_with(BACKUP_BUNDLE_MAGIC)
            || bundle.len() < 12
        {
            return Err(invalid_data("invalid backup bundle"));
        }
        let count = u32::from_be_bytes(bundle[8..12].try_into().expect("fixed slice")) as usize;
        if count == 0 || count > 128 {
            return Err(invalid_data("invalid backup bundle count"));
        }
        let mut cursor = 12;
        let mut entries = Vec::with_capacity(count);
        let mut unique = HashSet::new();
        for _ in 0..count {
            if bundle.len().saturating_sub(cursor) < 4 {
                return Err(invalid_data("truncated backup bundle"));
            }
            let len =
                u32::from_be_bytes(bundle[cursor..cursor + 4].try_into().expect("fixed slice"))
                    as usize;
            cursor += 4;
            if len > MAX_LEGACY_BACKUP_BYTES || bundle.len().saturating_sub(cursor) < len {
                return Err(invalid_data("truncated backup bundle"));
            }
            let (peer_id, messages, _) =
                decode_backup_with_links(identity, &bundle[cursor..cursor + len], None)?;
            if !unique.insert(peer_id.clone()) {
                return Err(invalid_data("duplicate conversation in backup bundle"));
            }
            entries.push((peer_id, messages));
            cursor += len;
        }
        if cursor != bundle.len() {
            return Err(invalid_data("unexpected backup bundle data"));
        }
        // Validate every encrypted child before the first local history is changed.
        let mut imported = Vec::with_capacity(entries.len());
        cursor = 12;
        for (peer_id, _) in entries {
            let result = (|| {
                let len =
                    u32::from_be_bytes(bundle[cursor..cursor + 4].try_into().expect("fixed slice"))
                        as usize;
                cursor += 4;
                let (_, messages, links) =
                    decode_backup_with_links(identity, &bundle[cursor..cursor + len], None)?;
                cursor += len;
                let (mut history, existing, _) = Self::open(identity, &peer_id)?;
                let merged = merge_snapshot(existing.clone(), messages)?;
                let count = merged.len();
                let has_links = !links.local.is_empty() || !links.peer.is_empty();
                history.replace(&merged)?;
                if let Err(error) = apply_backup_links(identity, &peer_id, &links) {
                    return match history.replace(&existing) {
                        Ok(()) => Err(error),
                        Err(rollback) => Err(io::Error::other(format!(
                            "{error}; conversation rollback failed ({rollback})"
                        ))),
                    };
                }
                Ok((peer_id, count, has_links))
            })();
            match result {
                Ok(item) => imported.push(item),
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "backup bundle stopped after {} conversations; {error}",
                        imported.len()
                    )))
                }
            }
        }
        Ok(imported)
    }

    /// Re-encrypt an existing portable backup for a new identity without
    /// importing it into either local history store or modifying the source.
    pub fn reprotect_backup(
        previous_identity: &Identity,
        replacement_identity: &Identity,
        backup: &[u8],
        previous_password: Option<&str>,
        replacement_password: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let (peer_id, messages, mut links) =
            decode_backup_with_links(previous_identity, backup, previous_password)?;
        // Re-protection is an explicit act by the old identity holder. Preserve
        // that authenticated identity as a local alias so proofs created before
        // the replacement remain verifiable under the new backup key.
        let previous_id = previous_identity.public_id();
        let replacement_id = replacement_identity.public_id();
        if previous_id != replacement_id {
            if !links.origins.contains(&previous_id) {
                links.origins.push(previous_id.clone());
            }
            links.local.insert(previous_id);
        }
        encode_backup_with_links(
            replacement_identity,
            &peer_id,
            &messages,
            replacement_password,
            &links,
        )
    }

    /// Authenticate a portable backup without importing or changing local history.
    pub fn verify_backup(
        identity: &Identity,
        backup: &[u8],
        password: Option<&str>,
    ) -> io::Result<(String, usize)> {
        let (peer_id, messages) = decode_backup(identity, backup, password)?;
        Ok((peer_id, messages.len()))
    }

    pub fn import_backup(
        identity: &Identity,
        backup: &[u8],
        password: Option<&str>,
    ) -> io::Result<(String, usize)> {
        let (peer_id, count, _) = Self::import_backup_with_info(identity, backup, password)?;
        Ok((peer_id, count))
    }

    pub fn import_backup_with_info(
        identity: &Identity,
        backup: &[u8],
        password: Option<&str>,
    ) -> io::Result<(String, usize, bool)> {
        let (peer_id, imported, links) = decode_backup_with_links(identity, backup, password)?;

        let (mut history, existing, _) = Self::open(identity, &peer_id)?;
        let merged = merge_snapshot(existing.clone(), imported)?;
        let count = merged.len();
        let has_links = !links.local.is_empty() || !links.peer.is_empty();
        history.replace(&merged)?;
        if let Err(error) = apply_backup_links(identity, &peer_id, &links) {
            return match history.replace(&existing) {
                Ok(()) => Err(error),
                Err(rollback) => Err(io::Error::other(format!("backup relationship restore failed ({error}); conversation rollback failed ({rollback})"))),
            };
        }
        Ok((peer_id, count, has_links))
    }
}
