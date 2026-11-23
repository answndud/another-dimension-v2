//! Multi-conversation bundles (ADPACK1-3).

use super::*;

pub(crate) fn import_backup_bundle_stream_v2<R: Read>(
    identity: &Identity,
    input: &mut R,
) -> io::Result<Vec<(String, usize, bool)>> {
    let mut imported = Vec::new();
    let result = (|| {
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != BACKUP_STREAM_BUNDLE_V2_MAGIC {
            return Err(invalid_data("invalid backup bundle"));
        }
        let mut count_bytes = [0; 4];
        input.read_exact(&mut count_bytes)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count == 0 || count > 128 {
            return Err(invalid_data("invalid backup bundle count"));
        }
        let mut unique = HashSet::new();
        for _ in 0..count {
            let mut len_bytes = [0; 8];
            input.read_exact(&mut len_bytes)?;
            let length = u64::from_be_bytes(len_bytes);
            if length < 8 + 1 + 32 + 1 + 8 + NONCE_BYTES as u64 + 4 + 27 {
                return Err(invalid_data("truncated backup bundle child"));
            }
            let mut child = input.take(length);
            let (peer_id, mut staging, links) =
                decode_backup_stream_v6(identity, &mut child, None)?;
            if child.limit() != 0 {
                return Err(invalid_data("unexpected data in backup bundle child"));
            }
            if !unique.insert(peer_id.clone()) {
                return Err(invalid_data("duplicate conversation in backup bundle"));
            }
            let message_count = staging.count() as usize;
            let has_links = !links.local.is_empty() || !links.peer.is_empty();
            import_verified_staging(identity, &peer_id, &mut staging, &links)?;
            imported.push((peer_id, message_count, has_links));
            staging.cleanup()?;
        }
        ensure_stream_eof(input)?;
        Ok(())
    })();
    result.map_err(|error| partial_bundle_error(imported.len(), error))?;
    Ok(imported)
}

pub(crate) fn partial_bundle_error(applied: usize, error: io::Error) -> io::Error {
    if applied == 0 {
        error
    } else {
        io::Error::other(format!(
            "backup bundle failed after applying {applied} conversation(s): {error}"
        ))
    }
}

pub(crate) fn import_backup_bundle_stream<R: Read>(
    identity: &Identity,
    input: &mut R,
) -> io::Result<Vec<(String, usize, bool)>> {
    let mut imported = Vec::new();
    let mut staged_children = Vec::new();
    let mut validated_children = Vec::new();
    let result = (|| {
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != BACKUP_STREAM_BUNDLE_MAGIC {
            return Err(invalid_data("invalid backup bundle"));
        }
        let mut bundle_id = [0; 16];
        input.read_exact(&mut bundle_id)?;
        let mut count_bytes = [0; 4];
        input.read_exact(&mut count_bytes)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count == 0 || count > 128 {
            return Err(invalid_data("invalid backup bundle count"));
        }
        let mut header = Vec::with_capacity(8 + bundle_id.len() + count_bytes.len());
        header.extend_from_slice(&magic);
        header.extend_from_slice(&bundle_id);
        header.extend_from_slice(&count_bytes);
        let bundle_key = derive_backup_bundle_key(identity, &bundle_id)?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(bundle_key.as_ref())
            .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
        mac.update(&header);
        let mut unique = HashSet::new();
        let directory = History::backup_transfer_directory(identity)?;

        for _ in 0..count {
            let mut length_bytes = [0; 8];
            input.read_exact(&mut length_bytes)?;
            mac.update(&length_bytes);
            let length = u64::from_be_bytes(length_bytes);
            if length < 8 + 1 + 16 + 1 + NONCE_BYTES as u64 + 4 + 8 + 32 + 16 {
                return Err(invalid_data("truncated backup bundle child"));
            }
            let child_name = format!(
                "bundle-import-child-{}.tmp",
                crate::hex::encode(&random_nonce()?)
            );
            let child_path = directory.join(&child_name);
            let child_result = (|| {
                let (_, mut child_file) =
                    History::create_backup_transfer_file(identity, &child_name)?;
                staged_children.push(child_path.clone());
                let mut remaining = length;
                let mut buffer = [0; 64 * 1024];
                while remaining > 0 {
                    let size = usize::try_from(remaining.min(buffer.len() as u64))
                        .expect("bounded to buffer length");
                    input.read_exact(&mut buffer[..size])?;
                    child_file.write_all(&buffer[..size])?;
                    mac.update(&buffer[..size]);
                    remaining -= size as u64;
                }
                child_file.flush()?;
                child_file.sync_all()?;
                child_file.seek(SeekFrom::Start(0))?;
                let (peer_id, staging, links) =
                    decode_backup_stream(identity, &mut child_file, None)?;
                ensure_stream_eof(&mut child_file)?;
                if !unique.insert(peer_id.clone()) {
                    staging.cleanup()?;
                    return Err(invalid_data("duplicate conversation in backup bundle"));
                }
                let message_count = usize::try_from(staging.count())
                    .map_err(|_| invalid_data("backup conversation count is too large"))?;
                let has_links = !links.local.is_empty() || !links.peer.is_empty();
                validated_children.push(Some((peer_id, staging, links, message_count, has_links)));
                Ok(())
            })();
            child_result?;
        }
        let mut supplied_tag = [0; BACKUP_BUNDLE_TAG_BYTES];
        input.read_exact(&mut supplied_tag)?;
        ensure_stream_eof(input)?;
        mac.verify_slice(&supplied_tag)
            .map_err(|_| invalid_data("backup bundle authentication failed"))?;

        // Keep the validated encrypted staging objects until the bundle HMAC
        // succeeds, then apply those exact verified records and relationships.
        for validated in &mut validated_children {
            let Some((peer_id, mut staging, links, message_count, has_links)) = validated.take()
            else {
                continue;
            };
            let apply_result = import_verified_staging(identity, &peer_id, &mut staging, &links);
            if apply_result.is_ok() {
                imported.push((peer_id, message_count, has_links));
            }
            let staging_cleanup = staging.cleanup();
            match (apply_result, staging_cleanup) {
                (Ok(()), Ok(())) => {}
                (Err(error), Ok(())) => return Err(error),
                (Ok(()), Err(cleanup_error)) => {
                    return Err(io::Error::other(format!(
                        "backup bundle applied {} conversation(s), but staging cleanup failed: {cleanup_error}",
                        imported.len()
                    )))
                }
                (Err(error), Err(cleanup_error)) => {
                    return Err(io::Error::other(format!(
                        "{error}; restore staging cleanup failed: {cleanup_error}"
                    )))
                }
            }
        }
        Ok(())
    })();
    let mut cleanup_errors = Vec::new();
    for (_, staging, _, _, _) in validated_children.into_iter().flatten() {
        if let Err(error) = staging.cleanup() {
            cleanup_errors.push(error.to_string());
        }
    }
    for path in staged_children {
        let cleanup = if path.exists() {
            std::fs::remove_file(path)
        } else {
            Ok(())
        };
        if let Err(error) = cleanup {
            cleanup_errors.push(error.to_string());
        }
    }
    let cleanup_result = if cleanup_errors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(cleanup_errors.join("; ")))
    };
    let result = match (result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(io::Error::other(format!(
            "backup bundle applied {} conversation(s), but temporary bundle cleanup failed: {cleanup_error}",
            imported.len()
        ))),
        (Err(error), Err(cleanup_error)) => Err(io::Error::other(format!(
            "{error}; temporary bundle cleanup failed: {cleanup_error}"
        ))),
    };
    result.map_err(|error| partial_bundle_error(imported.len(), error))?;
    Ok(imported)
}

pub(crate) fn derive_backup_bundle_key(
    identity: &Identity,
    bundle_id: &[u8; 16],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    let storage_key = identity.storage_key();
    Hkdf::<Sha256>::new(Some(bundle_id), storage_key.as_ref())
        .expand(b"another-dimension-v2/backup-bundle/ADPACK3", key.as_mut())
        .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
    Ok(key)
}
