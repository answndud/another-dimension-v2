//! Listing, paging and deleting stored conversations.

use super::*;

impl History {
    pub(crate) fn estimate_transfer(
        identity: &Identity,
        peer_id: &str,
        request_id: &str,
    ) -> io::Result<(HistoryReader, usize, u64)> {
        let mut reader = Self::reader_for_identity_copy(identity, peer_id)?;
        let mut count = 0usize;
        let mut bytes = 0u64;
        while let Some(message) = reader.next_record()? {
            let frame = encode_transfer_chunk(&message, request_id, 0)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("history record count overflow"))?;
            bytes = bytes.saturating_add(frame.len() as u64);
        }
        reader.rewind()?;
        Ok((reader, count, bytes))
    }

    /// Read the existing encrypted index without opening or creating histories.
    pub(crate) fn known_peer_ids(identity: &Identity) -> io::Result<Vec<String>> {
        let identity_id = identity.public_id();
        let directory = data_directory()?.join(&identity_id);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        read_index(identity, &identity_id, &directory)
    }

    pub fn list(identity: &Identity) -> io::Result<Vec<Summary>> {
        let identity_id = identity.public_id();
        let directory = data_directory()?.join(&identity_id);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let peers = read_index(identity, &identity_id, &directory)?;
        let mut summaries = Vec::with_capacity(peers.len());
        for peer_id in peers {
            let mut reader = Self::reader_for_identity_copy(identity, &peer_id)?;
            let mut message_count = 0usize;
            let mut last_message = None;
            while let Some(message) = reader.next_record()? {
                message_count = message_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("history record count overflow"))?;
                last_message = Some(message.unix_time);
            }
            summaries.push(Summary {
                peer_id,
                message_count,
                last_message,
            });
        }
        summaries.sort_by_key(|summary| std::cmp::Reverse(summary.last_message));
        Ok(summaries)
    }

    pub(crate) fn read_page(
        identity: &Identity,
        peer_id: &str,
        cursor: Option<&HistoryPageCursor>,
        limit: usize,
    ) -> io::Result<HistoryPage> {
        validate_peer_id(peer_id)?;
        if limit == 0 || limit > 100 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid history page size",
            ));
        }
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let path = data_directory()?.join(&identity_id).join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let file = File::open(&path)?;
        let version = history_file_version(&file)?;
        let token = format!(
            "{:x}-{:x}-{:x}-{:x}",
            version.device, version.inode, version.length, version.modified_nanos
        );
        if cursor.is_some_and(|cursor| cursor.version != token) {
            unlock_conversation_file(file_lock);
            drop(operation_guard);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "history changed; reload required",
            ));
        }
        let mut reader = if let Some(cursor) = cursor {
            open_history_reader_from(
                path,
                Zeroizing::new(*key),
                identity_id,
                peer_id,
                cursor.offset,
                cursor.index,
            )?
        } else {
            open_history_reader(path, Zeroizing::new(*key), identity_id, peer_id)?
        };
        unlock_conversation_file(file_lock);
        drop(operation_guard);
        let mut entries = Vec::with_capacity(limit);
        while entries.len() < limit {
            let index = reader.index();
            let Some(message) = reader.next_record()? else {
                break;
            };
            entries.push(HistoryPageEntry { index, message });
        }
        let next = if reader.has_remaining()? {
            Some(HistoryPageCursor {
                version: token.clone(),
                offset: reader.position()?,
                index: reader.index(),
            })
        } else {
            None
        };
        Ok(HistoryPage {
            entries,
            version: token,
            next,
        })
    }

    pub(crate) fn delete_indices_if_version(
        identity: &Identity,
        peer_id: &str,
        expected_version: &str,
        selected: &HashSet<usize>,
    ) -> io::Result<HistoryDeleteSummary> {
        if selected.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no history messages selected",
            ));
        }
        Self::delete_filtered(
            identity,
            peer_id,
            Some(expected_version),
            |index, _| usize::try_from(index).map_or(true, |index| !selected.contains(&index)),
            |count| {
                if selected.iter().any(|index| *index as u64 >= count) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "selected message index is outside history",
                    ));
                }
                Ok(())
            },
        )
    }

    pub(crate) fn delete_time_range(
        identity: &Identity,
        peer_id: &str,
        start: u64,
        end: u64,
    ) -> io::Result<HistoryDeleteSummary> {
        if start > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid history date range",
            ));
        }
        Self::delete_filtered(
            identity,
            peer_id,
            None,
            |_, message| message.unix_time < start || message.unix_time > end,
            |_| Ok(()),
        )
    }

    pub(crate) fn delete_filtered(
        identity: &Identity,
        peer_id: &str,
        expected_version: Option<&str>,
        keep: impl FnMut(u64, &StoredMessage) -> bool,
        validate: impl FnOnce(u64) -> io::Result<()>,
    ) -> io::Result<HistoryDeleteSummary> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let directory = data_directory()?.join(&identity_id);
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let result = (|| {
            let source = File::open(&path)?;
            let version = history_file_version(&source)?;
            let token = format!(
                "{:x}-{:x}-{:x}-{:x}",
                version.device, version.inode, version.length, version.modified_nanos
            );
            if expected_version.is_some_and(|expected| token != expected) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "history changed; reload required",
                ));
            }
            let mut reader = history_reader_from_file(
                source,
                Zeroizing::new(*key),
                identity_id.clone(),
                peer_id.clone(),
            )?;
            let format = reader.format;
            let append_file = crate::fsutil::private_options()
                .read(true)
                .append(true)
                .open(&path)?;
            let mut history = History {
                file: append_file,
                path,
                key,
                identity_id,
                peer_id,
                next_index: 0,
                file_version: version,
                format,
                integrity_warning: None,
                anchor_suspect: false,
                operation_lock: Arc::clone(&operation_lock),
            };
            history.replace_filtered_unlocked(&mut reader, keep, validate)
        })();
        unlock_conversation_file(file_lock);
        result
    }

    pub fn delete_conversation(identity: &Identity, peer_id: &str) -> io::Result<()> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let directory = data_directory()?.join(&identity_id);
        let key = identity.storage_key();
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let _file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let lock = INDEX_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| io::Error::other("history index unavailable"))?;
        let mut peers = read_index(identity, &identity_id, &directory)?;
        if !peers.iter().any(|existing| existing == &peer_id) {
            return Ok(());
        }
        let tombstone = directory.join(format!(
            ".deleted-{}.tmp",
            crate::hex::encode(&random_nonce()?)
        ));
        if path.exists() {
            crate::fsutil::rename_durable(&path, &tombstone)?;
        }
        peers.retain(|existing| existing != &peer_id);
        if let Err(error) = write_index(identity, &identity_id, &directory, &peers) {
            if tombstone.exists() {
                #[cfg(test)]
                let restore_result = if test_failure(FAIL_DELETE_RESTORE) {
                    Err(io::Error::other(
                        "injected prior conversation restore failure",
                    ))
                } else {
                    crate::fsutil::rename_durable(&tombstone, &path)
                };
                #[cfg(not(test))]
                let restore_result = crate::fsutil::rename_durable(&tombstone, &path);
                if let Err(restore_error) = restore_result {
                    return Err(io::Error::other(format!(
                        "history index update failed ({error}); restoring prior conversation failed ({restore_error}); recoverable file: {}",
                        tombstone.display()
                    )));
                }
            }
            return Err(error);
        }
        if tombstone.exists() {
            // The index update is the logical delete. A leftover encrypted
            // tombstone must not make callers believe the operation rolled back.
            let _ = std::fs::remove_file(tombstone);
        }
        if let Err(error) = crate::anchor::store(&key, &identity_id, &directory, &peer_id, None) {
            eprintln!("대화 기록 상태를 지우지 못했습니다: {error}");
        }
        Ok(())
    }
}
