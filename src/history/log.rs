//! The encrypted conversation log: header, records, readers, and the `History` operations on one file.

use super::*;

/// Which on-disk version a conversation log is in. Only `V3` carries a generation id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogFormat {
    V1,
    V2,
    V3 { generation: [u8; GENERATION_BYTES] },
}

impl LogFormat {
    pub(crate) fn header_len(self) -> u64 {
        match self {
            Self::V1 | Self::V2 => MAGIC.len() as u64,
            Self::V3 { .. } => HEADER_LEN,
        }
    }

    pub(crate) fn is_legacy(self) -> bool {
        self == Self::V1
    }

    pub(crate) fn needs_migration(self) -> bool {
        !matches!(self, Self::V3 { .. })
    }
}

/// The key that encrypts the records of a log. ADLOG3 uses a key of its own, derived
/// from the storage key, so the storage key itself no longer encrypts record data;
/// ADLOG1 and ADLOG2 used the storage key directly and are still read that way.
pub(crate) fn record_key(format: &LogFormat, storage_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    match format {
        LogFormat::V3 { .. } => crate::identity::purpose_key(storage_key, LOG_AEAD_LABEL),
        LogFormat::V1 | LogFormat::V2 => Zeroizing::new(*storage_key),
    }
}

/// Reads the header of a log whose cursor is at offset 0, leaving the cursor after it.
pub(crate) fn read_log_header(file: &mut File) -> io::Result<LogFormat> {
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    if &magic == LEGACY_MAGIC {
        Ok(LogFormat::V1)
    } else if &magic == PREVIOUS_MAGIC {
        Ok(LogFormat::V2)
    } else if &magic == MAGIC {
        let mut generation = [0; GENERATION_BYTES];
        file.read_exact(&mut generation)
            .map_err(|_| invalid_data("history header is incomplete"))?;
        Ok(LogFormat::V3 { generation })
    } else {
        Err(invalid_data("unsupported history format"))
    }
}

/// Writes the header of a new log with a fresh generation id and returns its format.
pub(crate) fn write_log_header(output: &mut impl Write) -> io::Result<LogFormat> {
    let mut generation = [0; GENERATION_BYTES];
    crate::random::fill(&mut generation)?;
    output.write_all(MAGIC)?;
    output.write_all(&generation)?;
    Ok(LogFormat::V3 { generation })
}

/// Makes sure a log file that was just created or opened has a complete header: an empty
/// file gets one, and a header cut short by a crash is rewritten. Returns whether a
/// partial header was discarded.
pub(crate) fn ensure_log_header(file: &mut File) -> io::Result<bool> {
    let length = file.metadata()?.len();
    let torn = if length == 0 {
        false
    } else if length < MAGIC.len() as u64 {
        true
    } else if length < HEADER_LEN {
        file.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        &magic == MAGIC
    } else {
        false
    };
    if length == 0 || torn {
        if torn {
            file.set_len(0)?;
        }
        write_log_header(file)?;
        file.sync_data()?;
    }
    Ok(torn)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HistoryFileVersion {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) length: u64,
    pub(crate) modified_nanos: u128,
}

pub(crate) fn history_file_version(file: &File) -> io::Result<HistoryFileVersion> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    let (device, inode) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    };
    #[cfg(not(unix))]
    let (device, inode) = (0, 0);
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    Ok(HistoryFileVersion {
        device,
        inode,
        length: metadata.len(),
        modified_nanos,
    })
}

/// Sequential, non-repairing view of a history file. The captured file length
/// prevents later appends from extending the offered snapshot; an atomic
/// replacement leaves this reader on the original inode.
pub(crate) struct HistoryReader {
    pub(crate) file: File,
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) identity_id: String,
    pub(crate) peer_id: String,
    pub(crate) index: u64,
    pub(crate) end: u64,
    pub(crate) valid_end: u64,
    pub(crate) truncated: bool,
    pub(crate) format: LogFormat,
}

impl HistoryReader {
    pub(crate) fn position(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    pub(crate) fn index(&self) -> u64 {
        self.index
    }

    pub(crate) fn has_remaining(&mut self) -> io::Result<bool> {
        Ok(self.file.stream_position()? < self.end)
    }

    #[cfg(test)]
    pub(crate) fn empty_for_test(file: File) -> Self {
        Self {
            file,
            key: Zeroizing::new([0; 32]),
            identity_id: "00".repeat(32),
            peer_id: "11".repeat(32),
            index: 0,
            end: 0,
            valid_end: 0,
            truncated: false,
            format: LogFormat::V3 {
                generation: [0; GENERATION_BYTES],
            },
        }
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        let header_len = self.format.header_len();
        self.file.seek(SeekFrom::Start(header_len))?;
        self.index = 0;
        self.valid_end = header_len;
        self.truncated = false;
        Ok(())
    }

    pub(crate) fn valid_end(&self) -> u64 {
        self.valid_end
    }

    pub(crate) fn was_truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn next_record(&mut self) -> io::Result<Option<StoredMessage>> {
        let position = self.file.stream_position()?;
        if position == self.end {
            return Ok(None);
        }
        if position > self.end || self.end - position < 4 {
            self.truncated = true;
            return Err(invalid_data("history snapshot ends in a partial record"));
        }
        let mut length = [0; 4];
        self.file.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(NONCE_BYTES + 16 + 13..=NONCE_BYTES + 16 + 16 + MAX_MESSAGE_BYTES + 144)
            .contains(&length)
        {
            return Err(invalid_data("invalid record in history snapshot"));
        }
        if self.end - position < 4 + length as u64 {
            self.truncated = true;
            return Err(invalid_data("history snapshot ends in a partial record"));
        }
        let mut record = vec![0; length];
        self.file.read_exact(&mut record)?;
        let (nonce, encrypted) = record.split_at(NONCE_BYTES);
        let record_key = record_key(&self.format, &self.key);
        let cipher = ChaCha20Poly1305::new_from_slice(record_key.as_ref())
            .map_err(|_| invalid_data("invalid history key"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: encrypted,
                        aad: &associated_data(
                            &self.identity_id,
                            &self.peer_id,
                            self.index,
                            &self.format,
                        ),
                    },
                )
                .map_err(|_| invalid_data("history authentication failed"))?,
        );
        let message = decode_history_plain(&plain, self.format.is_legacy())?;
        #[cfg(test)]
        TEST_DECRYPTED_RECORDS.with(|count| count.set(count.get() + 1));
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| invalid_data("history record index overflow"))?;
        self.valid_end = self.file.stream_position()?;
        Ok(Some(message))
    }
}

pub(crate) fn open_history_reader(
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
) -> io::Result<HistoryReader> {
    history_reader_from_file(File::open(path)?, key, identity_id, peer_id)
}

pub(crate) fn history_reader_from_file(
    mut file: File,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
) -> io::Result<HistoryReader> {
    let end = file.metadata()?.len();
    if end < MAGIC.len() as u64 {
        return Err(invalid_data("history snapshot header is incomplete"));
    }
    let format = read_log_header(&mut file)?;
    if end < format.header_len() {
        return Err(invalid_data("history snapshot header is incomplete"));
    }
    Ok(HistoryReader {
        file,
        key,
        identity_id,
        peer_id,
        index: 0,
        end,
        valid_end: format.header_len(),
        truncated: false,
        format,
    })
}

pub(crate) fn open_history_reader_from(
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
    offset: u64,
    index: u64,
) -> io::Result<HistoryReader> {
    let mut reader = open_history_reader(path, key, identity_id, peer_id)?;
    if offset < reader.format.header_len() || offset > reader.end {
        return Err(invalid_data("invalid append refresh offset"));
    }
    reader.file.seek(SeekFrom::Start(offset))?;
    reader.index = index;
    reader.valid_end = offset;
    Ok(reader)
}

pub(crate) fn migrate_history_streaming(
    path: &std::path::Path,
    key: Zeroizing<[u8; 32]>,
    identity_id: &str,
    peer_id: &str,
) -> io::Result<bool> {
    let mut reader = open_history_reader(
        path.to_owned(),
        Zeroizing::new(*key),
        identity_id.to_owned(),
        peer_id.to_owned(),
    )?;
    let suffix = hex_encode(&random_nonce()?);
    let temporary = path.with_file_name(format!(".history-migrate-{suffix}.tmp"));
    let result = (|| {
        let mut output = crate::fsutil::private_options()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        set_private_file(&output)?;
        let format = write_log_header(&mut output)?;
        let mut index = 0u64;
        let mut truncated = false;
        loop {
            match reader.next_record() {
                Ok(Some(message)) => {
                    output.write_all(&encode_record(
                        &key,
                        identity_id,
                        peer_id,
                        index,
                        &format,
                        &message,
                    )?)?;
                    index = index
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("history record index overflow"))?;
                }
                Ok(None) => break,
                Err(error) if reader.was_truncated() => {
                    let _ = error;
                    truncated = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        output.sync_all()?;
        crate::fsutil::rename_durable(&temporary, path)?;
        Ok(truncated)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn encode_record(
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    index: u64,
    format: &LogFormat,
    message: &StoredMessage,
) -> io::Result<Vec<u8>> {
    let text = message.text.as_bytes();
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid message size",
        ));
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(14 + text.len() + 144));
    plain.extend_from_slice(&message.unix_time.to_be_bytes());
    plain.push(match message.sender {
        MessageSender::Me => 0,
        MessageSender::Other => 1,
    });
    plain.extend_from_slice(&(text.len() as u32).to_be_bytes());
    plain.extend_from_slice(text);
    match &message.proof {
        Some(proof) => {
            plain.push(1);
            plain.extend_from_slice(&proof.id);
            plain.extend_from_slice(&proof.signer);
            plain.extend_from_slice(&proof.recipient);
            plain.extend_from_slice(&proof.signature);
        }
        None => plain.push(0),
    }
    let nonce_bytes = random_nonce()?;
    let record_key = record_key(format, key);
    let cipher = ChaCha20Poly1305::new_from_slice(record_key.as_ref())
        .map_err(|_| io::Error::other("history key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plain,
                aad: &associated_data(identity_id, peer_id, index, format),
            },
        )
        .map_err(|_| io::Error::other("history encryption failed"))?;
    let length = u32::try_from(NONCE_BYTES + encrypted.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;
    let mut record = Vec::with_capacity(4 + length as usize);
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&nonce_bytes);
    record.extend_from_slice(&encrypted);
    Ok(record)
}

pub(crate) fn read_records(
    file: &mut File,
    key: Zeroizing<[u8; 32]>,
    identity_id: &str,
    peer_id: &str,
    repair_partial: bool,
) -> io::Result<(Vec<StoredMessage>, u64, bool, LogFormat)> {
    let format = read_log_header(file)?;
    let legacy_format = format.is_legacy();
    let record_key = record_key(&format, &key);
    let cipher = ChaCha20Poly1305::new_from_slice(record_key.as_ref())
        .map_err(|_| invalid_data("invalid history key"))?;
    let mut messages = Vec::new();
    let mut index = 0_u64;
    let mut recovered_partial = false;
    loop {
        let record_start = file.stream_position()?;
        let file_len = file.metadata()?.len();
        let remaining = file_len.saturating_sub(record_start);
        if remaining == 0 {
            break;
        }
        if remaining < 4 {
            if repair_partial {
                file.set_len(record_start)?;
            }
            recovered_partial = true;
            break;
        }
        let mut length = [0; 4];
        file.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if !(NONCE_BYTES + 16 + 13..=NONCE_BYTES + 16 + 16 + MAX_MESSAGE_BYTES + 144)
            .contains(&length)
        {
            return Err(invalid_data("invalid history record length"));
        }
        if remaining < 4 + length as u64 {
            if repair_partial {
                file.set_len(record_start)?;
            }
            recovered_partial = true;
            break;
        }
        let mut record = vec![0; length];
        file.read_exact(&mut record)?;
        let (nonce_bytes, encrypted) = record.split_at(NONCE_BYTES);
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce_bytes),
                    Payload {
                        msg: encrypted,
                        aad: &associated_data(identity_id, peer_id, index, &format),
                    },
                )
                .map_err(|_| invalid_data("history authentication failed"))?,
        );
        #[cfg(test)]
        TEST_DECRYPTED_RECORDS.with(|count| count.set(count.get() + 1));
        if plain.len() < 13 {
            return Err(invalid_data("invalid history payload"));
        }
        let unix_time = u64::from_be_bytes(plain[..8].try_into().expect("fixed slice"));
        let sender = match plain[8] {
            0 => MessageSender::Me,
            1 => MessageSender::Other,
            _ => return Err(invalid_data("invalid history sender")),
        };
        let text_len = u32::from_be_bytes(plain[9..13].try_into().expect("fixed slice")) as usize;
        if text_len == 0 || text_len > MAX_MESSAGE_BYTES || plain.len() < 13 + text_len {
            return Err(invalid_data("invalid history text length"));
        }
        let text = std::str::from_utf8(&plain[13..13 + text_len])
            .map_err(|_| invalid_data("history text is not UTF-8"))?
            .to_owned();
        let proof = if legacy_format {
            if plain.len() != 13 + text_len {
                return Err(invalid_data("invalid legacy history record"));
            }
            None
        } else {
            let proof_pos = 13 + text_len;
            match plain.get(proof_pos).copied() {
                Some(0) if plain.len() == proof_pos + 1 => None,
                Some(1) if plain.len() == proof_pos + 1 + 144 => {
                    let mut cursor = proof_pos + 1;
                    let id = plain[cursor..cursor + 16].try_into().expect("fixed slice");
                    cursor += 16;
                    let signer = plain[cursor..cursor + 32].try_into().expect("fixed slice");
                    cursor += 32;
                    let recipient = plain[cursor..cursor + 32].try_into().expect("fixed slice");
                    cursor += 32;
                    let signature = plain[cursor..cursor + 64].try_into().expect("fixed slice");
                    Some(MessageProof {
                        id,
                        signer,
                        recipient,
                        signature,
                    })
                }
                _ => return Err(invalid_data("invalid history proof")),
            }
        };
        messages.push(StoredMessage {
            unix_time,
            sender,
            text,
            proof,
        });
        index = index
            .checked_add(1)
            .ok_or_else(|| invalid_data("history record limit reached"))?;
    }
    Ok((messages, index, recovered_partial, format))
}

pub(crate) fn decode_history_plain(plain: &[u8], legacy_format: bool) -> io::Result<StoredMessage> {
    if plain.len() < 13 {
        return Err(invalid_data("invalid history payload"));
    }
    let unix_time = u64::from_be_bytes(plain[..8].try_into().expect("fixed slice"));
    let sender = match plain[8] {
        0 => MessageSender::Me,
        1 => MessageSender::Other,
        _ => return Err(invalid_data("invalid history sender")),
    };
    let text_len = u32::from_be_bytes(plain[9..13].try_into().expect("fixed slice")) as usize;
    if text_len == 0 || text_len > MAX_MESSAGE_BYTES || plain.len() < 13 + text_len {
        return Err(invalid_data("invalid history text length"));
    }
    let text = std::str::from_utf8(&plain[13..13 + text_len])
        .map_err(|_| invalid_data("history text is not UTF-8"))?
        .to_owned();
    let proof = if legacy_format {
        if plain.len() != 13 + text_len {
            return Err(invalid_data("invalid legacy history record"));
        }
        None
    } else {
        let proof_pos = 13 + text_len;
        match plain.get(proof_pos).copied() {
            Some(0) if plain.len() == proof_pos + 1 => None,
            Some(1) if plain.len() == proof_pos + 1 + 144 => {
                let mut cursor = proof_pos + 1;
                let id = plain[cursor..cursor + 16].try_into().expect("fixed slice");
                cursor += 16;
                let signer = plain[cursor..cursor + 32].try_into().expect("fixed slice");
                cursor += 32;
                let recipient = plain[cursor..cursor + 32].try_into().expect("fixed slice");
                cursor += 32;
                let signature = plain[cursor..cursor + 64].try_into().expect("fixed slice");
                Some(MessageProof {
                    id,
                    signer,
                    recipient,
                    signature,
                })
            }
            _ => return Err(invalid_data("invalid history proof")),
        }
    };
    Ok(StoredMessage {
        unix_time,
        sender,
        text,
        proof,
    })
}

pub(crate) fn encode_history_plain(message: &StoredMessage) -> io::Result<Zeroizing<Vec<u8>>> {
    let text = message.text.as_bytes();
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(invalid_data("invalid history message size"));
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(14 + text.len() + 144));
    plain.extend_from_slice(&message.unix_time.to_be_bytes());
    plain.push(match message.sender {
        MessageSender::Me => 0,
        MessageSender::Other => 1,
    });
    plain.extend_from_slice(&(text.len() as u32).to_be_bytes());
    plain.extend_from_slice(text);
    match &message.proof {
        Some(proof) => {
            plain.push(1);
            plain.extend_from_slice(&proof.id);
            plain.extend_from_slice(&proof.signer);
            plain.extend_from_slice(&proof.recipient);
            plain.extend_from_slice(&proof.signature);
        }
        None => plain.push(0),
    }
    Ok(plain)
}

pub(crate) fn associated_data(
    identity_id: &str,
    peer_id: &str,
    index: u64,
    format: &LogFormat,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + GENERATION_BYTES + 64 + 64 + 8);
    match format {
        LogFormat::V1 => aad.extend_from_slice(b"ADLOG1"),
        LogFormat::V2 => aad.extend_from_slice(b"ADLOG2"),
        LogFormat::V3 { generation } => {
            aad.extend_from_slice(b"ADLOG3");
            aad.extend_from_slice(generation);
        }
    }
    aad.extend_from_slice(identity_id.as_bytes());
    aad.extend_from_slice(peer_id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

pub(crate) fn random_nonce() -> io::Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0; NONCE_BYTES];
    crate::random::fill(&mut nonce)?;
    Ok(nonce)
}

impl History {
    /// Open a chat history without collecting its messages in memory. The chat
    /// API pages directly from the encrypted file and keeps only the count.
    pub(crate) fn open_for_chat(
        identity: &Identity,
        peer_id: &str,
    ) -> io::Result<(Self, usize, bool)> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let directory = data_directory()?.join(&identity_id);
        crate::fsutil::create_private_dir_all(&directory)?;
        set_private_directory(&directory)?;
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        cleanup_orphaned_restore_outputs(&directory, &path)?;
        if !path.exists()
            && read_index(identity, &identity_id, &directory)?
                .iter()
                .any(|existing| existing == &peer_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("indexed conversation file is missing: {}", path.display()),
            ));
        }
        let mut file = crate::fsutil::private_options()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;
        let mut recovered_partial = ensure_log_header(&mut file)?;
        file.seek(SeekFrom::Start(0))?;
        if read_log_header(&mut file)?.needs_migration() {
            recovered_partial |=
                migrate_history_streaming(&path, Zeroizing::new(*key), &identity_id, &peer_id)?;
        }
        let mut reader = open_history_reader(
            path.clone(),
            Zeroizing::new(*key),
            identity_id.clone(),
            peer_id.clone(),
        )?;
        let format = reader.format;
        let mut count = 0usize;
        loop {
            match reader.next_record() {
                Ok(Some(_)) => {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("history record count overflow"))?;
                }
                Ok(None) => break,
                Err(error) if reader.was_truncated() => {
                    let valid_end = reader.valid_end();
                    drop(reader);
                    let file = crate::fsutil::private_options().write(true).open(&path)?;
                    file.set_len(valid_end)?;
                    file.sync_all()?;
                    recovered_partial = true;
                    let _ = error;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let file = crate::fsutil::private_options()
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;
        let file_version = history_file_version(&file)?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;
        let mut history = Self {
            file,
            path,
            key,
            identity_id,
            peer_id,
            next_index: count as u64,
            file_version,
            format,
            integrity_warning: None,
            operation_lock: Arc::clone(&operation_lock),
        };
        history.check_anchor();
        unlock_conversation_file(file_lock);
        drop(operation_guard);
        Ok((history, count, recovered_partial))
    }

    pub(crate) fn reader_for_identity_copy(
        identity: &Identity,
        peer_id: &str,
    ) -> io::Result<HistoryReader> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let path = data_directory()?.join(&identity_id).join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        let lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let _guard = lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let result = open_history_reader(path, key, identity_id, peer_id);
        unlock_conversation_file(file_lock);
        result
    }

    pub fn open(
        identity: &Identity,
        peer_id: &str,
    ) -> io::Result<(Self, Vec<StoredMessage>, bool)> {
        if peer_id.len() != 64 || !peer_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid peer id",
            ));
        }
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let directory = data_directory()?.join(&identity_id);
        crate::fsutil::create_private_dir_all(&directory)?;
        set_private_directory(&directory)?;
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let index_key = derive_index_key(&key);
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&index_key, &peer_id)
        ));
        cleanup_orphaned_restore_outputs(&directory, &path)?;
        if !path.exists()
            && read_index(identity, &identity_id, &directory)?
                .iter()
                .any(|existing| existing == &peer_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("indexed conversation file is missing: {}", path.display()),
            ));
        }
        let mut file = crate::fsutil::private_options()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;

        let recovered_header = ensure_log_header(&mut file)?;
        file.seek(SeekFrom::Start(0))?;
        let (messages, next_index, recovered_partial, format) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            true,
        )?;
        file.seek(SeekFrom::End(0))?;
        let file_version = history_file_version(&file)?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;
        let mut history = Self {
            file,
            path,
            key,
            identity_id,
            peer_id,
            next_index,
            file_version,
            format,
            integrity_warning: None,
            operation_lock: Arc::clone(&operation_lock),
        };
        history.check_anchor();
        unlock_conversation_file(file_lock);
        drop(operation_guard);
        if format.needs_migration() {
            history.replace(&messages)?;
        }
        Ok((history, messages, recovered_header || recovered_partial))
    }

    pub(crate) fn open_for_streaming_merge(identity: &Identity, peer_id: &str) -> io::Result<Self> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let directory = data_directory()?.join(&identity_id);
        crate::fsutil::create_private_dir_all(&directory)?;
        set_private_directory(&directory)?;
        let operation_lock = conversation_operation_lock(&identity_id, &peer_id)?;
        let operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&derive_index_key(&key), &peer_id)
        ));
        cleanup_orphaned_restore_outputs(&directory, &path)?;
        if !path.exists()
            && read_index(identity, &identity_id, &directory)?
                .iter()
                .any(|existing| existing == &peer_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("indexed conversation file is missing: {}", path.display()),
            ));
        }
        let mut file = crate::fsutil::private_options()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;
        ensure_log_header(&mut file)?;
        let mut reader = open_history_reader(
            path.clone(),
            Zeroizing::new(*key),
            identity_id.clone(),
            peer_id.clone(),
        )?;
        let format = reader.format;
        let mut next_index = 0u64;
        while reader.next_record()?.is_some() {
            next_index = next_index
                .checked_add(1)
                .ok_or_else(|| invalid_data("history record index overflow"))?;
        }
        let file_version = history_file_version(&file)?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;
        unlock_conversation_file(file_lock);
        drop(operation_guard);
        Ok(Self {
            file,
            path,
            key,
            identity_id,
            peer_id,
            next_index,
            file_version,
            format,
            integrity_warning: None,
            operation_lock,
        })
    }

    pub(crate) fn directory(&self) -> &std::path::Path {
        self.path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
    }

    pub(crate) fn generation(&self) -> Option<[u8; GENERATION_BYTES]> {
        match self.format {
            LogFormat::V3 { generation } => Some(generation),
            LogFormat::V1 | LogFormat::V2 => None,
        }
    }

    /// Records the log's current generation and length. The log is already durable, so
    /// a failure here leaves the anchor behind the log, which is the safe direction.
    pub(crate) fn record_anchor(&self) {
        let Some(generation) = self.generation() else {
            return;
        };
        let anchor = crate::anchor::Anchor {
            generation,
            records: self.next_index,
            pending: None,
        };
        if let Err(error) = crate::anchor::store(
            &self.key,
            &self.identity_id,
            self.directory(),
            &self.peer_id,
            Some(anchor),
        ) {
            eprintln!("대화 기록 상태를 저장하지 못했습니다: {error}");
        }
    }

    /// Records the generation a replacement is about to install, before the rename, so a
    /// crash right after it is not mistaken for tampering.
    pub(crate) fn announce_replacement(&self, next: &LogFormat) -> io::Result<()> {
        let LogFormat::V3 { generation } = next else {
            return Ok(());
        };
        let current = match crate::anchor::load(
            &self.key,
            &self.identity_id,
            self.directory(),
            &self.peer_id,
        ) {
            Ok(current) => current,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => None,
            Err(error) => return Err(error),
        };
        let anchor = crate::anchor::Anchor {
            generation: current.map_or(
                self.generation().unwrap_or([0; GENERATION_BYTES]),
                |anchor| anchor.generation,
            ),
            records: current.map_or(0, |anchor| anchor.records),
            pending: Some(*generation),
        };
        crate::anchor::store(
            &self.key,
            &self.identity_id,
            self.directory(),
            &self.peer_id,
            Some(anchor),
        )
    }

    /// Compares the log that was just opened with the recorded state, remembers any
    /// finding, and records the log's state from now on.
    pub(crate) fn check_anchor(&mut self) {
        let loaded = crate::anchor::load(
            &self.key,
            &self.identity_id,
            self.directory(),
            &self.peer_id,
        );
        self.integrity_warning = match (&loaded, self.generation()) {
            (Err(_), _) => Some(IntegrityWarning::AnchorUnreadable),
            // A log of an older format cannot have been the one this program anchored.
            (Ok(anchor), None) => anchor.map(|_| IntegrityWarning::UnknownGeneration),
            (Ok(anchor), Some(generation)) => {
                match crate::anchor::verify(anchor.as_ref(), generation, self.next_index) {
                    crate::anchor::Verdict::Unanchored | crate::anchor::Verdict::Consistent => None,
                    crate::anchor::Verdict::Truncated { recorded, found } => {
                        Some(IntegrityWarning::Truncated { recorded, found })
                    }
                    crate::anchor::Verdict::UnknownGeneration => {
                        Some(IntegrityWarning::UnknownGeneration)
                    }
                }
            }
        };
        self.record_anchor();
    }

    pub(crate) fn integrity_warning(&self) -> Option<IntegrityWarning> {
        self.integrity_warning
    }

    pub fn append(&mut self, message: &StoredMessage) -> io::Result<()> {
        let operation_lock = Arc::clone(&self.operation_lock);
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock_for_path(
            &self.path,
            &self.identity_id,
            &self.peer_id,
            &self.key,
        )?;
        self.refresh_for_append()?;
        let record = encode_record(
            &self.key,
            &self.identity_id,
            &self.peer_id,
            self.next_index,
            &self.format,
            message,
        )?;
        self.file.write_all(&record)?;
        self.file.sync_data()?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("history record limit reached"))?;
        self.file_version = history_file_version(&self.file)?;
        self.record_anchor();
        unlock_conversation_file(file_lock);
        Ok(())
    }

    pub fn replace(&mut self, messages: &[StoredMessage]) -> io::Result<()> {
        let operation_lock = Arc::clone(&self.operation_lock);
        let _operation_guard = operation_lock
            .lock()
            .map_err(|_| io::Error::other("conversation lock unavailable"))?;
        let file_lock = acquire_conversation_file_lock_for_path(
            &self.path,
            &self.identity_id,
            &self.peer_id,
            &self.key,
        )?;
        let result = self.replace_unlocked(messages);
        unlock_conversation_file(file_lock);
        result
    }

    pub(crate) fn replace_unlocked(&mut self, messages: &[StoredMessage]) -> io::Result<()> {
        #[cfg(test)]
        if test_failure_once(FAIL_HISTORY_REPLACE_ONCE) {
            return Err(io::Error::other("injected conversation replace failure"));
        }
        let suffix = hex_encode(&random_nonce()?);
        let temporary = self.path.with_extension(format!("{suffix}.tmp"));
        let result = (|| {
            let mut file = crate::fsutil::private_options()
                .create_new(true)
                .read(true)
                .append(true)
                .open(&temporary)?;
            set_private_file(&file)?;
            let format = write_log_header(&mut file)?;
            for (index, message) in messages.iter().enumerate() {
                let record = encode_record(
                    &self.key,
                    &self.identity_id,
                    &self.peer_id,
                    index as u64,
                    &format,
                    message,
                )?;
                file.write_all(&record)?;
            }
            file.sync_all()?;
            self.announce_replacement(&format)?;
            crate::fsutil::rename_durable(&temporary, &self.path)?;
            let file_version = history_file_version(&file)?;
            self.file = file;
            self.next_index = messages.len() as u64;
            self.file_version = file_version;
            self.format = format;
            self.record_anchor();
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    pub(crate) fn replace_filtered_unlocked(
        &mut self,
        reader: &mut HistoryReader,
        mut keep: impl FnMut(u64, &StoredMessage) -> bool,
        validate: impl FnOnce(u64) -> io::Result<()>,
    ) -> io::Result<HistoryDeleteSummary> {
        #[cfg(test)]
        wait_history_delete_test_gate();
        let suffix = hex_encode(&random_nonce()?);
        let filename = self
            .path
            .file_name()
            .ok_or_else(|| invalid_data("conversation filename unavailable"))?;
        let temporary = self.path.with_file_name(format!(
            ".{}.delete-{suffix}.tmp",
            filename.to_string_lossy()
        ));
        let result = (|| {
            let mut output = crate::fsutil::private_options()
                .create_new(true)
                .read(true)
                .append(true)
                .open(&temporary)?;
            set_private_file(&output)?;
            let format = write_log_header(&mut output)?;
            let mut summary = HistoryDeleteSummary::default();
            let mut next_index = 0_u64;
            while let Some(message) = reader.next_record()? {
                summary.peak_record_bytes = summary.peak_record_bytes.max(
                    std::mem::size_of::<StoredMessage>()
                        .saturating_add(message.text.capacity().saturating_mul(4))
                        .saturating_add(1024),
                );
                let source_index = reader.index().saturating_sub(1);
                if keep(source_index, &message) {
                    let record = encode_record(
                        &self.key,
                        &self.identity_id,
                        &self.peer_id,
                        next_index,
                        &format,
                        &message,
                    )?;
                    summary.peak_record_bytes = summary.peak_record_bytes.max(
                        std::mem::size_of::<StoredMessage>()
                            .saturating_add(message.text.capacity().saturating_mul(4))
                            .saturating_add(record.capacity())
                            .saturating_add(1024),
                    );
                    #[cfg(test)]
                    if test_failure_once(FAIL_HISTORY_DELETE_WRITE) {
                        return Err(io::Error::other("injected history delete write failure"));
                    }
                    output.write_all(&record)?;
                    next_index = next_index
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("history record index overflow"))?;
                    summary.remaining_count = next_index;
                } else {
                    summary.deleted_count = summary
                        .deleted_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("deleted history count overflow"))?;
                }
            }
            validate(reader.index())?;
            #[cfg(test)]
            if test_failure_once(FAIL_HISTORY_DELETE_SYNC) {
                return Err(io::Error::other("injected history delete sync failure"));
            }
            output.sync_all()?;
            #[cfg(test)]
            if test_failure_once(FAIL_HISTORY_DELETE_RENAME) {
                return Err(io::Error::other("injected history delete replace failure"));
            }
            let file_version = history_file_version(&output)?;
            self.announce_replacement(&format)?;
            crate::fsutil::rename_durable(&temporary, &self.path)?;
            self.file_version = file_version;
            self.file = output;
            self.next_index = next_index;
            self.format = format;
            self.record_anchor();
            Ok(summary)
        })();
        if let (Err(error), true) = (&result, temporary.exists()) {
            #[cfg(test)]
            let cleanup = if test_failure_once(FAIL_HISTORY_DELETE_CLEANUP) {
                Err(io::Error::other(
                    "injected history delete temporary cleanup failure",
                ))
            } else {
                std::fs::remove_file(&temporary)
            };
            #[cfg(not(test))]
            let cleanup = std::fs::remove_file(&temporary);
            if let Err(cleanup_error) = cleanup {
                return Err(io::Error::other(format!(
                    "history rewrite failed ({error}); temporary cleanup failed ({cleanup_error}); recoverable file: {}",
                    temporary.display()
                )));
            }
        }
        result
    }

    pub(crate) fn refresh_for_append(&mut self) -> io::Result<()> {
        let current = File::open(&self.path)?;
        let current_version = history_file_version(&current)?;
        let same_file = current_version.device == self.file_version.device
            && current_version.inode == self.file_version.inode;
        if same_file && current_version == self.file_version {
            return Ok(());
        }
        let mut next_index = self.next_index;
        let format;
        if same_file && current_version.length > self.file_version.length {
            let mut reader = open_history_reader_from(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
                self.file_version.length,
                self.next_index,
            )?;
            while reader.next_record()?.is_some() {
                next_index = next_index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("history record index overflow"))?;
            }
            format = reader.format;
        } else {
            let mut reader = open_history_reader(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
            )?;
            next_index = 0;
            while reader.next_record()?.is_some() {
                next_index = next_index
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("history record index overflow"))?;
            }
            format = reader.format;
        }
        let file = crate::fsutil::private_options()
            .read(true)
            .append(true)
            .open(&self.path)?;
        set_private_file(&file)?;
        self.file = file;
        self.next_index = next_index;
        self.format = format;
        self.file_version = history_file_version(&self.file)?;
        Ok(())
    }

    /// Read a source history for identity migration without repairing or
    /// otherwise changing a possibly incomplete original file.
    pub(crate) fn read_for_identity_copy(
        identity: &Identity,
        peer_id: &str,
    ) -> io::Result<(Vec<StoredMessage>, bool)> {
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
        let file_lock = acquire_conversation_file_lock(identity, &peer_id)?;
        let mut file = File::open(path)?;
        let (messages, _, recovered_partial, _) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            false,
        )?;
        unlock_conversation_file(file_lock);
        Ok((messages, recovered_partial))
    }

    pub fn append_system_once(
        &mut self,
        identity: &Identity,
        entry: StoredMessage,
    ) -> io::Result<bool> {
        if entry.sender != MessageSender::Me || !entry.text.starts_with(IDENTITY_EVENT_PREFIX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a system history entry",
            ));
        }
        let (messages, recovered_partial) = Self::read_for_identity_copy(identity, &self.peer_id)?;
        if recovered_partial {
            return Err(invalid_data("conversation has an incomplete record"));
        }
        if messages
            .iter()
            .any(|message| message.sender == entry.sender && message.text == entry.text)
        {
            return Ok(false);
        }
        self.append(&entry)?;
        Ok(true)
    }
}
