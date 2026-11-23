//! Streaming single-conversation backups (ADBACK6, ADBACK7).

use super::*;

pub(crate) struct BackupStreamWriter<'a, W> {
    pub(crate) peer: [u8; 32],
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) aad: Vec<u8>,
    pub(crate) output: &'a mut W,
    pub(crate) count: u64,
}

impl<'a, W: Write> BackupStreamWriter<'a, W> {
    pub(crate) fn new(
        identity: &'a Identity,
        peer_id: &str,
        password: Option<&str>,
        links: &BackupLinks,
        output: &'a mut W,
    ) -> io::Result<Self> {
        validate_backup_links(peer_id, links)?;
        if let Some(password) = password {
            validate_backup_password(password)?;
        }
        let peer = decode_peer_id(peer_id)?;
        let mut salt = [0; BACKUP_SALT_BYTES];
        let mut file_id = [0; 16];
        crate::random::fill(&mut file_id)?;
        if password.is_some() {
            crate::random::fill(&mut salt)?;
        }
        let mut header = Vec::with_capacity(8 + 1 + 16 + BACKUP_SALT_BYTES);
        header.extend_from_slice(BACKUP_STREAM_MAGIC);
        header.push(u8::from(password.is_some()));
        header.extend_from_slice(&file_id);
        if password.is_some() {
            header.extend_from_slice(&salt);
        }
        output.write_all(&header)?;
        let key = match password {
            Some(password) => {
                let password_key = derive_password_backup_key(password, &salt)?;
                derive_combined_backup_key(&identity.storage_key(), &password_key)
            }
            None => derive_backup_key(&identity.storage_key()),
        };
        let mut aad = backup_aad(
            identity,
            BACKUP_STREAM_MAGIC,
            password.is_some().then_some(&salt),
        );
        aad.push(u8::from(password.is_some()));
        aad.extend_from_slice(&file_id);
        let mut writer = Self {
            peer,
            key,
            aad,
            output,
            count: 0,
        };
        let mut metadata = Vec::with_capacity(BACKUP_PEER_METADATA.len() + peer.len());
        metadata.extend_from_slice(BACKUP_PEER_METADATA);
        metadata.extend_from_slice(&peer);
        writer.write_frame(FRAME_METADATA, 0, &metadata)?;
        Ok(writer)
    }

    pub(crate) fn write_message(&mut self, message: &StoredMessage) -> io::Result<()> {
        let plain = encode_history_plain(message)?;
        let index = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        self.write_frame(FRAME_MESSAGE, index, &plain)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        Ok(())
    }

    pub(crate) fn finish(&mut self, expected_count: u64, links: &BackupLinks) -> io::Result<()> {
        if expected_count != self.count {
            return Err(invalid_data("backup snapshot count changed"));
        }
        let peer_id = hex_encode(&self.peer);
        validate_backup_links(&peer_id, links)?;
        let trailer = encode_backup_links(links)?;
        let trailer_index = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        self.write_frame(FRAME_LINKS, trailer_index, &trailer)?;
        self.output.flush()
    }

    pub(crate) fn write_frame(&mut self, kind: u8, index: u64, plain: &[u8]) -> io::Result<()> {
        let nonce = random_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("backup key unavailable"))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &backup_stream_frame_aad(&self.aad, kind, index),
                },
            )
            .map_err(|_| io::Error::other("backup frame encryption failed"))?;
        let length = u32::try_from(encrypted.len())
            .map_err(|_| invalid_data("backup frame is too large"))?;
        self.output.write_all(&[kind])?;
        self.output.write_all(&index.to_be_bytes())?;
        self.output.write_all(&nonce)?;
        self.output.write_all(&length.to_be_bytes())?;
        self.output.write_all(&encrypted)
    }
}

/// The kinds of frame in a stream backup.
pub(crate) const FRAME_LINKS: u8 = 0;
pub(crate) const FRAME_MESSAGE: u8 = 1;
pub(crate) const FRAME_METADATA: u8 = 2;

pub(crate) fn backup_stream_frame_aad(base: &[u8], kind: u8, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(base.len() + 9);
    aad.extend_from_slice(base);
    aad.push(kind);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

pub(crate) fn decode_backup_stream_v6<R: Read>(
    identity: &Identity,
    input: &mut R,
    password: Option<&str>,
) -> io::Result<(String, RestoreStaging, BackupLinks)> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != BACKUP_STREAM_V6_MAGIC {
        return Err(invalid_data("unsupported backup format"));
    }
    let mut flags = [0; 1];
    input.read_exact(&mut flags)?;
    if flags[0] > 1 || (flags[0] == 1) != password.is_some() {
        return Err(invalid_data("backup password does not match format"));
    }
    let salt = if flags[0] == 1 {
        let mut salt = [0; BACKUP_SALT_BYTES];
        input.read_exact(&mut salt)?;
        Some(salt)
    } else {
        None
    };
    if let Some(password) = password {
        validate_backup_password(password)?;
    }
    let mut peer = [0; 32];
    input.read_exact(&mut peer)?;
    let peer_id = hex_encode(&peer);
    let key = match (password, salt.as_ref()) {
        (Some(password), Some(salt)) => {
            let password_key = derive_password_backup_key(password, salt)?;
            derive_combined_backup_key(&identity.storage_key(), &password_key)
        }
        (None, None) => derive_backup_key(&identity.storage_key()),
        _ => return Err(invalid_data("invalid backup password header")),
    };
    let mut base_aad = backup_aad(identity, BACKUP_STREAM_V6_MAGIC, salt.as_ref());
    base_aad.push(flags[0]);
    base_aad.extend_from_slice(&peer);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("invalid backup key"))?;
    read_stream_frames(input, identity, peer_id, &cipher, &base_aad, 0)
}

pub(crate) fn decode_backup_stream<R: Read>(
    identity: &Identity,
    input: &mut R,
    password: Option<&str>,
) -> io::Result<(String, RestoreStaging, BackupLinks)> {
    let mut magic = [0; 8];
    input.read_exact(&mut magic)?;
    if &magic != BACKUP_STREAM_MAGIC {
        return Err(invalid_data("unsupported backup format"));
    }
    let mut flags = [0; 1];
    input.read_exact(&mut flags)?;
    if flags[0] > 1 || (flags[0] == 1) != password.is_some() {
        return Err(invalid_data("backup password does not match format"));
    }
    let mut file_id = [0; 16];
    input.read_exact(&mut file_id)?;
    let salt = if flags[0] == 1 {
        let mut salt = [0; BACKUP_SALT_BYTES];
        input.read_exact(&mut salt)?;
        Some(salt)
    } else {
        None
    };
    if let Some(password) = password {
        validate_backup_password(password)?;
    }
    let key = match (password, salt.as_ref()) {
        (Some(password), Some(salt)) => {
            let password_key = derive_password_backup_key(password, salt)?;
            derive_combined_backup_key(&identity.storage_key(), &password_key)
        }
        (None, None) => derive_backup_key(&identity.storage_key()),
        _ => return Err(invalid_data("invalid backup password header")),
    };
    let mut base_aad = backup_aad(identity, BACKUP_STREAM_MAGIC, salt.as_ref());
    base_aad.push(flags[0]);
    base_aad.extend_from_slice(&file_id);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("invalid backup key"))?;

    let mut metadata_header = [0; 1 + 8 + NONCE_BYTES + 4];
    input.read_exact(&mut metadata_header)?;
    let metadata_kind = metadata_header[0];
    let metadata_index = u64::from_be_bytes(metadata_header[1..9].try_into().expect("fixed slice"));
    let metadata_nonce = &metadata_header[9..9 + NONCE_BYTES];
    let metadata_len = u32::from_be_bytes(
        metadata_header[9 + NONCE_BYTES..]
            .try_into()
            .expect("fixed slice"),
    ) as usize;
    if metadata_kind != FRAME_METADATA || metadata_index != 0 || metadata_len != 8 + 32 + 16 {
        return Err(invalid_data("invalid encrypted backup metadata frame"));
    }
    let mut encrypted_metadata = vec![0; metadata_len];
    input.read_exact(&mut encrypted_metadata)?;
    let metadata = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(metadata_nonce),
                Payload {
                    msg: &encrypted_metadata,
                    aad: &backup_stream_frame_aad(&base_aad, metadata_kind, metadata_index),
                },
            )
            .map_err(|_| invalid_data("backup metadata authentication failed"))?,
    );
    if metadata.len() != BACKUP_PEER_METADATA.len() + 32
        || !metadata.starts_with(BACKUP_PEER_METADATA)
    {
        return Err(invalid_data("invalid encrypted backup metadata"));
    }
    let peer_id = hex_encode(&metadata[BACKUP_PEER_METADATA.len()..]);
    read_stream_frames(input, identity, peer_id, &cipher, &base_aad, 1)
}

/// Reads the message frames and the closing links frame of a stream backup into a new
/// restore staging area. Message frames are numbered from `first_index` (0 in ADBACK6,
/// 1 in ADBACK7, where index 0 is the metadata frame).
fn read_stream_frames<R: Read>(
    input: &mut R,
    identity: &Identity,
    peer_id: String,
    cipher: &ChaCha20Poly1305,
    base_aad: &[u8],
    first_index: u64,
) -> io::Result<(String, RestoreStaging, BackupLinks)> {
    let mut staging = RestoreStaging::create(identity, &peer_id, &new_restore_request_id()?)?;
    let mut count = 0u64;
    let links = loop {
        let mut frame_header = [0; 1 + 8 + NONCE_BYTES + 4];
        input.read_exact(&mut frame_header)?;
        let kind = frame_header[0];
        let index = u64::from_be_bytes(frame_header[1..9].try_into().expect("fixed slice"));
        let nonce = &frame_header[9..9 + NONCE_BYTES];
        let length = u32::from_be_bytes(
            frame_header[9 + NONCE_BYTES..]
                .try_into()
                .expect("fixed slice"),
        ) as usize;
        if !(16..=MAX_MESSAGE_BYTES + 256).contains(&length) {
            return Err(invalid_data("invalid backup frame length"));
        }
        let mut encrypted = vec![0; length];
        input.read_exact(&mut encrypted)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: &encrypted,
                        aad: &backup_stream_frame_aad(base_aad, kind, index),
                    },
                )
                .map_err(|_| invalid_data("backup frame authentication failed"))?,
        );
        let expected_index = count
            .checked_add(first_index)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        match kind {
            FRAME_MESSAGE if index == expected_index => {
                let message = decode_history_plain(&plain, false)?;
                staging.append_verified(&message)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("backup message count overflow"))?;
            }
            FRAME_LINKS if index == expected_index => {
                break decode_backup_links(&plain, &peer_id, identity)?;
            }
            _ => return Err(invalid_data("backup frame order is invalid")),
        }
    };
    staging.finish()?;
    verify_stream_staged_proofs(identity, &peer_id, &mut staging, &links)?;
    Ok((peer_id, staging, links))
}

/// A fresh 64-hex id for one restore staging area.
pub(crate) fn new_restore_request_id() -> io::Result<String> {
    let mut id = String::with_capacity(72);
    for _ in 0..3 {
        id.push_str(&hex_encode(&random_nonce()?));
    }
    id.truncate(64);
    Ok(id)
}

pub(crate) fn ensure_stream_eof<R: Read>(input: &mut R) -> io::Result<()> {
    let mut trailing = [0; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(invalid_data("unexpected data after backup"));
    }
    Ok(())
}

pub(crate) fn verify_stream_staged_proofs(
    identity: &Identity,
    peer_id: &str,
    staging: &mut RestoreStaging,
    links: &BackupLinks,
) -> io::Result<()> {
    let previous_local_ids = crate::identity::previous_public_ids(identity)?;
    let (stored_local, stored_peer) = read_linked_keys(identity, peer_id)?;
    let mut local_ids: HashSet<_> = previous_local_ids.into_iter().collect();
    local_ids.extend(links.origins.iter().cloned());
    let local_aliases = stored_local
        .into_iter()
        .chain(links.local.iter().cloned())
        .filter(|id| local_ids.contains(id))
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<Vec<_>>>()?;
    let peer_aliases = stored_peer
        .into_iter()
        .chain(links.peer.iter().cloned())
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<Vec<_>>>()?;
    staging.rewind()?;
    while let Some(message) = staging.next_record()? {
        if message.proof.is_some() {
            verify_stored_proof(identity, peer_id, &message, &local_aliases, &peer_aliases)?;
        }
    }
    staging.rewind()
}

pub(crate) fn export_staging_stream<W: Write>(
    identity: &Identity,
    peer_id: &str,
    password: Option<&str>,
    links: &BackupLinks,
    staging: &mut RestoreStaging,
    output: &mut W,
) -> io::Result<()> {
    let mut writer = BackupStreamWriter::new(identity, peer_id, password, links, output)?;
    staging.rewind()?;
    while let Some(message) = staging.next_record()? {
        writer.write_message(&message)?;
    }
    writer.finish(staging.count(), links)
}

pub(crate) fn import_verified_staging(
    identity: &Identity,
    peer_id: &str,
    staging: &mut RestoreStaging,
    links: &BackupLinks,
) -> io::Result<()> {
    let old_links = read_linked_keys(identity, peer_id)?;
    let old_origins = crate::identity::previous_public_ids(identity)?;
    let has_links = !links.local.is_empty() || !links.peer.is_empty() || !links.origins.is_empty();
    if has_links {
        apply_backup_links(identity, peer_id, links)?;
    }
    let result = (|| {
        let mut history = History::open_for_streaming_merge(identity, peer_id)?;
        history.merge_restore_staging(identity, staging)?;
        Ok(())
    })();
    if let Err(error) = result {
        if has_links {
            let relationship_rollback = write_linked_keys(identity, peer_id, &old_links);
            let lineage_rollback =
                crate::identity::replace_previous_public_ids(identity, &old_origins);
            if relationship_rollback.is_err() || lineage_rollback.is_err() {
                return Err(io::Error::other(format!(
                    "backup import failed ({error}); relationship rollback failed ({}); lineage rollback failed ({})",
                    relationship_rollback.err().map_or_else(|| "succeeded".to_owned(), |e| e.to_string()),
                    lineage_rollback.err().map_or_else(|| "succeeded".to_owned(), |e| e.to_string()),
                )));
            }
        }
        return Err(error);
    }
    Ok(())
}
