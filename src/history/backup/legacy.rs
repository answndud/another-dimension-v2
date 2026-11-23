//! Single-conversation backups before the streaming format (ADBACK1-5), and the helpers every backup version shares.

use super::*;

#[cfg(test)]
pub(crate) fn encode_backup(
    identity: &Identity,
    peer_id: &str,
    messages: &[StoredMessage],
    password: Option<&str>,
) -> io::Result<Vec<u8>> {
    let links = backup_links_for(identity, peer_id)?;
    encode_backup_with_links(identity, peer_id, messages, password, &links)
}

pub(crate) fn validate_backup_links(peer_id: &str, links: &BackupLinks) -> io::Result<()> {
    if links.local.len() > 32 || links.peer.len() > 32 || links.origins.len() > 32 {
        return Err(invalid_data("too many linked identity records"));
    }
    if links.peer.iter().any(|id| id.eq_ignore_ascii_case(peer_id))
        || links.local.iter().any(|id| !links.origins.contains(id))
        || !links.local.is_disjoint(&links.peer)
    {
        return Err(invalid_data("invalid linked identity backup relationships"));
    }
    Ok(())
}

pub(crate) fn encode_backup_links(links: &BackupLinks) -> io::Result<Vec<u8>> {
    if links.local.len() > 32
        || links.peer.len() > 32
        || links.origins.len() > 32
        || links.local.iter().any(|id| !links.origins.contains(id))
        || !links.local.is_disjoint(&links.peer)
    {
        return Err(invalid_data("invalid linked identity backup relationships"));
    }
    let mut encoded =
        Vec::with_capacity(11 + (links.local.len() + links.peer.len() + links.origins.len()) * 32);
    encoded.extend_from_slice(BACKUP_LINKS_TRAILER);
    encoded.push(links.local.len() as u8);
    encoded.push(links.peer.len() as u8);
    encoded.push(links.origins.len() as u8);
    for id in links.local.iter().chain(&links.peer).chain(&links.origins) {
        encoded.extend_from_slice(&decode_peer_id(id)?);
    }
    Ok(encoded)
}

pub(crate) fn decode_backup_links(
    encoded: &[u8],
    peer_id: &str,
    identity: &Identity,
) -> io::Result<BackupLinks> {
    if encoded.len() < 11 || !encoded.starts_with(BACKUP_LINKS_TRAILER) {
        return Err(invalid_data("missing backup relationship trailer"));
    }
    let local_count = encoded[8] as usize;
    let peer_count = encoded[9] as usize;
    let origin_count = encoded[10] as usize;
    let records = local_count + peer_count + origin_count;
    if local_count > 32
        || peer_count > 32
        || origin_count > 32
        || encoded.len() != 11 + records * 32
    {
        return Err(invalid_data("invalid backup relationship trailer"));
    }
    let mut links = BackupLinks::default();
    let mut cursor = 11;
    for index in 0..records {
        let id = hex_encode(&encoded[cursor..cursor + 32]);
        cursor += 32;
        if index < local_count {
            links.local.insert(id);
        } else if index < local_count + peer_count {
            links.peer.insert(id);
        } else {
            links.origins.push(id);
        }
    }
    if links.local.len() != local_count
        || links.peer.len() != peer_count
        || links.origins.iter().collect::<HashSet<_>>().len() != links.origins.len()
        || links.origins.contains(&identity.public_id())
        || links.local.iter().any(|id| !links.origins.contains(id))
        || !links.local.is_disjoint(&links.peer)
        || links.peer.iter().any(|id| id == peer_id)
    {
        return Err(invalid_data("conflicting linked identity backup records"));
    }
    Ok(links)
}

pub(crate) fn backup_links_for(identity: &Identity, peer_id: &str) -> io::Result<BackupLinks> {
    let (local, peer) = read_linked_keys(identity, peer_id)?;
    let origins = crate::identity::previous_public_ids(identity)?;
    let local = local
        .into_iter()
        .filter(|id| origins.contains(id))
        .collect();
    Ok(BackupLinks {
        local,
        peer,
        origins,
    })
}

pub(crate) fn apply_backup_links(
    identity: &Identity,
    peer_id: &str,
    imported: &BackupLinks,
) -> io::Result<()> {
    if imported.local.is_empty() && imported.peer.is_empty() && imported.origins.is_empty() {
        return Ok(());
    }
    let current = read_linked_keys(identity, peer_id)?;
    let old_origins = crate::identity::previous_public_ids(identity)?;
    let mut origins: HashSet<String> = old_origins.iter().cloned().collect();
    origins.extend(imported.origins.iter().cloned());
    let mut local = current.0.clone();
    local.extend(imported.local.iter().cloned());
    let mut peer = current.1.clone();
    peer.extend(imported.peer.iter().cloned());
    if !local.is_disjoint(&peer) {
        return Err(invalid_data(
            "backup identity links conflict with local links",
        ));
    }
    if local.iter().any(|id| !origins.contains(id)) {
        return Err(invalid_data(
            "backup local identity link is outside confirmed lineage",
        ));
    }
    if peer.iter().any(|id| id == peer_id) {
        return Err(invalid_data(
            "backup peer identity link refers to current peer",
        ));
    }
    let new_origins: Vec<_> = origins.into_iter().collect();
    crate::identity::replace_previous_public_ids(identity, &new_origins)?;
    if let Err(error) = write_linked_keys(identity, peer_id, &(local, peer)) {
        if let Err(rollback_error) =
            crate::identity::replace_previous_public_ids(identity, &old_origins)
        {
            return Err(io::Error::other(format!("linked relationship save failed ({error}); lineage rollback failed ({rollback_error})")));
        }
        return Err(error);
    }
    Ok(())
}

pub(crate) fn encode_backup_with_links(
    identity: &Identity,
    peer_id: &str,
    messages: &[StoredMessage],
    password: Option<&str>,
    links: &BackupLinks,
) -> io::Result<Vec<u8>> {
    if links.peer.iter().any(|id| id.eq_ignore_ascii_case(peer_id)) {
        return Err(invalid_data("linked peer identity equals current peer"));
    }
    if links.local.iter().any(|id| !links.origins.contains(id))
        || !links.local.is_disjoint(&links.peer)
    {
        return Err(invalid_data("invalid linked identity backup relationships"));
    }
    let mut payload = Zeroizing::new(Vec::new());
    if let Some(password) = password {
        validate_backup_password(password)?;
    }
    let salt_len = if password.is_some() {
        BACKUP_SALT_BYTES
    } else {
        0
    };
    let header_len = BACKUP_SIGNED_MAGIC.len() + salt_len + NONCE_BYTES;
    let peer = decode_peer_id(peer_id)?;
    payload.extend_from_slice(&peer);
    let count = u32::try_from(messages.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many messages"))?;
    payload.extend_from_slice(&count.to_be_bytes());
    for message in messages {
        let text = message.text.as_bytes();
        payload.extend_from_slice(&message.unix_time.to_be_bytes());
        payload.push(match message.sender {
            MessageSender::Me => 0,
            MessageSender::Other => 1,
        });
        payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
        payload.extend_from_slice(text);
        match &message.proof {
            Some(proof) => {
                payload.push(1);
                payload.extend_from_slice(&proof.id);
                payload.extend_from_slice(&proof.signer);
                payload.extend_from_slice(&proof.recipient);
                payload.extend_from_slice(&proof.signature);
            }
            None => payload.push(0),
        }
        if payload.len().saturating_add(header_len + 16) > MAX_LEGACY_BACKUP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup is too large",
            ));
        }
    }
    if links.local.len() > 32 || links.peer.len() > 32 || links.origins.len() > 32 {
        return Err(invalid_data("too many linked identity records"));
    }
    payload.extend_from_slice(BACKUP_LINKS_TRAILER);
    payload.push(links.local.len() as u8);
    payload.push(links.peer.len() as u8);
    payload.push(links.origins.len() as u8);
    for id in &links.local {
        payload.extend_from_slice(&decode_peer_id(id)?);
    }
    for id in &links.peer {
        payload.extend_from_slice(&decode_peer_id(id)?);
    }
    for id in &links.origins {
        payload.extend_from_slice(&decode_peer_id(id)?);
    }
    if payload.len().saturating_add(header_len + 16) > MAX_LEGACY_BACKUP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup is too large",
        ));
    }
    let mut salt = [0; BACKUP_SALT_BYTES];
    crate::random::fill(&mut salt)?;
    let nonce = random_nonce()?;
    let (magic, key) = match password {
        Some(password) => {
            let password_key = derive_password_backup_key(password, &salt)?;
            (
                BACKUP_LINKED_MAGIC,
                derive_combined_backup_key(&identity.storage_key(), &password_key),
            )
        }
        None => (
            BACKUP_LINKED_MAGIC,
            derive_backup_key(&identity.storage_key()),
        ),
    };
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| io::Error::other("backup key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &backup_aad(identity, magic, password.is_some().then_some(&salt)),
            },
        )
        .map_err(|_| io::Error::other("backup encryption failed"))?;
    let mut backup = Vec::with_capacity(magic.len() + salt_len + NONCE_BYTES + encrypted.len());
    backup.extend_from_slice(magic);
    if password.is_some() {
        backup.extend_from_slice(&salt);
    }
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&encrypted);
    Ok(backup)
}

pub(crate) fn decode_backup(
    identity: &Identity,
    backup: &[u8],
    password: Option<&str>,
) -> io::Result<(String, Vec<StoredMessage>)> {
    let (peer_id, messages, _) = decode_backup_with_links(identity, backup, password)?;
    Ok((peer_id, messages))
}

pub(crate) fn decode_backup_with_links(
    identity: &Identity,
    backup: &[u8],
    password: Option<&str>,
) -> io::Result<(String, Vec<StoredMessage>, BackupLinks)> {
    if backup.len() > MAX_LEGACY_BACKUP_BYTES
        || backup.len() < BACKUP_MAGIC.len() + NONCE_BYTES + 16
    {
        return Err(invalid_data("invalid backup file"));
    }
    let magic = &backup[..BACKUP_MAGIC.len()];
    let signed_version = magic == BACKUP_SIGNED_MAGIC || magic == BACKUP_LINKED_MAGIC;
    let (salt, nonce_start, key) = if magic == BACKUP_MAGIC {
        if password.is_some() {
            return Err(invalid_data("legacy backup does not use a password"));
        }
        let nonce_start = BACKUP_MAGIC.len();
        (
            None,
            nonce_start,
            derive_backup_key(&identity.storage_key()),
        )
    } else if (magic == BACKUP_SIGNED_MAGIC || magic == BACKUP_LINKED_MAGIC) && password.is_none() {
        (
            None,
            BACKUP_SIGNED_MAGIC.len(),
            derive_backup_key(&identity.storage_key()),
        )
    } else if magic == BACKUP_PASSWORD_MAGIC {
        // ADBACK2 was password-only. Keep importing it, but new exports use
        // ADBACK3 so both the identity secret and password are required.
        let password = password.ok_or_else(|| invalid_data("backup password required"))?;
        validate_backup_password(password)?;
        let salt_start = BACKUP_MAGIC.len();
        let nonce_start = salt_start + BACKUP_SALT_BYTES;
        if backup.len() < nonce_start + NONCE_BYTES + 16 {
            return Err(invalid_data("invalid backup file"));
        }
        let salt: [u8; BACKUP_SALT_BYTES] = backup[salt_start..nonce_start]
            .try_into()
            .expect("fixed-size salt slice");
        (
            Some(salt),
            nonce_start,
            derive_password_backup_key(password, &salt)?,
        )
    } else if magic == BACKUP_COMBINED_MAGIC
        || magic == BACKUP_SIGNED_MAGIC
        || magic == BACKUP_LINKED_MAGIC
    {
        let password = password.ok_or_else(|| invalid_data("backup password required"))?;
        validate_backup_password(password)?;
        let salt_start = BACKUP_MAGIC.len();
        let nonce_start = salt_start + BACKUP_SALT_BYTES;
        if backup.len() < nonce_start + NONCE_BYTES + 16 {
            return Err(invalid_data("invalid backup file"));
        }
        let salt: [u8; BACKUP_SALT_BYTES] = backup[salt_start..nonce_start]
            .try_into()
            .expect("fixed-size salt slice");
        let password_key = derive_password_backup_key(password, &salt)?;
        (
            Some(salt),
            nonce_start,
            derive_combined_backup_key(&identity.storage_key(), &password_key),
        )
    } else {
        return Err(invalid_data("invalid backup file"));
    };
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("invalid backup key"))?;
    let payload = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&backup[nonce_start..nonce_start + NONCE_BYTES]),
                Payload {
                    msg: &backup[nonce_start + NONCE_BYTES..],
                    aad: &backup_aad(identity, magic, salt.as_ref()),
                },
            )
            .map_err(|_| invalid_data("backup authentication failed"))?,
    );
    if payload.len() < 36 {
        return Err(invalid_data("invalid backup payload"));
    }
    let peer_id = hex_encode(&payload[..32]);
    let count = u32::from_be_bytes(payload[32..36].try_into().expect("fixed slice")) as usize;
    if count > 1_000_000 || count > (payload.len() - 36) / 13 {
        return Err(invalid_data("too many backup messages"));
    }
    let mut cursor = 36;
    let mut imported = Vec::with_capacity(count);
    for _ in 0..count {
        if payload.len().saturating_sub(cursor) < 13 {
            return Err(invalid_data("truncated backup message"));
        }
        let unix_time =
            u64::from_be_bytes(payload[cursor..cursor + 8].try_into().expect("fixed slice"));
        cursor += 8;
        let sender = match payload[cursor] {
            0 => MessageSender::Me,
            1 => MessageSender::Other,
            _ => return Err(invalid_data("invalid backup sender")),
        };
        cursor += 1;
        let text_len =
            u32::from_be_bytes(payload[cursor..cursor + 4].try_into().expect("fixed slice"))
                as usize;
        cursor += 4;
        if text_len == 0
            || text_len > MAX_MESSAGE_BYTES
            || payload.len().saturating_sub(cursor) < text_len
        {
            return Err(invalid_data("invalid backup message length"));
        }
        let text = std::str::from_utf8(&payload[cursor..cursor + text_len])
            .map_err(|_| invalid_data("backup text is not UTF-8"))?
            .to_owned();
        cursor += text_len;
        let proof = if signed_version {
            match payload.get(cursor).copied() {
                Some(0) => {
                    cursor += 1;
                    None
                }
                Some(1) if payload.len().saturating_sub(cursor + 1) >= 144 => {
                    cursor += 1;
                    let id = payload[cursor..cursor + 16]
                        .try_into()
                        .expect("fixed slice");
                    cursor += 16;
                    let signer = payload[cursor..cursor + 32]
                        .try_into()
                        .expect("fixed slice");
                    cursor += 32;
                    let recipient = payload[cursor..cursor + 32]
                        .try_into()
                        .expect("fixed slice");
                    cursor += 32;
                    let signature = payload[cursor..cursor + 64]
                        .try_into()
                        .expect("fixed slice");
                    cursor += 64;
                    Some(MessageProof {
                        id,
                        signer,
                        recipient,
                        signature,
                    })
                }
                _ => return Err(invalid_data("invalid backup message proof")),
            }
        } else {
            None
        };
        let message = StoredMessage {
            unix_time,
            sender,
            text,
            proof,
        };
        imported.push(StoredMessage {
            unix_time: message.unix_time,
            sender: message.sender,
            text: message.text,
            proof: message.proof,
        });
    }
    let links = if magic == BACKUP_LINKED_MAGIC {
        if payload.len().saturating_sub(cursor) < 11
            || &payload[cursor..cursor + 8] != BACKUP_LINKS_TRAILER
        {
            return Err(invalid_data("missing linked identity backup data"));
        }
        cursor += 8;
        let local_count = payload[cursor] as usize;
        let peer_count = payload[cursor + 1] as usize;
        let origin_count = payload[cursor + 2] as usize;
        cursor += 3;
        if local_count > 32
            || peer_count > 32
            || origin_count > 32
            || payload.len() - cursor != (local_count + peer_count + origin_count) * 32
        {
            return Err(invalid_data("invalid linked identity backup data"));
        }
        let mut links = BackupLinks::default();
        for index in 0..local_count + peer_count + origin_count {
            let id = hex_encode(&payload[cursor..cursor + 32]);
            cursor += 32;
            if index < local_count {
                links.local.insert(id);
            } else if index < local_count + peer_count {
                links.peer.insert(id);
            } else {
                links.origins.push(id);
            }
        }
        if links.local.iter().any(|id| !links.origins.contains(id)) {
            return Err(invalid_data(
                "backup local identity link is outside its lineage",
            ));
        }
        if links.origins.iter().collect::<HashSet<_>>().len() != links.origins.len()
            || links.origins.contains(&identity.public_id())
            || !links.local.is_disjoint(&links.peer)
        {
            return Err(invalid_data("conflicting linked identity backup records"));
        }
        links
    } else {
        BackupLinks::default()
    };
    if cursor != payload.len() {
        return Err(invalid_data("unexpected backup data"));
    }
    let previous_local_ids = crate::identity::previous_public_ids(identity)?;
    let (stored_local, stored_peer) = read_linked_keys(identity, &peer_id)?;
    let mut local_ids: HashSet<_> = previous_local_ids.into_iter().collect();
    local_ids.extend(links.origins.iter().cloned());
    let mut local_keys: HashSet<_> = stored_local
        .into_iter()
        .chain(links.local.iter().cloned())
        .filter(|id| local_ids.contains(id))
        .collect();
    let mut peer_keys: HashSet<_> = stored_peer;
    peer_keys.extend(links.peer.iter().cloned());
    if !local_keys.is_disjoint(&peer_keys) {
        return Err(invalid_data("conflicting linked identity roles in backup"));
    }
    let local_aliases = local_keys
        .drain()
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<Vec<_>>>()?;
    let peer_aliases = peer_keys
        .into_iter()
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<Vec<_>>>()?;
    for message in imported.iter().filter(|message| message.proof.is_some()) {
        verify_stored_proof(identity, &peer_id, message, &local_aliases, &peer_aliases)?;
    }
    Ok((peer_id, imported, links))
}

/// Reads a whole legacy (in-memory) backup file, at most `MAX_LEGACY_BACKUP_BYTES`.
///
/// The length in the file's metadata is not trusted: a FIFO or a device reports zero,
/// and a file that is still growing can pass a size check and then keep going. So the
/// read itself is capped at one byte over the limit, and anything that is not a
/// regular file is refused before it is read.
pub(crate) fn read_legacy_backup(file: &mut File) -> io::Result<Vec<u8>> {
    if !file.metadata()?.is_file() {
        return Err(invalid_data("backup must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_LEGACY_BACKUP_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LEGACY_BACKUP_BYTES {
        zeroize::Zeroize::zeroize(&mut bytes);
        return Err(invalid_data(
            "legacy backup exceeds the supported 16 MiB format limit",
        ));
    }
    Ok(bytes)
}

/// Whether a backup in a format with weaker guarantees may be processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyBackupPolicy {
    /// Refuse formats that need an explicit decision from the user.
    Reject,
    /// The user has been shown the risk and confirmed it.
    Allow,
}

/// Returns the format name and the risk for backup formats that must not be
/// processed without the user's explicit confirmation. Formats that are
/// authenticated as a whole with the identity key (ADBACK1, ADBACK3-5, ADBACK7,
/// ADPACK3) need no confirmation.
pub(crate) fn legacy_backup_risk(magic: &[u8; 8]) -> Option<(&'static str, &'static str)> {
    if magic == BACKUP_PASSWORD_MAGIC {
        Some((
            "ADBACK2",
            "its key comes only from the password and its messages are unsigned, so anyone who knows the password can forge history",
        ))
    } else if magic == BACKUP_STREAM_V6_MAGIC {
        Some((
            "ADBACK6",
            "the peer id is stored in plaintext and, without a password, frames from different files cannot be told apart",
        ))
    } else if magic == BACKUP_BUNDLE_MAGIC {
        Some((
            "ADPACK1",
            "the bundle does not authenticate its conversation count or order",
        ))
    } else if magic == BACKUP_STREAM_BUNDLE_V2_MAGIC {
        Some((
            "ADPACK2",
            "the bundle does not authenticate its conversation count or order",
        ))
    } else {
        None
    }
}

pub(crate) fn require_legacy_opt_in(magic: &[u8; 8], policy: LegacyBackupPolicy) -> io::Result<()> {
    match legacy_backup_risk(magic) {
        Some((name, risk)) if policy == LegacyBackupPolicy::Reject => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("legacy backup format {name} requires explicit confirmation: {risk}"),
        )),
        _ => Ok(()),
    }
}

#[derive(Clone, Default)]
pub(crate) struct BackupLinks {
    pub(crate) local: HashSet<String>,
    pub(crate) peer: HashSet<String>,
    pub(crate) origins: Vec<String>,
}

pub(crate) fn derive_backup_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut backup_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(
            b"another-dimension-v2/portable-backup/v1",
            backup_key.as_mut(),
        )
        .expect("32 bytes is a valid HKDF output length");
    backup_key
}

pub(crate) fn derive_combined_backup_key(
    identity_key: &[u8; 32],
    password_key: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(password_key), identity_key)
        .expand(
            b"another-dimension-v2/portable-backup/identity-and-password/v1",
            key.as_mut(),
        )
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub(crate) fn validate_backup_password(password: &str) -> io::Result<()> {
    if password.chars().count() < 12 || password.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup password must be 12 to 1024 bytes/chars",
        ));
    }
    Ok(())
}

pub(crate) fn derive_password_backup_key(
    password: &str,
    salt: &[u8; BACKUP_SALT_BYTES],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|_| io::Error::other("backup KDF parameters unavailable"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| io::Error::other("backup key derivation failed"))?;
    Ok(key)
}

pub(crate) fn backup_aad(
    identity: &Identity,
    magic: &[u8],
    salt: Option<&[u8; BACKUP_SALT_BYTES]>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(magic.len() + BACKUP_SALT_BYTES + 32);
    aad.extend_from_slice(magic);
    if let Some(salt) = salt {
        aad.extend_from_slice(salt);
    }
    aad.extend_from_slice(&identity.public_key());
    aad
}
