//! Keys of previous identities that a conversation was linked to.

use super::*;

/// Persist an identity relationship independently of conversation content.
/// `previous_id` is accepted only from a completed local link flow.
pub(crate) fn record_linked_local_identity(
    identity: &Identity,
    peer_id: &str,
    previous_id: &str,
) -> io::Result<()> {
    validate_peer_id(previous_id)?;
    if !crate::identity::previous_public_ids(identity)?
        .iter()
        .any(|id| id.eq_ignore_ascii_case(previous_id))
    {
        return Err(invalid_data(
            "local identity link is outside confirmed lineage",
        ));
    }
    let mut linked = read_linked_keys(identity, peer_id)?;
    linked.0.insert(previous_id.to_ascii_lowercase());
    write_linked_keys(identity, peer_id, &linked)
}

pub(crate) fn is_linked_peer_identity(
    identity: &Identity,
    peer_id: &str,
    previous_id: &str,
) -> io::Result<bool> {
    validate_peer_id(previous_id)?;
    Ok(read_linked_keys(identity, peer_id)?
        .1
        .contains(&previous_id.to_ascii_lowercase()))
}

#[cfg(test)]
pub(crate) fn is_linked_local_identity(
    identity: &Identity,
    peer_id: &str,
    previous_id: &str,
) -> io::Result<bool> {
    validate_peer_id(previous_id)?;
    let in_lineage = crate::identity::previous_public_ids(identity)?
        .iter()
        .any(|id| id.eq_ignore_ascii_case(previous_id));
    Ok(in_lineage
        && read_linked_keys(identity, peer_id)?
            .0
            .contains(&previous_id.to_ascii_lowercase()))
}

pub(crate) fn pending_local_identity_links(
    identity: &Identity,
    peer_id: &str,
    previous_ids: &[String],
) -> io::Result<Vec<String>> {
    let (locals, _) = read_linked_keys(identity, peer_id)?;
    let lineage: HashSet<_> = crate::identity::previous_public_ids(identity)?
        .into_iter()
        .collect();
    Ok(previous_ids
        .iter()
        .filter(|id| {
            let id = id.to_ascii_lowercase();
            lineage.contains(&id) && !locals.contains(&id)
        })
        .cloned()
        .collect())
}

pub(crate) fn copy_linked_keys_to(
    source: &Identity,
    replacement: &Identity,
    peer_id: &str,
) -> io::Result<()> {
    let links = read_linked_keys(source, peer_id)?;
    let source_origins: HashSet<_> = crate::identity::previous_public_ids(source)?
        .into_iter()
        .collect();
    if links.0.iter().any(|id| !source_origins.contains(id)) {
        return Err(invalid_data(
            "source local identity link is outside confirmed lineage",
        ));
    }
    let target_origins: HashSet<_> = crate::identity::previous_public_ids(replacement)?
        .into_iter()
        .collect();
    if links.0.iter().any(|id| !target_origins.contains(id)) {
        return Err(invalid_data(
            "replacement identity lineage does not contain a linked key",
        ));
    }
    write_linked_keys(replacement, peer_id, &links)
}

/// Return only aliases whose explicit link marker is in the current local
/// conversation. Remote transition announcements alone are never sufficient.
/// Linked identity keys for one conversation: (local aliases, peer aliases).
pub(crate) type LinkedKeys = (Vec<[u8; 32]>, Vec<[u8; 32]>);

pub(crate) fn linked_identity_keys(
    identity: &Identity,
    _messages: &[StoredMessage],
    identity_id: &str,
    peer_id: &str,
    previous_local_ids: &[String],
) -> io::Result<LinkedKeys> {
    let identity_id = identity_id.to_ascii_lowercase();
    let peer_id = peer_id.to_ascii_lowercase();
    validate_peer_id(&identity_id)?;
    validate_peer_id(&peer_id)?;
    // Legacy text markers are untrusted conversation content: a restored
    // unsigned record can contain them. Only the identity-key authenticated
    // local relation store contributes aliases.
    let (locals, peers) = read_linked_keys(identity, &peer_id)?;
    let origins: HashSet<_> = previous_local_ids
        .iter()
        .map(|id| id.to_ascii_lowercase())
        .collect();
    let local_aliases = locals
        .into_iter()
        .filter(|id| origins.contains(id))
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<HashSet<_>>>()?;
    let peer_aliases = peers
        .into_iter()
        .map(|id| decode_peer_id(&id))
        .collect::<io::Result<HashSet<_>>>()?;
    Ok((
        local_aliases.into_iter().collect(),
        peer_aliases.into_iter().collect(),
    ))
}

pub(crate) type LinkedIds = (HashSet<String>, HashSet<String>);

pub(crate) fn linked_key_path(identity: &Identity, peer_id: &str) -> io::Result<PathBuf> {
    let identity_id = identity.public_id();
    let directory = data_directory()?.join(identity_id);
    let key = identity.storage_key();
    let index_key = derive_index_key(&key);
    Ok(directory.join(format!(
        ".linked-{}.adkey",
        opaque_conversation_name(&index_key, peer_id)
    )))
}

pub(crate) fn read_linked_keys(identity: &Identity, peer_id: &str) -> io::Result<LinkedIds> {
    validate_peer_id(peer_id)?;
    let identity_id = identity.public_id();
    let peer_id = peer_id.to_ascii_lowercase();
    let path = linked_key_path(identity, &peer_id)?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((HashSet::new(), HashSet::new()))
        }
        Err(error) => return Err(error),
    };
    if bytes.len() < 8 + NONCE_BYTES + 16 {
        return Err(invalid_data("invalid linked identity key store"));
    }
    let storage_key = identity.storage_key();
    let key = if bytes.starts_with(LINKED_KEYS_MAGIC_V2) {
        crate::identity::purpose_key(&storage_key, LINKED_KEYS_AEAD_LABEL)
    } else if bytes.starts_with(LINKED_KEYS_MAGIC) {
        // Written before the key was separated from the one used for log records.
        Zeroizing::new(*storage_key)
    } else {
        return Err(invalid_data("invalid linked identity key store"));
    };
    let nonce = Nonce::from_slice(&bytes[8..20]);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("linked identity key unavailable"))?;
    let aad = [identity_id.as_bytes(), peer_id.as_bytes()].concat();
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &bytes[20..],
                    aad: &aad,
                },
            )
            .map_err(|_| invalid_data("linked identity key store authentication failed"))?,
    );
    if plaintext.len() < 2 {
        return Err(invalid_data("invalid linked identity key data"));
    }
    let local_count = plaintext[0] as usize;
    let peer_count = plaintext[1] as usize;
    if local_count > 32 || peer_count > 32 || plaintext.len() != 2 + (local_count + peer_count) * 32
    {
        return Err(invalid_data("invalid linked identity key count"));
    }
    let mut locals = HashSet::new();
    let mut peers = HashSet::new();
    for (index, chunk) in plaintext[2..].chunks_exact(32).enumerate() {
        let id = hex_encode(chunk);
        if index < local_count {
            locals.insert(id);
        } else {
            peers.insert(id);
        }
    }
    Ok((locals, peers))
}

pub(crate) fn write_linked_keys(
    identity: &Identity,
    peer_id: &str,
    linked: &LinkedIds,
) -> io::Result<()> {
    #[cfg(test)]
    if test_failure(FAIL_LINKED_STORE) {
        return Err(io::Error::other("injected linked identity store failure"));
    }
    validate_peer_id(peer_id)?;
    if linked.0.len() > 32 || linked.1.len() > 32 {
        return Err(invalid_data("linked identity key count exceeded"));
    }
    let identity_id = identity.public_id();
    let peer_id = peer_id.to_ascii_lowercase();
    let path = linked_key_path(identity, &peer_id)?;
    let directory = path
        .parent()
        .ok_or_else(|| invalid_data("linked key directory unavailable"))?;
    crate::fsutil::create_private_dir_all(directory)?;
    set_private_directory(directory)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        2 + (linked.0.len() + linked.1.len()) * 32,
    ));
    plaintext.push(linked.0.len() as u8);
    plaintext.push(linked.1.len() as u8);
    for id in &linked.0 {
        plaintext.extend_from_slice(&decode_peer_id(id)?);
    }
    for id in &linked.1 {
        plaintext.extend_from_slice(&decode_peer_id(id)?);
    }
    let mut nonce = [0; NONCE_BYTES];
    crate::random::fill(&mut nonce)?;
    let key = crate::identity::purpose_key(&identity.storage_key(), LINKED_KEYS_AEAD_LABEL);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("linked identity key unavailable"))?;
    let aad = [identity_id.as_bytes(), peer_id.as_bytes()].concat();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| io::Error::other("linked identity key encryption failed"))?;
    let mut contents = LINKED_KEYS_MAGIC_V2.to_vec();
    contents.extend_from_slice(&nonce);
    contents.extend_from_slice(&encrypted);
    let temporary = path.with_extension(format!("{}.tmp", hex_encode(&random_nonce()?)));
    let mut options = crate::fsutil::private_options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        crate::fsutil::rename_durable(&temporary, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

impl History {
    /// Merge an explicitly linked prior conversation into this conversation.
    /// The destination is committed before the old entry is removed.
    pub fn link_prior_identity(
        &mut self,
        identity: &Identity,
        previous_peer_id: &str,
        transition: StoredMessage,
    ) -> io::Result<Vec<StoredMessage>> {
        validate_peer_id(previous_peer_id)?;
        if previous_peer_id.eq_ignore_ascii_case(&self.peer_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "identity transition must refer to a prior conversation",
            ));
        }
        let (previous, recovered_partial) =
            Self::read_for_identity_copy(identity, previous_peer_id)?;
        if recovered_partial {
            return Err(invalid_data("prior conversation has an incomplete record"));
        }
        let (current, recovered_partial) = Self::read_for_identity_copy(identity, &self.peer_id)?;
        if recovered_partial {
            return Err(invalid_data(
                "current conversation has an incomplete record",
            ));
        }
        // These snapshots belong to different identity epochs. Equal message
        // contents do not prove they are the same message, so preserve both.
        let mut merged = current.clone();
        merged.extend(previous);
        if !merged
            .iter()
            .any(|item| item.sender == transition.sender && item.text == transition.text)
        {
            merged.push(transition);
        }
        // Always restore chronological ordering, including when the transition
        // marker was already present in one of the snapshots.
        merged.sort_by_key(|item| item.unix_time);
        let old_trust = read_linked_keys(identity, &self.peer_id)?;
        let previous_trust = read_linked_keys(identity, previous_peer_id)?;
        let mut new_trust = old_trust.clone();
        new_trust.1.insert(previous_peer_id.to_ascii_lowercase());
        let local_lineage: HashSet<_> = crate::identity::previous_public_ids(identity)?
            .into_iter()
            .map(|id| id.to_ascii_lowercase())
            .collect();
        if previous_trust
            .0
            .iter()
            .any(|id| !local_lineage.contains(id))
        {
            return Err(invalid_data(
                "prior conversation contains a local identity link outside this identity lineage",
            ));
        }
        new_trust.0.extend(previous_trust.0);
        new_trust.1.extend(previous_trust.1);
        if !new_trust.0.is_disjoint(&new_trust.1) {
            return Err(invalid_data(
                "prior conversation has conflicting linked identity roles",
            ));
        }
        self.replace(&merged)?;
        if let Err(error) = write_linked_keys(identity, &self.peer_id, &new_trust) {
            let rollback = self.replace(&current);
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(io::Error::other(format!(
                    "identity link trust save failed ({error}); restoring destination failed ({rollback_error})"
                ))),
            };
        }
        if let Err(delete_error) = Self::delete_conversation(identity, previous_peer_id) {
            #[cfg(test)]
            let rollback = if test_failure(FAIL_ROLLBACK_REPLACE) {
                Err(io::Error::other(
                    "injected current conversation rollback failure",
                ))
            } else {
                self.replace(&current)
            };
            #[cfg(not(test))]
            let rollback = self.replace(&current);
            let trust_rollback = write_linked_keys(identity, &self.peer_id, &old_trust);
            match (rollback, trust_rollback) {
                (Ok(()), Ok(())) => {}
                (rollback, trust) => {
                    let rollback_error = rollback.err().map(|error| error.to_string());
                    let trust_error = trust.err().map(|error| error.to_string());
                    return Err(io::Error::other(format!(
                        "prior conversation cleanup failed ({delete_error}); destination rollback: {}; identity trust rollback: {}",
                        rollback_error.as_deref().unwrap_or("succeeded"),
                        trust_error.as_deref().unwrap_or("succeeded")
                    )));
                }
            }
            return Err(delete_error);
        }
        Ok(merged)
    }
}
