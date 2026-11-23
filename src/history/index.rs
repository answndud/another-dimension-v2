//! The conversation index and the locks that serialize access to a conversation.

use super::*;

pub(crate) fn conversation_operation_lock(
    identity_id: &str,
    peer_id: &str,
) -> io::Result<Arc<Mutex<()>>> {
    let key = format!(
        "{}:{}",
        identity_id.to_ascii_lowercase(),
        peer_id.to_ascii_lowercase()
    );
    let locks = CONVERSATION_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| io::Error::other("conversation lock table unavailable"))?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    Ok(lock)
}

/// Keeps a conversation's in-process lock held until dropped, so a test can make an
/// import wait at a known point without sleeping.
#[cfg(test)]
pub(crate) struct ConversationHold {
    pub(crate) release: Option<std::sync::mpsc::Sender<()>>,
    pub(crate) thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl Drop for ConversationHold {
    fn drop(&mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
pub(crate) fn hold_conversation_for_test(
    identity: &Identity,
    peer_id: &str,
) -> io::Result<ConversationHold> {
    let lock = conversation_operation_lock(&identity.public_id(), peer_id)?;
    let (locked_sender, locked_receiver) = std::sync::mpsc::channel();
    let (release_sender, release_receiver) = std::sync::mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let _guard = lock.lock().unwrap();
        locked_sender.send(()).unwrap();
        // Returns when the hold is dropped and the sender goes away.
        let _ = release_receiver.recv();
    });
    locked_receiver
        .recv()
        .map_err(|_| io::Error::other("conversation hold failed"))?;
    Ok(ConversationHold {
        release: Some(release_sender),
        thread: Some(thread),
    })
}

pub(crate) fn acquire_conversation_file_lock(
    identity: &Identity,
    peer_id: &str,
) -> io::Result<File> {
    let identity_id = identity.public_id();
    let directory = data_directory()?.join(&identity_id);
    acquire_conversation_file_lock_at(&directory, &identity_id, peer_id, &identity.storage_key())
}

pub(crate) fn acquire_conversation_file_lock_for_path(
    history_path: &std::path::Path,
    identity_id: &str,
    peer_id: &str,
    key: &[u8; 32],
) -> io::Result<File> {
    let directory = history_path
        .parent()
        .ok_or_else(|| invalid_data("conversation directory unavailable"))?;
    acquire_conversation_file_lock_at(directory, identity_id, peer_id, key)
}

pub(crate) fn acquire_conversation_file_lock_at(
    directory: &std::path::Path,
    _identity_id: &str,
    peer_id: &str,
    key: &[u8; 32],
) -> io::Result<File> {
    crate::fsutil::create_private_dir_all(directory)?;
    set_private_directory(directory)?;
    let filename = format!(
        ".conversation-{}.lock",
        opaque_conversation_name(&derive_index_key(key), &peer_id.to_ascii_lowercase())
    );
    let file = crate::fsutil::private_options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join(filename))?;
    set_private_file(&file)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only operates on the live descriptor owned by `file`.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(file)
}

pub(crate) fn unlock_conversation_file(file: File) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only operates on the live descriptor owned by `file`.
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    drop(file);
}

pub(crate) fn register_conversation(
    identity: &Identity,
    identity_id: &str,
    peer_id: &str,
    directory: &std::path::Path,
) -> io::Result<()> {
    let lock = INDEX_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| io::Error::other("history index unavailable"))?;
    let mut peers = read_index(identity, identity_id, directory)?;
    if peers.iter().any(|existing| existing == peer_id) {
        return Ok(());
    }
    peers.push(peer_id.to_owned());
    write_index(identity, identity_id, directory, &peers)
}

pub(crate) fn read_index(
    identity: &Identity,
    identity_id: &str,
    directory: &std::path::Path,
) -> io::Result<Vec<String>> {
    let path = directory.join("conversations.idx");
    let bytes = match crate::fsutil::read_regular_file(path, crate::fsutil::MAX_STATE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if bytes.len() < INDEX_MAGIC.len() + NONCE_BYTES + 16 {
        return Err(invalid_data("invalid history index"));
    }
    let storage_key = identity.storage_key();
    let key = if &bytes[..8] == INDEX_MAGIC_V2 {
        crate::identity::purpose_key(&storage_key, INDEX_AEAD_LABEL)
    } else if &bytes[..8] == INDEX_MAGIC {
        derive_index_key(&storage_key)
    } else {
        return Err(invalid_data("invalid history index"));
    };
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("invalid history index key"))?;
    let nonce = &bytes[INDEX_MAGIC.len()..INDEX_MAGIC.len() + NONCE_BYTES];
    let payload = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &bytes[INDEX_MAGIC.len() + NONCE_BYTES..],
                aad: identity_id.as_bytes(),
            },
        )
        .map_err(|_| invalid_data("history index authentication failed"))?;
    if payload.len() < 4 {
        return Err(invalid_data("invalid history index payload"));
    }
    let count = u32::from_be_bytes(payload[..4].try_into().expect("fixed slice")) as usize;
    if count > 100_000 || payload.len() != 4 + count * 32 {
        return Err(invalid_data("invalid history index count"));
    }
    Ok(payload[4..]
        .chunks_exact(32)
        .map(|chunk| chunk.iter().map(|byte| format!("{byte:02x}")).collect())
        .collect())
}

pub(crate) fn write_index(
    identity: &Identity,
    identity_id: &str,
    directory: &std::path::Path,
    peers: &[String],
) -> io::Result<()> {
    #[cfg(test)]
    if test_failure(FAIL_INDEX_WRITE) {
        return Err(io::Error::other("injected history index write failure"));
    }
    let count = u32::try_from(peers.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many conversations"))?;
    let mut payload = Vec::with_capacity(4 + peers.len() * 32);
    payload.extend_from_slice(&count.to_be_bytes());
    for peer in peers {
        let bytes = crate::hex::decode_array::<32>(peer)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer id"))?;
        payload.extend_from_slice(&bytes);
    }
    let nonce = random_nonce()?;
    let storage_key = identity.storage_key();
    // The filename key only names files. The index is encrypted with its own key.
    let filename_key = derive_index_key(&storage_key);
    let key = crate::identity::purpose_key(&storage_key, INDEX_AEAD_LABEL);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| io::Error::other("history index key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: identity_id.as_bytes(),
            },
        )
        .map_err(|_| io::Error::other("history index encryption failed"))?;
    let temporary = directory.join(format!(
        ".index-{}.tmp",
        opaque_conversation_name(&filename_key, &crate::hex::encode(&nonce))
    ));
    let path = directory.join("conversations.idx");
    let mut file = crate::fsutil::private_options()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    set_private_file(&file)?;
    file.write_all(INDEX_MAGIC_V2)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    drop(file);
    crate::fsutil::rename_durable(temporary, path)?;
    Ok(())
}

pub(crate) fn derive_index_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut index_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(
            b"another-dimension-v2/conversation-file-name/v1",
            index_key.as_mut(),
        )
        .expect("32 bytes is a valid HKDF output length");
    index_key
}

pub(crate) fn opaque_conversation_name(key: &[u8; 32], peer_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"another-dimension-v2/conversation-file/v1");
    mac.update(peer_id.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
