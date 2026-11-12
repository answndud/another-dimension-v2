//! Per-identity encrypted append-only message history.

use crate::identity::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADLOG2\0\0";
const LEGACY_MAGIC: &[u8; 8] = b"ADLOG1\0\0";
const MAX_MESSAGE_BYTES: usize = 4096;
const NONCE_BYTES: usize = 12;
const INDEX_MAGIC: &[u8; 8] = b"ADIDX1\0\0";
const BACKUP_MAGIC: &[u8; 8] = b"ADBACK1\0";
const BACKUP_PASSWORD_MAGIC: &[u8; 8] = b"ADBACK2\0";
const BACKUP_COMBINED_MAGIC: &[u8; 8] = b"ADBACK3\0";
const BACKUP_SIGNED_MAGIC: &[u8; 8] = b"ADBACK4\0";
const BACKUP_BUNDLE_MAGIC: &[u8; 8] = b"ADPACK1\0";
const TRANSFER_MAGIC: &[u8; 6] = b"ADREC1";
const TRANSFER_CHUNK_MAGIC: &[u8; 5] = b"ADCH1";
const MESSAGE_MAGIC: &[u8; 6] = b"ADMSG1";
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const BACKUP_SALT_BYTES: usize = 16;
pub(crate) const IDENTITY_EVENT_PREFIX: &str = "[AD2-IDENTITY-EVENT/1] ";
static INDEX_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static TEST_DATA_DIRECTORY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_FAILURES: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
const FAIL_INDEX_WRITE: u8 = 1;
#[cfg(test)]
const FAIL_DELETE_RESTORE: u8 = 2;
#[cfg(test)]
const FAIL_ROLLBACK_REPLACE: u8 = 8;

#[cfg(test)]
fn test_failure(failure: u8) -> bool {
    TEST_FAILURES.with(|failures| failures.get() & failure != 0)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoredMessage {
    pub unix_time: u64,
    pub sender: MessageSender,
    pub text: String,
    pub proof: Option<MessageProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MessageProof {
    pub id: [u8; 16],
    pub signer: [u8; 32],
    pub recipient: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageSender {
    Me,
    Other,
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub peer_id: String,
    pub message_count: usize,
    pub last_message: Option<u64>,
}

pub struct History {
    file: File,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
    next_index: u64,
}

impl History {
    /// Read the existing encrypted index without opening or creating histories.
    pub(crate) fn known_peer_ids(identity: &Identity) -> io::Result<Vec<String>> {
        let identity_id = identity.public_id();
        let directory = data_directory()?.join(&identity_id);
        if !directory.exists() {
            return Ok(Vec::new());
        }
        read_index(identity, &identity_id, &directory)
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
        create_dir_all(&directory)?;
        set_private_directory(&directory)?;
        let index_key = derive_index_key(&key);
        let path = directory.join(format!(
            "{}.adlog",
            opaque_conversation_name(&index_key, &peer_id)
        ));
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
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;

        let mut recovered_header = false;
        if file.metadata()?.len() < MAGIC.len() as u64 {
            if file.metadata()?.len() > 0 {
                file.set_len(0)?;
                recovered_header = true;
            }
            file.write_all(MAGIC)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::Start(0))?;
        let mut file_magic = [0; MAGIC.len()];
        file.read_exact(&mut file_magic)?;
        let migrate_legacy = &file_magic == LEGACY_MAGIC;
        if &file_magic != MAGIC && !migrate_legacy {
            return Err(invalid_data("unsupported history format"));
        }
        file.seek(SeekFrom::Start(0))?;
        let (messages, next_index, recovered_partial) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            true,
        )?;
        file.seek(SeekFrom::End(0))?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;
        let mut history = Self {
            file,
            path,
            key,
            identity_id,
            peer_id,
            next_index,
        };
        if migrate_legacy {
            history.replace(&messages)?;
        }
        Ok((history, messages, recovered_header || recovered_partial))
    }

    pub fn append(&mut self, message: &StoredMessage) -> io::Result<()> {
        let record = encode_record(
            &self.key,
            &self.identity_id,
            &self.peer_id,
            self.next_index,
            message,
        )?;
        self.file.write_all(&record)?;
        self.file.sync_data()?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("history record limit reached"))?;
        Ok(())
    }

    pub fn replace(&mut self, messages: &[StoredMessage]) -> io::Result<()> {
        let suffix = hex_encode(&random_nonce()?);
        let temporary = self.path.with_extension(format!("{suffix}.tmp"));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .append(true)
                .write(true)
                .open(&temporary)?;
            set_private_file(&file)?;
            file.write_all(MAGIC)?;
            for (index, message) in messages.iter().enumerate() {
                let record = encode_record(
                    &self.key,
                    &self.identity_id,
                    &self.peer_id,
                    index as u64,
                    message,
                )?;
                file.write_all(&record)?;
            }
            file.sync_all()?;
            rename(&temporary, &self.path)?;
            self.file = file;
            self.next_index = messages.len() as u64;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
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
            let (_, messages, _) = Self::open(identity, &peer_id)?;
            summaries.push(Summary {
                peer_id,
                message_count: messages.len(),
                last_message: messages.last().map(|item| item.unix_time),
            });
        }
        summaries.sort_by(|left, right| right.last_message.cmp(&left.last_message));
        Ok(summaries)
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
        let mut file = File::open(path)?;
        let (messages, _, recovered_partial) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            false,
        )?;
        Ok((messages, recovered_partial))
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
        let lock = INDEX_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| io::Error::other("history index unavailable"))?;
        let mut peers = read_index(identity, &identity_id, &directory)?;
        if !peers.iter().any(|existing| existing == &peer_id) {
            return Ok(());
        }
        let tombstone = directory.join(format!(".deleted-{}.tmp", hex_encode(&random_nonce()?)));
        if path.exists() {
            rename(&path, &tombstone)?;
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
                    rename(&tombstone, &path)
                };
                #[cfg(not(test))]
                let restore_result = rename(&tombstone, &path);
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
        Ok(())
    }

    pub fn export_backup(
        identity: &Identity,
        peer_id: &str,
        password: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let (_, messages, _) = Self::open(identity, peer_id)?;
        encode_backup(identity, peer_id, &messages, password)
    }

    /// Bundle separately authenticated conversation backups. Each child stays
    /// encrypted with the existing backup format, preserving import compatibility.
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
            if bundle.len().saturating_add(4 + backup.len()) > MAX_BACKUP_BYTES {
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
        if bundle.len() > MAX_BACKUP_BYTES
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
            if len > MAX_BACKUP_BYTES || bundle.len().saturating_sub(cursor) < len {
                return Err(invalid_data("truncated backup bundle"));
            }
            let (peer_id, messages) = decode_backup(identity, &bundle[cursor..cursor + len], None)?;
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
            let len =
                u32::from_be_bytes(bundle[cursor..cursor + 4].try_into().expect("fixed slice"))
                    as usize;
            cursor += 4;
            let (_, messages) = decode_backup(identity, &bundle[cursor..cursor + len], None)?;
            cursor += len;
            let (mut history, existing, _) = Self::open(identity, &peer_id)?;
            let merged = merge_snapshot(existing, messages)?;
            let count = merged.len();
            history.replace(&merged)?;
            imported.push((peer_id, count));
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
        let (peer_id, messages) = decode_backup(previous_identity, backup, previous_password)?;
        encode_backup(
            replacement_identity,
            &peer_id,
            &messages,
            replacement_password,
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
        self.replace(&merged)?;
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
            if let Err(rollback_error) = rollback {
                return Err(io::Error::other(format!(
                    "prior conversation cleanup failed ({delete_error}); restoring destination also failed ({rollback_error})"
                )));
            }
            return Err(delete_error);
        }
        Ok(merged)
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

    pub fn import_backup(
        identity: &Identity,
        backup: &[u8],
        password: Option<&str>,
    ) -> io::Result<(String, usize)> {
        let (peer_id, imported) = decode_backup(identity, backup, password)?;

        let (mut history, existing, _) = Self::open(identity, &peer_id)?;
        let merged = merge_snapshot(existing, imported)?;
        let count = merged.len();
        history.replace(&merged)?;
        Ok((peer_id, count))
    }
}

fn encode_backup(
    identity: &Identity,
    peer_id: &str,
    messages: &[StoredMessage],
    password: Option<&str>,
) -> io::Result<Vec<u8>> {
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
        if payload.len().saturating_add(header_len + 16) > MAX_BACKUP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backup is too large",
            ));
        }
    }
    let mut salt = [0; BACKUP_SALT_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
    let nonce = random_nonce()?;
    let (magic, key) = match password {
        Some(password) => {
            let password_key = derive_password_backup_key(password, &salt)?;
            (
                BACKUP_SIGNED_MAGIC,
                derive_combined_backup_key(&identity.storage_key(), &password_key),
            )
        }
        None => (
            BACKUP_SIGNED_MAGIC,
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

fn decode_backup(
    identity: &Identity,
    backup: &[u8],
    password: Option<&str>,
) -> io::Result<(String, Vec<StoredMessage>)> {
    if backup.len() > MAX_BACKUP_BYTES || backup.len() < BACKUP_MAGIC.len() + NONCE_BYTES + 16 {
        return Err(invalid_data("invalid backup file"));
    }
    let magic = &backup[..BACKUP_MAGIC.len()];
    let signed_version = magic == BACKUP_SIGNED_MAGIC;
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
    } else if magic == BACKUP_SIGNED_MAGIC && password.is_none() {
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
    } else if magic == BACKUP_COMBINED_MAGIC || magic == BACKUP_SIGNED_MAGIC {
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
    if cursor != payload.len() {
        return Err(invalid_data("unexpected backup data"));
    }
    let previous_local_ids = crate::identity::previous_public_ids(identity)?;
    let (local_aliases, peer_aliases) = linked_identity_keys(
        &imported,
        &identity.public_id(),
        &peer_id,
        &previous_local_ids,
    )?;
    for message in imported.iter().filter(|message| message.proof.is_some()) {
        verify_stored_proof(identity, &peer_id, message, &local_aliases, &peer_aliases)?;
    }
    Ok((peer_id, imported))
}

/// Backups contain snapshots without record IDs. Preserve the greatest count of
/// each exact message found in either copy: this makes re-import idempotent while
/// retaining identical messages already repeated within either snapshot.
fn merge_snapshot(
    existing: Vec<StoredMessage>,
    imported: Vec<StoredMessage>,
) -> io::Result<Vec<StoredMessage>> {
    merge_restored(&existing, &imported)
}

fn validate_peer_id(peer_id: &str) -> io::Result<()> {
    if peer_id.len() != 64 || !peer_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer id",
        ));
    }
    Ok(())
}

pub(crate) fn decode_peer_id(peer_id: &str) -> io::Result<[u8; 32]> {
    validate_peer_id(peer_id)?;
    let mut bytes = [0; 32];
    for (index, pair) in peer_id.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Ok(bytes)
}

pub(crate) fn sign_message(
    identity: &Identity,
    peer_id: &str,
    unix_time: u64,
    text: String,
) -> io::Result<StoredMessage> {
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid message size",
        ));
    }
    let mut id = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut id)?;
    let mut proof = MessageProof {
        id,
        signer: identity.public_key(),
        recipient: decode_peer_id(peer_id)?,
        signature: [0; 64],
    };
    proof.signature = identity.sign(&message_signing_payload(unix_time, &text, &proof));
    Ok(StoredMessage {
        unix_time,
        sender: MessageSender::Me,
        text,
        proof: Some(proof),
    })
}

pub(crate) fn encode_transfer(message: &StoredMessage) -> io::Result<Vec<u8>> {
    encode_wire_message(message, TRANSFER_MAGIC)
}

pub(crate) fn encode_transfer_chunk(
    message: &StoredMessage,
    request_id: &str,
    chunk_index: usize,
) -> io::Result<Vec<u8>> {
    if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("invalid history request ID"));
    }
    let chunk_index =
        u32::try_from(chunk_index).map_err(|_| invalid_data("history chunk index is too large"))?;
    let mut frame = Vec::new();
    frame.extend_from_slice(TRANSFER_CHUNK_MAGIC);
    frame.extend_from_slice(request_id.as_bytes());
    frame.extend_from_slice(&chunk_index.to_be_bytes());
    frame.extend_from_slice(&encode_transfer(message)?);
    Ok(frame)
}

pub(crate) fn transfer_chunk_metadata(frame: &[u8]) -> io::Result<(String, usize, &[u8])> {
    let header_len = TRANSFER_CHUNK_MAGIC.len() + 64 + 4;
    if frame.len() < header_len || !frame.starts_with(TRANSFER_CHUNK_MAGIC) {
        return Err(invalid_data("history record has no request and chunk ID"));
    }
    let request_id = std::str::from_utf8(&frame[5..69])
        .map_err(|_| invalid_data("invalid history request ID"))?;
    if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_data("invalid history request ID"));
    }
    let chunk = u32::from_be_bytes(frame[69..73].try_into().expect("fixed slice")) as usize;
    Ok((request_id.to_owned(), chunk, &frame[header_len..]))
}

pub(crate) fn encode_signed_message(message: &StoredMessage) -> io::Result<Vec<u8>> {
    if message.proof.is_none() || message.sender != MessageSender::Me {
        return Err(invalid_data("outgoing message is not signed"));
    }
    encode_wire_message(message, MESSAGE_MAGIC)
}

fn encode_wire_message(message: &StoredMessage, magic: &[u8; 6]) -> io::Result<Vec<u8>> {
    let text = message.text.as_bytes();
    if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid message size",
        ));
    }
    let mut frame = Vec::with_capacity(6 + 1 + 8 + 4 + text.len() + 1 + 144);
    frame.extend_from_slice(magic);
    frame.push(match message.sender {
        MessageSender::Me => 0,
        MessageSender::Other => 1,
    });
    frame.extend_from_slice(&message.unix_time.to_be_bytes());
    frame.extend_from_slice(&(text.len() as u32).to_be_bytes());
    frame.extend_from_slice(text);
    match &message.proof {
        Some(proof) => {
            frame.push(1);
            frame.extend_from_slice(&proof.id);
            frame.extend_from_slice(&proof.signer);
            frame.extend_from_slice(&proof.recipient);
            frame.extend_from_slice(&proof.signature);
        }
        None => frame.push(0),
    }
    Ok(frame)
}

pub(crate) fn decode_transfer(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
) -> io::Result<StoredMessage> {
    decode_transfer_with_linked_keys(identity, peer_id, peer_key, frame, &[], &[])
}

pub(crate) fn decode_transfer_with_linked_keys(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<StoredMessage> {
    decode_wire_message(
        identity,
        peer_id,
        peer_key,
        frame,
        TRANSFER_MAGIC,
        local_aliases,
        peer_aliases,
    )
}

pub(crate) fn decode_signed_message(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
) -> io::Result<StoredMessage> {
    let message = decode_wire_message(identity, peer_id, peer_key, frame, MESSAGE_MAGIC, &[], &[])?;
    if message.proof.is_none() {
        return Err(invalid_data("new message has no signature"));
    }
    if message.sender != MessageSender::Other {
        return Err(invalid_data("new message has an invalid sender"));
    }
    Ok(message)
}

fn decode_wire_message(
    identity: &Identity,
    peer_id: &str,
    peer_key: &[u8; 32],
    frame: &[u8],
    magic: &[u8; 6],
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<StoredMessage> {
    if frame.len() < magic.len() + 14 || !frame.starts_with(magic) {
        return Err(invalid_data("invalid history transfer frame"));
    }
    let mut cursor = TRANSFER_MAGIC.len();
    let sender = match frame[cursor] {
        0 => MessageSender::Other,
        1 => MessageSender::Me,
        _ => return Err(invalid_data("invalid transferred sender")),
    };
    cursor += 1;
    let unix_time = u64::from_be_bytes(frame[cursor..cursor + 8].try_into().expect("fixed slice"));
    cursor += 8;
    let text_len =
        u32::from_be_bytes(frame[cursor..cursor + 4].try_into().expect("fixed slice")) as usize;
    cursor += 4;
    if text_len == 0 || text_len > MAX_MESSAGE_BYTES || frame.len() < cursor + text_len + 1 {
        return Err(invalid_data("invalid transferred message length"));
    }
    let text = std::str::from_utf8(&frame[cursor..cursor + text_len])
        .map_err(|_| invalid_data("transferred message is not UTF-8"))?
        .to_owned();
    cursor += text_len;
    let proof = match frame[cursor] {
        0 if frame.len() == cursor + 1 => None,
        1 if frame.len() == cursor + 1 + 144 => {
            cursor += 1;
            let id = frame[cursor..cursor + 16].try_into().expect("fixed slice");
            cursor += 16;
            let signer = frame[cursor..cursor + 32].try_into().expect("fixed slice");
            cursor += 32;
            let recipient = frame[cursor..cursor + 32].try_into().expect("fixed slice");
            cursor += 32;
            let signature = frame[cursor..cursor + 64].try_into().expect("fixed slice");
            Some(MessageProof {
                id,
                signer,
                recipient,
                signature,
            })
        }
        _ => return Err(invalid_data("invalid transferred message proof")),
    };
    if let Some(proof) = &proof {
        let (expected_signer, expected_recipient) = match sender {
            MessageSender::Other => (*peer_key, identity.public_key()),
            MessageSender::Me => (identity.public_key(), decode_peer_id(peer_id)?),
        };
        let (signer_aliases, recipient_aliases) = match sender {
            MessageSender::Other => (peer_aliases, local_aliases),
            MessageSender::Me => (local_aliases, peer_aliases),
        };
        let key = VerifyingKey::from_bytes(&proof.signer)
            .map_err(|_| invalid_data("invalid transferred signing key"))?;
        let signature = Signature::from_bytes(&proof.signature);
        key.verify_strict(
            &message_signing_payload(unix_time, &text, proof),
            &signature,
        )
        .map_err(|_| invalid_data("transferred message signature failed"))?;
        if (proof.signer != expected_signer && !signer_aliases.contains(&proof.signer))
            || (proof.recipient != expected_recipient
                && !recipient_aliases.contains(&proof.recipient))
        {
            return Err(invalid_data(
                "transferred message uses an unlinked identity key or recipient",
            ));
        }
    }
    Ok(StoredMessage {
        unix_time,
        sender,
        text,
        proof,
    })
}

/// Return only aliases whose explicit link marker is in the current local
/// conversation. Remote transition announcements alone are never sufficient.
pub(crate) fn linked_identity_keys(
    messages: &[StoredMessage],
    identity_id: &str,
    peer_id: &str,
    previous_local_ids: &[String],
) -> io::Result<(Vec<[u8; 32]>, Vec<[u8; 32]>)> {
    let identity_id = identity_id.to_ascii_lowercase();
    let peer_id = peer_id.to_ascii_lowercase();
    validate_peer_id(&identity_id)?;
    validate_peer_id(&peer_id)?;
    let local_origins: HashSet<_> = previous_local_ids
        .iter()
        .map(|id| id.to_ascii_lowercase())
        .collect();
    let mut local_aliases = HashSet::new();
    let mut peer_aliases = HashSet::new();
    for message in messages {
        if message.sender != MessageSender::Me {
            continue;
        }
        let Some(marker) = message.text.strip_prefix(IDENTITY_EVENT_PREFIX) else {
            continue;
        };
        let fields: Vec<_> = marker.split(':').collect();
        if fields.len() != 3 || fields[1..].iter().any(|id| id.len() != 64) {
            continue;
        }
        let (role, current_id) = match fields[0] {
            "self" => ("self", identity_id.as_str()),
            "peer" => ("peer", peer_id.as_str()),
            _ => continue,
        };
        let previous_id = fields[1].to_ascii_lowercase();
        if !fields[2].eq_ignore_ascii_case(current_id)
            || previous_id == current_id
            || !previous_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        if role == "self" && !local_origins.contains(&previous_id) {
            continue;
        }
        let key = decode_peer_id(&previous_id)?;
        if role == "self" {
            local_aliases.insert(key);
        } else {
            peer_aliases.insert(key);
        }
    }
    Ok((
        local_aliases.into_iter().collect(),
        peer_aliases.into_iter().collect(),
    ))
}

pub(crate) fn is_transfer_frame(frame: &[u8]) -> bool {
    frame.starts_with(TRANSFER_MAGIC) || frame.starts_with(TRANSFER_CHUNK_MAGIC)
}

pub(crate) fn is_signed_message_frame(frame: &[u8]) -> bool {
    frame.starts_with(MESSAGE_MAGIC)
}

pub(crate) fn merge_restored(
    existing: &[StoredMessage],
    offered: &[StoredMessage],
) -> io::Result<Vec<StoredMessage>> {
    let mut by_id = HashMap::<[u8; 16], StoredMessage>::new();
    for message in existing.iter().chain(offered) {
        if let Some(proof) = &message.proof {
            if let Some(previous) = by_id.insert(proof.id, message.clone()) {
                if previous != *message {
                    return Err(invalid_data("message ID collision"));
                }
            }
        }
    }
    let mut merged = existing.to_vec();
    let mut legacy_counts = HashMap::<(u64, MessageSender, String), usize>::new();
    for message in existing.iter().filter(|message| message.proof.is_none()) {
        *legacy_counts
            .entry((message.unix_time, message.sender, message.text.clone()))
            .or_default() += 1;
    }
    let mut offered_legacy_counts = HashMap::<(u64, MessageSender, String), usize>::new();
    let mut seen_ids = HashSet::new();
    for message in offered {
        if let Some(proof) = &message.proof {
            if !seen_ids.insert(proof.id) {
                continue;
            }
            if existing
                .iter()
                .any(|old| old.proof.as_ref().is_some_and(|prior| prior.id == proof.id))
            {
                continue;
            }
            merged.push(message.clone());
        } else {
            let key = (message.unix_time, message.sender, message.text.clone());
            let count = offered_legacy_counts.entry(key.clone()).or_default();
            *count += 1;
            if *count > legacy_counts.get(&key).copied().unwrap_or(0) {
                merged.push(message.clone());
            }
        }
    }
    merged.sort_by_key(|message| message.unix_time);
    Ok(merged)
}

pub(crate) fn missing_restored(
    existing: &[StoredMessage],
    offered: &[StoredMessage],
) -> io::Result<Vec<StoredMessage>> {
    let merged = merge_restored(existing, offered)?;
    let mut counts = HashMap::<StoredMessage, usize>::new();
    for message in existing {
        *counts.entry(message.clone()).or_default() += 1;
    }
    let mut missing = Vec::new();
    for message in merged {
        let count = counts.entry(message.clone()).or_default();
        if *count > 0 {
            *count -= 1;
        } else {
            missing.push(message);
        }
    }
    Ok(missing)
}

pub(crate) fn outside_time_range(
    messages: &[StoredMessage],
    start: u64,
    end: u64,
) -> Vec<StoredMessage> {
    messages
        .iter()
        .filter(|item| item.unix_time < start || item.unix_time > end)
        .cloned()
        .collect()
}

fn message_signing_payload(unix_time: u64, text: &str, proof: &MessageProof) -> Vec<u8> {
    let mut payload = Vec::with_capacity(43 + 16 + 32 + 32 + text.len());
    payload.extend_from_slice(b"another-dimension-v2/chat-message/v1");
    payload.extend_from_slice(&proof.id);
    payload.extend_from_slice(&proof.signer);
    payload.extend_from_slice(&proof.recipient);
    payload.extend_from_slice(&unix_time.to_be_bytes());
    payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
    payload.extend_from_slice(text.as_bytes());
    payload
}

fn verify_stored_proof(
    identity: &Identity,
    peer_id: &str,
    message: &StoredMessage,
    local_aliases: &[[u8; 32]],
    peer_aliases: &[[u8; 32]],
) -> io::Result<()> {
    let proof = message
        .proof
        .as_ref()
        .ok_or_else(|| invalid_data("message has no signature"))?;
    let (signer, recipient) = match message.sender {
        MessageSender::Me => (identity.public_key(), decode_peer_id(peer_id)?),
        MessageSender::Other => (decode_peer_id(peer_id)?, identity.public_key()),
    };
    let (signer_aliases, recipient_aliases) = match message.sender {
        MessageSender::Me => (local_aliases, peer_aliases),
        MessageSender::Other => (peer_aliases, local_aliases),
    };
    let key = VerifyingKey::from_bytes(&proof.signer)
        .map_err(|_| invalid_data("invalid backup message signer"))?;
    key.verify_strict(
        &message_signing_payload(message.unix_time, &message.text, proof),
        &Signature::from_bytes(&proof.signature),
    )
    .map_err(|_| invalid_data("backup message signature failed"))
    .and_then(|()| {
        if (proof.signer != signer && !signer_aliases.contains(&proof.signer))
            || (proof.recipient != recipient && !recipient_aliases.contains(&proof.recipient))
        {
            Err(invalid_data(
                "backup message uses an unlinked identity key or recipient",
            ))
        } else {
            Ok(())
        }
    })
}

fn derive_backup_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut backup_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(
            b"another-dimension-v2/portable-backup/v1",
            backup_key.as_mut(),
        )
        .expect("32 bytes is a valid HKDF output length");
    backup_key
}

fn derive_combined_backup_key(
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

fn validate_backup_password(password: &str) -> io::Result<()> {
    if password.chars().count() < 12 || password.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup password must be 12 to 1024 bytes/chars",
        ));
    }
    Ok(())
}

fn derive_password_backup_key(
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

fn backup_aad(
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

fn encode_record(
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    index: u64,
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
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| io::Error::other("history key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plain,
                aad: &associated_data(identity_id, peer_id, index, false),
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

fn register_conversation(
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

fn read_index(
    identity: &Identity,
    identity_id: &str,
    directory: &std::path::Path,
) -> io::Result<Vec<String>> {
    let path = directory.join("conversations.idx");
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    if bytes.len() < INDEX_MAGIC.len() + NONCE_BYTES + 16 || &bytes[..8] != INDEX_MAGIC {
        return Err(invalid_data("invalid history index"));
    }
    let key = derive_index_key(&identity.storage_key());
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

fn write_index(
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
        for chunk in peer.as_bytes().chunks_exact(2) {
            payload.push((hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?);
        }
    }
    let nonce = random_nonce()?;
    let key = derive_index_key(&identity.storage_key());
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
        opaque_conversation_name(&key, &hex_encode(&nonce))
    ));
    let path = directory.join("conversations.idx");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    set_private_file(&file)?;
    file.write_all(INDEX_MAGIC)?;
    file.write_all(&nonce)?;
    file.write_all(&encrypted)?;
    file.sync_all()?;
    drop(file);
    rename(temporary, path)?;
    Ok(())
}

fn hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid peer id",
        )),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_records(
    file: &mut File,
    key: Zeroizing<[u8; 32]>,
    identity_id: &str,
    peer_id: &str,
    repair_partial: bool,
) -> io::Result<(Vec<StoredMessage>, u64, bool)> {
    let mut magic = [0; MAGIC.len()];
    file.read_exact(&mut magic)?;
    let legacy_format = &magic == LEGACY_MAGIC;
    if &magic != MAGIC && !legacy_format {
        return Err(invalid_data("unsupported history format"));
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
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
                        aad: &associated_data(identity_id, peer_id, index, legacy_format),
                    },
                )
                .map_err(|_| invalid_data("history authentication failed"))?,
        );
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
    Ok((messages, index, recovered_partial))
}

fn associated_data(identity_id: &str, peer_id: &str, index: u64, legacy: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + 64 + 64 + 8);
    aad.extend_from_slice(if legacy { b"ADLOG1" } else { b"ADLOG2" });
    aad.extend_from_slice(identity_id.as_bytes());
    aad.extend_from_slice(peer_id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

fn derive_index_key(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut index_key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, key)
        .expand(
            b"another-dimension-v2/conversation-file-name/v1",
            index_key.as_mut(),
        )
        .expect("32 bytes is a valid HKDF output length");
    index_key
}

fn opaque_conversation_name(key: &[u8; 32], peer_id: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"another-dimension-v2/conversation-file/v1");
    mac.update(peer_id.as_bytes());
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_nonce() -> io::Result<[u8; NONCE_BYTES]> {
    let mut nonce = [0; NONCE_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    Ok(nonce)
}

pub(crate) fn data_directory() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_DATA_DIRECTORY.with(|directory| directory.borrow().clone()) {
        return Ok(path);
    }
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("ANOTHER_DIMENSION_DATA_DIR") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data directory must be absolute",
            ));
        }
        return Ok(path);
    }
    #[cfg(target_os = "macos")]
    {
        return home_dir()
            .map(|home| home.join("Library/Application Support/Another Dimension v2"));
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Another Dimension v2"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "APPDATA is not set"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(path).join("another-dimension-v2"));
        }
        home_dir().map(|home| home.join(".local/share/another-dimension-v2"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_peer_id, History, MessageSender, StoredMessage, MAX_BACKUP_BYTES, MAX_MESSAGE_BYTES,
    };
    use crate::identity::Identity;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct IsolatedData(PathBuf);

    impl IsolatedData {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ad2-history-test-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            super::TEST_DATA_DIRECTORY
                .with(|directory| *directory.borrow_mut() = Some(path.clone()));
            Self(path)
        }
    }

    impl Drop for IsolatedData {
        fn drop(&mut self) {
            super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = None);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn message(time: u64, text: &str) -> StoredMessage {
        StoredMessage {
            unix_time: time,
            sender: MessageSender::Me,
            text: text.to_owned(),
            proof: None,
        }
    }

    #[test]
    fn restores_only_verified_missing_messages_and_rejects_tampering_and_id_collisions() {
        let _data = IsolatedData::new();
        let (alice, _) = Identity::create().unwrap();
        let (bob, _) = Identity::create().unwrap();
        let peer_id = super::hex_encode(&bob.public_key());
        let local_peer_id = super::hex_encode(&alice.public_key());
        let signed = super::sign_message(&alice, &peer_id, 123, "signed record".into()).unwrap();
        let frame = super::encode_transfer(&signed).unwrap();
        let received =
            super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &frame).unwrap();
        assert_eq!(received.sender, MessageSender::Other);
        assert_eq!(
            super::missing_restored(&[], &[received.clone()]).unwrap(),
            vec![received.clone()]
        );
        assert!(
            super::missing_restored(&[received.clone()], &[received.clone()])
                .unwrap()
                .is_empty()
        );

        let mut changed_text = frame.clone();
        let text_at = 6 + 1 + 8 + 4;
        changed_text[text_at] ^= 1;
        assert!(
            super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &changed_text)
                .is_err()
        );
        assert!(super::decode_transfer(&bob, &local_peer_id, &[9; 32], &frame).is_err());
        let mut wrong_sender = frame.clone();
        wrong_sender[6] = 1;
        assert!(
            super::decode_transfer(&bob, &local_peer_id, &alice.public_key(), &wrong_sender)
                .is_err()
        );

        let mut collision = received.clone();
        collision.text = "different contents".into();
        assert!(super::merge_restored(&[received], &[collision]).is_err());
    }

    #[test]
    fn new_message_decoder_requires_remote_sender_and_valid_proof() {
        let _data = IsolatedData::new();
        let (alice, _) = Identity::create().unwrap();
        let (bob, _) = Identity::create().unwrap();
        let bob_id = super::hex_encode(&bob.public_key());
        let alice_id = super::hex_encode(&alice.public_key());
        let outgoing = super::sign_message(&alice, &bob_id, 500, "authentic".into()).unwrap();
        let frame = super::encode_signed_message(&outgoing).unwrap();
        let received =
            super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &frame).unwrap();
        assert_eq!(received.sender, MessageSender::Other);

        let proof_at = 6 + 1 + 8 + 4 + outgoing.text.len();
        let mut unsigned = frame.clone();
        unsigned.truncate(proof_at + 1);
        unsigned[proof_at] = 0;
        assert!(
            super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &unsigned).is_err()
        );

        let mut wrong_sender = frame.clone();
        wrong_sender[6] = 1;
        assert!(
            super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &wrong_sender)
                .is_err()
        );

        let id_at = proof_at + 1;
        let signature_at = id_at + 16 + 32 + 32;
        for offset in [7, id_at, signature_at] {
            let mut altered = frame.clone();
            altered[offset] ^= 1;
            assert!(
                super::decode_signed_message(&bob, &alice_id, &alice.public_key(), &altered)
                    .is_err()
            );
        }

        let legacy = StoredMessage {
            proof: None,
            sender: MessageSender::Other,
            ..message(500, "unsigned legacy")
        };
        let legacy_frame = super::encode_transfer(&legacy).unwrap();
        let restored =
            super::decode_transfer(&bob, &alice_id, &alice.public_key(), &legacy_frame).unwrap();
        assert!(restored.proof.is_none());
    }

    #[test]
    fn explicitly_linked_identity_keys_validate_original_signatures_only_after_link() {
        let _data = IsolatedData::new();
        let (alice_old, _) = Identity::create().unwrap();
        let (bob, _) = Identity::create().unwrap();
        let alice_old_id = alice_old.public_id();
        let bob_id = bob.public_id();
        let alice_to_bob =
            super::sign_message(&alice_old, &bob_id, 100, "old Alice proof".into()).unwrap();
        let a_frame = super::encode_signed_message(&alice_to_bob).unwrap();
        let received_a =
            super::decode_signed_message(&bob, &alice_old_id, &alice_old.public_key(), &a_frame)
                .unwrap();
        let bob_to_alice =
            super::sign_message(&bob, &alice_old_id, 101, "old Bob proof".into()).unwrap();
        let b_frame = super::encode_signed_message(&bob_to_alice).unwrap();
        let received_b =
            super::decode_signed_message(&alice_old, &bob_id, &bob.public_key(), &b_frame).unwrap();

        let (mut bob_old_history, _, _) = History::open(&bob, &alice_old_id).unwrap();
        bob_old_history.append(&received_a).unwrap();
        bob_old_history.append(&bob_to_alice).unwrap();
        let (mut alice_old_history, _, _) = History::open(&alice_old, &bob_id).unwrap();
        alice_old_history.append(&received_b).unwrap();

        let (alice_new, _) = Identity::create().unwrap();
        alice_old.copy_local_data_to(&alice_new).unwrap();
        let alice_new_id = alice_new.public_id();
        let (mut bob_current, _, _) = History::open(&bob, &alice_new_id).unwrap();
        let peer_marker = StoredMessage {
            unix_time: 102,
            sender: MessageSender::Me,
            text: format!(
                "{}peer:{alice_old_id}:{alice_new_id}",
                super::IDENTITY_EVENT_PREFIX
            ),
            proof: None,
        };
        bob_current
            .link_prior_identity(&bob, &alice_old_id, peer_marker)
            .unwrap();

        let (mut alice_current, _, _) = History::open(&alice_new, &bob_id).unwrap();
        let self_marker = StoredMessage {
            unix_time: 103,
            sender: MessageSender::Me,
            text: format!(
                "{}self:{alice_old_id}:{alice_new_id}",
                super::IDENTITY_EVENT_PREFIX
            ),
            proof: None,
        };
        alice_current
            .append_system_once(&alice_new, self_marker)
            .unwrap();

        let (alice_messages, incomplete) =
            History::read_for_identity_copy(&alice_new, &bob_id).unwrap();
        assert!(!incomplete);
        let local_origins = crate::identity::previous_public_ids(&alice_new).unwrap();
        let (local_aliases, peer_aliases) =
            super::linked_identity_keys(&alice_messages, &alice_new_id, &bob_id, &local_origins)
                .unwrap();
        assert!(local_aliases.contains(&super::decode_peer_id(&alice_old_id).unwrap()));
        assert!(peer_aliases.is_empty());
        let alice_backup = History::export_backup(&alice_new, &bob_id, None).unwrap();
        assert_eq!(
            History::verify_backup(&alice_new, &alice_backup, None)
                .unwrap()
                .0,
            bob_id
        );

        let (bob_messages, incomplete) =
            History::read_for_identity_copy(&bob, &alice_new_id).unwrap();
        assert!(!incomplete);
        let (bob_local_aliases, bob_peer_aliases) =
            super::linked_identity_keys(&bob_messages, &bob.public_id(), &alice_new_id, &[])
                .unwrap();
        assert!(bob_local_aliases.is_empty());
        assert!(bob_peer_aliases.contains(&super::decode_peer_id(&alice_old_id).unwrap()));
        let bob_backup = History::export_backup(&bob, &alice_new_id, None).unwrap();
        assert_eq!(
            History::verify_backup(&bob, &bob_backup, None).unwrap().0,
            alice_new_id
        );

        for entry in bob_messages.iter().filter(|entry| entry.proof.is_some()) {
            let frame = super::encode_transfer(entry).unwrap();
            assert!(super::decode_transfer_with_linked_keys(
                &alice_new,
                &bob_id,
                &bob.public_key(),
                &frame,
                &[],
                &[]
            )
            .is_err());
            let restored = super::decode_transfer_with_linked_keys(
                &alice_new,
                &bob_id,
                &bob.public_key(),
                &frame,
                &local_aliases,
                &peer_aliases,
            )
            .unwrap();
            assert!(restored.proof.is_some());
        }

        let alice_local_entry = alice_messages
            .iter()
            .find(|entry| entry.proof.is_some())
            .unwrap();
        let frame = super::encode_transfer(alice_local_entry).unwrap();
        let restored = super::decode_transfer_with_linked_keys(
            &bob,
            &alice_new_id,
            &alice_new.public_key(),
            &frame,
            &bob_local_aliases,
            &bob_peer_aliases,
        )
        .unwrap();
        assert!(restored.proof.is_some());

        let mut wrong_recipient = frame.clone();
        let text_len = u32::from_be_bytes(wrong_recipient[15..19].try_into().unwrap()) as usize;
        let proof = 19 + text_len + 1;
        wrong_recipient[proof + 16 + 32] ^= 1;
        assert!(super::decode_transfer_with_linked_keys(
            &bob,
            &alice_new_id,
            &alice_new.public_key(),
            &wrong_recipient,
            &bob_local_aliases,
            &bob_peer_aliases
        )
        .is_err());
    }

    #[test]
    fn legacy_messages_remain_unsigned_and_are_not_claimed_as_verified() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "41".repeat(32);
        let legacy = message(10, "legacy record");
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&legacy).unwrap();
        let (_, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages, vec![legacy]);
        assert!(messages[0].proof.is_none());
    }

    #[test]
    fn legacy_adlog1_is_migrated_without_retroactive_signatures() {
        let data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "43".repeat(32);
        let identity_id = identity.public_id();
        let directory = data.0.join(&identity_id);
        std::fs::create_dir_all(&directory).unwrap();
        let key = identity.storage_key();
        let index_key = super::derive_index_key(&key);
        let path = directory.join(format!(
            "{}.adlog",
            super::opaque_conversation_name(&index_key, &peer)
        ));
        let entry = message(77, "unsigned legacy");
        let mut plain = Vec::new();
        plain.extend_from_slice(&entry.unix_time.to_be_bytes());
        plain.push(0);
        plain.extend_from_slice(&(entry.text.len() as u32).to_be_bytes());
        plain.extend_from_slice(entry.text.as_bytes());
        let nonce = super::random_nonce().unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &super::associated_data(&identity_id, &peer, 0, true),
                },
            )
            .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(super::LEGACY_MAGIC);
        bytes.extend_from_slice(&((nonce.len() + encrypted.len()) as u32).to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encrypted);
        std::fs::write(&path, bytes).unwrap();

        let (_, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages, vec![entry]);
        assert!(messages[0].proof.is_none());
        assert_eq!(&std::fs::read(path).unwrap()[..8], super::MAGIC);
    }

    #[test]
    fn encrypted_bundle_exports_and_restores_multiple_conversations() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let first = "61".repeat(32);
        let second = "62".repeat(32);
        for (peer, text) in [
            (&first, "first conversation"),
            (&second, "second conversation"),
        ] {
            let (mut history, _, _) = History::open(&identity, peer).unwrap();
            history.append(&message(1, text)).unwrap();
        }
        let bundle =
            History::export_backup_bundle(&identity, &[first.clone(), second.clone()]).unwrap();
        History::delete_conversation(&identity, &first).unwrap();
        History::delete_conversation(&identity, &second).unwrap();
        let mut corrupted = bundle.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(History::import_backup_bundle(&identity, &corrupted).is_err());
        assert!(History::known_peer_ids(&identity).unwrap().is_empty());
        let restored = History::import_backup_bundle(&identity, &bundle).unwrap();
        assert_eq!(restored, vec![(first.clone(), 1), (second.clone(), 1)]);
        assert_eq!(
            History::open(&identity, &first).unwrap().1[0].text,
            "first conversation"
        );
        assert_eq!(
            History::open(&identity, &second).unwrap().1[0].text,
            "second conversation"
        );
    }

    #[test]
    fn date_range_and_recent_retention_keep_their_boundary_messages() {
        let messages = vec![
            message(9, "before"),
            message(10, "start"),
            message(20, "end"),
            message(21, "after"),
        ];
        assert_eq!(
            super::outside_time_range(&messages, 10, 20),
            vec![messages[0].clone(), messages[3].clone()]
        );
        // Recent retention removes the inclusive range 0..=cutoff.
        assert_eq!(
            super::outside_time_range(&messages, 0, 20),
            vec![messages[3].clone()]
        );
    }

    #[test]
    fn verified_contact_listing_skips_legacy_histories_and_rejects_corruption() {
        let data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let verified = "11".repeat(32);
        let legacy = "22".repeat(32);
        History::open(&identity, &verified).unwrap();
        History::open(&identity, &legacy).unwrap();
        let directory = data.0.join(identity.public_id()).join("verified-contacts");
        let contact = crate::contacts::VerifiedContact {
            peer_key: [0x11; 32],
            rendezvous_secret: zeroize::Zeroizing::new([3; 32]),
        };
        crate::contacts::save(&directory, &identity, &contact).unwrap();
        let contacts = crate::contacts::list_known(&directory, &identity).unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].peer_key, [0x11; 32]);
        let record = std::fs::read_dir(directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut bytes = std::fs::read(&record).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(record, bytes).unwrap();
        assert!(crate::contacts::list_known(
            &data.0.join(identity.public_id()).join("verified-contacts"),
            &identity
        )
        .is_err());
    }

    #[test]
    fn replacing_identity_copies_encrypted_history_and_contacts_without_removing_source() {
        let data = IsolatedData::new();
        let (old_identity, _) = Identity::create().unwrap();
        let peer_id = "33".repeat(32);
        let (mut old_history, _, _) = History::open(&old_identity, &peer_id).unwrap();
        let repeated = StoredMessage {
            unix_time: 123,
            sender: MessageSender::Other,
            text: "same message".to_owned(),
            proof: None,
        };
        old_history.append(&repeated).unwrap();
        old_history.append(&repeated).unwrap();
        let old_directory = data.0.join(old_identity.public_id());
        let history_path = old_history.path.clone();
        let original_history = std::fs::read(&history_path).unwrap();
        let contact = crate::contacts::VerifiedContact {
            peer_key: decode_peer_id(&peer_id).unwrap(),
            rendezvous_secret: zeroize::Zeroizing::new([8; 32]),
        };
        crate::contacts::save(
            &old_directory.join("verified-contacts"),
            &old_identity,
            &contact,
        )
        .unwrap();
        let contact_path = std::fs::read_dir(old_directory.join("verified-contacts"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let original_contact = std::fs::read(&contact_path).unwrap();

        let (replacement, code) = Identity::create().unwrap();
        old_identity.copy_local_data_to(&replacement).unwrap();
        assert_ne!(old_identity.public_id(), replacement.public_id());
        assert_eq!(
            Identity::from_code(&code).unwrap().public_id(),
            replacement.public_id()
        );
        let (_, old_messages, _) = History::open(&old_identity, &peer_id).unwrap();
        let (_, new_messages, _) = History::open(&replacement, &peer_id).unwrap();
        assert_eq!(old_messages, vec![repeated.clone(), repeated.clone()]);
        assert_eq!(new_messages, old_messages);
        assert_eq!(
            *crate::contacts::load(
                &data
                    .0
                    .join(replacement.public_id())
                    .join("verified-contacts"),
                &replacement,
                contact.peer_key
            )
            .unwrap()
            .rendezvous_secret,
            [8; 32]
        );
        assert_eq!(std::fs::read(history_path).unwrap(), original_history);
        assert_eq!(std::fs::read(contact_path).unwrap(), original_contact);
        assert_eq!(
            crate::identity::previous_public_ids(&replacement).unwrap(),
            vec![old_identity.public_id()]
        );
    }

    #[test]
    fn identity_transition_link_merges_before_removing_previous_conversation() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let previous_peer = "51".repeat(32);
        let current_peer = "52".repeat(32);
        let repeated = StoredMessage {
            unix_time: 10,
            sender: MessageSender::Other,
            text: "repeated before transition".to_owned(),
            proof: None,
        };
        let current = message(20, "new identity session");
        let (mut old_history, _, _) = History::open(&identity, &previous_peer).unwrap();
        old_history.append(&repeated).unwrap();
        old_history.append(&repeated).unwrap();
        let (mut new_history, _, _) = History::open(&identity, &current_peer).unwrap();
        new_history.append(&current).unwrap();
        let transition = StoredMessage {
            unix_time: 30,
            sender: MessageSender::Me,
            text: format!(
                "{}peer:{previous_peer}:{current_peer}",
                super::IDENTITY_EVENT_PREFIX
            ),
            proof: None,
        };

        let merged = new_history
            .link_prior_identity(&identity, &previous_peer, transition.clone())
            .unwrap();

        assert_eq!(merged.iter().filter(|item| *item == &repeated).count(), 2);
        assert!(merged.contains(&current));
        assert!(merged.contains(&transition));
        assert!(History::known_peer_ids(&identity)
            .unwrap()
            .contains(&current_peer));
        assert!(!History::known_peer_ids(&identity)
            .unwrap()
            .contains(&previous_peer));
    }

    #[test]
    fn delete_index_write_failure_restores_encrypted_history() {
        let data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "71".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "preserve me")).unwrap();
        let original = std::fs::read(&history.path).unwrap();
        drop(history);
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_INDEX_WRITE));
        assert!(History::delete_conversation(&identity, &peer).is_err());
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert_eq!(
            std::fs::read(data.0.join(identity.public_id()).join(format!(
                "{}.adlog",
                super::opaque_conversation_name(
                    &super::derive_index_key(&identity.storage_key()),
                    &peer
                )
            )))
            .unwrap(),
            original
        );
    }

    #[test]
    fn delete_restore_failure_reports_recoverable_tombstone() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "72".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "preserve me")).unwrap();
        let original = std::fs::read(&history.path).unwrap();
        drop(history);
        super::TEST_FAILURES
            .with(|flags| flags.set(super::FAIL_INDEX_WRITE | super::FAIL_DELETE_RESTORE));
        let error = History::delete_conversation(&identity, &peer)
            .unwrap_err()
            .to_string();
        super::TEST_FAILURES.with(|flags| flags.set(0));
        let tombstone = error.split("recoverable file: ").nth(1).unwrap();
        assert_eq!(std::fs::read(tombstone).unwrap(), original);
        assert!(error.contains("injected prior conversation restore failure"));
    }

    #[test]
    fn missing_indexed_history_is_not_recreated_as_empty() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "73".repeat(32);
        let (history, _, _) = History::open(&identity, &peer).unwrap();
        let path = history.path.clone();
        drop(history);
        std::fs::remove_file(path).unwrap();
        let error = match History::open(&identity, &peer) {
            Ok(_) => panic!("missing indexed history was recreated"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn link_reports_prior_recovery_and_current_rollback_failures_together() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let previous_peer = "74".repeat(32);
        let current_peer = "75".repeat(32);
        let (mut previous, _, _) = History::open(&identity, &previous_peer).unwrap();
        previous.append(&message(1, "prior record")).unwrap();
        let (mut current, _, _) = History::open(&identity, &current_peer).unwrap();
        current.append(&message(2, "current record")).unwrap();
        super::TEST_FAILURES.with(|flags| {
            flags.set(
                super::FAIL_INDEX_WRITE | super::FAIL_DELETE_RESTORE | super::FAIL_ROLLBACK_REPLACE,
            )
        });
        let error = current
            .link_prior_identity(&identity, &previous_peer, message(3, "transition"))
            .unwrap_err()
            .to_string();
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert!(error.contains("recoverable file:"));
        let recovery_path = error
            .split("recoverable file: ")
            .nth(1)
            .unwrap()
            .split("); restoring destination")
            .next()
            .unwrap();
        assert!(std::path::Path::new(recovery_path).is_file());
        assert!(error.contains("restoring destination also failed"));
        assert!(error.contains("injected current conversation rollback failure"));
    }

    #[test]
    fn identity_transition_merge_preserves_equal_messages_from_both_epochs() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let previous_peer = "61".repeat(32);
        let current_peer = "62".repeat(32);
        let same = message(10, "same text at same second");
        let (mut old_history, _, _) = History::open(&identity, &previous_peer).unwrap();
        old_history.append(&same).unwrap();
        let (mut new_history, _, _) = History::open(&identity, &current_peer).unwrap();
        new_history.append(&same).unwrap();
        let transition = message(20, "transition marker");
        let merged = new_history
            .link_prior_identity(&identity, &previous_peer, transition)
            .unwrap();
        assert_eq!(merged.iter().filter(|item| *item == &same).count(), 2);
    }

    #[test]
    fn identity_replacement_stops_on_partial_source_without_changing_it() {
        let data = IsolatedData::new();
        let (old_identity, _) = Identity::create().unwrap();
        let peer_id = "44".repeat(32);
        let (mut history, _, _) = History::open(&old_identity, &peer_id).unwrap();
        history
            .append(&StoredMessage {
                unix_time: 456,
                sender: MessageSender::Me,
                text: "keep original".to_owned(),
                proof: None,
            })
            .unwrap();
        let source_path = history.path.clone();
        drop(history);
        let length = std::fs::metadata(&source_path).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_len(length - 1)
            .unwrap();
        let incomplete_source = std::fs::read(&source_path).unwrap();
        let (replacement, _) = Identity::create().unwrap();

        assert!(old_identity.copy_local_data_to(&replacement).is_err());
        assert_eq!(std::fs::read(source_path).unwrap(), incomplete_source);
        assert!(!data.0.join(replacement.public_id()).exists());
    }

    fn legacy_password_backup(
        identity: &Identity,
        peer: &str,
        messages: &[StoredMessage],
        password: &str,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
        payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
        for message in messages {
            let text = message.text.as_bytes();
            payload.extend_from_slice(&message.unix_time.to_be_bytes());
            payload.push(match message.sender {
                MessageSender::Me => 0,
                MessageSender::Other => 1,
            });
            payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
            payload.extend_from_slice(text);
        }
        let salt = [0x31; super::BACKUP_SALT_BYTES];
        let nonce = [0x52; super::NONCE_BYTES];
        let key = super::derive_password_backup_key(password, &salt).unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &super::backup_aad(identity, super::BACKUP_PASSWORD_MAGIC, Some(&salt)),
                },
            )
            .unwrap();
        let mut backup = Vec::new();
        backup.extend_from_slice(super::BACKUP_PASSWORD_MAGIC);
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&encrypted);
        backup
    }

    fn legacy_identity_backup(
        identity: &Identity,
        peer: &str,
        messages: &[StoredMessage],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
        payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
        for message in messages {
            payload.extend_from_slice(&message.unix_time.to_be_bytes());
            payload.push(match message.sender {
                MessageSender::Me => 0,
                MessageSender::Other => 1,
            });
            payload.extend_from_slice(&(message.text.len() as u32).to_be_bytes());
            payload.extend_from_slice(message.text.as_bytes());
        }
        let nonce = [0x52; super::NONCE_BYTES];
        let key = super::derive_backup_key(&identity.storage_key());
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &super::backup_aad(identity, super::BACKUP_MAGIC, None),
                },
            )
            .unwrap();
        let mut backup = Vec::new();
        backup.extend_from_slice(super::BACKUP_MAGIC);
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&encrypted);
        backup
    }

    fn legacy_combined_backup(
        identity: &Identity,
        peer: &str,
        messages: &[StoredMessage],
        password: &str,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&super::decode_peer_id(peer).unwrap());
        payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
        for message in messages {
            payload.extend_from_slice(&message.unix_time.to_be_bytes());
            payload.push(match message.sender {
                MessageSender::Me => 0,
                MessageSender::Other => 1,
            });
            payload.extend_from_slice(&(message.text.len() as u32).to_be_bytes());
            payload.extend_from_slice(message.text.as_bytes());
        }
        let salt = [0x31; super::BACKUP_SALT_BYTES];
        let nonce = [0x53; super::NONCE_BYTES];
        let password_key = super::derive_password_backup_key(password, &salt).unwrap();
        let key = super::derive_combined_backup_key(&identity.storage_key(), &password_key);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &super::backup_aad(identity, super::BACKUP_COMBINED_MAGIC, Some(&salt)),
                },
            )
            .unwrap();
        let mut backup = Vec::new();
        backup.extend_from_slice(super::BACKUP_COMBINED_MAGIC);
        backup.extend_from_slice(&salt);
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&encrypted);
        backup
    }

    #[test]
    fn backup_import_preserves_repeats_and_reads_existing_legacy_format() {
        let _data = IsolatedData::new();
        let identity = Identity::from_code(&Identity::create().unwrap().1).unwrap();
        let peer = "ab".repeat(32);
        let repeated = message(1_700_000_000, "same message");
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history
            .replace(&[repeated.clone(), repeated.clone()])
            .unwrap();

        // New exports use ADBACK4 and remain idempotent on repeated imports.
        let backup = History::export_backup(&identity, &peer, None).unwrap();
        assert_eq!(&backup[..8], b"ADBACK4\0");
        assert_eq!(
            History::import_backup(&identity, &backup, None).unwrap().1,
            2
        );
        assert_eq!(
            History::import_backup(&identity, &backup, None).unwrap().1,
            2
        );
        let (_, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages, vec![repeated.clone(), repeated]);

        let password_backup =
            History::export_backup(&identity, &peer, Some("correct horse battery")).unwrap();
        assert_eq!(&password_backup[..8], b"ADBACK4\0");
        let other_identity = Identity::create().unwrap().0;
        assert!(History::import_backup(
            &other_identity,
            &password_backup,
            Some("correct horse battery")
        )
        .is_err());
        assert!(
            History::import_backup(&identity, &password_backup, Some("wrong password")).is_err()
        );
        let mut tampered = password_backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            History::import_backup(&identity, &tampered, Some("correct horse battery")).is_err()
        );
        assert_eq!(
            History::import_backup(&identity, &password_backup, Some("correct horse battery"))
                .unwrap()
                .1,
            2
        );

        // ADBACK2 was password-only. It remains importable for existing users.
        let old_password_backup = legacy_password_backup(
            &identity,
            &peer,
            &[message(1_700_000_001, "legacy")],
            "correct horse battery",
        );
        assert_eq!(&old_password_backup[..8], b"ADBACK2\0");
        assert_eq!(
            History::import_backup(
                &identity,
                &old_password_backup,
                Some("correct horse battery")
            )
            .unwrap()
            .1,
            3
        );
        let old_identity_backup = legacy_identity_backup(
            &identity,
            &peer,
            &[message(1_700_000_002, "legacy identity backup")],
        );
        assert_eq!(&old_identity_backup[..8], b"ADBACK1\0");
        assert_eq!(
            History::import_backup(&identity, &old_identity_backup, None)
                .unwrap()
                .1,
            4
        );
        let old_combined_backup = legacy_combined_backup(
            &identity,
            &peer,
            &[message(1_700_000_003, "legacy combined backup")],
            "correct horse battery",
        );
        assert_eq!(&old_combined_backup[..8], b"ADBACK3\0");
        assert_eq!(
            History::import_backup(
                &identity,
                &old_combined_backup,
                Some("correct horse battery")
            )
            .unwrap()
            .1,
            5
        );
    }

    #[test]
    fn old_identity_backup_can_be_reprotected_without_changing_the_source() {
        let _data = IsolatedData::new();
        let (old_identity, old_code) = Identity::create().unwrap();
        let (replacement, _) = Identity::create().unwrap();
        let peer = "ac".repeat(32);
        let original_messages = vec![
            message(1_700_000_001, "first"),
            message(1_700_000_001, "first"),
        ];
        let source = legacy_password_backup(
            &old_identity,
            &peer,
            &original_messages,
            "previous backup password",
        );
        let source_copy = source.clone();

        assert!(History::reprotect_backup(
            &old_identity,
            &replacement,
            &source,
            Some("wrong previous password"),
            None,
        )
        .is_err());
        let reprotected = History::reprotect_backup(
            &old_identity,
            &replacement,
            &source,
            Some("previous backup password"),
            Some("new backup password"),
        )
        .unwrap();

        assert_eq!(source, source_copy);
        assert_eq!(
            History::verify_backup(&replacement, &reprotected, Some("new backup password"))
                .unwrap(),
            (peer.clone(), original_messages.len())
        );
        assert!(
            History::verify_backup(&old_identity, &reprotected, Some("new backup password"))
                .is_err()
        );
        assert_eq!(
            History::verify_backup(&old_identity, &source, Some("previous backup password"))
                .unwrap(),
            (peer, original_messages.len())
        );
        assert_eq!(
            Identity::from_code(&old_code).unwrap().public_id(),
            old_identity.public_id()
        );
    }

    fn messages_with_payload_len(payload_len: usize) -> Vec<StoredMessage> {
        // ADBACK4 adds one proof-presence byte to each legacy record.
        let record_bytes = payload_len - 36;
        let count = record_bytes.div_ceil(MAX_MESSAGE_BYTES + 14);
        let mut remaining = record_bytes;
        let mut messages = Vec::with_capacity(count);
        for index in 0..count {
            let slots_left = count - index - 1;
            let size = remaining.saturating_sub(slots_left * (MAX_MESSAGE_BYTES + 14));
            let text_len = (size - 14).clamp(1, MAX_MESSAGE_BYTES);
            messages.push(message(index as u64, &"x".repeat(text_len)));
            remaining -= text_len + 14;
        }
        assert_eq!(remaining, 0);
        messages
    }

    #[test]
    fn exports_enforce_the_final_file_size_limit_for_both_formats() {
        let _data = IsolatedData::new();
        let identity = Identity::create().unwrap().0;
        let peer = "cd".repeat(32);
        for password in [None, Some("correct horse battery")] {
            let envelope_len = 8 + password.map_or(0, |_| 16) + 12 + 16;
            let exact_payload_len = MAX_BACKUP_BYTES - envelope_len;
            let mut history = History::open(&identity, &peer).unwrap().0;
            history
                .replace(&messages_with_payload_len(exact_payload_len))
                .unwrap();
            let backup = History::export_backup(&identity, &peer, password).unwrap();
            assert_eq!(backup.len(), MAX_BACKUP_BYTES);

            history
                .replace(&messages_with_payload_len(exact_payload_len + 1))
                .unwrap();
            assert_eq!(
                History::export_backup(&identity, &peer, password)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }
}

fn home_dir() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory is unavailable"))
}

#[cfg(unix)]
fn set_private_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_: &File) -> io::Result<()> {
    Ok(())
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
