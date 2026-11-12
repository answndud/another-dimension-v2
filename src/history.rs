//! Per-identity encrypted append-only message history.

use crate::identity::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADLOG1\0\0";
const MAX_MESSAGE_BYTES: usize = 4096;
const NONCE_BYTES: usize = 12;
const INDEX_MAGIC: &[u8; 8] = b"ADIDX1\0\0";
const BACKUP_MAGIC: &[u8; 8] = b"ADBACK1\0";
const BACKUP_PASSWORD_MAGIC: &[u8; 8] = b"ADBACK2\0";
const BACKUP_COMBINED_MAGIC: &[u8; 8] = b"ADBACK3\0";
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const BACKUP_SALT_BYTES: usize = 16;
pub(crate) const IDENTITY_EVENT_PREFIX: &str = "[AD2-IDENTITY-EVENT/1] ";
static INDEX_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
#[cfg(test)]
thread_local! {
    static TEST_DATA_DIRECTORY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoredMessage {
    pub unix_time: u64,
    pub sender: MessageSender,
    pub text: String,
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
        let (messages, next_index, recovered_partial) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            true,
        )?;
        file.seek(SeekFrom::End(0))?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;

        Ok((
            Self {
                file,
                path,
                key,
                identity_id,
                peer_id,
                next_index,
            },
            messages,
            recovered_header || recovered_partial,
        ))
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
                let _ = rename(&tombstone, &path);
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
            merged.sort_by_key(|item| item.unix_time);
        }
        self.replace(&merged)?;
        if let Err(delete_error) = Self::delete_conversation(identity, previous_peer_id) {
            if let Err(rollback_error) = self.replace(&current) {
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
        let merged = merge_snapshot(existing, imported);
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
    let header_len = if password.is_some() {
        BACKUP_COMBINED_MAGIC.len()
    } else {
        BACKUP_MAGIC.len()
    } + salt_len
        + NONCE_BYTES;
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
                BACKUP_COMBINED_MAGIC,
                derive_combined_backup_key(&identity.storage_key(), &password_key),
            )
        }
        None => (BACKUP_MAGIC, derive_backup_key(&identity.storage_key())),
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
    } else if magic == BACKUP_COMBINED_MAGIC {
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
        imported.push(StoredMessage {
            unix_time,
            sender,
            text,
        });
    }
    if cursor != payload.len() {
        return Err(invalid_data("unexpected backup data"));
    }
    Ok((peer_id, imported))
}

/// Backups contain snapshots without record IDs. Preserve the greatest count of
/// each exact message found in either copy: this makes re-import idempotent while
/// retaining identical messages already repeated within either snapshot.
fn merge_snapshot(
    existing: Vec<StoredMessage>,
    imported: Vec<StoredMessage>,
) -> Vec<StoredMessage> {
    let mut existing_counts = HashMap::<StoredMessage, usize>::new();
    let mut imported_counts = HashMap::<StoredMessage, usize>::new();
    let mut merged = existing;
    for message in &merged {
        *existing_counts.entry(message.clone()).or_default() += 1;
    }
    for message in imported {
        let count = imported_counts.entry(message.clone()).or_default();
        *count += 1;
        if *count > existing_counts.get(&message).copied().unwrap_or(0) {
            merged.push(message);
        }
    }
    merged.sort_by_key(|message| message.unix_time);
    merged
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
    let mut plain = Zeroizing::new(Vec::with_capacity(13 + text.len()));
    plain.extend_from_slice(&message.unix_time.to_be_bytes());
    plain.push(match message.sender {
        MessageSender::Me => 0,
        MessageSender::Other => 1,
    });
    plain.extend_from_slice(&(text.len() as u32).to_be_bytes());
    plain.extend_from_slice(text);
    let nonce_bytes = random_nonce()?;
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| io::Error::other("history key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plain,
                aad: &associated_data(identity_id, peer_id, index),
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
    if &magic != MAGIC {
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
        if !(NONCE_BYTES + 16 + 13..=NONCE_BYTES + 16 + 13 + MAX_MESSAGE_BYTES).contains(&length) {
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
                        aad: &associated_data(identity_id, peer_id, index),
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
        if text_len == 0 || text_len > MAX_MESSAGE_BYTES || plain.len() != 13 + text_len {
            return Err(invalid_data("invalid history text length"));
        }
        let text = std::str::from_utf8(&plain[13..])
            .map_err(|_| invalid_data("history text is not UTF-8"))?
            .to_owned();
        messages.push(StoredMessage {
            unix_time,
            sender,
            text,
        });
        index = index
            .checked_add(1)
            .ok_or_else(|| invalid_data("history record limit reached"))?;
    }
    Ok((messages, index, recovered_partial))
}

fn associated_data(identity_id: &str, peer_id: &str, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + 64 + 64 + 8);
    aad.extend_from_slice(b"ADLOG1");
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
        }
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

        // The original ADBACK1 envelope is unchanged and can be imported twice.
        let backup = History::export_backup(&identity, &peer, None).unwrap();
        assert_eq!(&backup[..8], b"ADBACK1\0");
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
        assert_eq!(&password_backup[..8], b"ADBACK3\0");
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
        let record_bytes = payload_len - 36;
        let count = record_bytes.div_ceil(MAX_MESSAGE_BYTES + 13);
        let mut remaining = record_bytes;
        let mut messages = Vec::with_capacity(count);
        for index in 0..count {
            let slots_left = count - index - 1;
            let size = remaining.saturating_sub(slots_left * (MAX_MESSAGE_BYTES + 13));
            let text_len = (size - 13).clamp(1, MAX_MESSAGE_BYTES);
            messages.push(message(index as u64, &"x".repeat(text_len)));
            remaining -= text_len + 13;
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
