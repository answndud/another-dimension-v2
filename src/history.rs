//! Per-identity encrypted append-only message history.

use crate::identity::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
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
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
static INDEX_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
        let (messages, next_index, recovered_partial) =
            read_records(&mut file, Zeroizing::new(*key), &identity_id, &peer_id)?;
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
            std::fs::remove_file(tombstone)?;
        }
        Ok(())
    }

    pub fn export_backup(identity: &Identity, peer_id: &str) -> io::Result<Vec<u8>> {
        let (_, messages, _) = Self::open(identity, peer_id)?;
        let mut payload = Zeroizing::new(Vec::new());
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
            if payload.len() + BACKUP_MAGIC.len() + NONCE_BYTES + 16 > MAX_BACKUP_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "backup is too large",
                ));
            }
        }
        let nonce = random_nonce()?;
        let key = derive_backup_key(&identity.storage_key());
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| io::Error::other("backup key unavailable"))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &backup_aad(identity),
                },
            )
            .map_err(|_| io::Error::other("backup encryption failed"))?;
        let mut backup = Vec::with_capacity(BACKUP_MAGIC.len() + NONCE_BYTES + encrypted.len());
        backup.extend_from_slice(BACKUP_MAGIC);
        backup.extend_from_slice(&nonce);
        backup.extend_from_slice(&encrypted);
        Ok(backup)
    }

    pub fn import_backup(identity: &Identity, backup: &[u8]) -> io::Result<(String, usize)> {
        if backup.len() > MAX_BACKUP_BYTES
            || backup.len() < BACKUP_MAGIC.len() + NONCE_BYTES + 16
            || &backup[..BACKUP_MAGIC.len()] != BACKUP_MAGIC
        {
            return Err(invalid_data("invalid backup file"));
        }
        let nonce_start = BACKUP_MAGIC.len();
        let key = derive_backup_key(&identity.storage_key());
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| invalid_data("invalid backup key"))?;
        let payload = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&backup[nonce_start..nonce_start + NONCE_BYTES]),
                    Payload {
                        msg: &backup[nonce_start + NONCE_BYTES..],
                        aad: &backup_aad(identity),
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

        let (mut history, existing, _) = Self::open(identity, &peer_id)?;
        let mut merged = existing;
        let mut seen: HashSet<StoredMessage> = merged.iter().cloned().collect();
        for message in imported {
            if seen.insert(message.clone()) {
                merged.push(message);
            }
        }
        merged.sort_by_key(|message| message.unix_time);
        let count = merged.len();
        history.replace(&merged)?;
        Ok((peer_id, count))
    }
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

fn decode_peer_id(peer_id: &str) -> io::Result<[u8; 32]> {
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

fn backup_aad(identity: &Identity) -> Vec<u8> {
    let mut aad = Vec::with_capacity(BACKUP_MAGIC.len() + 32);
    aad.extend_from_slice(BACKUP_MAGIC);
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
            file.set_len(record_start)?;
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
            file.set_len(record_start)?;
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

fn data_directory() -> io::Result<PathBuf> {
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
