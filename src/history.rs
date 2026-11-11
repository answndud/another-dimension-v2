//! Per-identity encrypted append-only message history.

use crate::identity::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADLOG1\0\0";
const MAX_MESSAGE_BYTES: usize = 4096;
const NONCE_BYTES: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    pub unix_time: u64,
    pub sender: MessageSender,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSender {
    Me,
    Other,
}

pub struct History {
    file: File,
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
            .open(path)?;
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

        Ok((
            Self {
                file,
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
        let text = message.text.as_bytes();
        if text.is_empty() || text.len() > MAX_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid message size",
            ));
        }
        let mut plain = Vec::with_capacity(13 + text.len());
        plain.extend_from_slice(&message.unix_time.to_be_bytes());
        plain.push(match message.sender {
            MessageSender::Me => 0,
            MessageSender::Other => 1,
        });
        plain.extend_from_slice(&(text.len() as u32).to_be_bytes());
        plain.extend_from_slice(text);
        let nonce_bytes = random_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("history key unavailable"))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plain,
                    aad: &associated_data(&self.identity_id, &self.peer_id, self.next_index),
                },
            )
            .map_err(|_| io::Error::other("history encryption failed"))?;
        let record_len = NONCE_BYTES + encrypted.len();
        let record_len = u32::try_from(record_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;

        self.file.write_all(&record_len.to_be_bytes())?;
        self.file.write_all(&nonce_bytes)?;
        self.file.write_all(&encrypted)?;
        self.file.sync_data()?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("history record limit reached"))?;
        Ok(())
    }
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
