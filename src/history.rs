//! Per-identity encrypted append-only message history.

use crate::identity::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};
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
const BACKUP_LINKED_MAGIC: &[u8; 8] = b"ADBACK5\0";
const BACKUP_STREAM_V6_MAGIC: &[u8; 8] = b"ADBACK6\0";
const BACKUP_STREAM_MAGIC: &[u8; 8] = b"ADBACK7\0";
const BACKUP_LINKS_TRAILER: &[u8; 8] = b"ADLNK1\0\0";
const BACKUP_BUNDLE_MAGIC: &[u8; 8] = b"ADPACK1\0";
const BACKUP_STREAM_BUNDLE_V2_MAGIC: &[u8; 8] = b"ADPACK2\0";
const BACKUP_STREAM_BUNDLE_MAGIC: &[u8; 8] = b"ADPACK3\0";
const BACKUP_PEER_METADATA: &[u8; 8] = b"ADPEER1\0";
const BACKUP_BUNDLE_TAG_BYTES: usize = 32;
const LINKED_KEYS_MAGIC: &[u8; 8] = b"ADLKEY1\0";
const RESTORE_STAGING_MAGIC: &[u8; 8] = b"ADRSTG1\0";
const TRANSFER_MAGIC: &[u8; 6] = b"ADREC1";
const TRANSFER_CHUNK_MAGIC: &[u8; 5] = b"ADCH1";
const MESSAGE_MAGIC: &[u8; 6] = b"ADMSG1";
const MAX_LEGACY_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const BACKUP_SALT_BYTES: usize = 16;
pub(crate) const IDENTITY_EVENT_PREFIX: &str = "[AD2-IDENTITY-EVENT/1] ";
static INDEX_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static CONVERSATION_LOCKS: OnceLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();
#[cfg(test)]
pub(crate) type HistoryDeleteTestGate = Arc<(Mutex<(bool, bool)>, std::sync::Condvar)>;
#[cfg(test)]
static HISTORY_DELETE_TEST_GATE: Mutex<Option<HistoryDeleteTestGate>> = Mutex::new(None);
const RESTORE_SORT_RUN_RECORDS: usize = 512;
const RESTORE_SORT_RUN_BYTES: usize = 2 * 1024 * 1024;
const RESTORE_MERGE_FAN_IN: usize = 16;
#[cfg(test)]
thread_local! {
    static TEST_DATA_DIRECTORY: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    static TEST_FAILURES: std::cell::Cell<u16> = const { std::cell::Cell::new(0) };
    static TEST_DECRYPTED_RECORDS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
const FAIL_INDEX_WRITE: u16 = 1;
#[cfg(test)]
const FAIL_DELETE_RESTORE: u16 = 2;
#[cfg(test)]
const FAIL_ROLLBACK_REPLACE: u16 = 8;
#[cfg(test)]
const FAIL_LINKED_STORE: u16 = 16;
#[cfg(test)]
const FAIL_HISTORY_REPLACE_ONCE: u16 = 32;
#[cfg(test)]
const FAIL_RESTORE_INDEX: u16 = 64;
#[cfg(test)]
const FAIL_RESTORE_OUTPUT: u16 = 128;
#[cfg(test)]
const FAIL_RESTORE_RENAME: u16 = 256;
#[cfg(test)]
const FAIL_RESTORE_CLEANUP_ONCE: u16 = 512;
#[cfg(test)]
const FAIL_RESTORE_STAGE_WRITE: u16 = 1024;
#[cfg(test)]
const FAIL_RESTORE_RESULT_CLEANUP: u16 = 2048;
#[cfg(test)]
const FAIL_HISTORY_DELETE_WRITE: u16 = 4096;
#[cfg(test)]
const FAIL_HISTORY_DELETE_SYNC: u16 = 8192;
#[cfg(test)]
const FAIL_HISTORY_DELETE_RENAME: u16 = 16384;
#[cfg(test)]
const FAIL_HISTORY_DELETE_CLEANUP: u16 = 32768;

#[cfg(test)]
fn test_failure(failure: u16) -> bool {
    TEST_FAILURES.with(|failures| failures.get() & failure != 0)
}

#[cfg(test)]
fn test_failure_once(failure: u16) -> bool {
    TEST_FAILURES.with(|failures| {
        let current = failures.get();
        if current & failure == 0 {
            false
        } else {
            failures.set(current & !failure);
            true
        }
    })
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HistoryPageCursor {
    pub(crate) version: String,
    pub(crate) offset: u64,
    pub(crate) index: u64,
}

#[derive(Debug)]
pub(crate) struct HistoryPageEntry {
    pub(crate) index: u64,
    pub(crate) message: StoredMessage,
}

#[derive(Debug)]
pub(crate) struct HistoryPage {
    pub(crate) entries: Vec<HistoryPageEntry>,
    pub(crate) version: String,
    pub(crate) next: Option<HistoryPageCursor>,
}

#[derive(Debug)]
pub(crate) struct RestoreMergeSummary {
    pub(crate) total_count: u64,
    pub(crate) imported_count: u64,
    #[cfg(test)]
    pub(crate) peak_sort_buffer_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HistoryDeleteSummary {
    pub(crate) remaining_count: u64,
    pub(crate) deleted_count: u64,
    /// Conservative bound for per-record message/decode/encode buffers; does
    /// not include allocator bookkeeping or fixed reader state.
    pub(crate) peak_record_bytes: usize,
}

pub struct History {
    file: File,
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
    next_index: u64,
    file_version: HistoryFileVersion,
    operation_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HistoryFileVersion {
    device: u64,
    inode: u64,
    length: u64,
    modified_nanos: u128,
}

fn history_file_version(file: &File) -> io::Result<HistoryFileVersion> {
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
    file: File,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
    index: u64,
    end: u64,
    valid_end: u64,
    truncated: bool,
    legacy: bool,
}

pub(crate) struct RestoreStaging {
    directory: PathBuf,
    file: File,
    _lock: File,
    identity_id: String,
    peer_id: String,
    request_id: String,
    key: Zeroizing<[u8; 32]>,
    count: u64,
    read_index: u64,
    read_end: u64,
    finished: bool,
    cleaned: bool,
}

impl RestoreStaging {
    pub(crate) fn create(identity: &Identity, peer_id: &str, request_id: &str) -> io::Result<Self> {
        validate_peer_id(peer_id)?;
        if request_id.len() != 64 || !request_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_data("invalid history restore request ID"));
        }
        let identity_id = identity.public_id();
        let root = data_directory()?
            .join(&identity_id)
            .join(".history-restore");
        create_dir_all(&root)?;
        set_private_directory(&root)?;
        cleanup_stale_restore_staging(&root)?;
        let directory = root.join(hex_encode(&random_nonce()?));
        std::fs::create_dir(&directory)?;
        set_private_directory(&directory)?;
        let result = (|| {
            let lock = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.join("owner.lock"))?;
            set_private_file(&lock)?;
            lock_restore_directory(&lock)?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(directory.join("records.enc"))?;
            set_private_file(&file)?;
            file.write_all(RESTORE_STAGING_MAGIC)?;
            file.sync_data()?;
            let mut key = Zeroizing::new([0; 32]);
            Hkdf::<Sha256>::new(Some(request_id.as_bytes()), identity.storage_key().as_ref())
                .expand(
                    b"another-dimension-v2/history-restore-staging/v1",
                    key.as_mut(),
                )
                .map_err(|_| io::Error::other("restore staging key derivation failed"))?;
            Ok(Self {
                directory: directory.clone(),
                file,
                _lock: lock,
                identity_id,
                peer_id: peer_id.to_ascii_lowercase(),
                request_id: request_id.to_ascii_lowercase(),
                key,
                count: 0,
                read_index: 0,
                read_end: 0,
                finished: false,
                cleaned: false,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(directory);
        }
        result
    }

    pub(crate) fn append_verified(&mut self, message: &StoredMessage) -> io::Result<()> {
        if self.finished {
            return Err(invalid_data("restore staging is already finished"));
        }
        #[cfg(test)]
        if test_failure(FAIL_RESTORE_STAGE_WRITE) {
            return Err(io::Error::other("injected restore staging write failure"));
        }
        let plaintext = encode_history_plain(message)?;
        let nonce = random_nonce()?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| io::Error::other("restore staging key unavailable"))?;
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &restore_staging_aad(
                        &self.identity_id,
                        &self.peer_id,
                        &self.request_id,
                        self.count,
                    ),
                },
            )
            .map_err(|_| io::Error::other("restore staging encryption failed"))?;
        let length = u32::try_from(encrypted.len())
            .map_err(|_| invalid_data("restore staging record is too large"))?;
        self.file.write_all(&length.to_be_bytes())?;
        self.file.write_all(&nonce)?;
        self.file.write_all(&encrypted)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("restore staging record count overflow"))?;
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut magic = [0; RESTORE_STAGING_MAGIC.len()];
        self.file.read_exact(&mut magic)?;
        if &magic != RESTORE_STAGING_MAGIC {
            return Err(invalid_data("invalid restore staging header"));
        }
        self.read_end = self.file.metadata()?.len();
        self.file
            .seek(SeekFrom::Start(RESTORE_STAGING_MAGIC.len() as u64))?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn next_record(&mut self) -> io::Result<Option<StoredMessage>> {
        if !self.finished {
            return Err(invalid_data("restore staging is not complete"));
        }
        let position = self.file.stream_position()?;
        if position == self.read_end {
            if self.read_index != self.count {
                return Err(invalid_data("restore staging record count mismatch"));
            }
            return Ok(None);
        }
        if position > self.read_end || self.read_end - position < (4 + NONCE_BYTES + 16) as u64 {
            return Err(invalid_data("restore staging is truncated"));
        }
        let mut length = [0; 4];
        self.file.read_exact(&mut length)?;
        let length = u32::from_be_bytes(length) as usize;
        if length < 13 + 1 + 16
            || length > 13 + MAX_MESSAGE_BYTES + 145
            || self.read_end - position < 4 + NONCE_BYTES as u64 + length as u64
        {
            return Err(invalid_data("invalid restore staging record length"));
        }
        let mut nonce = [0; NONCE_BYTES];
        self.file.read_exact(&mut nonce)?;
        let mut encrypted = vec![0; length];
        self.file.read_exact(&mut encrypted)?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| invalid_data("restore staging key unavailable"))?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &encrypted,
                        aad: &restore_staging_aad(
                            &self.identity_id,
                            &self.peer_id,
                            &self.request_id,
                            self.read_index,
                        ),
                    },
                )
                .map_err(|_| invalid_data("restore staging authentication failed"))?,
        );
        let message = decode_history_plain(&plain, false)?;
        self.read_index += 1;
        Ok(Some(message))
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        if !self.finished {
            return Err(invalid_data("restore staging is not complete"));
        }
        self.file
            .seek(SeekFrom::Start(RESTORE_STAGING_MAGIC.len() as u64))?;
        self.read_index = 0;
        Ok(())
    }

    pub(crate) fn count(&self) -> u64 {
        self.count
    }

    #[cfg(test)]
    pub(crate) fn storage_bytes(&self) -> io::Result<u64> {
        self.file.metadata().map(|metadata| metadata.len())
    }

    pub(crate) fn cleanup(mut self) -> io::Result<()> {
        #[cfg(test)]
        if test_failure_once(FAIL_RESTORE_CLEANUP_ONCE) {
            return Err(io::Error::other("injected restore staging cleanup failure"));
        }
        std::fs::remove_dir_all(&self.directory)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for RestoreStaging {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
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
            legacy: false,
        }
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(MAGIC.len() as u64))?;
        self.index = 0;
        self.valid_end = MAGIC.len() as u64;
        self.truncated = false;
        Ok(())
    }

    fn valid_end(&self) -> u64 {
        self.valid_end
    }

    fn was_truncated(&self) -> bool {
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
        let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_ref())
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
                            self.legacy,
                        ),
                    },
                )
                .map_err(|_| invalid_data("history authentication failed"))?,
        );
        let message = decode_history_plain(&plain, self.legacy)?;
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

fn open_history_reader(
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
) -> io::Result<HistoryReader> {
    history_reader_from_file(File::open(path)?, key, identity_id, peer_id)
}

fn history_reader_from_file(
    mut file: File,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
) -> io::Result<HistoryReader> {
    let end = file.metadata()?.len();
    if end < MAGIC.len() as u64 {
        return Err(invalid_data("history snapshot header is incomplete"));
    }
    let mut magic = [0; 8];
    file.read_exact(&mut magic)?;
    let legacy = &magic == LEGACY_MAGIC;
    if &magic != MAGIC && !legacy {
        return Err(invalid_data("unsupported history format"));
    }
    Ok(HistoryReader {
        file,
        key,
        identity_id,
        peer_id,
        index: 0,
        end,
        valid_end: MAGIC.len() as u64,
        truncated: false,
        legacy,
    })
}

fn open_history_reader_from(
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    identity_id: String,
    peer_id: String,
    offset: u64,
    index: u64,
) -> io::Result<HistoryReader> {
    let mut reader = open_history_reader(path, key, identity_id, peer_id)?;
    if offset < MAGIC.len() as u64 || offset > reader.end {
        return Err(invalid_data("invalid append refresh offset"));
    }
    reader.file.seek(SeekFrom::Start(offset))?;
    reader.index = index;
    reader.valid_end = offset;
    Ok(reader)
}

fn migrate_legacy_history_streaming(
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
        let mut output = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        set_private_file(&output)?;
        output.write_all(MAGIC)?;
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
        rename(&temporary, path)?;
        Ok(truncated)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn conversation_operation_lock(identity_id: &str, peer_id: &str) -> io::Result<Arc<Mutex<()>>> {
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

fn acquire_conversation_file_lock(identity: &Identity, peer_id: &str) -> io::Result<File> {
    let identity_id = identity.public_id();
    let directory = data_directory()?.join(&identity_id);
    acquire_conversation_file_lock_at(&directory, &identity_id, peer_id, &identity.storage_key())
}

fn acquire_conversation_file_lock_for_path(
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

fn acquire_conversation_file_lock_at(
    directory: &std::path::Path,
    _identity_id: &str,
    peer_id: &str,
    key: &[u8; 32],
) -> io::Result<File> {
    create_dir_all(&directory)?;
    set_private_directory(&directory)?;
    let filename = format!(
        ".conversation-{}.lock",
        opaque_conversation_name(&derive_index_key(key), &peer_id.to_ascii_lowercase())
    );
    let file = OpenOptions::new()
        .create(true)
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

fn unlock_conversation_file(file: File) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only operates on the live descriptor owned by `file`.
        let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    drop(file);
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
        create_dir_all(&directory)?;
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
        let mut recovered_partial = false;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;
        if file.metadata()?.len() < MAGIC.len() as u64 {
            if file.metadata()?.len() > 0 {
                file.set_len(0)?;
                recovered_partial = true;
            }
            file.write_all(MAGIC)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::Start(0))?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        if &magic == LEGACY_MAGIC {
            recovered_partial |= migrate_legacy_history_streaming(
                &path,
                Zeroizing::new(*key),
                &identity_id,
                &peer_id,
            )?;
        } else if &magic != MAGIC {
            return Err(invalid_data("unsupported history format"));
        }
        let mut reader = open_history_reader(
            path.clone(),
            Zeroizing::new(*key),
            identity_id.clone(),
            peer_id.clone(),
        )?;
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
                    let file = OpenOptions::new().write(true).open(&path)?;
                    file.set_len(valid_end)?;
                    file.sync_all()?;
                    recovered_partial = true;
                    let _ = error;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let file = OpenOptions::new().read(true).append(true).open(&path)?;
        set_private_file(&file)?;
        let file_version = history_file_version(&file)?;
        register_conversation(identity, &identity_id, &peer_id, &directory)?;
        let history = Self {
            file,
            path,
            key,
            identity_id,
            peer_id,
            next_index: count as u64,
            file_version,
            operation_lock: Arc::clone(&operation_lock),
        };
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
            operation_lock: Arc::clone(&operation_lock),
        };
        unlock_conversation_file(file_lock);
        drop(operation_guard);
        if migrate_legacy {
            history.replace(&messages)?;
        }
        Ok((history, messages, recovered_header || recovered_partial))
    }

    fn open_for_streaming_merge(identity: &Identity, peer_id: &str) -> io::Result<Self> {
        validate_peer_id(peer_id)?;
        let identity_id = identity.public_id();
        let peer_id = peer_id.to_ascii_lowercase();
        let key = identity.storage_key();
        let directory = data_directory()?.join(&identity_id);
        create_dir_all(&directory)?;
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
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        set_private_file(&file)?;
        if file.metadata()?.len() == 0 {
            file.write_all(MAGIC)?;
            file.sync_data()?;
        }
        let mut reader = open_history_reader(
            path.clone(),
            Zeroizing::new(*key),
            identity_id.clone(),
            peer_id.clone(),
        )?;
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
            operation_lock,
        })
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
            message,
        )?;
        self.file.write_all(&record)?;
        self.file.sync_data()?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("history record limit reached"))?;
        self.file_version = history_file_version(&self.file)?;
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

    fn replace_unlocked(&mut self, messages: &[StoredMessage]) -> io::Result<()> {
        #[cfg(test)]
        if test_failure_once(FAIL_HISTORY_REPLACE_ONCE) {
            return Err(io::Error::other("injected conversation replace failure"));
        }
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
            let file_version = history_file_version(&file)?;
            self.file = file;
            self.next_index = messages.len() as u64;
            self.file_version = file_version;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }

    fn replace_filtered_unlocked(
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
            let mut output = OpenOptions::new()
                .create_new(true)
                .read(true)
                .append(true)
                .write(true)
                .open(&temporary)?;
            set_private_file(&output)?;
            output.write_all(MAGIC)?;
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
            rename(&temporary, &self.path)?;
            self.file_version = file_version;
            self.file = output;
            self.next_index = next_index;
            Ok(summary)
        })();
        if result.is_err() && temporary.exists() {
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
                let error = result.unwrap_err();
                return Err(io::Error::other(format!(
                    "history rewrite failed ({error}); temporary cleanup failed ({cleanup_error}); recoverable file: {}",
                    temporary.display()
                )));
            }
        }
        result
    }

    fn refresh_for_append(&mut self) -> io::Result<()> {
        let current = File::open(&self.path)?;
        let current_version = history_file_version(&current)?;
        let same_file = current_version.device == self.file_version.device
            && current_version.inode == self.file_version.inode;
        if same_file && current_version == self.file_version {
            return Ok(());
        }
        let mut next_index = self.next_index;
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
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        set_private_file(&file)?;
        self.file = file;
        self.next_index = next_index;
        self.file_version = history_file_version(&self.file)?;
        Ok(())
    }

    pub(crate) fn merge_restore_staging(
        &mut self,
        identity: &Identity,
        staging: &mut RestoreStaging,
    ) -> io::Result<RestoreMergeSummary> {
        if identity.public_id() != self.identity_id
            || staging.identity_id != self.identity_id
            || staging.peer_id != self.peer_id
            || !staging.finished
        {
            return Err(invalid_data(
                "restore staging does not match this conversation",
            ));
        }
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
        let mut final_temp = None::<PathBuf>;
        let result = (|| {
            let stage_root = staging.directory.clone();
            cleanup_restore_merge_attempt(&stage_root)?;
            let mut count_reader = open_history_reader(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
            )?;
            let mut existing_count = 0u64;
            while count_reader.next_record()?.is_some() {
                existing_count = existing_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("history record count overflow"))?;
            }
            let total_capacity = existing_count
                .checked_add(staging.count())
                .ok_or_else(|| invalid_data("restore record count overflow"))?;
            let mut index = RestoreDiskIndex::new(staging, total_capacity)?;
            let mut levels = Vec::<Vec<PathBuf>>::new();
            let mut serial = 0u64;
            let mut buffer = Vec::<(u64, StoredMessage)>::new();
            let mut buffer_bytes = 0usize;
            let mut peak_buffer_bytes = 0usize;
            let mut existing = open_history_reader(
                self.path.clone(),
                Zeroizing::new(*self.key),
                self.identity_id.clone(),
                self.peer_id.clone(),
            )?;
            while let Some(message) = existing.next_record()? {
                index.index_message(&message, false)?;
                push_restore_sort_item(
                    message,
                    &mut buffer,
                    &mut buffer_bytes,
                    &mut peak_buffer_bytes,
                    &mut levels,
                    &mut serial,
                    &self.key,
                    &self.identity_id,
                    &self.peer_id,
                    &stage_root,
                )?;
            }
            staging.rewind()?;
            let mut imported_count = 0u64;
            while let Some(message) = staging.next_record()? {
                if index.index_message(&message, true)? {
                    imported_count = imported_count
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("restore count overflow"))?;
                    push_restore_sort_item(
                        message,
                        &mut buffer,
                        &mut buffer_bytes,
                        &mut peak_buffer_bytes,
                        &mut levels,
                        &mut serial,
                        &self.key,
                        &self.identity_id,
                        &self.peer_id,
                        &stage_root,
                    )?;
                }
            }
            if !buffer.is_empty() {
                let run = write_restore_sort_run(
                    &stage_root,
                    &mut serial,
                    &self.key,
                    &self.identity_id,
                    &self.peer_id,
                    &mut buffer,
                )?;
                add_restore_run_level(
                    run,
                    &mut levels,
                    &mut serial,
                    &self.key,
                    &self.identity_id,
                    &self.peer_id,
                    &stage_root,
                )?;
            }
            let mut runs: Vec<_> = levels.into_iter().flatten().collect();
            while runs.len() > RESTORE_MERGE_FAN_IN {
                let mut reduced = Vec::new();
                for group in runs.chunks(RESTORE_MERGE_FAN_IN) {
                    if group.len() == 1 {
                        reduced.push(group[0].clone());
                        continue;
                    }
                    let output = stage_root.join(format!("merge-{:016x}.adlog", serial));
                    serial = serial
                        .checked_add(1)
                        .ok_or_else(|| invalid_data("restore merge run counter overflow"))?;
                    merge_encrypted_runs(
                        group,
                        &output,
                        &self.key,
                        &self.identity_id,
                        &self.peer_id,
                    )?;
                    for input in group {
                        std::fs::remove_file(input)?;
                    }
                    reduced.push(output);
                }
                runs = reduced;
            }
            let suffix = hex_encode(&random_nonce()?);
            let filename = self
                .path
                .file_name()
                .ok_or_else(|| invalid_data("conversation filename unavailable"))?;
            let temporary = self.path.with_file_name(format!(
                ".{}.restore-merge-{suffix}.tmp",
                filename.to_string_lossy()
            ));
            final_temp = Some(temporary.clone());
            let total_count = merge_encrypted_runs(
                &runs,
                &temporary,
                &self.key,
                &self.identity_id,
                &self.peer_id,
            )?;
            let append_file = OpenOptions::new()
                .read(true)
                .append(true)
                .open(&temporary)?;
            set_private_file(&append_file)?;
            #[cfg(test)]
            if test_failure(FAIL_RESTORE_RENAME) {
                return Err(io::Error::other(
                    "injected restore atomic replacement failure",
                ));
            }
            rename(&temporary, &self.path)?;
            final_temp = None;
            let file_version = history_file_version(&append_file)?;
            self.file = append_file;
            self.next_index = total_count;
            self.file_version = file_version;
            Ok(RestoreMergeSummary {
                total_count,
                imported_count,
                #[cfg(test)]
                peak_sort_buffer_bytes: peak_buffer_bytes,
            })
        })();
        let result = match (result, final_temp) {
            (Err(error), Some(path)) => match {
                #[cfg(test)]
                if test_failure(FAIL_RESTORE_RESULT_CLEANUP) {
                    Err(io::Error::other("injected restore result cleanup failure"))
                } else {
                    std::fs::remove_file(&path)
                }
                #[cfg(not(test))]
                std::fs::remove_file(&path)
            } {
                Ok(()) => Err(error),
                Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
                Err(cleanup) => Err(io::Error::other(format!(
                    "restore merge failed ({error}); temporary result cleanup failed ({cleanup}); recoverable file: {}",
                    path.display()
                ))),
            },
            (result, _) => result,
        };
        unlock_conversation_file(file_lock);
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
        summaries.sort_by(|left, right| right.last_message.cmp(&left.last_message));
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

    fn delete_filtered(
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
            let append_file = OpenOptions::new().read(true).append(true).open(&path)?;
            let mut history = History {
                file: append_file,
                path,
                key,
                identity_id,
                peer_id,
                next_index: 0,
                file_version: version,
                operation_lock: Arc::clone(&operation_lock),
            };
            history.replace_filtered_unlocked(&mut reader, keep, validate)
        })();
        unlock_conversation_file(file_lock);
        result
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
        let (messages, _, recovered_partial) = read_records(
            &mut file,
            Zeroizing::new(*key),
            &identity_id,
            &peer_id,
            false,
        )?;
        unlock_conversation_file(file_lock);
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

    #[cfg(test)]
    pub fn export_backup(
        identity: &Identity,
        peer_id: &str,
        password: Option<&str>,
    ) -> io::Result<Vec<u8>> {
        let (_, messages, _) = Self::open(identity, peer_id)?;
        encode_backup(identity, peer_id, &messages, password)
    }

    /// Write a versioned, independently authenticated backup frame by frame.
    /// The largest plaintext buffer is one stored message plus its AEAD tag.
    pub(crate) fn export_backup_stream<W: Write>(
        identity: &Identity,
        peer_id: &str,
        password: Option<&str>,
        output: &mut W,
    ) -> io::Result<u64> {
        let links = backup_links_for(identity, peer_id)?;
        let mut reader = Self::reader_for_identity_copy(identity, peer_id)?;
        let mut writer = BackupStreamWriter::new(identity, peer_id, password, &links, output)?;
        let mut count = 0u64;
        while let Some(message) = reader.next_record()? {
            writer.write_message(&message)?;
            count = count
                .checked_add(1)
                .ok_or_else(|| invalid_data("backup message count overflow"))?;
        }
        writer.finish(count, &links)?;
        Ok(count)
    }

    /// ADPACK2 stores independently authenticated ADBACK6 children. A child
    /// is first written to a private temporary file so its length can be
    /// emitted without buffering the backup in memory.
    pub(crate) fn export_backup_bundle_stream<W: Write>(
        identity: &Identity,
        peer_ids: &[String],
        output: &mut W,
    ) -> io::Result<()> {
        if peer_ids.is_empty() || peer_ids.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid conversation selection",
            ));
        }
        let mut unique = HashSet::new();
        for peer_id in peer_ids {
            validate_peer_id(peer_id)?;
            if !unique.insert(peer_id.to_ascii_lowercase()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate conversation",
                ));
            }
        }
        let directory = Self::backup_transfer_directory(identity)?;
        let suffix = hex_encode(&random_nonce()?);
        let child_path = directory.join(format!("bundle-child-{suffix}.tmp"));
        let result = (|| {
            let mut bundle_id = [0; 16];
            File::open("/dev/urandom")?.read_exact(&mut bundle_id)?;
            let mut header = Vec::with_capacity(8 + bundle_id.len() + 4);
            header.extend_from_slice(BACKUP_STREAM_BUNDLE_MAGIC);
            header.extend_from_slice(&bundle_id);
            header.extend_from_slice(&(peer_ids.len() as u32).to_be_bytes());
            output.write_all(&header)?;
            let bundle_key = derive_backup_bundle_key(identity, &bundle_id)?;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(bundle_key.as_ref())
                .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
            mac.update(&header);
            for peer_id in peer_ids {
                let mut child = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&child_path)?;
                set_private_file(&child)?;
                Self::export_backup_stream(identity, peer_id, None, &mut child)?;
                child.flush()?;
                child.sync_all()?;
                let length = child.metadata()?.len();
                let length_bytes = length.to_be_bytes();
                output.write_all(&length_bytes)?;
                mac.update(&length_bytes);
                child.seek(SeekFrom::Start(0))?;
                let mut buffer = [0; 64 * 1024];
                loop {
                    let read = child.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    output.write_all(&buffer[..read])?;
                    mac.update(&buffer[..read]);
                }
                drop(child);
                std::fs::remove_file(&child_path)?;
            }
            output.write_all(&mac.finalize().into_bytes())?;
            output.flush()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(child_path);
        }
        result
    }

    pub(crate) fn backup_transfer_directory(identity: &Identity) -> io::Result<PathBuf> {
        let directory = data_directory()?
            .join(identity.public_id())
            .join(".backup-transfer");
        create_dir_all(&directory)?;
        set_private_directory(&directory)?;
        Ok(directory)
    }

    pub(crate) fn import_backup_file(
        identity: &Identity,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> io::Result<Vec<(String, usize, bool)>> {
        let mut file = File::open(path)?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;
        if &magic == BACKUP_STREAM_MAGIC || &magic == BACKUP_STREAM_V6_MAGIC {
            let (peer_id, mut staging, links) = if &magic == BACKUP_STREAM_MAGIC {
                decode_backup_stream(identity, &mut file, password)?
            } else {
                decode_backup_stream_v6(identity, &mut file, password)?
            };
            ensure_stream_eof(&mut file)?;
            let count = staging.count();
            import_verified_staging(identity, &peer_id, &mut staging, &links)?;
            staging.cleanup()?;
            return Ok(vec![(
                peer_id,
                count as usize,
                !links.local.is_empty() || !links.peer.is_empty(),
            )]);
        }
        if &magic == BACKUP_STREAM_BUNDLE_MAGIC {
            return import_backup_bundle_stream(identity, &mut file);
        }
        if &magic == BACKUP_STREAM_BUNDLE_V2_MAGIC {
            return import_backup_bundle_stream_v2(identity, &mut file);
        }
        let length = file.metadata()?.len();
        if length > MAX_LEGACY_BACKUP_BYTES as u64 {
            return Err(invalid_data(
                "legacy backup exceeds the supported 16 MiB format limit",
            ));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.read_to_end(&mut bytes)?;
        if bytes.starts_with(BACKUP_BUNDLE_MAGIC) {
            return Self::import_backup_bundle_with_info(identity, &bytes);
        }
        Ok(vec![Self::import_backup_with_info(
            identity, &bytes, password,
        )?])
    }

    pub(crate) fn verify_backup_file(
        identity: &Identity,
        path: &std::path::Path,
        password: Option<&str>,
    ) -> io::Result<(String, u64)> {
        let mut file = File::open(path)?;
        let mut magic = [0; 8];
        file.read_exact(&mut magic)?;
        file.seek(SeekFrom::Start(0))?;
        if &magic == BACKUP_STREAM_MAGIC || &magic == BACKUP_STREAM_V6_MAGIC {
            let (peer_id, staging, _) = if &magic == BACKUP_STREAM_MAGIC {
                decode_backup_stream(identity, &mut file, password)?
            } else {
                decode_backup_stream_v6(identity, &mut file, password)?
            };
            ensure_stream_eof(&mut file)?;
            let result = (peer_id, staging.count());
            staging.cleanup()?;
            return Ok(result);
        }
        let length = file.metadata()?.len();
        if length > MAX_LEGACY_BACKUP_BYTES as u64 {
            return Err(invalid_data(
                "legacy backup exceeds the supported 16 MiB format limit",
            ));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.read_to_end(&mut bytes)?;
        let (peer_id, count) = Self::verify_backup(identity, &bytes, password)?;
        Ok((peer_id, count as u64))
    }

    pub(crate) fn reprotect_backup_file(
        previous_identity: &Identity,
        replacement_identity: &Identity,
        source: &std::path::Path,
        output: &mut File,
        previous_password: Option<&str>,
        replacement_password: Option<&str>,
    ) -> io::Result<u64> {
        let mut input = File::open(source)?;
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        input.seek(SeekFrom::Start(0))?;
        if &magic != BACKUP_STREAM_MAGIC && &magic != BACKUP_STREAM_V6_MAGIC {
            let length = input.metadata()?.len();
            if length > MAX_LEGACY_BACKUP_BYTES as u64 {
                return Err(invalid_data(
                    "legacy backup exceeds the supported 16 MiB format limit",
                ));
            }
            let mut bytes = Vec::with_capacity(length as usize);
            input.read_to_end(&mut bytes)?;
            let bytes = Self::reprotect_backup(
                previous_identity,
                replacement_identity,
                &bytes,
                previous_password,
                replacement_password,
            )?;
            output.write_all(&bytes)?;
            return Ok(0);
        }
        let (peer_id, mut staging, mut links) = if &magic == BACKUP_STREAM_MAGIC {
            decode_backup_stream(previous_identity, &mut input, previous_password)?
        } else {
            decode_backup_stream_v6(previous_identity, &mut input, previous_password)?
        };
        ensure_stream_eof(&mut input)?;
        let previous_id = previous_identity.public_id();
        let replacement_id = replacement_identity.public_id();
        if previous_id != replacement_id {
            if !links.origins.contains(&previous_id) {
                links.origins.push(previous_id.clone());
            }
            links.local.insert(previous_id);
        }
        let count = staging.count();
        export_staging_stream(
            replacement_identity,
            &peer_id,
            replacement_password,
            &links,
            &mut staging,
            output,
        )?;
        staging.cleanup()?;
        Ok(count)
    }

    /// Bundle separately authenticated conversation backups. Each child stays
    /// encrypted with the existing backup format, preserving import compatibility.
    #[cfg(test)]
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
            if bundle.len().saturating_add(4 + backup.len()) > MAX_LEGACY_BACKUP_BYTES {
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
        Ok(Self::import_backup_bundle_with_info(identity, bundle)?
            .into_iter()
            .map(|(peer, count, _)| (peer, count))
            .collect())
    }

    pub fn import_backup_bundle_with_info(
        identity: &Identity,
        bundle: &[u8],
    ) -> io::Result<Vec<(String, usize, bool)>> {
        if bundle.len() > MAX_LEGACY_BACKUP_BYTES
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
            if len > MAX_LEGACY_BACKUP_BYTES || bundle.len().saturating_sub(cursor) < len {
                return Err(invalid_data("truncated backup bundle"));
            }
            let (peer_id, messages, _) =
                decode_backup_with_links(identity, &bundle[cursor..cursor + len], None)?;
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
            let result = (|| {
                let len =
                    u32::from_be_bytes(bundle[cursor..cursor + 4].try_into().expect("fixed slice"))
                        as usize;
                cursor += 4;
                let (_, messages, links) =
                    decode_backup_with_links(identity, &bundle[cursor..cursor + len], None)?;
                cursor += len;
                let (mut history, existing, _) = Self::open(identity, &peer_id)?;
                let merged = merge_snapshot(existing.clone(), messages)?;
                let count = merged.len();
                let has_links = !links.local.is_empty() || !links.peer.is_empty();
                history.replace(&merged)?;
                if let Err(error) = apply_backup_links(identity, &peer_id, &links) {
                    return match history.replace(&existing) {
                        Ok(()) => Err(error),
                        Err(rollback) => Err(io::Error::other(format!(
                            "{error}; conversation rollback failed ({rollback})"
                        ))),
                    };
                }
                Ok((peer_id, count, has_links))
            })();
            match result {
                Ok(item) => imported.push(item),
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "backup bundle stopped after {} conversations; {error}",
                        imported.len()
                    )))
                }
            }
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
        let (peer_id, messages, mut links) =
            decode_backup_with_links(previous_identity, backup, previous_password)?;
        // Re-protection is an explicit act by the old identity holder. Preserve
        // that authenticated identity as a local alias so proofs created before
        // the replacement remain verifiable under the new backup key.
        let previous_id = previous_identity.public_id();
        let replacement_id = replacement_identity.public_id();
        if previous_id != replacement_id {
            if !links.origins.contains(&previous_id) {
                links.origins.push(previous_id.clone());
            }
            links.local.insert(previous_id);
        }
        encode_backup_with_links(
            replacement_identity,
            &peer_id,
            &messages,
            replacement_password,
            &links,
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
        let (peer_id, count, _) = Self::import_backup_with_info(identity, backup, password)?;
        Ok((peer_id, count))
    }

    pub fn import_backup_with_info(
        identity: &Identity,
        backup: &[u8],
        password: Option<&str>,
    ) -> io::Result<(String, usize, bool)> {
        let (peer_id, imported, links) = decode_backup_with_links(identity, backup, password)?;

        let (mut history, existing, _) = Self::open(identity, &peer_id)?;
        let merged = merge_snapshot(existing.clone(), imported)?;
        let count = merged.len();
        let has_links = !links.local.is_empty() || !links.peer.is_empty();
        history.replace(&merged)?;
        if let Err(error) = apply_backup_links(identity, &peer_id, &links) {
            return match history.replace(&existing) {
                Ok(()) => Err(error),
                Err(rollback) => Err(io::Error::other(format!("backup relationship restore failed ({error}); conversation rollback failed ({rollback})"))),
            };
        }
        Ok((peer_id, count, has_links))
    }
}

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

fn encode_backup(
    identity: &Identity,
    peer_id: &str,
    messages: &[StoredMessage],
    password: Option<&str>,
) -> io::Result<Vec<u8>> {
    let links = backup_links_for(identity, peer_id)?;
    encode_backup_with_links(identity, peer_id, messages, password, &links)
}

struct BackupStreamWriter<'a, W> {
    peer: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    aad: Vec<u8>,
    output: &'a mut W,
    count: u64,
}

impl<'a, W: Write> BackupStreamWriter<'a, W> {
    fn new(
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
        File::open("/dev/urandom")?.read_exact(&mut file_id)?;
        if password.is_some() {
            File::open("/dev/urandom")?.read_exact(&mut salt)?;
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
        writer.write_frame(2, 0, &metadata)?;
        Ok(writer)
    }

    fn write_message(&mut self, message: &StoredMessage) -> io::Result<()> {
        let plain = encode_history_plain(message)?;
        let index = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        self.write_frame(1, index, &plain)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        Ok(())
    }

    fn finish(&mut self, expected_count: u64, links: &BackupLinks) -> io::Result<()> {
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
        self.write_frame(0, trailer_index, &trailer)?;
        self.output.flush()
    }

    fn write_frame(&mut self, kind: u8, index: u64, plain: &[u8]) -> io::Result<()> {
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

fn backup_stream_frame_aad(base: &[u8], kind: u8, index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(base.len() + 9);
    aad.extend_from_slice(base);
    aad.push(kind);
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

fn validate_backup_links(peer_id: &str, links: &BackupLinks) -> io::Result<()> {
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

fn encode_backup_links(links: &BackupLinks) -> io::Result<Vec<u8>> {
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

fn decode_backup_links(
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

fn decode_backup_stream_v6<R: Read>(
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
    let request_id = format!(
        "{}{}{}",
        hex_encode(&random_nonce()?),
        hex_encode(&random_nonce()?),
        hex_encode(&random_nonce()?)
    )[..64]
        .to_owned();
    let mut staging = RestoreStaging::create(identity, &peer_id, &request_id)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid_data("invalid backup key"))?;
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
        if length < 16 || length > MAX_MESSAGE_BYTES + 256 {
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
                        aad: &backup_stream_frame_aad(&base_aad, kind, index),
                    },
                )
                .map_err(|_| invalid_data("backup frame authentication failed"))?,
        );
        match kind {
            1 if index == count => {
                let message = decode_history_plain(&plain, false)?;
                staging.append_verified(&message)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("backup message count overflow"))?;
            }
            0 if index == count => break decode_backup_links(&plain, &peer_id, identity)?,
            _ => return Err(invalid_data("backup frame order is invalid")),
        }
    };
    staging.finish()?;
    verify_stream_staged_proofs(identity, &peer_id, &mut staging, &links)?;
    Ok((peer_id, staging, links))
}

fn decode_backup_stream<R: Read>(
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
    if metadata_kind != 2 || metadata_index != 0 || metadata_len != 8 + 32 + 16 {
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
    let request_id = format!(
        "{}{}{}",
        hex_encode(&random_nonce()?),
        hex_encode(&random_nonce()?),
        hex_encode(&random_nonce()?)
    )[..64]
        .to_owned();
    let mut staging = RestoreStaging::create(identity, &peer_id, &request_id)?;
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
        if length < 16 || length > MAX_MESSAGE_BYTES + 256 {
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
                        aad: &backup_stream_frame_aad(&base_aad, kind, index),
                    },
                )
                .map_err(|_| invalid_data("backup frame authentication failed"))?,
        );
        let expected_index = count
            .checked_add(1)
            .ok_or_else(|| invalid_data("backup message count overflow"))?;
        match kind {
            1 if index == expected_index => {
                let message = decode_history_plain(&plain, false)?;
                staging.append_verified(&message)?;
                count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("backup message count overflow"))?;
            }
            0 if index == expected_index => break decode_backup_links(&plain, &peer_id, identity)?,
            _ => return Err(invalid_data("backup frame order is invalid")),
        }
    };
    staging.finish()?;
    verify_stream_staged_proofs(identity, &peer_id, &mut staging, &links)?;
    Ok((peer_id, staging, links))
}

fn ensure_stream_eof<R: Read>(input: &mut R) -> io::Result<()> {
    let mut trailing = [0; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(invalid_data("unexpected data after backup"));
    }
    Ok(())
}

fn verify_stream_staged_proofs(
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

fn export_staging_stream<W: Write>(
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

fn import_verified_staging(
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

fn import_backup_bundle_stream_v2<R: Read>(
    identity: &Identity,
    input: &mut R,
) -> io::Result<Vec<(String, usize, bool)>> {
    let mut imported = Vec::new();
    let result = (|| {
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != BACKUP_STREAM_BUNDLE_V2_MAGIC {
            return Err(invalid_data("invalid backup bundle"));
        }
        let mut count_bytes = [0; 4];
        input.read_exact(&mut count_bytes)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count == 0 || count > 128 {
            return Err(invalid_data("invalid backup bundle count"));
        }
        let mut unique = HashSet::new();
        for _ in 0..count {
            let mut len_bytes = [0; 8];
            input.read_exact(&mut len_bytes)?;
            let length = u64::from_be_bytes(len_bytes);
            if length < 8 + 1 + 32 + 1 + 8 + NONCE_BYTES as u64 + 4 + 27 {
                return Err(invalid_data("truncated backup bundle child"));
            }
            let mut child = input.take(length);
            let (peer_id, mut staging, links) =
                decode_backup_stream_v6(identity, &mut child, None)?;
            if child.limit() != 0 {
                return Err(invalid_data("unexpected data in backup bundle child"));
            }
            if !unique.insert(peer_id.clone()) {
                return Err(invalid_data("duplicate conversation in backup bundle"));
            }
            let message_count = staging.count() as usize;
            let has_links = !links.local.is_empty() || !links.peer.is_empty();
            import_verified_staging(identity, &peer_id, &mut staging, &links)?;
            imported.push((peer_id, message_count, has_links));
            staging.cleanup()?;
        }
        ensure_stream_eof(input)?;
        Ok(())
    })();
    result.map_err(|error| partial_bundle_error(imported.len(), error))?;
    Ok(imported)
}

fn partial_bundle_error(applied: usize, error: io::Error) -> io::Error {
    if applied == 0 {
        error
    } else {
        io::Error::other(format!(
            "backup bundle failed after applying {applied} conversation(s): {error}"
        ))
    }
}

fn import_backup_bundle_stream<R: Read>(
    identity: &Identity,
    input: &mut R,
) -> io::Result<Vec<(String, usize, bool)>> {
    let mut imported = Vec::new();
    let result = (|| {
        let mut magic = [0; 8];
        input.read_exact(&mut magic)?;
        if &magic != BACKUP_STREAM_BUNDLE_MAGIC {
            return Err(invalid_data("invalid backup bundle"));
        }
        let mut bundle_id = [0; 16];
        input.read_exact(&mut bundle_id)?;
        let mut count_bytes = [0; 4];
        input.read_exact(&mut count_bytes)?;
        let count = u32::from_be_bytes(count_bytes) as usize;
        if count == 0 || count > 128 {
            return Err(invalid_data("invalid backup bundle count"));
        }
        let mut header = Vec::with_capacity(8 + bundle_id.len() + count_bytes.len());
        header.extend_from_slice(&magic);
        header.extend_from_slice(&bundle_id);
        header.extend_from_slice(&count_bytes);
        let bundle_key = derive_backup_bundle_key(identity, &bundle_id)?;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(bundle_key.as_ref())
            .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
        mac.update(&header);
        let mut unique = HashSet::new();
        let directory = History::backup_transfer_directory(identity)?;

        for _ in 0..count {
            let mut length_bytes = [0; 8];
            input.read_exact(&mut length_bytes)?;
            mac.update(&length_bytes);
            let length = u64::from_be_bytes(length_bytes);
            if length < 8 + 1 + 16 + 1 + NONCE_BYTES as u64 + 4 + 8 + 32 + 16 {
                return Err(invalid_data("truncated backup bundle child"));
            }
            let child_path = directory.join(format!(
                "bundle-import-child-{}.tmp",
                hex_encode(&random_nonce()?)
            ));
            let child_result = (|| {
                let mut child_file = OpenOptions::new()
                    .create_new(true)
                    .read(true)
                    .write(true)
                    .open(&child_path)?;
                set_private_file(&child_file)?;
                let mut remaining = length;
                let mut buffer = [0; 64 * 1024];
                while remaining > 0 {
                    let size = usize::try_from(remaining.min(buffer.len() as u64))
                        .expect("bounded to buffer length");
                    input.read_exact(&mut buffer[..size])?;
                    child_file.write_all(&buffer[..size])?;
                    mac.update(&buffer[..size]);
                    remaining -= size as u64;
                }
                child_file.flush()?;
                child_file.sync_all()?;
                child_file.seek(SeekFrom::Start(0))?;
                let (peer_id, mut staging, links) =
                    decode_backup_stream(identity, &mut child_file, None)?;
                ensure_stream_eof(&mut child_file)?;
                if !unique.insert(peer_id.clone()) {
                    return Err(invalid_data("duplicate conversation in backup bundle"));
                }
                let message_count = usize::try_from(staging.count())
                    .map_err(|_| invalid_data("backup conversation count is too large"))?;
                let has_links = !links.local.is_empty() || !links.peer.is_empty();
                import_verified_staging(identity, &peer_id, &mut staging, &links)?;
                imported.push((peer_id, message_count, has_links));
                staging
                    .cleanup()
                    .map_err(|error| partial_bundle_error(imported.len(), error))?;
                Ok(())
            })();
            let cleanup = if child_path.exists() {
                std::fs::remove_file(&child_path)
            } else {
                Ok(())
            };
            match (child_result, cleanup) {
                (Ok(()), Ok(())) => {}
                (Err(error), Ok(())) => return Err(error),
                (Ok(()), Err(cleanup_error)) => {
                    return Err(io::Error::other(format!(
                        "backup bundle child was applied but temporary file cleanup failed: {cleanup_error}"
                    )))
                }
                (Err(error), Err(cleanup_error)) => {
                    return Err(io::Error::other(format!(
                        "{error}; temporary bundle child cleanup failed: {cleanup_error}"
                    )))
                }
            }
        }
        let mut supplied_tag = [0; BACKUP_BUNDLE_TAG_BYTES];
        input.read_exact(&mut supplied_tag)?;
        ensure_stream_eof(input)?;
        mac.verify_slice(&supplied_tag)
            .map_err(|_| invalid_data("backup bundle authentication failed"))?;
        Ok(())
    })();
    result.map_err(|error| partial_bundle_error(imported.len(), error))?;
    Ok(imported)
}

fn backup_links_for(identity: &Identity, peer_id: &str) -> io::Result<BackupLinks> {
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

fn apply_backup_links(
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

fn encode_backup_with_links(
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
    File::open("/dev/urandom")?.read_exact(&mut salt)?;
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

fn decode_backup(
    identity: &Identity,
    backup: &[u8],
    password: Option<&str>,
) -> io::Result<(String, Vec<StoredMessage>)> {
    let (peer_id, messages, _) = decode_backup_with_links(identity, backup, password)?;
    Ok((peer_id, messages))
}

fn decode_backup_with_links(
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

#[cfg(test)]
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
    identity: &Identity,
    _messages: &[StoredMessage],
    identity_id: &str,
    peer_id: &str,
    previous_local_ids: &[String],
) -> io::Result<(Vec<[u8; 32]>, Vec<[u8; 32]>)> {
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

type LinkedIds = (HashSet<String>, HashSet<String>);

#[derive(Clone, Default)]
struct BackupLinks {
    local: HashSet<String>,
    peer: HashSet<String>,
    origins: Vec<String>,
}

fn linked_key_path(identity: &Identity, peer_id: &str) -> io::Result<PathBuf> {
    let identity_id = identity.public_id();
    let directory = data_directory()?.join(identity_id);
    let key = identity.storage_key();
    let index_key = derive_index_key(&key);
    Ok(directory.join(format!(
        ".linked-{}.adkey",
        opaque_conversation_name(&index_key, peer_id)
    )))
}

fn read_linked_keys(identity: &Identity, peer_id: &str) -> io::Result<LinkedIds> {
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
    if bytes.len() < 8 + NONCE_BYTES + 16 || !bytes.starts_with(LINKED_KEYS_MAGIC) {
        return Err(invalid_data("invalid linked identity key store"));
    }
    let nonce = Nonce::from_slice(&bytes[8..20]);
    let key = identity.storage_key();
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

fn write_linked_keys(identity: &Identity, peer_id: &str, linked: &LinkedIds) -> io::Result<()> {
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
    create_dir_all(directory)?;
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
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let key = identity.storage_key();
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
    let mut contents = LINKED_KEYS_MAGIC.to_vec();
    contents.extend_from_slice(&nonce);
    contents.extend_from_slice(&encrypted);
    let temporary = path.with_extension(format!("{}.tmp", hex_encode(&random_nonce()?)));
    let mut options = OpenOptions::new();
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
        rename(&temporary, &path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
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

fn derive_backup_bundle_key(
    identity: &Identity,
    bundle_id: &[u8; 16],
) -> io::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0; 32]);
    let storage_key = identity.storage_key();
    Hkdf::<Sha256>::new(Some(bundle_id), storage_key.as_ref())
        .expand(b"another-dimension-v2/backup-bundle/ADPACK3", key.as_mut())
        .map_err(|_| invalid_data("backup bundle authentication key unavailable"))?;
    Ok(key)
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
    Ok((messages, index, recovered_partial))
}

fn decode_history_plain(plain: &[u8], legacy_format: bool) -> io::Result<StoredMessage> {
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

fn encode_history_plain(message: &StoredMessage) -> io::Result<Zeroizing<Vec<u8>>> {
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

fn restore_staging_aad(identity_id: &str, peer_id: &str, request_id: &str, index: u64) -> Vec<u8> {
    [
        RESTORE_STAGING_MAGIC.as_slice(),
        identity_id.as_bytes(),
        peer_id.as_bytes(),
        request_id.as_bytes(),
        &index.to_be_bytes(),
    ]
    .concat()
}

fn lock_restore_directory(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only operates on the live descriptor owned by `file`.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn cleanup_stale_restore_staging(root: &std::path::Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let directory_name = entry.file_name();
        let directory_name = directory_name.to_string_lossy();
        if directory_name.len() != NONCE_BYTES * 2
            || !directory_name.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }
        let records_path = entry.path().join("records.enc");
        if !std::fs::symlink_metadata(&records_path)
            .is_ok_and(|metadata| metadata.file_type().is_file())
        {
            continue;
        }
        let mut records = File::open(&records_path)?;
        let mut magic = [0; RESTORE_STAGING_MAGIC.len()];
        if records.read_exact(&mut magic).is_err() || &magic != RESTORE_STAGING_MAGIC {
            continue;
        }
        let lock_path = entry.path().join("owner.lock");
        let lock = match OpenOptions::new().read(true).write(true).open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock only operates on the live descriptor owned by `lock`.
            let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(error);
            }
        }
        std::fs::remove_dir_all(entry.path())?;
    }
    Ok(())
}

fn cleanup_restore_merge_attempt(root: &std::path::Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "merge-index"
            || (entry.file_type()?.is_file()
                && ((name.starts_with("sort-") || name.starts_with("merge-"))
                    && name.ends_with(".adlog")))
        {
            if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(entry.path())?;
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

fn cleanup_orphaned_restore_outputs(
    directory: &std::path::Path,
    history_path: &std::path::Path,
) -> io::Result<()> {
    let filename = history_path
        .file_name()
        .ok_or_else(|| invalid_data("conversation filename unavailable"))?
        .to_string_lossy();
    let prefix = format!(".{filename}.restore-merge-");
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(suffix) = name
            .strip_prefix(&prefix)
            .and_then(|tail| tail.strip_suffix(".tmp"))
        else {
            continue;
        };
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

struct RestoreDiskIndex {
    file: File,
    capacity: u64,
    key: Zeroizing<[u8; 32]>,
}

impl RestoreDiskIndex {
    const SLOT_BYTES: u64 = 82;

    fn new(staging: &RestoreStaging, entries: u64) -> io::Result<Self> {
        let capacity = entries
            .checked_mul(2)
            .and_then(u64::checked_next_power_of_two)
            .unwrap_or(u64::MAX)
            .max(16);
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(staging.directory.join("merge-index"))?;
        set_private_file(&file)?;
        file.set_len(
            capacity
                .checked_mul(Self::SLOT_BYTES)
                .ok_or_else(|| invalid_data("restore index is too large"))?,
        )?;
        Ok(Self {
            file,
            capacity,
            key: Zeroizing::new(*staging.key),
        })
    }

    fn index_message(&mut self, message: &StoredMessage, offered: bool) -> io::Result<bool> {
        #[cfg(test)]
        if test_failure(FAIL_RESTORE_INDEX) {
            return Err(io::Error::other("injected restore index write failure"));
        }
        if let Some(proof) = &message.proof {
            self.index_signed(proof.id, message, offered)
        } else {
            self.index_legacy(message, offered)
        }
    }

    fn index_signed(
        &mut self,
        id: [u8; 16],
        message: &StoredMessage,
        offered: bool,
    ) -> io::Result<bool> {
        let mut id_input = b"signed-id\0".to_vec();
        id_input.extend_from_slice(&id);
        let id_hash = keyed_restore_hash(&self.key, &id_input);
        let mut content_input = b"signed-content\0".to_vec();
        content_input.extend_from_slice(&encode_history_plain(message)?);
        let content_hash = keyed_restore_hash(&self.key, &content_input);
        let slot = self.find_slot(1, &id_hash)?;
        if let Some((_, stored)) = slot {
            if stored[34..66] != content_hash {
                return Err(invalid_data("message ID collision in restore proposal"));
            }
            return Ok(!offered);
        }
        self.write_slot(self.empty_slot(1, &id_hash, &content_hash, 0, 0)?)?;
        Ok(true)
    }

    fn index_legacy(&mut self, message: &StoredMessage, offered: bool) -> io::Result<bool> {
        let mut key_input = b"legacy-message\0".to_vec();
        key_input.extend_from_slice(&encode_history_plain(message)?);
        let legacy_hash = keyed_restore_hash(&self.key, &key_input);
        let slot = self.find_slot(2, &legacy_hash)?;
        let (existing, seen) = slot
            .as_ref()
            .map(|(_, raw)| {
                (
                    u64::from_be_bytes(raw[66..74].try_into().expect("fixed slot")),
                    u64::from_be_bytes(raw[74..82].try_into().expect("fixed slot")),
                )
            })
            .unwrap_or((0, 0));
        let (next_existing, next_seen, keep) = if offered {
            let next_seen = seen
                .checked_add(1)
                .ok_or_else(|| invalid_data("legacy restore duplicate count overflow"))?;
            (existing, next_seen, next_seen > existing)
        } else {
            (
                existing
                    .checked_add(1)
                    .ok_or_else(|| invalid_data("legacy restore duplicate count overflow"))?,
                seen,
                true,
            )
        };
        let raw = self.empty_slot(2, &legacy_hash, &[0; 32], next_existing, next_seen)?;
        if let Some((position, _)) = slot {
            self.file.seek(SeekFrom::Start(position))?;
            self.file.write_all(&raw)?;
        } else {
            self.write_slot(raw)?;
        }
        Ok(keep)
    }

    fn find_slot(&mut self, kind: u8, digest: &[u8; 32]) -> io::Result<Option<(u64, [u8; 82])>> {
        let start =
            u64::from_be_bytes(digest[..8].try_into().expect("fixed digest")) & (self.capacity - 1);
        for offset in 0..self.capacity {
            let slot = (start + offset) & (self.capacity - 1);
            let position = slot * Self::SLOT_BYTES;
            self.file.seek(SeekFrom::Start(position))?;
            let mut raw = [0; 82];
            self.file.read_exact(&mut raw)?;
            if raw[0] == 0 {
                return Ok(None);
            }
            if raw[0] != 1 || raw[1] != kind {
                continue;
            }
            if &raw[2..34] == digest {
                return Ok(Some((position, raw)));
            }
        }
        Err(invalid_data("restore disk index is full"))
    }

    fn empty_slot(
        &self,
        kind: u8,
        digest: &[u8; 32],
        value: &[u8; 32],
        existing: u64,
        seen: u64,
    ) -> io::Result<[u8; 82]> {
        let mut raw = [0; 82];
        raw[0] = 1;
        raw[1] = kind;
        raw[2..34].copy_from_slice(digest);
        raw[34..66].copy_from_slice(value);
        raw[66..74].copy_from_slice(&existing.to_be_bytes());
        raw[74..82].copy_from_slice(&seen.to_be_bytes());
        Ok(raw)
    }

    fn write_slot(&mut self, raw: [u8; 82]) -> io::Result<()> {
        let digest = &raw[2..34];
        let start =
            u64::from_be_bytes(digest[..8].try_into().expect("fixed digest")) & (self.capacity - 1);
        for offset in 0..self.capacity {
            let position = ((start + offset) & (self.capacity - 1)) * Self::SLOT_BYTES;
            self.file.seek(SeekFrom::Start(position))?;
            let mut existing = [0; 82];
            self.file.read_exact(&mut existing)?;
            if existing[0] == 0 {
                self.file.seek(SeekFrom::Start(position))?;
                self.file.write_all(&raw)?;
                return Ok(());
            }
        }
        Err(invalid_data("restore disk index is full"))
    }
}

fn keyed_restore_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn write_restore_sort_run(
    directory: &std::path::Path,
    serial: &mut u64,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    items: &mut Vec<(u64, StoredMessage)>,
) -> io::Result<PathBuf> {
    items.sort_by_key(|(_, message)| message.unix_time);
    let path = directory.join(format!("sort-{:016x}.adlog", *serial));
    *serial = serial
        .checked_add(1)
        .ok_or_else(|| invalid_data("restore sort run counter overflow"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    set_private_file(&file)?;
    file.write_all(MAGIC)?;
    for (index, (_, message)) in items.drain(..).enumerate() {
        file.write_all(&encode_record(
            key,
            identity_id,
            peer_id,
            index as u64,
            &message,
        )?)?;
    }
    file.sync_all()?;
    Ok(path)
}

fn merge_encrypted_runs(
    input_paths: &[PathBuf],
    output_path: &std::path::Path,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
) -> io::Result<u64> {
    if input_paths.len() > RESTORE_MERGE_FAN_IN {
        return Err(invalid_data("too many restore sort inputs"));
    }
    let mut readers = input_paths
        .iter()
        .map(|path| {
            open_history_reader(
                path.clone(),
                Zeroizing::new(*key),
                identity_id.to_owned(),
                peer_id.to_owned(),
            )
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut current = Vec::<Option<StoredMessage>>::with_capacity(readers.len());
    let mut heap = BinaryHeap::<Reverse<(u64, usize)>>::new();
    for (index, reader) in readers.iter_mut().enumerate() {
        let message = reader.next_record()?;
        if let Some(message) = &message {
            heap.push(Reverse((message.unix_time, index)));
        }
        current.push(message);
    }
    let mut output = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(output_path)?;
    set_private_file(&output)?;
    output.write_all(MAGIC)?;
    let mut output_index = 0u64;
    while let Some(Reverse((_, source))) = heap.pop() {
        let message = current[source]
            .take()
            .ok_or_else(|| invalid_data("restore sort cursor is unavailable"))?;
        output.write_all(&encode_record(
            key,
            identity_id,
            peer_id,
            output_index,
            &message,
        )?)?;
        output_index = output_index
            .checked_add(1)
            .ok_or_else(|| invalid_data("restored history is too large"))?;
        #[cfg(test)]
        if output_index == 1 && test_failure(FAIL_RESTORE_OUTPUT) {
            return Err(io::Error::other("injected restore output write failure"));
        }
        current[source] = readers[source].next_record()?;
        if let Some(next) = &current[source] {
            heap.push(Reverse((next.unix_time, source)));
        }
    }
    output.sync_all()?;
    Ok(output_index)
}

fn add_restore_run_level(
    mut path: PathBuf,
    levels: &mut Vec<Vec<PathBuf>>,
    serial: &mut u64,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    directory: &std::path::Path,
) -> io::Result<()> {
    let mut level = 0usize;
    loop {
        if levels.len() <= level {
            levels.push(Vec::new());
        }
        levels[level].push(path);
        if levels[level].len() < RESTORE_MERGE_FAN_IN {
            return Ok(());
        }
        let inputs = std::mem::take(&mut levels[level]);
        let output = directory.join(format!("merge-{:016x}.adlog", *serial));
        *serial = serial
            .checked_add(1)
            .ok_or_else(|| invalid_data("restore merge run counter overflow"))?;
        merge_encrypted_runs(&inputs, &output, key, identity_id, peer_id)?;
        for input in inputs {
            std::fs::remove_file(input)?;
        }
        path = output;
        level += 1;
    }
}

fn push_restore_sort_item(
    message: StoredMessage,
    buffer: &mut Vec<(u64, StoredMessage)>,
    buffer_bytes: &mut usize,
    peak_buffer_bytes: &mut usize,
    levels: &mut Vec<Vec<PathBuf>>,
    serial: &mut u64,
    key: &[u8; 32],
    identity_id: &str,
    peer_id: &str,
    directory: &std::path::Path,
) -> io::Result<()> {
    let size = std::mem::size_of::<StoredMessage>()
        + message.text.len()
        + if message.proof.is_some() { 144 } else { 0 };
    if !buffer.is_empty()
        && (buffer.len() >= RESTORE_SORT_RUN_RECORDS
            || buffer_bytes.saturating_add(size) > RESTORE_SORT_RUN_BYTES)
    {
        let run = write_restore_sort_run(directory, serial, key, identity_id, peer_id, buffer)?;
        *buffer_bytes = 0;
        add_restore_run_level(run, levels, serial, key, identity_id, peer_id, directory)?;
    }
    *buffer_bytes = buffer_bytes.saturating_add(size);
    *peak_buffer_bytes = (*peak_buffer_bytes).max(*buffer_bytes);
    buffer.push((0, message));
    if buffer.len() >= RESTORE_SORT_RUN_RECORDS || *buffer_bytes >= RESTORE_SORT_RUN_BYTES {
        let run = write_restore_sort_run(directory, serial, key, identity_id, peer_id, buffer)?;
        *buffer_bytes = 0;
        add_restore_run_level(run, levels, serial, key, identity_id, peer_id, directory)?;
    }
    Ok(())
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
pub(crate) fn set_test_data_directory(path: Option<PathBuf>) {
    TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = path);
}

#[cfg(test)]
pub(crate) fn test_data_directory() -> Option<PathBuf> {
    TEST_DATA_DIRECTORY.with(|directory| directory.borrow().clone())
}

#[cfg(test)]
pub(crate) fn set_history_delete_test_gate(gate: Option<HistoryDeleteTestGate>) {
    *HISTORY_DELETE_TEST_GATE.lock().unwrap() = gate;
}

#[cfg(test)]
fn wait_history_delete_test_gate() {
    let gate = HISTORY_DELETE_TEST_GATE.lock().unwrap().clone();
    let Some(gate) = gate else { return };
    let (state, changed) = &*gate;
    let mut state = state.lock().unwrap();
    state.0 = true;
    changed.notify_all();
    while !state.1 {
        state = changed.wait(state).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_peer_id, History, MessageSender, RestoreStaging, StoredMessage,
        MAX_LEGACY_BACKUP_BYTES, MAX_MESSAGE_BYTES,
    };
    use crate::identity::Identity;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use std::collections::HashSet;
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
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

    fn encode_v6_fixture(
        identity: &Identity,
        peer_id: &str,
        messages: &[StoredMessage],
    ) -> Vec<u8> {
        let peer = super::decode_peer_id(peer_id).unwrap();
        let links = super::backup_links_for(identity, peer_id).unwrap();
        let key = super::derive_backup_key(&identity.storage_key());
        let mut aad = super::backup_aad(identity, super::BACKUP_STREAM_V6_MAGIC, None);
        aad.push(0);
        aad.extend_from_slice(&peer);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let mut output = Vec::new();
        output.extend_from_slice(super::BACKUP_STREAM_V6_MAGIC);
        output.push(0);
        output.extend_from_slice(&peer);
        for (index, stored) in messages.iter().enumerate() {
            write_v6_fixture_frame(
                &mut output,
                &cipher,
                &aad,
                1,
                index as u64,
                &super::encode_history_plain(stored).unwrap(),
            );
        }
        write_v6_fixture_frame(
            &mut output,
            &cipher,
            &aad,
            0,
            messages.len() as u64,
            &super::encode_backup_links(&links).unwrap(),
        );
        output
    }

    fn write_v6_fixture_frame(
        output: &mut Vec<u8>,
        cipher: &ChaCha20Poly1305,
        aad: &[u8],
        kind: u8,
        index: u64,
        plaintext: &[u8],
    ) {
        let nonce = super::random_nonce().unwrap();
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &super::backup_stream_frame_aad(aad, kind, index),
                },
            )
            .unwrap();
        output.push(kind);
        output.extend_from_slice(&index.to_be_bytes());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
        output.extend_from_slice(&encrypted);
    }

    fn bundle3_children(bundle: &[u8]) -> Vec<(usize, usize)> {
        assert!(bundle.starts_with(super::BACKUP_STREAM_BUNDLE_MAGIC));
        let count = u32::from_be_bytes(bundle[24..28].try_into().unwrap()) as usize;
        let mut offset = 28;
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            let length =
                u64::from_be_bytes(bundle[offset..offset + 8].try_into().unwrap()) as usize;
            let start = offset + 8;
            let end = start + length;
            children.push((offset, end));
            offset = end;
        }
        assert_eq!(offset + super::BACKUP_BUNDLE_TAG_BYTES, bundle.len());
        children
    }

    fn append_bundle3_child(output: &mut Vec<u8>, bundle: &[u8], child: (usize, usize)) {
        output.extend_from_slice(&bundle[child.0..child.0 + 8]);
        output.extend_from_slice(&bundle[child.0 + 8..child.1]);
    }

    #[test]
    fn sequential_history_reader_holds_file_length_snapshot_without_repairing() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "39".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "snapshot one")).unwrap();
        let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
        history.append(&message(2, "appended later")).unwrap();
        assert_eq!(
            reader.next_record().unwrap(),
            Some(message(1, "snapshot one"))
        );
        assert_eq!(reader.next_record().unwrap(), None);
    }

    #[test]
    fn append_uses_cached_index_and_refreshes_stale_handles_safely() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "3f".repeat(32);
        let (mut first, _, _) = History::open(&identity, &peer).unwrap();
        for index in 0..256 {
            first.append(&message(index, "cached append")).unwrap();
        }
        let (mut second, _, _) = History::open(&identity, &peer).unwrap();

        super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
        first.append(&message(257, "fast path")).unwrap();
        super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 0));

        super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
        second
            .append(&message(258, "external append refresh"))
            .unwrap();
        super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 1));

        first
            .replace(&[
                message(300, "replacement one"),
                message(301, "replacement two"),
            ])
            .unwrap();
        super::TEST_DECRYPTED_RECORDS.with(|count| count.set(0));
        second.append(&message(302, "after replacement")).unwrap();
        super::TEST_DECRYPTED_RECORDS.with(|count| assert_eq!(count.get(), 2));

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&second.path)
            .unwrap();
        file.seek(SeekFrom::Start(8 + 4 + 12 + 2)).unwrap();
        let mut byte = [0];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Current(-1)).unwrap();
        file.write_all(&[byte[0] ^ 0x80]).unwrap();
        file.sync_all().unwrap();
        let length = file.metadata().unwrap().len();
        drop(file);
        assert!(second.append(&message(303, "must fail")).is_err());
        assert_eq!(std::fs::metadata(&second.path).unwrap().len(), length);
        let result = History::open(&identity, &peer);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn history_pages_are_bounded_and_stale_selection_is_rejected() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "41".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        for index in 0..237 {
            history.append(&message(index, "page item")).unwrap();
        }
        let first = History::read_page(&identity, &peer, None, 50).unwrap();
        assert_eq!(first.entries.len(), 50);
        let cursor = first.next.clone().unwrap();
        assert_eq!(cursor.index, 50);
        let second = History::read_page(&identity, &peer, Some(&cursor), 50).unwrap();
        assert_eq!(second.entries.len(), 50);
        assert_eq!(second.entries[0].index, 50);

        history
            .append(&message(238, "concurrent update invalidates selection"))
            .unwrap();
        let selected = HashSet::from([0usize]);
        let stale = History::delete_indices_if_version(&identity, &peer, &first.version, &selected);
        assert_eq!(stale.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(
            History::read_page(&identity, &peer, None, 100)
                .unwrap()
                .entries
                .len(),
            100
        );

        let fresh = History::read_page(&identity, &peer, None, 100).unwrap();
        let kept = History::delete_indices_if_version(&identity, &peer, &fresh.version, &selected)
            .unwrap();
        assert_eq!(kept.remaining_count, 237);
        let after = History::read_page(&identity, &peer, None, 100).unwrap();
        assert_eq!(after.entries[0].message.text, "page item");
        assert_eq!(History::list(&identity).unwrap()[0].message_count, 237);
    }

    #[test]
    fn streaming_history_deletion_preserves_boundaries_rejects_bad_indices_and_refreshes_handles() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "42".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        let mut first = message(10, "same timestamp one");
        first.sender = MessageSender::Other;
        first.proof = Some(super::MessageProof {
            id: [9; 16],
            signer: [1; 32],
            recipient: [2; 32],
            signature: [3; 64],
        });
        let second = message(10, "same timestamp two");
        let last = message(20, "inclusive end");
        history
            .replace(&[first.clone(), second.clone(), last.clone()])
            .unwrap();
        let old = History::read_page(&identity, &peer, None, 10).unwrap();
        let out_of_range = HashSet::from([3]);
        assert_eq!(
            History::delete_indices_if_version(&identity, &peer, &old.version, &out_of_range)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
        let selected_same_time = HashSet::from([1]);
        let selected_result =
            History::delete_indices_if_version(&identity, &peer, &old.version, &selected_same_time)
                .unwrap();
        assert_eq!(selected_result.remaining_count, 2);
        let after_selection = History::read_page(&identity, &peer, None, 10).unwrap();
        assert_eq!(after_selection.entries[0].message, first);
        assert_eq!(
            after_selection.entries[0]
                .message
                .proof
                .as_ref()
                .unwrap()
                .id,
            [9; 16]
        );
        let ranged = History::delete_time_range(&identity, &peer, 10, 10).unwrap();
        assert_eq!(ranged.deleted_count, 1);
        assert_eq!(ranged.remaining_count, 1);
        let page = History::read_page(&identity, &peer, None, 10).unwrap();
        assert_eq!(page.entries[0].message, last);
        history
            .append(&message(30, "append after rewrite"))
            .unwrap();
        let page = History::read_page(&identity, &peer, None, 10).unwrap();
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[1].message.text, "append after rewrite");

        let page = History::read_page(&identity, &peer, None, 10).unwrap();
        let selected = HashSet::from([0]);
        let deleted =
            History::delete_indices_if_version(&identity, &peer, &page.version, &selected).unwrap();
        assert_eq!(deleted.remaining_count, 1);
    }

    #[test]
    fn streaming_history_deletion_failures_preserve_original_and_report_cleanup_path() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "43".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "preserve me")).unwrap();
        history.append(&message(2, "keep this record")).unwrap();
        let before = std::fs::read(&history.path).unwrap();
        let page = History::read_page(&identity, &peer, None, 10).unwrap();
        let selected = HashSet::from([0]);
        for failure in [
            super::FAIL_HISTORY_DELETE_WRITE,
            super::FAIL_HISTORY_DELETE_SYNC,
            super::FAIL_HISTORY_DELETE_RENAME,
        ] {
            super::TEST_FAILURES.with(|failures| failures.set(failure));
            assert!(
                History::delete_indices_if_version(&identity, &peer, &page.version, &selected)
                    .is_err()
            );
            assert_eq!(std::fs::read(&history.path).unwrap(), before);
        }
        super::TEST_FAILURES.with(|failures| {
            failures.set(super::FAIL_HISTORY_DELETE_WRITE | super::FAIL_HISTORY_DELETE_CLEANUP)
        });
        let error = History::delete_indices_if_version(&identity, &peer, &page.version, &selected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("recoverable file:"));
        assert_eq!(std::fs::read(&history.path).unwrap(), before);
        let retry =
            History::delete_indices_if_version(&identity, &peer, &page.version, &selected).unwrap();
        assert_eq!(retry.remaining_count, 1);
    }

    #[test]
    fn streaming_history_deletion_rejects_partial_source_without_repairing_it() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "46".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "valid record")).unwrap();
        let mut file = OpenOptions::new().append(true).open(&history.path).unwrap();
        file.write_all(&[0, 0]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let original = std::fs::read(&history.path).unwrap();
        assert!(History::delete_time_range(&identity, &peer, 0, 2).is_err());
        assert_eq!(std::fs::read(&history.path).unwrap(), original);
    }

    fn write_synthetic_history(history: &History, count: u64, text: &str) -> u64 {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&history.path)
            .unwrap();
        file.write_all(super::MAGIC).unwrap();
        for index in 0..count {
            let record = super::encode_record(
                &history.key,
                &history.identity_id,
                &history.peer_id,
                index,
                &message(index, text),
            )
            .unwrap();
            file.write_all(&record).unwrap();
        }
        file.sync_all().unwrap();
        file.metadata().unwrap().len()
    }

    #[test]
    fn streaming_selection_deletion_handles_over_one_hundred_thousand_records() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "44".repeat(32);
        let (history, _, _) = History::open(&identity, &peer).unwrap();
        let _bytes = write_synthetic_history(&history, 100_005, "bounded record");
        let version = History::read_page(&identity, &peer, None, 1)
            .unwrap()
            .version;
        let selected = HashSet::from([0, 50_000, 100_004]);
        let result =
            History::delete_indices_if_version(&identity, &peer, &version, &selected).unwrap();
        assert_eq!(result.remaining_count, 100_002);
        assert_eq!(result.deleted_count, 3);
        assert!(result.peak_record_bytes < 32 * 1024);
        assert_eq!(History::list(&identity).unwrap()[0].message_count, 100_002);
    }

    #[test]
    fn streaming_range_deletion_handles_over_sixty_four_mib_and_inclusive_cutoff() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "45".repeat(32);
        let (history, _, _) = History::open(&identity, &peer).unwrap();
        let source_bytes = write_synthetic_history(&history, 17_000, &"x".repeat(4096));
        assert!(source_bytes > 64 * 1024 * 1024);
        // Keep-recent uses an inclusive end; the exact cutoff second is deleted.
        let result = History::delete_time_range(&identity, &peer, 0, 8_499).unwrap();
        assert_eq!(result.deleted_count, 8_500);
        assert_eq!(result.remaining_count, 8_500);
        assert!(result.peak_record_bytes < 32 * 1024);
        let page = History::read_page(&identity, &peer, None, 1).unwrap();
        assert_eq!(page.entries[0].message.unix_time, 8_500);
        let last = History::read_page(&identity, &peer, page.next.as_ref(), 1).unwrap();
        assert_eq!(last.entries[0].message.unix_time, 8_501);
    }

    #[test]
    fn simultaneous_history_handles_append_without_duplicate_indices() {
        let data = IsolatedData::new();
        let (identity, access_code) = Identity::create().unwrap();
        let code = access_code.to_string();
        let peer = "40".repeat(32);
        let _ = History::open(&identity, &peer).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for (index, text) in [(1u64, "concurrent one"), (2, "concurrent two")] {
            let directory = data.0.clone();
            let peer = peer.clone();
            let code = code.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                super::TEST_DATA_DIRECTORY.with(|slot| *slot.borrow_mut() = Some(directory));
                let identity = Identity::from_code(&code).unwrap();
                let (mut history, _, _) = History::open_for_chat(&identity, &peer).unwrap();
                barrier.wait();
                history.append(&message(index, text)).unwrap();
                super::TEST_DATA_DIRECTORY.with(|slot| *slot.borrow_mut() = None);
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().unwrap();
        }
        let (mut history, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages.len(), 2);
        history
            .append(&message(3, "after concurrent append"))
            .unwrap();
        let (_, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages.len(), 3);
        let texts: HashSet<_> = messages.iter().map(|item| item.text.as_str()).collect();
        assert!(texts.contains("concurrent one"));
        assert!(texts.contains("concurrent two"));
    }

    #[test]
    fn chat_history_open_keeps_only_count_and_page_sized_results() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "3a".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        for index in 0..600 {
            history.append(&message(index, "page item")).unwrap();
        }
        drop(history);
        let (history, count, recovered) = History::open_for_chat(&identity, &peer).unwrap();
        assert_eq!(count, 600);
        assert!(!recovered);
        let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
        for _ in 0..500 {
            reader.next_record().unwrap().unwrap();
        }
        assert_eq!(
            (0..256)
                .filter(|_| reader.next_record().unwrap().is_some())
                .count(),
            100
        );
        drop(history);
    }

    #[test]
    fn restore_staging_encrypts_records_and_removes_only_its_owned_directory() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "3a".repeat(32);
        let request = "3b".repeat(32);
        let root = super::data_directory()
            .unwrap()
            .join(identity.public_id())
            .join(".history-restore");
        std::fs::create_dir_all(&root).unwrap();
        let unrelated = root.join("unrelated.keep");
        std::fs::write(&unrelated, b"preserve").unwrap();
        let staged = message(9, "secret staged proposal");
        {
            let mut writer = super::RestoreStaging::create(&identity, &peer, &request).unwrap();
            writer.append_verified(&staged).unwrap();
            writer.finish().unwrap();
            assert_eq!(writer.count(), 1);
            let file = std::fs::read(writer.directory.join("records.enc")).unwrap();
            assert!(!file
                .windows(b"secret staged proposal".len())
                .any(|window| window == b"secret staged proposal"));
            assert_eq!(writer.next_record().unwrap(), Some(staged.clone()));
            assert_eq!(writer.next_record().unwrap(), None);
            let path = writer.directory.join("records.enc");
            let mut tampered = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            let end = tampered.seek(SeekFrom::End(-1)).unwrap();
            let mut byte = [0];
            tampered.read_exact(&mut byte).unwrap();
            tampered.seek(SeekFrom::Start(end)).unwrap();
            byte[0] ^= 1;
            tampered.write_all(&byte).unwrap();
            writer.rewind().unwrap();
            assert!(writer.next_record().is_err());
        }
        assert!(unrelated.exists());
        assert_eq!(std::fs::read(unrelated).unwrap(), b"preserve");
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 1);
    }

    #[test]
    fn stale_restore_cleanup_preserves_active_and_unowned_directories() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "4a".repeat(32);
        let root = super::data_directory()
            .unwrap()
            .join(identity.public_id())
            .join(".history-restore");
        let mut active = RestoreStaging::create(&identity, &peer, &"4b".repeat(32)).unwrap();
        active.append_verified(&message(1, "active")).unwrap();
        let stale = root.join("4c".repeat(12));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("owner.lock"), []).unwrap();
        std::fs::write(stale.join("records.enc"), super::RESTORE_STAGING_MAGIC).unwrap();
        let unowned = root.join("notes");
        std::fs::create_dir(&unowned).unwrap();
        std::fs::write(unowned.join("keep"), b"keep").unwrap();
        super::cleanup_stale_restore_staging(&root).unwrap();
        assert!(active.directory.exists());
        assert!(!stale.exists());
        assert_eq!(std::fs::read(unowned.join("keep")).unwrap(), b"keep");
        active.cleanup().unwrap();
    }

    #[test]
    fn restore_result_cleanup_failure_reports_recoverable_path_and_open_cleans_it() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "4d".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "original")).unwrap();
        let mut staging = RestoreStaging::create(&identity, &peer, &"4e".repeat(32)).unwrap();
        staging.append_verified(&message(2, "proposal")).unwrap();
        staging.finish().unwrap();
        super::TEST_FAILURES.with(|failures| {
            failures.set(super::FAIL_RESTORE_RENAME | super::FAIL_RESTORE_RESULT_CLEANUP)
        });
        let error = history
            .merge_restore_staging(&identity, &mut staging)
            .unwrap_err();
        super::TEST_FAILURES.with(|failures| failures.set(0));
        let text = error.to_string();
        assert!(text.contains("recoverable file:"));
        let path = text.split("recoverable file: ").nth(1).unwrap();
        let path = PathBuf::from(path);
        assert!(path.exists());
        assert_eq!(
            History::read_for_identity_copy(&identity, &peer)
                .unwrap()
                .0
                .len(),
            1
        );
        drop(history);
        let (_, messages, _) = History::open(&identity, &peer).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(!path.exists());
    }

    #[test]
    fn streamed_restore_merge_preserves_order_multiplicity_and_reports_bounded_buffer() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "40".repeat(32);
        let request = "41".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history
            .append(&message(2, "same time existing one"))
            .unwrap();
        history
            .append(&message(2, "same time existing two"))
            .unwrap();
        history.append(&message(3, "legacy repeat")).unwrap();
        history.append(&message(3, "legacy repeat")).unwrap();
        let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
        staging
            .append_verified(&message(1, "earlier proposal"))
            .unwrap();
        staging
            .append_verified(&message(2, "same time proposal"))
            .unwrap();
        staging
            .append_verified(&message(3, "legacy repeat"))
            .unwrap();
        staging
            .append_verified(&message(3, "legacy repeat"))
            .unwrap();
        staging
            .append_verified(&message(3, "legacy repeat"))
            .unwrap();
        staging.finish().unwrap();
        let summary = history
            .merge_restore_staging(&identity, &mut staging)
            .unwrap();
        assert_eq!(summary.imported_count, 3);
        assert!(summary.peak_sort_buffer_bytes <= super::RESTORE_SORT_RUN_BYTES);
        let messages = History::read_for_identity_copy(&identity, &peer).unwrap().0;
        assert_eq!(messages.len() as u64, summary.total_count);
        assert_eq!(
            messages
                .iter()
                .map(|item| item.unix_time)
                .collect::<Vec<_>>(),
            vec![1, 2, 2, 2, 3, 3, 3]
        );
        assert_eq!(
            messages
                .iter()
                .filter(|item| item.text == "legacy repeat")
                .count(),
            3
        );
        assert_eq!(
            messages.iter().filter(|item| item.unix_time == 2).count(),
            3
        );
        assert_eq!(
            messages
                .iter()
                .filter(|item| item.unix_time == 2)
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec![
                "same time existing one",
                "same time existing two",
                "same time proposal"
            ]
        );
    }

    #[test]
    fn restore_staging_write_failure_leaves_no_completed_proposal() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let mut staging =
            RestoreStaging::create(&identity, &"4f".repeat(32), &"50".repeat(32)).unwrap();
        super::TEST_FAILURES.with(|failures| failures.set(super::FAIL_RESTORE_STAGE_WRITE));
        assert!(staging.append_verified(&message(1, "not stored")).is_err());
        super::TEST_FAILURES.with(|failures| failures.set(0));
        staging.finish().unwrap();
        assert_eq!(staging.count(), 0);
        assert_eq!(staging.next_record().unwrap(), None);
    }

    #[test]
    fn restore_staging_cleanup_failure_is_returned_to_the_caller() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let staging =
            RestoreStaging::create(&identity, &"53".repeat(32), &"54".repeat(32)).unwrap();
        let directory = staging.directory.clone();
        super::TEST_FAILURES.with(|failures| failures.set(super::FAIL_RESTORE_CLEANUP_ONCE));
        let error = staging.cleanup().unwrap_err();
        super::TEST_FAILURES.with(|failures| failures.set(0));
        assert!(error.to_string().contains("cleanup failure"));
        assert!(!directory.exists());
    }

    #[test]
    fn streamed_restore_merge_retries_and_preserves_original_on_injected_failures() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "42".repeat(32);
        let request = "43".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "keep original")).unwrap();
        let original = History::read_for_identity_copy(&identity, &peer).unwrap().0;
        let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
        staging.append_verified(&message(2, "offer")).unwrap();
        staging.finish().unwrap();
        for failure in [
            super::FAIL_RESTORE_INDEX,
            super::FAIL_RESTORE_OUTPUT,
            super::FAIL_RESTORE_RENAME,
        ] {
            super::TEST_FAILURES.with(|failures| failures.set(failure));
            assert!(history
                .merge_restore_staging(&identity, &mut staging)
                .is_err());
            super::TEST_FAILURES.with(|failures| failures.set(0));
            assert_eq!(
                History::read_for_identity_copy(&identity, &peer).unwrap().0,
                original
            );
        }
        let merged = history
            .merge_restore_staging(&identity, &mut staging)
            .unwrap();
        assert_eq!(merged.imported_count, 1);
        assert_eq!(
            History::read_for_identity_copy(&identity, &peer)
                .unwrap()
                .0
                .len(),
            2
        );
    }

    #[test]
    fn streamed_restore_merge_rejects_signed_id_collision_without_replacing_history() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "44".repeat(32);
        let request = "45".repeat(32);
        let mut original =
            super::sign_message(&identity, &peer, 7, "signed original".into()).unwrap();
        let mut conflict = original.clone();
        conflict.text = "same ID with changed content".into();
        let proof = original.proof.as_mut().unwrap();
        proof.id = [9; 16];
        conflict.proof.as_mut().unwrap().id = [9; 16];
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&original).unwrap();
        let mut staging = RestoreStaging::create(&identity, &peer, &request).unwrap();
        staging.append_verified(&conflict).unwrap();
        staging.finish().unwrap();
        assert!(history
            .merge_restore_staging(&identity, &mut staging)
            .is_err());
        assert_eq!(
            History::read_for_identity_copy(&identity, &peer).unwrap().0,
            vec![original]
        );
    }

    #[test]
    fn streamed_restore_merge_skips_identical_signed_ids() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "51".repeat(32);
        let original = super::sign_message(&identity, &peer, 7, "signed duplicate".into()).unwrap();
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&original).unwrap();
        let mut staging = RestoreStaging::create(&identity, &peer, &"52".repeat(32)).unwrap();
        staging.append_verified(&original).unwrap();
        staging.append_verified(&original).unwrap();
        staging.finish().unwrap();
        let summary = history
            .merge_restore_staging(&identity, &mut staging)
            .unwrap();
        assert_eq!(summary.imported_count, 0);
        assert_eq!(summary.total_count, 1);
    }

    #[test]
    fn transfer_estimate_scans_over_legacy_count_and_byte_thresholds_sequentially() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer_count = "3c".repeat(32);
        let (mut count_history, _, _) = History::open(&identity, &peer_count).unwrap();
        for index in 0..100_001u64 {
            let item = message(index, "x");
            let record = super::encode_record(
                &count_history.key,
                &count_history.identity_id,
                &count_history.peer_id,
                index,
                &item,
            )
            .unwrap();
            count_history.file.write_all(&record).unwrap();
        }
        count_history.file.sync_all().unwrap();
        let (mut reader, count, estimate) =
            History::estimate_transfer(&identity, &peer_count, &"3d".repeat(32)).unwrap();
        assert_eq!(count, 100_001);
        assert!(estimate > count as u64);
        let summaries = History::list(&identity).unwrap();
        assert_eq!(summaries[0].message_count, 100_001);
        let first_page = History::read_page(&identity, &peer_count, None, 100).unwrap();
        assert_eq!(first_page.entries.len(), 100);
        let next_page =
            History::read_page(&identity, &peer_count, first_page.next.as_ref(), 100).unwrap();
        assert_eq!(next_page.entries.len(), 100);
        assert_eq!(next_page.entries[0].index, 100);
        let mut streamed = 0;
        while reader.next_record().unwrap().is_some() {
            streamed += 1;
        }
        assert_eq!(streamed, count);

        let peer_bytes = "3e".repeat(32);
        let (mut byte_history, _, _) = History::open(&identity, &peer_bytes).unwrap();
        for index in 0..17_000u64 {
            let item = message(index, &"y".repeat(4096));
            let record = super::encode_record(
                &byte_history.key,
                &byte_history.identity_id,
                &byte_history.peer_id,
                index,
                &item,
            )
            .unwrap();
            byte_history.file.write_all(&record).unwrap();
        }
        byte_history.file.sync_all().unwrap();
        let (_, byte_count, byte_estimate) =
            History::estimate_transfer(&identity, &peer_bytes, &"3f".repeat(32)).unwrap();
        assert_eq!(byte_count, 17_000);
        assert!(byte_estimate > 64 * 1024 * 1024);
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
            super::merge_restored(&[], &[received.clone()]).unwrap(),
            vec![received.clone()]
        );
        assert_eq!(
            super::merge_restored(&[received.clone()], &[received.clone()]).unwrap(),
            vec![received.clone()]
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
        let fake_message = StoredMessage {
            unix_time: 104,
            sender: MessageSender::Me,
            text: format!(
                "{}self:{}:{}",
                super::IDENTITY_EVENT_PREFIX,
                "55".repeat(32),
                alice_new_id
            ),
            proof: None,
        };
        let (untrusted_local, untrusted_peer) = super::linked_identity_keys(
            &alice_new,
            &[fake_message],
            &alice_new_id,
            &bob_id,
            &local_origins,
        )
        .unwrap();
        assert!(untrusted_local.is_empty());
        assert!(untrusted_peer.is_empty());
        super::record_linked_local_identity(&alice_new, &bob_id, &alice_old_id).unwrap();
        let (local_aliases, peer_aliases) = super::linked_identity_keys(
            &alice_new,
            &alice_messages,
            &alice_new_id,
            &bob_id,
            &local_origins,
        )
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
            super::linked_identity_keys(&bob, &bob_messages, &bob.public_id(), &alice_new_id, &[])
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
    fn linked_backup_restores_original_proofs_and_relations_on_another_store() {
        let _data = IsolatedData::new();
        let root = super::data_directory().unwrap();
        let store_a = root.join("store-a");
        let store_b = root.join("store-b");
        std::fs::create_dir_all(&store_a).unwrap();
        std::fs::create_dir_all(&store_b).unwrap();
        super::TEST_DATA_DIRECTORY
            .with(|directory| *directory.borrow_mut() = Some(store_a.clone()));
        let (old_local, _) = Identity::create().unwrap();
        let (replacement, code) = Identity::create().unwrap();
        old_local.copy_local_data_to(&replacement).unwrap();
        let (peer, _) = Identity::create().unwrap();
        let peer_id = peer.public_id();
        let old_proof =
            super::sign_message(&old_local, &peer_id, 777, "before replacement".into()).unwrap();
        let (mut history, _, _) = History::open(&replacement, &peer_id).unwrap();
        history.append(&old_proof).unwrap();
        super::record_linked_local_identity(&replacement, &peer_id, &old_local.public_id())
            .unwrap();
        let backup = History::export_backup(&replacement, &peer_id, None).unwrap();
        assert!(backup.starts_with(super::BACKUP_LINKED_MAGIC));

        super::TEST_DATA_DIRECTORY
            .with(|directory| *directory.borrow_mut() = Some(store_b.clone()));
        let restored_identity = Identity::from_code(&code).unwrap();
        assert_eq!(restored_identity.public_id(), replacement.public_id());
        let (restored_peer, _) = History::import_backup(&restored_identity, &backup, None).unwrap();
        assert_eq!(restored_peer, peer_id);
        let (messages, _) = History::read_for_identity_copy(&restored_identity, &peer_id).unwrap();
        assert_eq!(messages, vec![old_proof.clone()]);
        let (locals, _) = super::linked_identity_keys(
            &restored_identity,
            &messages,
            &restored_identity.public_id(),
            &peer_id,
            &crate::identity::previous_public_ids(&restored_identity).unwrap(),
        )
        .unwrap();
        assert!(locals.contains(&old_local.public_key()));

        let mut tampered = backup.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(History::verify_backup(&restored_identity, &tampered, None).is_err());

        let mut bad_signature = old_proof.clone();
        bad_signature.proof.as_mut().unwrap().signature[0] ^= 1;
        let bad_signature_backup =
            super::encode_backup(&replacement, &peer_id, &[bad_signature], None).unwrap();
        assert!(History::verify_backup(&restored_identity, &bad_signature_backup, None).is_err());

        let bundle = History::export_backup_bundle(&replacement, &[peer_id.clone()]).unwrap();
        let store_c = root.join("store-c");
        std::fs::create_dir_all(&store_c).unwrap();
        super::TEST_DATA_DIRECTORY
            .with(|directory| *directory.borrow_mut() = Some(store_c.clone()));
        let bundle_identity = Identity::from_code(&code).unwrap();
        History::import_backup_bundle(&bundle_identity, &bundle).unwrap();
        let (bundle_messages, _) =
            History::read_for_identity_copy(&bundle_identity, &peer_id).unwrap();
        let (bundle_local, _) = super::linked_identity_keys(
            &bundle_identity,
            &bundle_messages,
            &bundle_identity.public_id(),
            &peer_id,
            &crate::identity::previous_public_ids(&bundle_identity).unwrap(),
        )
        .unwrap();
        assert!(bundle_local.contains(&old_local.public_key()));

        let store_d = root.join("store-d");
        std::fs::create_dir_all(&store_d).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_d));
        let failed_identity = Identity::from_code(&code).unwrap();
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
        let failure = History::import_backup(&failed_identity, &backup, None).unwrap_err();
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert!(failure
            .to_string()
            .contains("injected linked identity store failure"));
        assert!(crate::identity::previous_public_ids(&failed_identity)
            .unwrap()
            .is_empty());
        assert!(!super::is_linked_local_identity(
            &failed_identity,
            &peer_id,
            &old_local.public_id()
        )
        .unwrap());
        let (untouched, _) = History::read_for_identity_copy(&failed_identity, &peer_id).unwrap();
        assert!(untouched.is_empty());

        let store_e = root.join("store-e");
        std::fs::create_dir_all(&store_e).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(store_e));
        let replace_failed_identity = Identity::from_code(&code).unwrap();
        let (mut preexisting, _, _) = History::open(&replace_failed_identity, &peer_id).unwrap();
        preexisting
            .append(&message(3, "preserve this record"))
            .unwrap();
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_HISTORY_REPLACE_ONCE));
        assert!(History::import_backup(&replace_failed_identity, &backup, None).is_err());
        super::TEST_FAILURES.with(|flags| flags.set(0));
        let (preserved, _) =
            History::read_for_identity_copy(&replace_failed_identity, &peer_id).unwrap();
        assert_eq!(preserved, vec![message(3, "preserve this record")]);

        // ADBACK4 carries signed messages but no authenticated relationship metadata.
        let mut legacy_payload = Vec::new();
        legacy_payload.extend_from_slice(&super::decode_peer_id(&peer_id).unwrap());
        legacy_payload.extend_from_slice(&1_u32.to_be_bytes());
        let text = old_proof.text.as_bytes();
        legacy_payload.extend_from_slice(&old_proof.unix_time.to_be_bytes());
        legacy_payload.push(0);
        legacy_payload.extend_from_slice(&(text.len() as u32).to_be_bytes());
        legacy_payload.extend_from_slice(text);
        let proof = old_proof.proof.as_ref().unwrap();
        legacy_payload.push(1);
        legacy_payload.extend_from_slice(&proof.id);
        legacy_payload.extend_from_slice(&proof.signer);
        legacy_payload.extend_from_slice(&proof.recipient);
        legacy_payload.extend_from_slice(&proof.signature);
        let nonce = super::random_nonce().unwrap();
        let cipher = ChaCha20Poly1305::new_from_slice(
            super::derive_backup_key(&replacement.storage_key()).as_ref(),
        )
        .unwrap();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &legacy_payload,
                    aad: &super::backup_aad(&replacement, super::BACKUP_SIGNED_MAGIC, None),
                },
            )
            .unwrap();
        let mut old_backup = super::BACKUP_SIGNED_MAGIC.to_vec();
        old_backup.extend_from_slice(&nonce);
        old_backup.extend_from_slice(&ciphertext);
        assert!(History::verify_backup(&failed_identity, &old_backup, None).is_err());
    }

    #[test]
    fn pending_link_retries_marker_only_partial_failure_without_duplicate_marker() {
        let _data = IsolatedData::new();
        let (old, _) = Identity::create().unwrap();
        let (current, _) = Identity::create().unwrap();
        old.copy_local_data_to(&current).unwrap();
        let peer = "4a".repeat(32);
        let old_id = old.public_id();
        let entry = StoredMessage {
            unix_time: 22,
            sender: MessageSender::Me,
            text: format!(
                "{}self:{old_id}:{}",
                super::IDENTITY_EVENT_PREFIX,
                current.public_id()
            ),
            proof: None,
        };
        let (mut history, _, _) = History::open(&current, &peer).unwrap();
        assert!(history.append_system_once(&current, entry.clone()).unwrap());
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
        assert!(super::record_linked_local_identity(&current, &peer, &old_id).is_err());
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert_eq!(
            super::pending_local_identity_links(&current, &peer, &[old_id.clone()]).unwrap(),
            vec![old_id.clone()]
        );
        assert!(!history.append_system_once(&current, entry).unwrap());
        super::record_linked_local_identity(&current, &peer, &old_id).unwrap();
        assert!(super::record_linked_local_identity(&current, &peer, &"ff".repeat(32)).is_err());
        assert!(
            super::pending_local_identity_links(&current, &peer, &[old_id])
                .unwrap()
                .is_empty()
        );
        let (messages, _) = History::read_for_identity_copy(&current, &peer).unwrap();
        assert_eq!(messages.len(), 1);

        let path = super::linked_key_path(&current, &peer).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(path, bytes).unwrap();
        assert!(super::pending_local_identity_links(&current, &peer, &["ff".repeat(32)]).is_err());
    }

    #[test]
    fn repeated_identity_replacement_preserves_authenticated_peer_links_and_proofs() {
        let _data = IsolatedData::new();
        let (local_a, _) = Identity::create().unwrap();
        let (local_b, _) = Identity::create().unwrap();
        let (local_c, _) = Identity::create().unwrap();
        let (peer_old, _) = Identity::create().unwrap();
        let (peer_current, _) = Identity::create().unwrap();
        let current_peer_id = peer_current.public_id();
        let old_peer_id = peer_old.public_id();
        let mut proof =
            super::sign_message(&peer_old, &local_a.public_id(), 91, "old peer proof".into())
                .unwrap();
        proof.sender = MessageSender::Other;
        let (mut history, _, _) = History::open(&local_a, &current_peer_id).unwrap();
        history.append(&proof).unwrap();
        let mut links = (HashSet::new(), HashSet::new());
        links.1.insert(old_peer_id.clone());
        super::write_linked_keys(&local_a, &current_peer_id, &links).unwrap();

        local_a.copy_local_data_to(&local_b).unwrap();
        super::record_linked_local_identity(&local_b, &current_peer_id, &local_a.public_id())
            .unwrap();
        local_b.copy_local_data_to(&local_c).unwrap();
        let (messages, _) = History::read_for_identity_copy(&local_c, &current_peer_id).unwrap();
        let (local_aliases, peer_aliases) = super::linked_identity_keys(
            &local_c,
            &messages,
            &local_c.public_id(),
            &current_peer_id,
            &crate::identity::previous_public_ids(&local_c).unwrap(),
        )
        .unwrap();
        assert!(local_aliases.contains(&local_a.public_key()));
        assert!(peer_aliases.contains(&peer_old.public_key()));
        super::verify_stored_proof(
            &local_c,
            &current_peer_id,
            &proof,
            &local_aliases,
            &peer_aliases,
        )
        .unwrap();

        let source_path = super::linked_key_path(&local_c, &current_peer_id).unwrap();
        let source_bytes = std::fs::read(&source_path).unwrap();
        let (failed_replacement, _) = Identity::create().unwrap();
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
        assert!(local_c.copy_local_data_to(&failed_replacement).is_err());
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert_eq!(std::fs::read(&source_path).unwrap(), source_bytes);
        assert!(!super::data_directory()
            .unwrap()
            .join(failed_replacement.public_id())
            .exists());

        let (corrupt_replacement, _) = Identity::create().unwrap();
        let mut tampered = source_bytes;
        *tampered.last_mut().unwrap() ^= 1;
        std::fs::write(&source_path, tampered.clone()).unwrap();
        assert!(local_c.copy_local_data_to(&corrupt_replacement).is_err());
        assert_eq!(std::fs::read(&source_path).unwrap(), tampered);
        assert!(!super::data_directory()
            .unwrap()
            .join(corrupt_replacement.public_id())
            .exists());
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

        let (history, count, _) = History::open_for_chat(&identity, &peer).unwrap();
        let mut reader = History::reader_for_identity_copy(&identity, &peer).unwrap();
        assert_eq!(count, 1);
        let restored = reader.next_record().unwrap().unwrap();
        assert_eq!(restored, entry);
        assert!(restored.proof.is_none());
        assert_eq!(reader.next_record().unwrap(), None);
        drop(history);
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
    fn bundle_partial_restore_error_reports_already_applied_conversations() {
        let data = IsolatedData::new();
        let (identity, code) = Identity::create().unwrap();
        let first = "63".repeat(32);
        let second = "64".repeat(32);
        for (peer, text) in [(&first, "first"), (&second, "second")] {
            let (mut history, _, _) = History::open(&identity, peer).unwrap();
            history.append(&message(1, text)).unwrap();
        }
        let bundle =
            History::export_backup_bundle(&identity, &[first.clone(), second.clone()]).unwrap();
        let destination = data.0.join("bundle-target");
        std::fs::create_dir_all(&destination).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(destination));
        let target_identity = Identity::from_code(&code).unwrap();
        let (missing_history, _, _) = History::open(&target_identity, &second).unwrap();
        let missing_path = missing_history.path.clone();
        drop(missing_history);
        std::fs::remove_file(missing_path).unwrap();

        let error = History::import_backup_bundle(&target_identity, &bundle)
            .unwrap_err()
            .to_string();
        assert!(error.contains("stopped after 1 conversations"));
        assert_eq!(
            History::read_for_identity_copy(&target_identity, &first)
                .unwrap()
                .0[0]
                .text,
            "first"
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
            .split("); destination rollback")
            .next()
            .unwrap();
        assert!(std::path::Path::new(recovery_path).is_file());
        assert!(
            error.contains("destination rollback: injected current conversation rollback failure")
        );
        assert!(error.contains("injected current conversation rollback failure"));
    }

    #[test]
    fn linked_identity_store_failure_rolls_back_merged_history() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let previous_peer = "76".repeat(32);
        let current_peer = "77".repeat(32);
        let (mut previous, _, _) = History::open(&identity, &previous_peer).unwrap();
        previous.append(&message(1, "prior record")).unwrap();
        let (mut current, _, _) = History::open(&identity, &current_peer).unwrap();
        current.append(&message(2, "current record")).unwrap();
        super::TEST_FAILURES.with(|flags| flags.set(super::FAIL_LINKED_STORE));
        let error = current.link_prior_identity(&identity, &previous_peer, message(3, "link"));
        super::TEST_FAILURES.with(|flags| flags.set(0));
        assert!(error
            .unwrap_err()
            .to_string()
            .contains("injected linked identity store failure"));
        let (current_messages, _) =
            History::read_for_identity_copy(&identity, &current_peer).unwrap();
        let (prior_messages, _) =
            History::read_for_identity_copy(&identity, &previous_peer).unwrap();
        assert_eq!(current_messages.len(), 1);
        assert_eq!(current_messages[0].text, "current record");
        assert_eq!(prior_messages.len(), 1);
        assert!(!super::is_linked_peer_identity(&identity, &current_peer, &previous_peer).unwrap());
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

        // New exports use ADBACK5 and remain idempotent on repeated imports.
        let backup = History::export_backup(&identity, &peer, None).unwrap();
        assert_eq!(&backup[..8], b"ADBACK5\0");
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
        assert_eq!(&password_backup[..8], b"ADBACK5\0");
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

    #[test]
    fn reprotected_backup_preserves_proofs_bound_to_previous_local_identity() {
        let _data = IsolatedData::new();
        let (previous, _) = Identity::create().unwrap();
        let (replacement, _) = Identity::create().unwrap();
        let (peer, _) = Identity::create().unwrap();
        let peer_id = peer.public_id();
        let outgoing =
            super::sign_message(&previous, &peer_id, 41, "signed before change".into()).unwrap();
        let mut incoming = super::sign_message(
            &peer,
            &previous.public_id(),
            42,
            "received before change".into(),
        )
        .unwrap();
        incoming.sender = super::MessageSender::Other;
        let source = super::encode_backup_with_links(
            &previous,
            &peer_id,
            &[outgoing, incoming],
            None,
            &super::BackupLinks::default(),
        )
        .unwrap();

        let result =
            History::reprotect_backup(&previous, &replacement, &source, None, None).unwrap();
        assert_eq!(
            History::verify_backup(&replacement, &result, None).unwrap(),
            (peer_id, 2)
        );
        let (_, _, links) = super::decode_backup_with_links(&replacement, &result, None).unwrap();
        assert!(links.local.contains(&previous.public_id()));
        assert!(links.origins.contains(&previous.public_id()));
    }

    #[test]
    fn linking_multiple_peer_identity_epochs_carries_authenticated_aliases() {
        let _data = IsolatedData::new();
        let (local, _) = Identity::create().unwrap();
        let (peer_a, _) = Identity::create().unwrap();
        let (peer_b, _) = Identity::create().unwrap();
        let (peer_c, _) = Identity::create().unwrap();
        let peer_a_id = peer_a.public_id();
        let peer_b_id = peer_b.public_id();
        let peer_c_id = peer_c.public_id();
        let mut signed_by_a = super::sign_message(
            &peer_a,
            &local.public_id(),
            70,
            "proof from first peer identity".into(),
        )
        .unwrap();
        signed_by_a.sender = super::MessageSender::Other;
        let (mut history_a, _, _) = History::open(&local, &peer_a_id).unwrap();
        history_a.append(&signed_by_a).unwrap();

        let (mut history_b, _, _) = History::open(&local, &peer_b_id).unwrap();
        history_b
            .link_prior_identity(
                &local,
                &peer_a_id,
                message(
                    71,
                    &format!(
                        "{}peer:{peer_a_id}:{peer_b_id}",
                        super::IDENTITY_EVENT_PREFIX
                    ),
                ),
            )
            .unwrap();
        let (mut history_c, _, _) = History::open(&local, &peer_c_id).unwrap();
        history_c
            .link_prior_identity(
                &local,
                &peer_b_id,
                message(
                    72,
                    &format!(
                        "{}peer:{peer_b_id}:{peer_c_id}",
                        super::IDENTITY_EVENT_PREFIX
                    ),
                ),
            )
            .unwrap();

        let (messages, _) = History::read_for_identity_copy(&local, &peer_c_id).unwrap();
        let (_, peer_aliases) =
            super::linked_identity_keys(&local, &messages, &local.public_id(), &peer_c_id, &[])
                .unwrap();
        assert!(peer_aliases.contains(&peer_a.public_key()));
        assert!(peer_aliases.contains(&peer_b.public_key()));
        super::verify_stored_proof(&local, &peer_c_id, &signed_by_a, &[], &peer_aliases).unwrap();
    }

    fn messages_with_payload_len(payload_len: usize) -> Vec<StoredMessage> {
        // ADBACK4/5 add one proof-presence byte to each legacy record.
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
    fn streaming_backup_import_bundle_and_reprotection_exceed_legacy_limit() {
        let data = IsolatedData::new();
        let (identity, identity_code) = Identity::create().unwrap();
        let peer = "c9".repeat(32);
        let empty_peer = "ca".repeat(32);
        let long_text = "m".repeat(MAX_MESSAGE_BYTES);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        for index in 0..4_200 {
            history.append(&message(index, &long_text)).unwrap();
        }
        History::open(&identity, &empty_peer).unwrap();

        let transfer_dir = History::backup_transfer_directory(&identity).unwrap();
        let single_path = transfer_dir.join("large-single-fixture.adbak");
        let mut single = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&single_path)
            .unwrap();
        super::set_private_file(&single).unwrap();
        assert_eq!(
            History::export_backup_stream(
                &identity,
                &peer,
                Some("old backup password"),
                &mut single
            )
            .unwrap(),
            4_200
        );
        single.flush().unwrap();
        single.sync_all().unwrap();
        assert!(single.metadata().unwrap().len() > MAX_LEGACY_BACKUP_BYTES as u64);
        drop(single);
        let original_len = std::fs::metadata(&single_path).unwrap().len();
        assert_eq!(
            History::verify_backup_file(&identity, &single_path, Some("old backup password"))
                .unwrap(),
            (peer.clone(), 4_200)
        );

        let replacement = Identity::create().unwrap().0;
        let reprotected_path = transfer_dir.join("large-reprotected-fixture.adbak");
        let mut reprotected = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&reprotected_path)
            .unwrap();
        super::set_private_file(&reprotected).unwrap();
        assert_eq!(
            History::reprotect_backup_file(
                &identity,
                &replacement,
                &single_path,
                &mut reprotected,
                Some("old backup password"),
                Some("new backup password"),
            )
            .unwrap(),
            4_200
        );
        reprotected.flush().unwrap();
        reprotected.sync_all().unwrap();
        drop(reprotected);
        assert_eq!(
            History::verify_backup_file(
                &replacement,
                &reprotected_path,
                Some("new backup password")
            )
            .unwrap(),
            (peer.clone(), 4_200)
        );
        assert_eq!(std::fs::metadata(&single_path).unwrap().len(), original_len);

        let bundle_path = transfer_dir.join("large-bundle-fixture.adbak");
        let mut bundle = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&bundle_path)
            .unwrap();
        super::set_private_file(&bundle).unwrap();
        History::export_backup_bundle_stream(
            &identity,
            &[peer.clone(), empty_peer.clone()],
            &mut bundle,
        )
        .unwrap();
        bundle.flush().unwrap();
        bundle.sync_all().unwrap();
        assert!(bundle.metadata().unwrap().len() > MAX_LEGACY_BACKUP_BYTES as u64);
        drop(bundle);

        let target = data.0.join("stream-backup-target");
        std::fs::create_dir_all(&target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
        let target_identity = Identity::from_code(&identity_code).unwrap();
        let (mut original_history, _, _) = History::open(&target_identity, &peer).unwrap();
        original_history
            .append(&message(9_000, "preserve on authentication failure"))
            .unwrap();
        let corrupted_path = transfer_dir.join("corrupted-large-fixture.adbak");
        std::fs::copy(&single_path, &corrupted_path).unwrap();
        let mut corrupted = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&corrupted_path)
            .unwrap();
        corrupted.seek(SeekFrom::Start(90)).unwrap();
        let mut byte = [0];
        corrupted.read_exact(&mut byte).unwrap();
        byte[0] ^= 1;
        corrupted.seek(SeekFrom::Start(90)).unwrap();
        corrupted.write_all(&byte).unwrap();
        corrupted.sync_all().unwrap();
        assert!(History::import_backup_file(
            &target_identity,
            &corrupted_path,
            Some("old backup password")
        )
        .is_err());
        let mut unchanged = History::reader_for_identity_copy(&target_identity, &peer).unwrap();
        assert_eq!(
            unchanged.next_record().unwrap(),
            Some(message(9_000, "preserve on authentication failure"))
        );
        assert_eq!(unchanged.next_record().unwrap(), None);
        let imported = History::import_backup_file(
            &target_identity,
            &single_path,
            Some("old backup password"),
        )
        .unwrap();
        assert_eq!(imported, vec![(peer.clone(), 4_200, false)]);
        let bundle_imported =
            History::import_backup_file(&target_identity, &bundle_path, None).unwrap();
        assert_eq!(bundle_imported.len(), 2);
        assert_eq!(bundle_imported[0].1, 4_200);
        assert_eq!(bundle_imported[1].1, 0);
        let mut reader = History::reader_for_identity_copy(&target_identity, &peer).unwrap();
        assert_eq!(reader.next_record().unwrap(), Some(message(0, &long_text)));
        assert_eq!(reader.next_record().unwrap(), Some(message(1, &long_text)));
        assert_eq!(reader.next_record().unwrap(), Some(message(2, &long_text)));
    }

    #[test]
    fn backup_stream_file_id_rejects_cross_file_frame_and_completion_swaps() {
        let _data = IsolatedData::new();
        let (identity, _) = Identity::create().unwrap();
        let peer = "d1".repeat(32);
        let (mut history, _, _) = History::open(&identity, &peer).unwrap();
        history.append(&message(1, "frame one")).unwrap();
        history.append(&message(2, "frame two")).unwrap();

        let mut backups = Vec::new();
        for _ in 0..2 {
            let mut backup = Vec::new();
            History::export_backup_stream(&identity, &peer, None, &mut backup).unwrap();
            backups.push(backup);
        }
        assert!(backups[0].starts_with(b"ADBACK7\0"));
        let peer_bytes = super::decode_peer_id(&peer).unwrap();
        assert!(!backups[0][..25]
            .windows(peer_bytes.len())
            .any(|window| window == peer_bytes));
        let mut password_backup = Vec::new();
        History::export_backup_stream(
            &identity,
            &peer,
            Some("correct horse battery"),
            &mut password_backup,
        )
        .unwrap();
        let password_path = History::backup_transfer_directory(&identity)
            .unwrap()
            .join("wrong-password.adbak");
        std::fs::write(&password_path, password_backup).unwrap();
        assert!(History::verify_backup_file(
            &identity,
            &password_path,
            Some("incorrect horse battery")
        )
        .is_err());

        let frames_a = super::tests::stream_frame_ranges(&backups[0]);
        let frames_b = super::tests::stream_frame_ranges(&backups[1]);
        for (kind, index) in [(1, 1), (0, 3)] {
            let range_a = frames_a
                .iter()
                .find(|frame| frame.0 == kind && frame.1 == index)
                .unwrap()
                .2
                .clone();
            let range_b = frames_b
                .iter()
                .find(|frame| frame.0 == kind && frame.1 == index)
                .unwrap()
                .2
                .clone();
            assert_eq!(range_a.len(), range_b.len());
            let mut mixed = backups[0].clone();
            mixed[range_a].copy_from_slice(&backups[1][range_b]);
            let path = History::backup_transfer_directory(&identity)
                .unwrap()
                .join(format!("swapped-{kind}-{index}.adbak"));
            std::fs::write(&path, mixed).unwrap();
            assert!(History::verify_backup_file(&identity, &path, None).is_err());
        }
    }

    fn stream_frame_ranges(backup: &[u8]) -> Vec<(u8, u64, std::ops::Range<usize>)> {
        assert!(backup.starts_with(super::BACKUP_STREAM_MAGIC));
        let mut offset = 8 + 1 + 16;
        if backup[8] == 1 {
            offset += super::BACKUP_SALT_BYTES;
        }
        let mut frames = Vec::new();
        loop {
            let start = offset;
            let kind = backup[offset];
            let index = u64::from_be_bytes(backup[offset + 1..offset + 9].try_into().unwrap());
            let length = u32::from_be_bytes(
                backup[offset + 9 + super::NONCE_BYTES..offset + 13 + super::NONCE_BYTES]
                    .try_into()
                    .unwrap(),
            ) as usize;
            offset += 1 + 8 + super::NONCE_BYTES + 4 + length;
            frames.push((kind, index, start..offset));
            if kind == 0 {
                break;
            }
        }
        frames
    }

    #[test]
    fn v6_backup_and_v2_bundle_remain_importable() {
        let data = IsolatedData::new();
        let (identity, code) = Identity::create().unwrap();
        let peer = "d2".repeat(32);
        let record = message(7, "legacy streaming backup");
        let backup = encode_v6_fixture(&identity, &peer, std::slice::from_ref(&record));
        let mut bundle = super::BACKUP_STREAM_BUNDLE_V2_MAGIC.to_vec();
        bundle.extend_from_slice(&1_u32.to_be_bytes());
        bundle.extend_from_slice(&(backup.len() as u64).to_be_bytes());
        bundle.extend_from_slice(&backup);

        let target = data.0.join("legacy-stream-target");
        std::fs::create_dir_all(&target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
        let target_identity = Identity::from_code(&code).unwrap();
        let backup_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("legacy-v6.adbak");
        std::fs::write(&backup_path, backup).unwrap();
        assert!(
            History::verify_backup_file(&Identity::create().unwrap().0, &backup_path, None)
                .is_err()
        );
        assert_eq!(
            History::import_backup_file(&target_identity, &backup_path, None).unwrap(),
            vec![(peer.clone(), 1, false)]
        );

        let replacement = Identity::create().unwrap().0;
        let reprotected_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("reprotected-v6.adbak");
        let mut reprotected = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&reprotected_path)
            .unwrap();
        History::reprotect_backup_file(
            &target_identity,
            &replacement,
            &backup_path,
            &mut reprotected,
            None,
            None,
        )
        .unwrap();
        reprotected.flush().unwrap();
        drop(reprotected);
        assert!(std::fs::read(&reprotected_path)
            .unwrap()
            .starts_with(super::BACKUP_STREAM_MAGIC));
        assert_eq!(
            History::verify_backup_file(&replacement, &reprotected_path, None).unwrap(),
            (peer.clone(), 1)
        );

        let bundle_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("legacy-v2.adbak");
        std::fs::write(&bundle_path, bundle).unwrap();
        let bundle_target = data.0.join("legacy-v2-target");
        std::fs::create_dir_all(&bundle_target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(bundle_target));
        let bundle_identity = Identity::from_code(&code).unwrap();
        assert_eq!(
            History::import_backup_file(&bundle_identity, &bundle_path, None).unwrap(),
            vec![(peer.clone(), 1, false)]
        );
        let mut reader = History::reader_for_identity_copy(&bundle_identity, &peer).unwrap();
        assert_eq!(reader.next_record().unwrap(), Some(record));
        assert_eq!(reader.next_record().unwrap(), None);
    }

    #[test]
    fn bundle3_authenticates_membership_and_reports_partial_application() {
        let data = IsolatedData::new();
        let (identity, code) = Identity::create().unwrap();
        let peers = ["d3".repeat(32), "d4".repeat(32), "d5".repeat(32)];
        for (index, peer) in peers.iter().enumerate() {
            History::open(&identity, peer)
                .unwrap()
                .0
                .append(&message(index as u64 + 1, "bundle member"))
                .unwrap();
        }
        let directory = History::backup_transfer_directory(&identity).unwrap();
        let bundle_path = directory.join("members.adbak");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&bundle_path)
            .unwrap();
        History::export_backup_bundle_stream(&identity, &peers[..2], &mut output).unwrap();
        output.flush().unwrap();
        drop(output);
        let bundle = std::fs::read(&bundle_path).unwrap();
        let children = bundle3_children(&bundle);

        let replacement_path = directory.join("replacement-member.adbak");
        let mut replacement_output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&replacement_path)
            .unwrap();
        History::export_backup_bundle_stream(&identity, &peers[2..], &mut replacement_output)
            .unwrap();
        replacement_output.flush().unwrap();
        drop(replacement_output);
        let replacement = std::fs::read(&replacement_path).unwrap();
        let replacement_child = bundle3_children(&replacement)[0];

        let mut removed = bundle[..24].to_vec();
        removed.extend_from_slice(&1_u32.to_be_bytes());
        append_bundle3_child(&mut removed, &bundle, children[0]);
        removed.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);

        let mut replaced = bundle[..24].to_vec();
        replaced.extend_from_slice(&2_u32.to_be_bytes());
        append_bundle3_child(&mut replaced, &bundle, children[0]);
        append_bundle3_child(&mut replaced, &replacement, replacement_child);
        replaced.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);

        let mut reordered = bundle[..24].to_vec();
        reordered.extend_from_slice(&2_u32.to_be_bytes());
        append_bundle3_child(&mut reordered, &bundle, children[1]);
        append_bundle3_child(&mut reordered, &bundle, children[0]);
        reordered.extend_from_slice(&bundle[bundle.len() - super::BACKUP_BUNDLE_TAG_BYTES..]);

        let target_a = data.0.join("bundle-removed-target");
        std::fs::create_dir_all(&target_a).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target_a));
        let target_identity = Identity::from_code(&code).unwrap();
        let removed_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("removed.adbak");
        std::fs::write(&removed_path, removed).unwrap();
        let error = History::import_backup_file(&target_identity, &removed_path, None).unwrap_err();
        assert!(
            error.to_string().contains("applying 1 conversation"),
            "{error}"
        );

        let target_b = data.0.join("bundle-replaced-target");
        std::fs::create_dir_all(&target_b).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target_b));
        let target_identity = Identity::from_code(&code).unwrap();
        let replaced_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("replaced.adbak");
        std::fs::write(&replaced_path, replaced).unwrap();
        let error =
            History::import_backup_file(&target_identity, &replaced_path, None).unwrap_err();
        assert!(
            error.to_string().contains("applying 2 conversation"),
            "{error}"
        );

        let target_c = data.0.join("bundle-reordered-target");
        std::fs::create_dir_all(&target_c).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target_c));
        let target_identity = Identity::from_code(&code).unwrap();
        let reordered_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("reordered.adbak");
        std::fs::write(&reordered_path, reordered).unwrap();
        let error =
            History::import_backup_file(&target_identity, &reordered_path, None).unwrap_err();
        assert!(
            error.to_string().contains("applying 2 conversation"),
            "{error}"
        );
    }

    #[test]
    fn bundle3_late_child_authentication_error_reports_applied_count() {
        let data = IsolatedData::new();
        let (identity, code) = Identity::create().unwrap();
        let peers = ["d6".repeat(32), "d7".repeat(32)];
        for peer in &peers {
            History::open(&identity, peer)
                .unwrap()
                .0
                .append(&message(1, "verified child"))
                .unwrap();
        }
        let directory = History::backup_transfer_directory(&identity).unwrap();
        let path = directory.join("late-error-source.adbak");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        History::export_backup_bundle_stream(&identity, &peers, &mut output).unwrap();
        output.flush().unwrap();
        drop(output);
        let mut bundle = std::fs::read(&path).unwrap();
        let children = bundle3_children(&bundle);
        let second_child = children[1];
        bundle[second_child.1 - 1] ^= 1;

        let target = data.0.join("late-error-target");
        std::fs::create_dir_all(&target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
        let target_identity = Identity::from_code(&code).unwrap();
        let damaged_path = History::backup_transfer_directory(&target_identity)
            .unwrap()
            .join("late-error.adbak");
        std::fs::write(&damaged_path, bundle).unwrap();
        let error = History::import_backup_file(&target_identity, &damaged_path, None).unwrap_err();
        assert!(
            error.to_string().contains("applying 1 conversation"),
            "{error}"
        );
        let mut reader = History::reader_for_identity_copy(&target_identity, &peers[0]).unwrap();
        assert_eq!(
            reader.next_record().unwrap(),
            Some(message(1, "verified child"))
        );
    }

    #[test]
    fn streaming_bundle_import_accepts_an_empty_conversation() {
        let data = IsolatedData::new();
        let (identity, code) = Identity::create().unwrap();
        let peer = "cb".repeat(32);
        History::open(&identity, &peer).unwrap();
        let directory = History::backup_transfer_directory(&identity).unwrap();
        let path = directory.join("empty-bundle-test.adbak");
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        History::export_backup_bundle_stream(&identity, std::slice::from_ref(&peer), &mut output)
            .unwrap();
        output.flush().unwrap();
        output.sync_all().unwrap();
        drop(output);
        let target = data.0.join("empty-bundle-target");
        std::fs::create_dir_all(&target).unwrap();
        super::TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = Some(target));
        let target_identity = Identity::from_code(&code).unwrap();
        assert_eq!(
            History::import_backup_file(&target_identity, &path, None).unwrap(),
            vec![(peer, 0, false)]
        );
    }

    #[test]
    fn exports_enforce_the_final_file_size_limit_for_both_formats() {
        let _data = IsolatedData::new();
        let identity = Identity::create().unwrap().0;
        let peer = "cd".repeat(32);
        for password in [None, Some("correct horse battery")] {
            let envelope_len = 8 + password.map_or(0, |_| 16) + 12 + 16;
            let exact_payload_len = MAX_LEGACY_BACKUP_BYTES - envelope_len - 11;
            let mut history = History::open(&identity, &peer).unwrap().0;
            history
                .replace(&messages_with_payload_len(exact_payload_len))
                .unwrap();
            let backup = History::export_backup(&identity, &peer, password).unwrap();
            assert_eq!(backup.len(), MAX_LEGACY_BACKUP_BYTES);

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
