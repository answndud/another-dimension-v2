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

use std::fs::{read_dir, remove_dir, remove_file, File};

use std::io::{self, Read, Seek, SeekFrom, Write};

use std::path::PathBuf;

use std::sync::{Arc, Mutex, OnceLock, Weak};

use zeroize::Zeroizing;

// The conversation log. ADLOG3 stores a random generation id right after the magic and
// binds it into every record's associated data, so a record from an earlier version of
// the file (before a replace or delete) does not authenticate in the current one.
// ADLOG1 and ADLOG2 are still read, and are rewritten as ADLOG3 when a conversation
// is opened for chat.
const MAGIC: &[u8; 8] = b"ADLOG3\0\0";

const PREVIOUS_MAGIC: &[u8; 8] = b"ADLOG2\0\0";

const LEGACY_MAGIC: &[u8; 8] = b"ADLOG1\0\0";

const GENERATION_BYTES: usize = 16;

const HEADER_LEN: u64 = (MAGIC.len() + GENERATION_BYTES) as u64;

const MAX_MESSAGE_BYTES: usize = 4096;

const NONCE_BYTES: usize = 12;

// Index files written before 2026-11 encrypted with the same key that names the
// conversation files (ADIDX1). ADIDX2 uses a key of its own; ADIDX1 is still read.
const INDEX_MAGIC: &[u8; 8] = b"ADIDX1\0\0";

const INDEX_MAGIC_V2: &[u8; 8] = b"ADIDX2\0\0";

const LOG_AEAD_LABEL: &[u8] = b"another-dimension-v2/history-log-aead/v3";

const INDEX_AEAD_LABEL: &[u8] = b"another-dimension-v2/history-index-aead/v2";

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

// ADLKEY1 stores were encrypted with the storage key itself, shared with the log
// records. ADLKEY2 uses a key of its own; ADLKEY1 is still read.
const LINKED_KEYS_MAGIC: &[u8; 8] = b"ADLKEY1\0";

const LINKED_KEYS_MAGIC_V2: &[u8; 8] = b"ADLKEY2\0";

const LINKED_KEYS_AEAD_LABEL: &[u8] = b"another-dimension-v2/linked-keys-aead/v2";

const RESTORE_STAGING_MAGIC: &[u8; 8] = b"ADRSTG1\0";

const TRANSFER_MAGIC: &[u8; 6] = b"ADREC1";

const TRANSFER_CHUNK_MAGIC: &[u8; 5] = b"ADCH1";

const MESSAGE_MAGIC: &[u8; 6] = b"ADMSG1";

const MAX_LEGACY_BACKUP_BYTES: usize = 16 * 1024 * 1024;

const BACKUP_SALT_BYTES: usize = 16;

pub(crate) const IDENTITY_EVENT_PREFIX: &str = "[AD2-IDENTITY-EVENT/1] ";

static INDEX_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

static CONVERSATION_LOCKS: OnceLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();

static BACKUP_TRANSFER_WORKSPACES: OnceLock<Mutex<HashMap<PathBuf, Arc<BackupTransferWorkspace>>>> =
    OnceLock::new();

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
    format: LogFormat,
    integrity_warning: Option<IntegrityWarning>,
    /// Set when a write path found the log inconsistent with the anchor. The anchor is
    /// then left as it was, so the finding is not erased by the next write and the next
    /// open of the conversation reports it.
    anchor_suspect: bool,
    operation_lock: Arc<Mutex<()>>,
}

/// What opening a conversation found when it compared the log with the state this
/// program last recorded for it. The conversation still opens, and the state is
/// recorded again, so each finding is reported once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntegrityWarning {
    /// The log holds fewer records than were written: its end may have been cut off.
    Truncated { recorded: u64, found: u64 },
    /// The log is not a version this program wrote: an older copy may have been put back.
    UnknownGeneration,
    /// The record of the log's state could not be read.
    AnchorUnreadable,
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

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

mod backup;
mod conversations;
mod index;
mod linked_keys;
mod log;
mod paths;
mod staging;
#[cfg(test)]
pub(crate) mod tests;
mod transfer_workspace;
mod wire;

pub(crate) use backup::*;
pub(crate) use index::*;
pub(crate) use linked_keys::*;
pub(crate) use log::*;
pub(crate) use paths::*;
pub(crate) use staging::*;
pub(crate) use transfer_workspace::*;
pub(crate) use wire::*;
