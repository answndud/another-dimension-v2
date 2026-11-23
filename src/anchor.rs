//! Remembers, outside each conversation log, which version of the log is the current
//! one and how many records it held.
//!
//! The log itself cannot tell that its tail was cut off at a record boundary, or that
//! an older copy of the file was put back: every record that is still there
//! authenticates. This file keeps the generation id and the record count of every
//! conversation, so opening a log can notice when it is older or shorter than the last
//! state this program wrote.
//!
//! It raises the cost of tampering with one file. It does not stop an attacker who can
//! replace every file in the data directory together, or delete this file along with
//! truncating a log: on a single device with no trusted counter that cannot be
//! prevented. See SECURITY.md.
//!
//! The anchor is written after the log is durable, so after a crash it can only be
//! behind the log, never ahead. A replacement (which starts a new generation) first
//! records the generation it is about to install as `pending`, so a crash between the
//! rename and the final update is not mistaken for tampering.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADANC1\0\0";
const FILE_NAME: &str = "conversations.anchor";
const LABEL: &[u8] = b"another-dimension-v2/history-anchor-aead/v1";
const NONCE_BYTES: usize = 12;
const GENERATION_BYTES: usize = 16;
const ENTRY_BYTES: usize = 32 + GENERATION_BYTES + 8 + GENERATION_BYTES;
const MAX_ENTRIES: usize = 100_000;
const NO_GENERATION: [u8; GENERATION_BYTES] = [0; GENERATION_BYTES];

static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// What was last recorded about one conversation log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Anchor {
    pub(crate) generation: [u8; GENERATION_BYTES],
    pub(crate) records: u64,
    /// The generation a replacement was about to install when it was last recorded.
    pub(crate) pending: Option<[u8; GENERATION_BYTES]>,
}

/// What opening a log found, compared with its anchor.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing was recorded yet (a new log, or one from before anchors existed).
    Unanchored,
    /// The log is at least as long as the recorded state of the same generation.
    Consistent,
    /// The log is the recorded generation but holds fewer records than were written.
    Truncated { recorded: u64, found: u64 },
    /// The log is a generation that was never installed: an older copy was put back, or
    /// the file was replaced by another one.
    UnknownGeneration,
}

pub(crate) fn verify(
    anchor: Option<&Anchor>,
    generation: [u8; GENERATION_BYTES],
    records: u64,
) -> Verdict {
    let Some(anchor) = anchor else {
        return Verdict::Unanchored;
    };
    if anchor.generation == generation {
        if records < anchor.records {
            Verdict::Truncated {
                recorded: anchor.records,
                found: records,
            }
        } else {
            Verdict::Consistent
        }
    } else if anchor.pending == Some(generation) {
        // A replacement finished its rename and stopped before the final update.
        Verdict::Consistent
    } else {
        Verdict::UnknownGeneration
    }
}

fn peer_bytes(peer_id: &str) -> io::Result<[u8; 32]> {
    crate::hex::decode_array::<32>(peer_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer id"))
}

type Entries = Vec<([u8; 32], Anchor)>;

fn read_all(storage_key: &[u8; 32], identity_id: &str, directory: &Path) -> io::Result<Entries> {
    let bytes = match crate::fsutil::read_regular_file(
        directory.join(FILE_NAME),
        crate::fsutil::MAX_STATE_FILE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let invalid = |reason| io::Error::new(io::ErrorKind::InvalidData, reason);
    if bytes.len() < MAGIC.len() + NONCE_BYTES + 16 || &bytes[..MAGIC.len()] != MAGIC {
        return Err(invalid("invalid history anchor"));
    }
    let key = crate::identity::purpose_key(storage_key, LABEL);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| invalid("invalid history anchor key"))?;
    let nonce = &bytes[MAGIC.len()..MAGIC.len() + NONCE_BYTES];
    let payload = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &bytes[MAGIC.len() + NONCE_BYTES..],
                    aad: identity_id.as_bytes(),
                },
            )
            .map_err(|_| invalid("history anchor authentication failed"))?,
    );
    if payload.len() < 4 {
        return Err(invalid("invalid history anchor payload"));
    }
    let count = u32::from_be_bytes(payload[..4].try_into().expect("fixed slice")) as usize;
    if count > MAX_ENTRIES || payload.len() != 4 + count * ENTRY_BYTES {
        return Err(invalid("invalid history anchor count"));
    }
    Ok(payload[4..]
        .chunks_exact(ENTRY_BYTES)
        .map(|entry| {
            let peer: [u8; 32] = entry[..32].try_into().expect("fixed slice");
            let generation: [u8; GENERATION_BYTES] = entry[32..48].try_into().expect("fixed slice");
            let records = u64::from_be_bytes(entry[48..56].try_into().expect("fixed slice"));
            let pending: [u8; GENERATION_BYTES] = entry[56..72].try_into().expect("fixed slice");
            (
                peer,
                Anchor {
                    generation,
                    records,
                    pending: (pending != NO_GENERATION).then_some(pending),
                },
            )
        })
        .collect())
}

fn write_all(
    storage_key: &[u8; 32],
    identity_id: &str,
    directory: &Path,
    entries: &Entries,
) -> io::Result<()> {
    let count = u32::try_from(entries.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many anchors"))?;
    let mut payload = Zeroizing::new(Vec::with_capacity(4 + entries.len() * ENTRY_BYTES));
    payload.extend_from_slice(&count.to_be_bytes());
    for (peer, anchor) in entries {
        payload.extend_from_slice(peer);
        payload.extend_from_slice(&anchor.generation);
        payload.extend_from_slice(&anchor.records.to_be_bytes());
        payload.extend_from_slice(&anchor.pending.unwrap_or(NO_GENERATION));
    }
    let mut nonce = [0; NONCE_BYTES];
    crate::random::fill(&mut nonce)?;
    let key = crate::identity::purpose_key(storage_key, LABEL);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| io::Error::other("history anchor key unavailable"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: identity_id.as_bytes(),
            },
        )
        .map_err(|_| io::Error::other("history anchor encryption failed"))?;
    let mut suffix = [0; 8];
    crate::random::fill(&mut suffix)?;
    let suffix: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = directory.join(format!(".anchor-{suffix}.tmp"));
    let mut file = crate::fsutil::private_options()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    let written = (|| {
        file.write_all(MAGIC)?;
        file.write_all(&nonce)?;
        file.write_all(&encrypted)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    crate::fsutil::rename_durable(&temporary, directory.join(FILE_NAME)).inspect_err(|_| {
        let _ = std::fs::remove_file(&temporary);
    })
}

/// The recorded state of one conversation, if any.
pub(crate) fn load(
    storage_key: &[u8; 32],
    identity_id: &str,
    directory: &Path,
    peer_id: &str,
) -> io::Result<Option<Anchor>> {
    let peer = peer_bytes(peer_id)?;
    let _guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("history anchor unavailable"))?;
    Ok(read_all(storage_key, identity_id, directory)?
        .into_iter()
        .find(|(existing, _)| *existing == peer)
        .map(|(_, anchor)| anchor))
}

/// Records the state of one conversation, or forgets it for `None`.
pub(crate) fn store(
    storage_key: &[u8; 32],
    identity_id: &str,
    directory: &Path,
    peer_id: &str,
    anchor: Option<Anchor>,
) -> io::Result<()> {
    let peer = peer_bytes(peer_id)?;
    let _guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("history anchor unavailable"))?;
    let mut entries = match read_all(storage_key, identity_id, directory) {
        Ok(entries) => entries,
        // A file that cannot be read is replaced rather than blocking every write: the
        // anchor is a detector, and it must not be able to stop the program from saving.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => Vec::new(),
        Err(error) => return Err(error),
    };
    entries.retain(|(existing, _)| *existing != peer);
    if let Some(anchor) = anchor {
        entries.push((peer, anchor));
    }
    if entries.is_empty() {
        match std::fs::remove_file(directory.join(FILE_NAME)) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    write_all(storage_key, identity_id, directory, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GEN_A: [u8; 16] = [1; 16];
    const GEN_B: [u8; 16] = [2; 16];
    const GEN_C: [u8; 16] = [3; 16];

    fn anchor(generation: [u8; 16], records: u64) -> Anchor {
        Anchor {
            generation,
            records,
            pending: None,
        }
    }

    #[test]
    fn nothing_recorded_is_not_a_problem() {
        assert_eq!(verify(None, GEN_A, 5), Verdict::Unanchored);
    }

    #[test]
    fn a_log_at_least_as_long_as_the_record_is_consistent() {
        let recorded = anchor(GEN_A, 5);
        assert_eq!(verify(Some(&recorded), GEN_A, 5), Verdict::Consistent);
        // An append whose anchor update was lost in a crash leaves the log ahead.
        assert_eq!(verify(Some(&recorded), GEN_A, 7), Verdict::Consistent);
    }

    #[test]
    fn a_shorter_log_of_the_same_generation_is_truncated() {
        assert_eq!(
            verify(Some(&anchor(GEN_A, 5)), GEN_A, 4),
            Verdict::Truncated {
                recorded: 5,
                found: 4
            }
        );
        assert_eq!(
            verify(Some(&anchor(GEN_A, 5)), GEN_A, 0),
            Verdict::Truncated {
                recorded: 5,
                found: 0
            }
        );
    }

    #[test]
    fn an_unrecorded_generation_is_rejected_unless_it_is_the_pending_one() {
        let mut recorded = anchor(GEN_A, 5);
        assert_eq!(
            verify(Some(&recorded), GEN_B, 9),
            Verdict::UnknownGeneration
        );
        recorded.pending = Some(GEN_B);
        // A replacement that stopped before its final update is accepted, with any count
        // (a delete may have made the log shorter).
        assert_eq!(verify(Some(&recorded), GEN_B, 1), Verdict::Consistent);
        assert_eq!(
            verify(Some(&recorded), GEN_C, 9),
            Verdict::UnknownGeneration
        );
        // The old generation is still accepted while the replacement is pending: the
        // crash may have come before the rename.
        assert_eq!(verify(Some(&recorded), GEN_A, 5), Verdict::Consistent);
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ad2-anchor-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn anchors_round_trip_per_conversation_and_can_be_forgotten() {
        let directory = scratch("roundtrip");
        let key = [9; 32];
        let (first, second) = ("aa".repeat(32), "bb".repeat(32));
        assert_eq!(load(&key, "me", &directory, &first).unwrap(), None);
        store(&key, "me", &directory, &first, Some(anchor(GEN_A, 3))).unwrap();
        let mut pending = anchor(GEN_B, 8);
        pending.pending = Some(GEN_C);
        store(&key, "me", &directory, &second, Some(pending)).unwrap();
        assert_eq!(
            load(&key, "me", &directory, &first).unwrap(),
            Some(anchor(GEN_A, 3))
        );
        assert_eq!(
            load(&key, "me", &directory, &second).unwrap(),
            Some(pending)
        );
        store(&key, "me", &directory, &first, Some(anchor(GEN_A, 4))).unwrap();
        assert_eq!(
            load(&key, "me", &directory, &first).unwrap(),
            Some(anchor(GEN_A, 4))
        );
        store(&key, "me", &directory, &first, None).unwrap();
        assert_eq!(load(&key, "me", &directory, &first).unwrap(), None);
        store(&key, "me", &directory, &second, None).unwrap();
        assert!(
            !directory.join(FILE_NAME).exists(),
            "the last entry removes the file"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_tampered_or_foreign_anchor_file_is_not_trusted() {
        let directory = scratch("tamper");
        let key = [9; 32];
        let peer = "cc".repeat(32);
        store(&key, "me", &directory, &peer, Some(anchor(GEN_A, 3))).unwrap();
        // Another identity's or another key's reader cannot use it.
        assert!(load(&key, "someone else", &directory, &peer).is_err());
        assert!(load(&[8; 32], "me", &directory, &peer).is_err());
        let path = directory.join(FILE_NAME);
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(load(&key, "me", &directory, &peer).is_err());
        // Saving still works over an unreadable file, so tampering cannot stop writes.
        store(&key, "me", &directory, &peer, Some(anchor(GEN_B, 1))).unwrap();
        assert_eq!(
            load(&key, "me", &directory, &peer).unwrap(),
            Some(anchor(GEN_B, 1))
        );
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_invalid_peer_id_is_rejected() {
        let directory = scratch("peer");
        assert!(load(&[9; 32], "me", &directory, "short").is_err());
        assert!(store(&[9; 32], "me", &directory, &"zz".repeat(32), None).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
