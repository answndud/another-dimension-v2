//! Encrypted, per-identity verified connection records.
//!
//! This module is storage groundwork; callers must only save records after
//! both participants have confirmed each other over the authenticated channel.
use crate::identity::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Where one identity's verified-contact records live.
pub(crate) fn directory_for(identity: &Identity) -> io::Result<PathBuf> {
    Ok(crate::history::data_directory()?
        .join(identity.public_id())
        .join("verified-contacts"))
}

// Records and backups used to be encrypted with the same key that names the files
// (ADPEER1, ADCONB1). The ADPEER2 and ADCONB2 formats give each use its own key. The
// older formats are still read, and everything written is the new format.
const LEGACY_MAGIC: &[u8; 8] = b"ADPEER1\0";
const MAGIC: &[u8; 8] = b"ADPEER2\0";
const LEGACY_BACKUP_MAGIC: &[u8; 8] = b"ADCONB1\0";
const BACKUP_MAGIC: &[u8; 8] = b"ADCONB2\0";
const RECORD_AEAD_LABEL: &[u8] = b"another-dimension-v2/verified-contact-record-aead/v2";
const BACKUP_AEAD_LABEL: &[u8] = b"another-dimension-v2/contact-backup-aead/v2";
static CONTACT_WRITE_LOCK: Mutex<()> = Mutex::new(());

/// The rendezvous secret is separate from the initial invite and identifies
/// a single verified relationship. Never display or log it.
pub struct VerifiedContact {
    pub peer_key: [u8; 32],
    pub rendezvous_secret: Zeroizing<[u8; 32]>,
}

/// Enumerate authenticated contacts through the encrypted conversation index.
/// Histories imported from old backups can have no corresponding contact.
pub fn list_known(directory: &Path, identity: &Identity) -> io::Result<Vec<VerifiedContact>> {
    let mut contacts = Vec::new();
    for id in crate::history::History::known_peer_ids(identity)? {
        let peer = crate::history::decode_peer_id(&id)?;
        match load(directory, identity, peer) {
            Ok(contact) => contacts.push(contact),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(contacts)
}

fn key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    let storage_key = identity.storage_key();
    let mut result = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, storage_key.as_ref())
        .expand(b"another-dimension-v2/verified-contact/v1", result.as_mut())
        .expect("valid HKDF output length");
    result
}

/// Key for contact records. Distinct from the filename key and the backup key.
fn record_key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    crate::identity::purpose_key(&identity.storage_key(), RECORD_AEAD_LABEL)
}

/// Key for portable contact backups.
fn backup_key(identity: &Identity) -> Zeroizing<[u8; 32]> {
    crate::identity::purpose_key(&identity.storage_key(), BACKUP_AEAD_LABEL)
}

fn filename(identity: &Identity, peer: &[u8; 32]) -> String {
    let key = key(identity);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).expect("valid HMAC key");
    mac.update(b"another-dimension-v2/contact-filename/v1");
    mac.update(peer);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn save(directory: &Path, identity: &Identity, contact: &VerifiedContact) -> io::Result<()> {
    save_inner(directory, identity, contact, false)
}

/// Replace the previous relationship only after a fresh mutual user check.
pub fn save_after_confirmation(
    directory: &Path,
    identity: &Identity,
    contact: &VerifiedContact,
) -> io::Result<()> {
    save_inner(directory, identity, contact, true)
}

fn save_inner(
    directory: &Path,
    identity: &Identity,
    contact: &VerifiedContact,
    replace_confirmed: bool,
) -> io::Result<()> {
    let _guard = CONTACT_WRITE_LOCK
        .lock()
        .map_err(|_| io::Error::other("contact storage unavailable"))?;
    crate::fsutil::create_private_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let name = filename(identity, &contact.peer_key);
    let path = directory.join(format!("{name}.peer"));
    // Existing records must never be silently replaced by another secret.
    if path.exists() {
        match load(directory, identity, contact.peer_key) {
            Ok(old) => {
                if old.rendezvous_secret.as_ref() == contact.rendezvous_secret.as_ref() {
                    return Ok(());
                }
                if !replace_confirmed {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "contact conflict",
                    ));
                }
            }
            // A record that cannot be authenticated holds no secret worth protecting
            // from replacement. Without this a damaged file blocked every later
            // confirmation of the same peer until someone deleted it by hand. Only a
            // fresh mutual confirmation may replace it, and the old bytes stay aside.
            Err(error) if replace_confirmed && error.kind() == io::ErrorKind::InvalidData => {
                let mut tag = [0; 6];
                crate::random::fill(&mut tag)?;
                let aside = directory.join(format!(
                    "{name}.peer.damaged-{}",
                    tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ));
                fs::hard_link(&path, &aside)?;
            }
            Err(error) => return Err(error),
        }
    }
    let mut nonce = [0; 12];
    crate::random::fill(&mut nonce)?;
    let cipher = ChaCha20Poly1305::new_from_slice(record_key(identity).as_ref())
        .map_err(io::Error::other)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: contact.rendezvous_secret.as_ref(),
                aad: &contact.peer_key,
            },
        )
        .map_err(|_| io::Error::other("contact encryption failed"))?;
    let temporary = directory.join(format!(
        ".{name}-{}.tmp",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let result = (|| {
        let mut file = crate::fsutil::private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(MAGIC)?;
        file.write_all(&nonce)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        if replace_confirmed {
            crate::fsutil::rename_durable(&temporary, &path)?;
        } else {
            // A hard link avoids overwriting a concurrent writer.
            fs::hard_link(&temporary, &path)?;
            crate::fsutil::sync_parent(&path);
        }
        Ok(())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

pub fn load(
    directory: &Path,
    identity: &Identity,
    peer_key: [u8; 32],
) -> io::Result<VerifiedContact> {
    let name = filename(identity, &peer_key);
    let bytes = fs::read(directory.join(format!("{name}.peer")))?;
    if bytes.len() != 8 + 12 + 32 + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact record",
        ));
    }
    let record_key = if &bytes[..8] == MAGIC {
        record_key(identity)
    } else if &bytes[..8] == LEGACY_MAGIC {
        key(identity)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact record",
        ));
    };
    let cipher = ChaCha20Poly1305::new_from_slice(record_key.as_ref()).map_err(io::Error::other)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&bytes[8..20]),
                Payload {
                    msg: &bytes[20..],
                    aad: &peer_key,
                },
            )
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "contact authentication failed")
            })?,
    );
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&plain);
    Ok(VerifiedContact {
        peer_key,
        rendezvous_secret: secret,
    })
}

/// Exports a verified relationship, including its peer key, encrypted to the
/// same personal identity. This does not include the personal access code.
pub fn export_backup(identity: &Identity, contact: &VerifiedContact) -> io::Result<Vec<u8>> {
    let mut nonce = [0; 12];
    crate::random::fill(&mut nonce)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(64));
    plain.extend_from_slice(&contact.peer_key);
    plain.extend_from_slice(contact.rendezvous_secret.as_ref());
    let cipher = ChaCha20Poly1305::new_from_slice(backup_key(identity).as_ref())
        .map_err(io::Error::other)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: BACKUP_MAGIC,
            },
        )
        .map_err(|_| io::Error::other("contact backup encryption failed"))?;
    let mut backup = Vec::with_capacity(8 + 12 + encrypted.len());
    backup.extend_from_slice(BACKUP_MAGIC);
    backup.extend_from_slice(&nonce);
    backup.extend_from_slice(&encrypted);
    Ok(backup)
}

/// Authenticates before writing; a conflicting local record is preserved.
pub fn import_backup(directory: &Path, identity: &Identity, backup: &[u8]) -> io::Result<[u8; 32]> {
    if backup.len() != 8 + 12 + 64 + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact backup",
        ));
    }
    // The authenticated data is the magic the backup was written with.
    let (backup_key, aad) = if &backup[..8] == BACKUP_MAGIC {
        (backup_key(identity), BACKUP_MAGIC)
    } else if &backup[..8] == LEGACY_BACKUP_MAGIC {
        (key(identity), LEGACY_BACKUP_MAGIC)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact backup",
        ));
    };
    let cipher = ChaCha20Poly1305::new_from_slice(backup_key.as_ref()).map_err(io::Error::other)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&backup[8..20]),
                Payload {
                    msg: &backup[20..],
                    aad,
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "contact backup authentication failed",
                )
            })?,
    );
    let mut peer_key = [0; 32];
    peer_key.copy_from_slice(&plain[..32]);
    let mut rendezvous_secret = Zeroizing::new([0; 32]);
    rendezvous_secret.copy_from_slice(&plain[32..]);
    save(
        directory,
        identity,
        &VerifiedContact {
            peer_key,
            rendezvous_secret,
        },
    )?;
    Ok(peer_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_conflicting_imports_preserve_one_complete_record() {
        use std::sync::{Arc, Barrier};
        let path = std::env::temp_dir().join(format!(
            "ad-contact-race-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&path).unwrap();
        let (identity, _) = Identity::create().unwrap();
        let identity = Arc::new(identity);
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = [1_u8, 2]
            .into_iter()
            .map(|value| {
                let identity = Arc::clone(&identity);
                let barrier = Arc::clone(&barrier);
                let path = path.clone();
                std::thread::spawn(move || {
                    let contact = VerifiedContact {
                        peer_key: [7; 32],
                        rendezvous_secret: Zeroizing::new([value; 32]),
                    };
                    let backup = export_backup(&identity, &contact).unwrap();
                    barrier.wait();
                    (value, import_backup(&path, &identity, &backup))
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| result
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::AlreadyExists))
                .count(),
            1
        );
        let winner = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
        assert_eq!(
            *load(&path, &identity, [7; 32]).unwrap().rendezvous_secret,
            [winner; 32]
        );
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn record_roundtrip_rejects_wrong_identity_tampering_and_conflicts() {
        let path = std::env::temp_dir().join(format!(
            "ad-contact-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir(&path).unwrap();
        let (identity, _) = Identity::create().unwrap();
        let (other, _) = Identity::create().unwrap();
        let record = VerifiedContact {
            peer_key: [7; 32],
            rendezvous_secret: Zeroizing::new([8; 32]),
        };
        save(&path, &identity, &record).unwrap();
        let backup = export_backup(&identity, &record).unwrap();
        let restored = path.join("restored");
        assert!(import_backup(&restored, &other, &backup).is_err());
        let mut tampered_backup = backup.clone();
        *tampered_backup.last_mut().unwrap() ^= 1;
        assert!(import_backup(&restored, &identity, &tampered_backup).is_err());
        assert_eq!(
            import_backup(&restored, &identity, &backup).unwrap(),
            [7; 32]
        );
        assert_eq!(
            *load(&restored, &identity, [7; 32])
                .unwrap()
                .rendezvous_secret,
            [8; 32]
        );
        assert_eq!(
            *load(&path, &identity, [7; 32]).unwrap().rendezvous_secret,
            [8; 32]
        );
        assert!(load(&path, &other, [7; 32]).is_err());
        assert!(save(
            &path,
            &identity,
            &VerifiedContact {
                peer_key: [7; 32],
                rendezvous_secret: Zeroizing::new([9; 32])
            }
        )
        .is_err());
        let replacement = VerifiedContact {
            peer_key: [7; 32],
            rendezvous_secret: Zeroizing::new([9; 32]),
        };
        save_after_confirmation(&path, &identity, &replacement).unwrap();
        assert_eq!(
            *load(&path, &identity, [7; 32]).unwrap().rendezvous_secret,
            [9; 32]
        );
        assert!(import_backup(&path, &identity, &backup).is_err());
        let file = path.join(format!("{}.peer", filename(&identity, &[7; 32])));
        let mut bytes = fs::read(&file).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(file, bytes).unwrap();
        assert!(load(&path, &identity, [7; 32]).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    fn scratch_directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ad-contact-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// A contact record as the previous version wrote it: ADPEER1, encrypted with the
    /// same key that names the file.
    fn legacy_record(identity: &Identity, contact: &VerifiedContact) -> (String, Vec<u8>) {
        let nonce = [0x42; 12];
        let encrypted = ChaCha20Poly1305::new_from_slice(key(identity).as_ref())
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: contact.rendezvous_secret.as_ref(),
                    aad: &contact.peer_key,
                },
            )
            .unwrap();
        let mut bytes = LEGACY_MAGIC.to_vec();
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&encrypted);
        (filename(identity, &contact.peer_key), bytes)
    }

    fn contact(value: u8) -> VerifiedContact {
        VerifiedContact {
            peer_key: [7; 32],
            rendezvous_secret: Zeroizing::new([value; 32]),
        }
    }

    #[test]
    fn a_record_written_by_the_previous_version_still_loads_and_is_upgraded_on_rewrite() {
        let directory = scratch_directory("legacy-record");
        let (identity, _) = Identity::create().unwrap();
        let (name, bytes) = legacy_record(&identity, &contact(3));
        let path = directory.join(format!("{name}.peer"));
        fs::write(&path, &bytes).unwrap();

        let loaded = load(&directory, &identity, [7; 32]).unwrap();
        assert_eq!(*loaded.rendezvous_secret, [3; 32]);

        // Confirming a replacement rewrites it in the new format.
        save_after_confirmation(&directory, &identity, &contact(4)).unwrap();
        let rewritten = fs::read(&path).unwrap();
        assert_eq!(&rewritten[..8], MAGIC, "the rewrite uses ADPEER2");
        assert_eq!(
            *load(&directory, &identity, [7; 32])
                .unwrap()
                .rendezvous_secret,
            [4; 32]
        );
        // The upgrade must not have broken the legacy path for other records.
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_damaged_record_does_not_block_a_fresh_confirmation_and_is_kept_aside() {
        let directory = scratch_directory("damaged-record");
        let (identity, _) = Identity::create().unwrap();
        save(&directory, &identity, &contact(5)).unwrap();
        let path = directory.join(format!("{}.peer", filename(&identity, &[7; 32])));
        let mut damaged = fs::read(&path).unwrap();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&path, &damaged).unwrap();

        // Saving without a confirmation still refuses: nothing may overwrite a record on
        // the strength of its being unreadable alone.
        assert!(save(&directory, &identity, &contact(6)).is_err());
        assert_eq!(fs::read(&path).unwrap(), damaged);

        // A fresh mutual confirmation replaces it, and the bytes are not thrown away.
        save_after_confirmation(&directory, &identity, &contact(6)).unwrap();
        assert_eq!(
            *load(&directory, &identity, [7; 32])
                .unwrap()
                .rendezvous_secret,
            [6; 32]
        );
        let kept: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.to_string_lossy().contains(".damaged-"))
            .collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(fs::read(&kept[0]).unwrap(), damaged);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_new_record_is_not_encrypted_with_the_filename_key() {
        let directory = scratch_directory("new-record");
        let (identity, _) = Identity::create().unwrap();
        save(&directory, &identity, &contact(5)).unwrap();
        let path = directory.join(format!("{}.peer", filename(&identity, &[7; 32])));
        let bytes = fs::read(&path).unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        let decrypt_with = |key: &[u8; 32]| {
            ChaCha20Poly1305::new_from_slice(key)
                .unwrap()
                .decrypt(
                    Nonce::from_slice(&bytes[8..20]),
                    Payload {
                        msg: &bytes[20..],
                        aad: &[7; 32],
                    },
                )
                .is_ok()
        };
        assert!(decrypt_with(&record_key(&identity)));
        assert!(
            !decrypt_with(&key(&identity)),
            "the key that names files must not open records"
        );
        assert!(!decrypt_with(&backup_key(&identity)), "nor the backup key");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_backup_from_the_previous_version_still_imports_and_new_backups_use_their_own_key() {
        let directory = scratch_directory("backups");
        let (identity, _) = Identity::create().unwrap();
        // ADCONB1 as the previous version exported it.
        let nonce = [0x24; 12];
        let mut plain = Vec::new();
        plain.extend_from_slice(&[7; 32]);
        plain.extend_from_slice(&[8; 32]);
        let encrypted = ChaCha20Poly1305::new_from_slice(key(&identity).as_ref())
            .unwrap()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: LEGACY_BACKUP_MAGIC,
                },
            )
            .unwrap();
        let mut legacy = LEGACY_BACKUP_MAGIC.to_vec();
        legacy.extend_from_slice(&nonce);
        legacy.extend_from_slice(&encrypted);
        assert_eq!(
            import_backup(&directory, &identity, &legacy).unwrap(),
            [7; 32]
        );
        assert_eq!(
            *load(&directory, &identity, [7; 32])
                .unwrap()
                .rendezvous_secret,
            [8; 32]
        );

        // New exports are ADCONB2 under the backup key, and they import too.
        let exported = export_backup(&identity, &contact(9)).unwrap();
        assert_eq!(&exported[..8], BACKUP_MAGIC);
        let opens_with = |key: &[u8; 32]| {
            ChaCha20Poly1305::new_from_slice(key)
                .unwrap()
                .decrypt(
                    Nonce::from_slice(&exported[8..20]),
                    Payload {
                        msg: &exported[20..],
                        aad: BACKUP_MAGIC,
                    },
                )
                .is_ok()
        };
        assert!(opens_with(&backup_key(&identity)));
        assert!(!opens_with(&key(&identity)));
        assert!(!opens_with(&record_key(&identity)));
        let second_directory = scratch_directory("backups-second");
        assert_eq!(
            import_backup(&second_directory, &identity, &exported).unwrap(),
            [7; 32]
        );
        // A backup cannot be passed off under the other format's magic.
        let mut mislabelled = exported.clone();
        mislabelled[..8].copy_from_slice(LEGACY_BACKUP_MAGIC);
        assert!(
            import_backup(&scratch_directory("backups-third"), &identity, &mislabelled).is_err()
        );
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(second_directory).unwrap();
    }
}
