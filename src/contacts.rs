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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADPEER1\0";
const BACKUP_MAGIC: &[u8; 8] = b"ADCONB1\0";
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
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    let name = filename(identity, &contact.peer_key);
    let path = directory.join(format!("{name}.peer"));
    // Existing records must never be silently replaced by another secret.
    if path.exists() {
        let old = load(directory, identity, contact.peer_key)?;
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
    let mut nonce = [0; 12];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key(identity).as_ref()).map_err(io::Error::other)?;
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
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(MAGIC)?;
        file.write_all(&nonce)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        if replace_confirmed {
            fs::rename(&temporary, &path)?;
        } else {
            // A hard link avoids overwriting a concurrent writer.
            fs::hard_link(&temporary, &path)?;
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
    if bytes.len() != 8 + 12 + 32 + 16 || &bytes[..8] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact record",
        ));
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key(identity).as_ref()).map_err(io::Error::other)?;
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
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let mut plain = Zeroizing::new(Vec::with_capacity(64));
    plain.extend_from_slice(&contact.peer_key);
    plain.extend_from_slice(contact.rendezvous_secret.as_ref());
    let cipher =
        ChaCha20Poly1305::new_from_slice(key(identity).as_ref()).map_err(io::Error::other)?;
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
    if backup.len() != 8 + 12 + 64 + 16 || &backup[..8] != BACKUP_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid contact backup",
        ));
    }
    let cipher =
        ChaCha20Poly1305::new_from_slice(key(identity).as_ref()).map_err(io::Error::other)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&backup[8..20]),
                Payload {
                    msg: &backup[20..],
                    aad: BACKUP_MAGIC,
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
}
