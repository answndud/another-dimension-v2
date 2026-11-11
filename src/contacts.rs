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
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"ADPEER1\0";

/// The rendezvous secret is separate from the initial invite and identifies
/// a single verified relationship. Never display or log it.
pub struct VerifiedContact {
    pub peer_key: [u8; 32],
    pub rendezvous_secret: Zeroizing<[u8; 32]>,
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
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "contact conflict",
        ));
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
        // A hard link avoids overwriting a concurrent writer.
        fs::hard_link(&temporary, &path)?;
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

#[cfg(test)]
mod tests {
    use super::*;
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
        let file = fs::read_dir(&path).unwrap().next().unwrap().unwrap().path();
        let mut bytes = fs::read(&file).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(file, bytes).unwrap();
        assert!(load(&path, &identity, [7; 32]).is_err());
        fs::remove_dir_all(path).unwrap();
    }
}
