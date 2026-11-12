use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

const LEGACY_PREFIX: &str = "AD1-";
const PREFIX: &str = "AD2-";
const KEY_CONTEXT: &[u8] = b"another-dimension-v2/identity-signing/v1";
const CODE_KEY_CONTEXT: &[u8] = b"another-dimension-v2/identity-code-wrap/v2";
const CODE_AAD: &[u8] = b"another-dimension-v2/identity-code/v2";
const STORAGE_KEY_CONTEXT: &[u8] = b"another-dimension-v2/local-history/v1";
const CODE_KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const WRAPPED_SEED_BYTES: usize = 32 + 16;
const ORIGINS_FILE: &str = "identity-origins.txt";

pub struct Identity {
    // Retained for independently derived storage and identity-code wrapping keys.
    _seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey,
}

impl Identity {
    pub fn create() -> io::Result<(Self, Zeroizing<String>)> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        File::open("/dev/urandom")?.read_exact(seed.as_mut())?;
        let identity = Self::from_seed(seed);
        let code = identity.create_access_code()?;
        Ok((identity, code))
    }

    pub fn from_code(code: &str) -> Option<Self> {
        if code.len() != LEGACY_PREFIX.len() + 64 && code.len() != 190 {
            return None;
        }
        if let Some(hex) = code.strip_prefix(LEGACY_PREFIX) {
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(&decode_hex::<32>(hex)?);
            return Some(Self::from_seed(seed));
        }

        let mut parts = code.split('-');
        if parts.next()? != "AD2" {
            return None;
        }
        let wrap_key = Zeroizing::new(decode_hex::<CODE_KEY_BYTES>(parts.next()?)?);
        let nonce = decode_hex::<NONCE_BYTES>(parts.next()?)?;
        let ciphertext = decode_hex::<WRAPPED_SEED_BYTES>(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        let key = derive_code_key(&wrap_key);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref()).ok()?;
        let seed = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: CODE_AAD,
                    },
                )
                .ok()?,
        );
        if seed.len() != 32 {
            return None;
        }
        let mut seed_bytes = Zeroizing::new([0; 32]);
        seed_bytes.copy_from_slice(seed.as_slice());
        Some(Self::from_seed(seed_bytes))
    }

    /// Creates a fresh code that unlocks the same identity seed.
    /// Older codes remain valid because they contain their own encrypted seed envelope.
    pub fn create_access_code(&self) -> io::Result<Zeroizing<String>> {
        let mut wrap_key = Zeroizing::new([0_u8; CODE_KEY_BYTES]);
        let mut nonce = [0_u8; NONCE_BYTES];
        File::open("/dev/urandom")?.read_exact(wrap_key.as_mut())?;
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let key = derive_code_key(&wrap_key);
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| io::Error::other("identity code key unavailable"))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: self._seed.as_ref(),
                    aad: CODE_AAD,
                },
            )
            .map_err(|_| io::Error::other("identity code generation failed"))?;
        let mut code = Zeroizing::new(String::with_capacity(
            PREFIX.len() + (CODE_KEY_BYTES + NONCE_BYTES + ciphertext.len() + 2) * 2,
        ));
        code.push_str(PREFIX);
        append_hex(&mut code, wrap_key.as_ref());
        code.push('-');
        append_hex(&mut code, &nonce);
        code.push('-');
        append_hex(&mut code, &ciphertext);
        Ok(code)
    }

    fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        let mut signing_seed = Zeroizing::new([0_u8; 32]);
        Hkdf::<Sha256>::new(None, seed.as_ref())
            .expand(KEY_CONTEXT, signing_seed.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        let signing_key = SigningKey::from_bytes(&signing_seed);
        Self {
            _seed: seed,
            signing_key,
        }
    }

    pub fn public_id(&self) -> String {
        self.signing_key
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(crate) fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub(crate) fn storage_key(&self) -> Zeroizing<[u8; 32]> {
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&self.public_key()), self._seed.as_ref())
            .expand(STORAGE_KEY_CONTEXT, key.as_mut())
            .expect("32 bytes is a valid HKDF output length");
        key
    }

    /// Re-encrypt local histories and verified-contact secrets under a freshly
    /// created identity before it replaces the active identity in memory.
    /// The old identity directory remains intact as a recovery source.
    pub(crate) fn copy_local_data_to(&self, replacement: &Identity) -> io::Result<()> {
        if self.public_key() == replacement.public_key() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "replacement identity must be new",
            ));
        }
        let destination = crate::history::data_directory()?.join(replacement.public_id());
        if destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "replacement identity data already exists",
            ));
        }

        let result = (|| {
            fs::create_dir_all(&destination)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
            }
            for peer_id in crate::history::History::known_peer_ids(self)? {
                let (messages, recovered_partial) =
                    crate::history::History::read_for_identity_copy(self, &peer_id)?;
                if recovered_partial {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "source history has an incomplete record",
                    ));
                }
                let (mut history, _, _) = crate::history::History::open(replacement, &peer_id)?;
                history.replace(&messages)?;
            }

            let source_contacts = crate::contacts::list_known(
                &crate::history::data_directory()?
                    .join(self.public_id())
                    .join("verified-contacts"),
                self,
            )?;
            let contact_directory = destination.join("verified-contacts");
            for contact in &source_contacts {
                crate::contacts::save(&contact_directory, replacement, contact)?;
            }
            let mut origins = previous_public_ids(self)?;
            origins.push(self.public_id());
            origins.sort();
            origins.dedup();
            if origins.len() > 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "identity lineage is too long",
                ));
            }
            let origin_path = destination.join(ORIGINS_FILE);
            let temporary = destination.join(format!(".{ORIGINS_FILE}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            for id in origins {
                writeln!(file, "{id}")?;
            }
            file.sync_all()?;
            fs::rename(temporary, origin_path)?;
            Ok(())
        })();

        if result.is_err() && destination.exists() {
            let _ = std::fs::remove_dir_all(&destination);
        }
        result
    }
}

pub(crate) fn previous_public_ids(identity: &Identity) -> io::Result<Vec<String>> {
    let path = crate::history::data_directory()?
        .join(identity.public_id())
        .join(ORIGINS_FILE);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.len() > 32 * 65 => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "identity lineage is too large",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    }
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut ids = Vec::new();
    for id in contents.lines() {
        if id.len() != 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid identity lineage record",
            ));
        }
        ids.push(id.to_ascii_lowercase());
        if ids.len() > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "identity lineage is too long",
            ));
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn derive_code_key(wrap_key: &[u8; CODE_KEY_BYTES]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(None, wrap_key)
        .expand(CODE_KEY_CONTEXT, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    use std::fmt::Write;
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
}

fn decode_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0; N];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        output[index] = digit(pair[0]) << 4 | digit(pair[1]);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::Identity;

    #[test]
    fn code_restores_same_identity_and_rejects_invalid_format() {
        let (identity, code) = Identity::create().unwrap();
        let restored = Identity::from_code(&code).unwrap();
        assert_eq!(identity.public_id(), restored.public_id());
        assert!(Identity::from_code("AD1-not-a-code").is_none());
        assert!(Identity::from_code(&code.to_ascii_uppercase()).is_none());
        let (_, other_code) = Identity::create().unwrap();
        assert_ne!(code.as_str(), other_code.as_str());
    }
}
