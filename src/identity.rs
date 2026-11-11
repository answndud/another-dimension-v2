use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs::File;
use std::io::{self, Read};
use zeroize::Zeroizing;

const PREFIX: &str = "AD1-";
const KEY_CONTEXT: &[u8] = b"another-dimension-v2/identity-signing/v1";

pub struct Identity {
    // Retained for future independently derived storage keys; never persisted here.
    _seed: Zeroizing<[u8; 32]>,
    signing_key: SigningKey,
}

impl Identity {
    pub fn create() -> io::Result<(Self, Zeroizing<String>)> {
        let mut seed = Zeroizing::new([0_u8; 32]);
        File::open("/dev/urandom")?.read_exact(seed.as_mut())?;
        let mut code = Zeroizing::new(String::with_capacity(PREFIX.len() + 64));
        code.push_str(PREFIX);
        for byte in seed.iter() {
            use std::fmt::Write;
            write!(&mut *code, "{byte:02x}").expect("writing to a string cannot fail");
        }
        Ok((Self::from_seed(seed), code))
    }

    pub fn from_code(code: &str) -> Option<Self> {
        let hex = code.strip_prefix(PREFIX)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            seed[index] = digit(chunk[0]) << 4 | digit(chunk[1]);
        }
        Some(Self::from_seed(seed))
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
