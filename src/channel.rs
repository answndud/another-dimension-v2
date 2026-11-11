//! Noise handshake only. The peer identity and user confirmation are not yet
//! implemented, so the resulting transport deliberately exposes no chat API.

use zeroize::Zeroizing;

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"another-dimension-v2/noise-handshake/v1";
const MAX_HANDSHAKE_MESSAGE: usize = 128;
const HASH_SIZE: usize = 32;

#[derive(Clone, Copy)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Debug)]
pub enum HandshakeError {
    Noise(snow::Error),
    InvalidMessage,
    Incomplete,
    Aborted,
}

impl From<snow::Error> for HandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

pub struct Handshake {
    state: snow::HandshakeState,
    aborted: bool,
}

impl Handshake {
    pub fn new(role: Role) -> Result<Self, HandshakeError> {
        let params = PATTERN.parse()?;
        let keypair = snow::Builder::new(params).generate_keypair()?;
        // This Noise static key belongs only to this connection, not the identity.
        let private_key = Zeroizing::new(keypair.private);
        let builder = snow::Builder::new(PATTERN.parse()?)
            .prologue(PROLOGUE)?
            .local_private_key(&private_key)?;
        let state = match role {
            Role::Initiator => builder.build_initiator()?,
            Role::Responder => builder.build_responder()?,
        };
        Ok(Self {
            state,
            aborted: false,
        })
    }

    pub fn write(&mut self) -> Result<Vec<u8>, HandshakeError> {
        if self.aborted {
            return Err(HandshakeError::Aborted);
        }
        let mut output = vec![0; MAX_HANDSHAKE_MESSAGE];
        match self.state.write_message(&[], &mut output) {
            Ok(length) => {
                output.truncate(length);
                Ok(output)
            }
            Err(error) => {
                self.aborted = true;
                Err(error.into())
            }
        }
    }

    pub fn read(&mut self, message: &[u8]) -> Result<(), HandshakeError> {
        if self.aborted {
            return Err(HandshakeError::Aborted);
        }
        if message.len() > MAX_HANDSHAKE_MESSAGE {
            self.aborted = true;
            return Err(HandshakeError::InvalidMessage);
        }
        let mut payload = [0; MAX_HANDSHAKE_MESSAGE];
        match self.state.read_message(message, &mut payload) {
            Ok(0) => Ok(()),
            Ok(_) => {
                self.aborted = true;
                Err(HandshakeError::InvalidMessage)
            }
            Err(error) => {
                self.aborted = true;
                Err(error.into())
            }
        }
    }

    pub fn finish(self) -> Result<PendingChannel, HandshakeError> {
        if self.aborted {
            return Err(HandshakeError::Aborted);
        }
        if !self.state.is_handshake_finished() {
            return Err(HandshakeError::Incomplete);
        }
        let hash: [u8; HASH_SIZE] = self
            .state
            .get_handshake_hash()
            .try_into()
            .map_err(|_| HandshakeError::InvalidMessage)?;
        Ok(PendingChannel {
            hash,
            _transport: self.state.into_transport_mode()?,
        })
    }
}

/// A finished Noise exchange, not an authenticated or user-approved peer.
/// No message encryption/decryption is exposed until peer authentication exists.
pub struct PendingChannel {
    hash: [u8; HASH_SIZE],
    _transport: snow::TransportState,
}

impl PendingChannel {
    pub fn handshake_hash(&self) -> &[u8; HASH_SIZE] {
        &self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::{Handshake, HandshakeError, Role};

    fn exchange() -> ([u8; 32], [u8; 32]) {
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        (
            *a.finish().unwrap().handshake_hash(),
            *b.finish().unwrap().handshake_hash(),
        )
    }

    #[test]
    fn completed_handshakes_match_and_each_connection_is_fresh() {
        let (a, b) = exchange();
        let (next_a, next_b) = exchange();
        assert_eq!(a, b);
        assert_eq!(next_a, next_b);
        assert_ne!(a, next_a);
    }

    #[test]
    fn tampered_handshake_is_rejected_and_cannot_continue() {
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        let mut message = b.write().unwrap();
        *message.last_mut().unwrap() ^= 1;
        assert!(a.read(&message).is_err());
        assert!(matches!(a.write(), Err(HandshakeError::Aborted)));
        assert!(matches!(a.finish(), Err(HandshakeError::Aborted)));
    }

    #[test]
    fn incomplete_or_oversized_handshake_is_rejected() {
        let a = Handshake::new(Role::Initiator).unwrap();
        assert!(matches!(a.finish(), Err(HandshakeError::Incomplete)));
        let mut b = Handshake::new(Role::Responder).unwrap();
        assert!(matches!(
            b.read(&[0; 129]),
            Err(HandshakeError::InvalidMessage)
        ));
        assert!(matches!(b.finish(), Err(HandshakeError::Aborted)));
    }
}
