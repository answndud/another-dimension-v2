//! Authenticated-channel state machine used by the relay adapter.
//! Chat frames are available only after local confirmation and an encrypted
//! peer confirmation frame.

use ed25519_dalek::{Signature, VerifyingKey};
use nostr::prelude::{Keys, PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::identity::Identity;

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
// Protocol version 3 adds a commitment to a random value in the identity proof and a
// reveal step, so both users compare a short code that neither side could steer. A
// peer running version 2 fails the Noise handshake because the prologue differs.
const PROLOGUE: &[u8] = b"another-dimension-v2/noise-handshake/v3";
const SIGN_DOMAIN: &[u8] = b"another-dimension-v2/identity-proof/v3";
const CONFIRM_DOMAIN: &[u8] = b"another-dimension-v2/user-confirmation/v3";
const COMMIT_DOMAIN: &[u8] = b"another-dimension-v2/code-commitment/v3";
/// Random value each side contributes to the confirmation code.
const NONCE_SIZE: usize = 16;
const MAX_HANDSHAKE_MESSAGE: usize = 128;
const MAX_FRAME: usize = 8192;
/// The largest relay envelope: the sequence header and a full frame.
pub(crate) const MAX_ENVELOPE: usize = ENVELOPE_HEADER + MAX_FRAME;
const FRAME_TAG: usize = 16;
/// A relay envelope is the direction-local sequence number followed by the ciphertext.
/// There is no fixed marker and no session tag: the event is already routed by its topic
/// tag and signed by the peer's session key, and a frame from any other session fails to
/// decrypt, so neither would add anything but a way to recognise this program's traffic.
const ENVELOPE_HEADER: usize = 8;
/// What kind of frame an encrypted payload carries. Only chat messages travel in a session.
const FRAME_KIND_CHAT: u8 = 3;
/// Chat payloads are padded with zeros to one of these sizes (before the 16 byte tag),
/// so the length of an encrypted event tells an observer only which size class a message
/// falls into. The last is the largest payload a frame can carry.
const PADDING_BUCKETS: [usize; 4] = [256, 1024, 4096, MAX_FRAME - FRAME_TAG];
/// Kind byte, sender role byte and the length of the message.
const CHAT_PAYLOAD_HEADER: usize = 1 + 1 + 2;
/// The smallest encrypted frame a padded payload produces.
pub(crate) const SMALLEST_PADDED_FRAME: usize = PADDING_BUCKETS[0] + FRAME_TAG;
const MAX_REORDER: u64 = 32;
/// How long a hole in the sequence may stay open before the receiver gives up on the
/// missing frames. Relay events are ephemeral and never retransmitted, so a frame that
/// has not shown up by then is not going to.
pub(crate) const GAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Messages sent between two key changes. After this many messages in a direction the
/// sender derives a new key (Noise Rekey), so one key never protects a whole long chat.
const REKEY_INTERVAL: u64 = 1000;
const ROUTE_DOMAIN: &[u8] = b"another-dimension-v2/relay-route/v2";
const HASH_SIZE: usize = 32;
const PROOF_SIZE: usize = 1 + 32 + 32 + HASH_SIZE + 64;
const REVEAL_SIZE: usize = 1 + NONCE_SIZE;
const CONFIRM_SIZE: usize = 1 + 32 + HASH_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Responder => 2,
        }
    }

    pub(crate) fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    Noise(snow::Error),
    InvalidMessage,
    Incomplete,
    Aborted,
    IdentityMismatch,
    InvalidIdentity,
    InvalidProof,
    SelfConnection,
    PeerNotConfirmed,
    InvalidEnvelope,
    OutsideReorderWindow,
    SequenceExhausted,
    Closed,
    InvalidRelayKey,
    RoleMismatch,
    /// The revealed value does not match the commitment the peer sent earlier.
    CommitmentMismatch,
}

impl From<snow::Error> for HandshakeError {
    fn from(error: snow::Error) -> Self {
        Self::Noise(error)
    }
}

pub struct Handshake {
    state: snow::HandshakeState,
    role: Role,
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
            role,
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
            role: self.role,
            transport: self.state.into_transport_mode()?,
        })
    }
}

/// A finished Noise exchange, not yet bound to a personal identity.
pub struct PendingChannel {
    hash: [u8; HASH_SIZE],
    role: Role,
    transport: snow::TransportState,
}

impl PendingChannel {
    pub(crate) fn role(&self) -> Role {
        self.role
    }

    /// Creates a transcript-bound identity proof. Send this frame to the peer,
    /// then pass its response to `receive_peer_proof`.
    pub fn prove_identity(
        mut self,
        identity: &Identity,
    ) -> Result<(IdentityPending, Vec<u8>), HandshakeError> {
        let public_key = identity.public_key();
        let relay_keys = generate_relay_keys()?;
        let relay_public_key = relay_keys.public_key().to_bytes();
        // Commit to a random value now and reveal it only after the peer's commitment
        // has arrived, so neither side can choose its value after seeing the other's.
        let mut nonce = Zeroizing::new([0_u8; NONCE_SIZE]);
        crate::random::fill(nonce.as_mut()).map_err(|_| HandshakeError::InvalidMessage)?;
        let commitment = commitment(self.role, &nonce);
        let signed = identity_proof_input(
            &self.hash,
            self.role,
            &public_key,
            &relay_public_key,
            &commitment,
        );
        let signature = identity.sign(&signed);
        let mut proof = Vec::with_capacity(PROOF_SIZE);
        proof.push(self.role.byte());
        proof.extend_from_slice(&public_key);
        proof.extend_from_slice(&relay_public_key);
        proof.extend_from_slice(&commitment);
        proof.extend_from_slice(&signature);
        let frame = encrypt(&mut self.transport, &proof)?;
        Ok((
            IdentityPending {
                hash: self.hash,
                role: self.role,
                local_key: public_key,
                relay_keys,
                nonce,
                transport: self.transport,
            },
            frame,
        ))
    }
}

/// Identity proof was sent; no chat API exists until peer proof and user check.
pub struct IdentityPending {
    hash: [u8; HASH_SIZE],
    role: Role,
    local_key: [u8; 32],
    relay_keys: Keys,
    nonce: Zeroizing<[u8; NONCE_SIZE]>,
    transport: snow::TransportState,
}

impl IdentityPending {
    /// `expected_peer` pins a previously verified key when one is known.
    /// Passing `None` requires the user to verify the displayed code.
    ///
    /// The peer's commitment has arrived, so the frame returned with the next state
    /// reveals our own random value. Send it, then pass the peer's reveal to
    /// `RevealPending::receive_peer_reveal`.
    pub fn receive_peer_proof(
        mut self,
        frame: &[u8],
        expected_peer: Option<[u8; 32]>,
    ) -> Result<(RevealPending, Vec<u8>), HandshakeError> {
        let proof = decrypt(&mut self.transport, frame, PROOF_SIZE)?;
        if proof.len() != PROOF_SIZE || proof[0] != self.role.peer().byte() {
            return Err(HandshakeError::InvalidProof);
        }
        let peer_key: [u8; 32] = proof[1..33]
            .try_into()
            .map_err(|_| HandshakeError::InvalidProof)?;
        if peer_key == self.local_key {
            return Err(HandshakeError::SelfConnection);
        }
        if expected_peer.is_some_and(|expected| expected != peer_key) {
            return Err(HandshakeError::IdentityMismatch);
        }
        let peer_relay_key =
            PublicKey::from_slice(&proof[33..65]).map_err(|_| HandshakeError::InvalidRelayKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&peer_key).map_err(|_| HandshakeError::InvalidIdentity)?;
        let signature = Signature::from_slice(&proof[65 + HASH_SIZE..])
            .map_err(|_| HandshakeError::InvalidProof)?;
        let relay_key_bytes = peer_relay_key.to_bytes();
        let peer_commitment: [u8; HASH_SIZE] = proof[65..65 + HASH_SIZE]
            .try_into()
            .map_err(|_| HandshakeError::InvalidProof)?;
        let signed = identity_proof_input(
            &self.hash,
            self.role.peer(),
            &peer_key,
            &relay_key_bytes,
            &peer_commitment,
        );
        verifying_key
            .verify_strict(&signed, &signature)
            .map_err(|_| HandshakeError::InvalidProof)?;

        // The nonce is secret until revealed, so the plaintext frame is wiped on drop.
        let mut reveal = Zeroizing::new(Vec::with_capacity(REVEAL_SIZE));
        reveal.push(self.role.byte());
        reveal.extend_from_slice(self.nonce.as_ref());
        let reveal_frame = encrypt(&mut self.transport, &reveal)?;
        Ok((
            RevealPending {
                hash: self.hash,
                role: self.role,
                local_key: self.local_key,
                peer_key,
                local_relay_keys: self.relay_keys,
                peer_relay_key,
                local_nonce: self.nonce,
                peer_commitment,
                transport: self.transport,
            },
            reveal_frame,
        ))
    }
}

/// Both identities are proven and both commitments are in; the peer's random value is
/// still hidden. The confirmation code exists only after it has been revealed and
/// checked against the commitment.
pub struct RevealPending {
    hash: [u8; HASH_SIZE],
    role: Role,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    local_relay_keys: Keys,
    peer_relay_key: PublicKey,
    local_nonce: Zeroizing<[u8; NONCE_SIZE]>,
    peer_commitment: [u8; HASH_SIZE],
    transport: snow::TransportState,
}

impl RevealPending {
    pub fn receive_peer_reveal(
        mut self,
        frame: &[u8],
    ) -> Result<VerificationPending, HandshakeError> {
        let reveal = decrypt(&mut self.transport, frame, REVEAL_SIZE)?;
        if reveal.len() != REVEAL_SIZE || reveal[0] != self.role.peer().byte() {
            return Err(HandshakeError::InvalidProof);
        }
        let peer_nonce: [u8; NONCE_SIZE] = reveal[1..]
            .try_into()
            .map_err(|_| HandshakeError::InvalidProof)?;
        // A value that does not open the commitment sent earlier is a steered value.
        let expected = commitment(self.role.peer(), &peer_nonce);
        if !constant_time_equal(&expected, &self.peer_commitment) {
            return Err(HandshakeError::CommitmentMismatch);
        }
        let fingerprint = fingerprint(
            &self.hash,
            self.role,
            (&self.local_key, &self.local_nonce),
            (&self.peer_key, &peer_nonce),
        );
        Ok(VerificationPending {
            session: PeerSession {
                hash: self.hash,
                session_tag: session_tag(&self.hash),
                role: self.role,
                local_key: self.local_key,
                peer_key: self.peer_key,
                local_relay_keys: self.local_relay_keys,
                peer_relay_key: self.peer_relay_key,
                fingerprint,
            },
            transport: self.transport,
        })
    }
}

/// What the two sides know about each other once both identity proofs have been
/// checked and the confirmation code exists. The states from there to the active
/// channel carry the same facts, so they share this instead of repeating the fields.
struct PeerSession {
    hash: [u8; HASH_SIZE],
    session_tag: [u8; 16],
    role: Role,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    local_relay_keys: Keys,
    peer_relay_key: PublicKey,
    fingerprint: [u8; HASH_SIZE],
}

/// Both identities are cryptographically bound to the same Noise transcript.
/// The fingerprint must be compared out of band by the users.
pub struct VerificationPending {
    session: PeerSession,
    transport: snow::TransportState,
}

impl VerificationPending {
    pub(crate) fn role(&self) -> Role {
        self.session.role
    }

    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.session.peer_key
    }

    /// Full SHA-256 fingerprint, kept for anyone who wants to compare all of it.
    pub fn fingerprint(&self) -> &[u8; HASH_SIZE] {
        &self.session.fingerprint
    }

    /// The short code the two users compare out of band.
    pub fn confirmation_code(&self) -> String {
        confirmation_code(&self.session.fingerprint)
    }

    /// Call only after the local user has compared the fingerprint.
    /// The returned encrypted frame asks the peer to confirm its own view.
    pub fn confirm_after_user_check(
        mut self,
    ) -> Result<(ConfirmationPending, Vec<u8>), HandshakeError> {
        let mut confirmation = Vec::with_capacity(CONFIRM_SIZE);
        confirmation.push(self.session.role.byte());
        confirmation.extend_from_slice(&self.session.fingerprint);
        confirmation.extend_from_slice(&self.session.hash);
        let frame = encrypt(&mut self.transport, &confirmation)?;
        Ok((
            ConfirmationPending {
                session: self.session,
                transport: self.transport,
            },
            frame,
        ))
    }
}

/// Local user has confirmed; activation still requires a matching peer frame.
pub struct ConfirmationPending {
    session: PeerSession,
    transport: snow::TransportState,
}

impl ConfirmationPending {
    pub fn receive_peer_confirmation(
        mut self,
        frame: &[u8],
    ) -> Result<ActiveChannel, HandshakeError> {
        let confirmation = decrypt(&mut self.transport, frame, CONFIRM_SIZE)?;
        if confirmation.len() != CONFIRM_SIZE
            || confirmation[0] != self.session.role.peer().byte()
            || confirmation[1..33] != self.session.fingerprint
            || confirmation[33..] != self.session.hash
        {
            return Err(HandshakeError::PeerNotConfirmed);
        }
        Ok(ActiveChannel {
            role: self.session.role,
            local_key: self.session.local_key,
            peer_key: self.session.peer_key,
            local_relay_keys: self.session.local_relay_keys,
            peer_relay_key: self.session.peer_relay_key,
            fingerprint: self.session.fingerprint,
            session_tag: self.session.session_tag,
            transport: self.transport,
        })
    }
}

/// Chat transport. Constructible only after local confirmation and receipt of
/// a matching peer confirmation frame. The peer frame itself cannot prove a
/// human clicked anything; that remains a UI-level assertion.
pub struct ActiveChannel {
    role: Role,
    local_key: [u8; 32],
    peer_key: [u8; 32],
    local_relay_keys: Keys,
    peer_relay_key: PublicKey,
    fingerprint: [u8; HASH_SIZE],
    session_tag: [u8; 16],
    transport: snow::TransportState,
}

impl ActiveChannel {
    pub fn fingerprint(&self) -> &[u8; HASH_SIZE] {
        &self.fingerprint
    }

    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.peer_key
    }

    /// The largest message one frame can carry once the header and padding are counted.
    pub(crate) const MAX_MESSAGE: usize = MAX_FRAME - FRAME_TAG - CHAT_PAYLOAD_HEADER;

    pub fn write_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if message.len() > Self::MAX_MESSAGE {
            return Err(HandshakeError::InvalidMessage);
        }
        let needed = CHAT_PAYLOAD_HEADER + message.len();
        let size = PADDING_BUCKETS
            .iter()
            .copied()
            .find(|bucket| *bucket >= needed)
            .ok_or(HandshakeError::InvalidMessage)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(size));
        payload.push(FRAME_KIND_CHAT);
        payload.push(self.role.byte());
        payload.extend_from_slice(&(message.len() as u16).to_be_bytes());
        payload.extend_from_slice(message);
        payload.resize(size, 0);
        encrypt(&mut self.transport, &payload)
    }

    /// Derives a new key for everything sent from now on (Noise Rekey).
    fn rekey_outgoing(&mut self) {
        self.transport.rekey_outgoing();
    }

    /// Derives the next key for everything received from now on.
    fn rekey_incoming(&mut self) {
        self.transport.rekey_incoming();
    }

    /// The nonce the next received frame will be decrypted with.
    fn receiving_nonce(&self) -> u64 {
        self.transport.receiving_nonce()
    }

    /// Sets the nonce the next received frame is decrypted with, so frames can be read
    /// across a hole left by frames that never arrived.
    fn set_receiving_nonce(&mut self, nonce: u64) {
        self.transport.set_receiving_nonce(nonce);
    }

    pub fn read_message(&mut self, frame: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let payload = decrypt(&mut self.transport, frame, MAX_FRAME - FRAME_TAG)?;
        if payload.len() < CHAT_PAYLOAD_HEADER
            || payload[0] != FRAME_KIND_CHAT
            || payload[1] != self.role.peer().byte()
            // Only the sizes we send are valid, so a frame cannot hide extra bytes.
            || !PADDING_BUCKETS.contains(&payload.len())
        {
            return Err(HandshakeError::InvalidMessage);
        }
        let length = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
        let end = CHAT_PAYLOAD_HEADER + length;
        if end > payload.len() {
            return Err(HandshakeError::InvalidMessage);
        }
        // The padding is all zeros; anything else would be a hidden channel.
        if payload[end..].iter().any(|byte| *byte != 0) {
            return Err(HandshakeError::InvalidMessage);
        }
        Ok(payload[CHAT_PAYLOAD_HEADER..end].to_vec())
    }

    pub fn local_public_key(&self) -> &[u8; 32] {
        &self.local_key
    }

    pub(crate) fn relay_credentials(&self) -> (&Keys, PublicKey, &[u8; 16]) {
        (
            &self.local_relay_keys,
            self.peer_relay_key,
            &self.session_tag,
        )
    }
}

/// Relay-compatible envelope ordering for one confirmed Noise session. The
/// relay sees a per-session tag, direction-local sequence, and ciphertext; it
/// cannot read the application payload. The tag is linkable within this
/// session, but is derived from fresh handshake material, not the identity.
pub struct SessionTransport {
    channel: ActiveChannel,
    send_sequence: u64,
    receive_sequence: u64,
    buffered: BTreeMap<u64, Vec<u8>>,
    closed: bool,
    /// When the oldest frame that is still held back began waiting for an earlier one.
    gap_since: Option<Instant>,
    /// Key changes already applied to the receiving direction.
    receive_rekeys: u64,
    rekey_interval: u64,
    /// The Noise nonce of the first chat frame. The handshake, the identity proofs and the
    /// confirmation frames use nonces before it, so the frame with sequence `n` was
    /// encrypted with nonce `receive_base_nonce + n`, not `n`.
    receive_base_nonce: u64,
}

impl SessionTransport {
    pub fn new(channel: ActiveChannel) -> Self {
        let receive_base_nonce = channel.receiving_nonce();
        Self {
            channel,
            send_sequence: 0,
            receive_sequence: 0,
            buffered: BTreeMap::new(),
            closed: false,
            gap_since: None,
            receive_rekeys: 0,
            rekey_interval: REKEY_INTERVAL,
            receive_base_nonce,
        }
    }

    /// Encodes one encrypted message for relay forwarding.
    pub fn send(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        self.ensure_open()?;
        let sequence = self.send_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(HandshakeError::SequenceExhausted)?;
        let ciphertext = self.channel.write_message(message)?;
        self.send_sequence = next_sequence;
        // The peer derives the same key from the sequence number, so a lost frame cannot
        // put the two directions out of step.
        if next_sequence % self.rekey_interval == 0 {
            self.channel.rekey_outgoing();
        }
        let mut envelope = Vec::with_capacity(ENVELOPE_HEADER + ciphertext.len());
        envelope.extend_from_slice(&sequence.to_be_bytes());
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// Accepts one relay frame. Out-of-order frames are held in a bounded
    /// window; duplicates already delivered or buffered are ignored. Returns
    /// zero or more application messages in sequence order.
    pub fn receive(&mut self, envelope: &[u8]) -> Result<Vec<Vec<u8>>, HandshakeError> {
        self.ensure_open()?;
        if envelope.len() < ENVELOPE_HEADER + FRAME_TAG
            || envelope.len() > ENVELOPE_HEADER + MAX_FRAME
        {
            return Err(HandshakeError::InvalidEnvelope);
        }
        let sequence = u64::from_be_bytes(
            envelope[..ENVELOPE_HEADER]
                .try_into()
                .map_err(|_| HandshakeError::InvalidEnvelope)?,
        );
        if sequence < self.receive_sequence {
            return Ok(Vec::new());
        }
        if sequence - self.receive_sequence >= MAX_REORDER {
            return Err(HandshakeError::OutsideReorderWindow);
        }
        let ciphertext = &envelope[ENVELOPE_HEADER..];
        if let Some(buffered) = self.buffered.get(&sequence) {
            if buffered == ciphertext {
                return Ok(Vec::new());
            }
            self.closed = true;
            self.buffered.clear();
            return Err(HandshakeError::InvalidEnvelope);
        }
        self.buffered.insert(sequence, ciphertext.to_vec());

        let mut messages = Vec::new();
        self.deliver_in_order(&mut messages)?;
        self.update_gap_clock(Instant::now());
        Ok(messages)
    }

    /// Delivers every buffered frame that is next in sequence.
    fn deliver_in_order(&mut self, messages: &mut Vec<Vec<u8>>) -> Result<(), HandshakeError> {
        while let Some(ciphertext) = self.buffered.remove(&self.receive_sequence) {
            match self.decrypt_at(self.receive_sequence, &ciphertext) {
                Ok(message) => messages.push(message),
                Err(error) => {
                    self.closed = true;
                    self.buffered.clear();
                    return Err(error);
                }
            }
            let Some(next) = self.receive_sequence.checked_add(1) else {
                self.closed = true;
                self.buffered.clear();
                return Err(HandshakeError::SequenceExhausted);
            };
            self.receive_sequence = next;
        }
        Ok(())
    }

    /// Decrypts the frame with sequence number `sequence`. The key is the one in force at
    /// that number, so any key changes before it are applied first, in order, whether or
    /// not the frames in between ever arrived, and the nonce is set to the sequence.
    fn decrypt_at(&mut self, sequence: u64, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let epoch = sequence / self.rekey_interval;
        while self.receive_rekeys < epoch {
            self.channel.rekey_incoming();
            self.receive_rekeys += 1;
        }
        self.channel
            .set_receiving_nonce(self.receive_base_nonce + sequence);
        self.channel.read_message(ciphertext)
    }

    fn update_gap_clock(&mut self, now: Instant) {
        self.gap_since = if self.buffered.is_empty() {
            None
        } else {
            self.gap_since.or(Some(now))
        };
    }

    /// Makes the current hole look as though it had been open for `age`, so a test does not
    /// have to wait for the real timeout.
    #[cfg(test)]
    pub(crate) fn age_gap_for_test(&mut self, age: std::time::Duration) {
        if let Some(since) = self.gap_since {
            self.gap_since = Some(since.checked_sub(age).unwrap_or(since));
        }
    }

    /// Gives up on frames that never arrived once the hole has stayed open for
    /// `GAP_TIMEOUT`: the receiver jumps to the first frame it does hold and delivers
    /// from there. Returns the messages that became deliverable and how many sequence
    /// numbers were skipped; the caller should tell the user that messages may have been
    /// lost. A skipped frame that turns up later is ignored. Call this periodically.
    pub fn skip_expired_gap(
        &mut self,
        now: Instant,
    ) -> Result<(Vec<Vec<u8>>, u64), HandshakeError> {
        self.ensure_open()?;
        let Some(since) = self.gap_since else {
            return Ok((Vec::new(), 0));
        };
        if now.saturating_duration_since(since) < GAP_TIMEOUT {
            return Ok((Vec::new(), 0));
        }
        let Some(&first_held) = self.buffered.keys().next() else {
            self.gap_since = None;
            return Ok((Vec::new(), 0));
        };
        let skipped = first_held - self.receive_sequence;
        self.receive_sequence = first_held;
        let mut messages = Vec::new();
        self.deliver_in_order(&mut messages)?;
        self.gap_since = None;
        self.update_gap_clock(now);
        Ok((messages, skipped))
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn relay_credentials(&self) -> (&Keys, PublicKey, &[u8; 16]) {
        self.channel.relay_credentials()
    }

    fn ensure_open(&self) -> Result<(), HandshakeError> {
        if self.closed {
            Err(HandshakeError::Closed)
        } else {
            Ok(())
        }
    }
}

fn identity_proof_input(
    hash: &[u8; HASH_SIZE],
    role: Role,
    key: &[u8; 32],
    relay_key: &[u8; 32],
    commitment: &[u8; HASH_SIZE],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGN_DOMAIN.len() + 1 + HASH_SIZE + 64 + HASH_SIZE);
    input.extend_from_slice(SIGN_DOMAIN);
    input.push(role.byte());
    input.extend_from_slice(hash);
    input.extend_from_slice(key);
    input.extend_from_slice(relay_key);
    input.extend_from_slice(commitment);
    input
}

fn generate_relay_keys() -> Result<Keys, HandshakeError> {
    for _ in 0..8 {
        let mut secret = Zeroizing::new([0_u8; 32]);
        crate::random::fill(secret.as_mut()).map_err(|_| HandshakeError::InvalidRelayKey)?;
        if let Ok(secret) = SecretKey::from_slice(secret.as_ref()) {
            return Ok(Keys::new(secret));
        }
    }
    Err(HandshakeError::InvalidRelayKey)
}

fn commitment(role: Role, nonce: &[u8; NONCE_SIZE]) -> [u8; HASH_SIZE] {
    let mut digest = Sha256::new();
    digest.update(COMMIT_DOMAIN);
    digest.update([role.byte()]);
    digest.update(nonce);
    digest.finalize().into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// Binds the transcript, both identities and both revealed random values. Each
/// argument is (identity key, random value) for one side.
fn fingerprint(
    hash: &[u8; HASH_SIZE],
    role: Role,
    local: (&[u8; 32], &[u8; NONCE_SIZE]),
    peer: (&[u8; 32], &[u8; NONCE_SIZE]),
) -> [u8; HASH_SIZE] {
    let (initiator, responder) = match role {
        Role::Initiator => (local, peer),
        Role::Responder => (peer, local),
    };
    let mut digest = Sha256::new();
    digest.update(CONFIRM_DOMAIN);
    digest.update(hash);
    digest.update(initiator.0);
    digest.update(responder.0);
    digest.update(initiator.1);
    digest.update(responder.1);
    digest.finalize().into()
}

/// The short code users compare: twelve decimal digits (about 40 bits) in two groups,
/// derived from the fingerprint. Because both random values are committed before
/// either is revealed, a man in the middle cannot pick values that make the codes on
/// his two connections agree; he can only guess, once per attempt.
pub fn confirmation_code(fingerprint: &[u8; HASH_SIZE]) -> String {
    let value = u64::from_be_bytes(fingerprint[..8].try_into().expect("fixed digest prefix"))
        % 1_000_000_000_000;
    format!("{:06} {:06}", value / 1_000_000, value % 1_000_000)
}

fn session_tag(hash: &[u8; HASH_SIZE]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(ROUTE_DOMAIN);
    digest.update(hash);
    let full: [u8; HASH_SIZE] = digest.finalize().into();
    full[..16].try_into().expect("fixed digest prefix")
}

fn encrypt(
    transport: &mut snow::TransportState,
    payload: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    if payload.len() + FRAME_TAG > MAX_FRAME {
        return Err(HandshakeError::InvalidMessage);
    }
    let mut frame = vec![0; payload.len() + FRAME_TAG];
    let length = transport.write_message(payload, &mut frame)?;
    frame.truncate(length);
    Ok(frame)
}

fn decrypt(
    transport: &mut snow::TransportState,
    frame: &[u8],
    max_payload: usize,
) -> Result<Zeroizing<Vec<u8>>, HandshakeError> {
    if frame.len() < FRAME_TAG || frame.len() > max_payload + FRAME_TAG {
        return Err(HandshakeError::InvalidMessage);
    }
    let mut payload = Zeroizing::new(vec![0; frame.len() - FRAME_TAG]);
    let length = transport.read_message(frame, &mut payload)?;
    payload.truncate(length);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{ActiveChannel, Handshake, HandshakeError, Role, VerificationPending};
    use crate::identity::Identity;
    use std::time::{Duration, Instant};

    fn identity() -> Identity {
        Identity::create().unwrap().0
    }

    fn exchange() -> (VerificationPending, VerificationPending) {
        let alice = identity();
        let bob = identity();
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        let (a_pending, a_proof) = a.finish().unwrap().prove_identity(&alice).unwrap();
        let (b_pending, b_proof) = b.finish().unwrap().prove_identity(&bob).unwrap();
        // Each side reveals only after it has the other's commitment.
        let (a_reveal_state, a_reveal) = a_pending.receive_peer_proof(&b_proof, None).unwrap();
        let (b_reveal_state, b_reveal) = b_pending.receive_peer_proof(&a_proof, None).unwrap();
        let a_verified = a_reveal_state.receive_peer_reveal(&b_reveal).unwrap();
        let b_verified = b_reveal_state.receive_peer_reveal(&a_reveal).unwrap();
        (a_verified, b_verified)
    }

    /// A completed handshake with identity proofs sent but nothing received yet.
    fn proofs_sent() -> (
        super::IdentityPending,
        Vec<u8>,
        super::IdentityPending,
        Vec<u8>,
    ) {
        let (a, b) = handshake_pair();
        let (a_pending, a_proof) = a.finish().unwrap().prove_identity(&identity()).unwrap();
        let (b_pending, b_proof) = b.finish().unwrap().prove_identity(&identity()).unwrap();
        (a_pending, a_proof, b_pending, b_proof)
    }

    fn confirm_pair(
        a: VerificationPending,
        b: VerificationPending,
    ) -> (ActiveChannel, ActiveChannel) {
        assert_eq!(a.fingerprint(), b.fingerprint());
        let (a_pending, a_frame) = a.confirm_after_user_check().unwrap();
        let (b_pending, b_frame) = b.confirm_after_user_check().unwrap();
        (
            a_pending.receive_peer_confirmation(&b_frame).unwrap(),
            b_pending.receive_peer_confirmation(&a_frame).unwrap(),
        )
    }

    fn handshake_pair() -> (Handshake, Handshake) {
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        (a, b)
    }

    #[test]
    fn completed_handshakes_match_and_each_connection_is_fresh() {
        let (a, b) = handshake_pair();
        let first = a.finish().unwrap().hash;
        assert_eq!(first, b.finish().unwrap().hash);
        let (a, b) = handshake_pair();
        assert_eq!(a.role, Role::Initiator);
        assert_eq!(b.role, Role::Responder);
        assert_ne!(first, a.finish().unwrap().hash);
        b.finish().unwrap();
    }

    #[test]
    fn tampered_handshake_is_rejected_and_cannot_continue() {
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        let mut message = b.write().unwrap();
        let last = message.len() - 1;
        message[last] ^= 1;
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

    #[test]
    fn identity_proofs_bind_both_identities_to_same_session() {
        let (a, b) = exchange();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.peer_public_key(), b.peer_public_key());
    }

    #[test]
    fn chat_is_only_available_after_both_confirmation_frames() {
        let (a, b) = exchange();
        let (mut a, mut b) = confirm_pair(a, b);
        let frame = a.write_message(b"hello").unwrap();
        assert_eq!(b.read_message(&frame).unwrap(), b"hello");
        let reply = b.write_message(b"world").unwrap();
        assert_eq!(a.read_message(&reply).unwrap(), b"world");
        assert!(a.local_public_key() != a.peer_public_key());
    }

    #[test]
    fn wrong_pinned_identity_is_rejected() {
        let mut first = Handshake::new(Role::Initiator).unwrap();
        let mut second = Handshake::new(Role::Responder).unwrap();
        second.read(&first.write().unwrap()).unwrap();
        first.read(&second.write().unwrap()).unwrap();
        second.read(&first.write().unwrap()).unwrap();
        let left = identity();
        let right = identity();
        let (left, _) = first.finish().unwrap().prove_identity(&left).unwrap();
        let (right, proof) = second.finish().unwrap().prove_identity(&right).unwrap();
        assert!(matches!(
            left.receive_peer_proof(&proof, Some([0; 32])),
            Err(HandshakeError::IdentityMismatch)
        ));
        drop(right);
    }

    #[test]
    fn identity_proof_ciphertext_tampering_is_rejected() {
        let alice = identity();
        let bob = identity();
        let mut a = Handshake::new(Role::Initiator).unwrap();
        let mut b = Handshake::new(Role::Responder).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        a.read(&b.write().unwrap()).unwrap();
        b.read(&a.write().unwrap()).unwrap();
        let (a, _) = a.finish().unwrap().prove_identity(&alice).unwrap();
        let (_, mut proof) = b.finish().unwrap().prove_identity(&bob).unwrap();
        let last = proof.len() - 1;
        proof[last] ^= 1;
        assert!(a.receive_peer_proof(&proof, None).is_err());
    }

    #[test]
    fn changed_confirmation_fingerprint_is_rejected() {
        let (a, b) = exchange();
        let (a, a_frame) = a.confirm_after_user_check().unwrap();
        let (b, _) = b.confirm_after_user_check().unwrap();
        let mut modified = a_frame;
        let last = modified.len() - 1;
        modified[last] ^= 1;
        assert!(b.receive_peer_confirmation(&modified).is_err());
        drop(a);
    }

    #[test]
    fn messages_are_bounded_and_tampering_is_rejected() {
        let (a, b) = exchange();
        let (mut a, mut b) = confirm_pair(a, b);
        assert!(a.write_message(&vec![0; 8192]).is_err());
        let mut frame = a.write_message(b"test").unwrap();
        frame[0] ^= 1;
        assert!(b.read_message(&frame).is_err());
    }

    #[test]
    fn relay_frames_buffer_reordering_and_drop_duplicates() {
        let (a, b) = exchange();
        let (a, b) = confirm_pair(a, b);
        let mut sender = super::SessionTransport::new(a);
        let mut receiver = super::SessionTransport::new(b);
        let first = sender.send(b"first").unwrap();
        let second = sender.send(b"second").unwrap();

        assert!(receiver.receive(&second).unwrap().is_empty());
        assert_eq!(
            receiver.receive(&first).unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
        assert!(receiver.receive(&first).unwrap().is_empty());
        assert!(!receiver.is_closed());
    }

    /// A connected pair of session transports.
    fn transport_pair() -> (super::SessionTransport, super::SessionTransport) {
        let (a, b) = exchange();
        let (a, b) = confirm_pair(a, b);
        (
            super::SessionTransport::new(a),
            super::SessionTransport::new(b),
        )
    }

    /// A connected pair whose key changes every `interval` messages, so a test can cross
    /// several key changes without sending a thousand messages.
    fn transport_pair_rekeying_every(
        interval: u64,
    ) -> (super::SessionTransport, super::SessionTransport) {
        let (mut sender, mut receiver) = transport_pair();
        sender.rekey_interval = interval;
        receiver.rekey_interval = interval;
        (sender, receiver)
    }

    fn at(base: Instant, seconds: u64) -> Instant {
        base + Duration::from_secs(seconds)
    }

    #[test]
    fn a_lost_frame_stops_delivery_only_until_the_gap_times_out() {
        let (mut sender, mut receiver) = transport_pair();
        let start = Instant::now();
        sender.send(b"lost in transit").unwrap();
        let mut held = Vec::new();
        for index in 0..5_u8 {
            let frame = sender.send(&[index]).unwrap();
            held.push(receiver.receive(&frame).unwrap());
        }
        assert!(
            held.iter().all(Vec::is_empty),
            "frames after the hole are held back"
        );
        // Before the timeout nothing is given up.
        let (messages, skipped) = receiver.skip_expired_gap(at(start, 1)).unwrap();
        assert!(messages.is_empty());
        assert_eq!(skipped, 0);
        // After it, the receiver moves past the hole and delivers what it holds, in order.
        let (messages, skipped) = receiver
            .skip_expired_gap(start + super::GAP_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(
            messages,
            (0..5_u8).map(|index| vec![index]).collect::<Vec<_>>()
        );
        assert!(!receiver.is_closed());
        // The conversation carries on normally.
        let next = sender.send(b"after the loss").unwrap();
        assert_eq!(
            receiver.receive(&next).unwrap(),
            vec![b"after the loss".to_vec()]
        );
    }

    #[test]
    fn a_skipped_frame_that_arrives_late_is_ignored_and_cannot_be_replayed() {
        let (mut sender, mut receiver) = transport_pair();
        let start = Instant::now();
        let late = sender.send(b"late").unwrap();
        let next = sender.send(b"next").unwrap();
        assert!(receiver.receive(&next).unwrap().is_empty());
        receiver
            .skip_expired_gap(start + super::GAP_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        // It arrives after all. Its nonce is behind the receiver now, so it is dropped.
        assert!(receiver.receive(&late).unwrap().is_empty());
        assert!(!receiver.is_closed());
        // And a frame that has been delivered cannot be delivered again.
        assert!(receiver.receive(&next).unwrap().is_empty());
    }

    #[test]
    fn a_gap_that_fills_in_time_is_not_skipped_and_nothing_is_reported_lost() {
        let (mut sender, mut receiver) = transport_pair();
        let start = Instant::now();
        let first = sender.send(b"first").unwrap();
        let second = sender.send(b"second").unwrap();
        assert!(receiver.receive(&second).unwrap().is_empty());
        assert_eq!(
            receiver.receive(&first).unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()]
        );
        let (messages, skipped) = receiver
            .skip_expired_gap(start + super::GAP_TIMEOUT * 3)
            .unwrap();
        assert!(messages.is_empty());
        assert_eq!(skipped, 0, "no hole is left, so there is nothing to skip");
    }

    #[test]
    fn several_separate_losses_are_each_counted() {
        let (mut sender, mut receiver) = transport_pair();
        let start = Instant::now();
        let mut skipped_total = 0;
        let mut delivered = Vec::new();
        for round in 0..3_u8 {
            sender.send(b"lost").unwrap();
            let frame = sender.send(&[round]).unwrap();
            assert!(receiver.receive(&frame).unwrap().is_empty());
            let now = start + super::GAP_TIMEOUT * (u32::from(round) + 1) + Duration::from_secs(1);
            let (messages, skipped) = receiver.skip_expired_gap(now).unwrap();
            skipped_total += skipped;
            delivered.extend(messages);
        }
        assert_eq!(skipped_total, 3);
        assert_eq!(delivered, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn frames_keep_flowing_across_many_key_changes() {
        // Sending and receiving derive each new key from the sequence number alone.
        let (mut sender, mut receiver) = transport_pair_rekeying_every(4);
        for index in 0..25_u8 {
            let frame = sender.send(&[index]).unwrap();
            assert_eq!(
                receiver.receive(&frame).unwrap(),
                vec![vec![index]],
                "message {index}"
            );
        }
        // And in the other direction too.
        for index in 0..25_u8 {
            let frame = receiver.send(&[index]).unwrap();
            assert_eq!(
                sender.receive(&frame).unwrap(),
                vec![vec![index]],
                "reply {index}"
            );
        }
    }

    #[test]
    fn a_hole_that_spans_a_key_change_is_crossed_with_the_right_key() {
        // Frames 3..=5 are lost; the key changes after frame 3 (interval 4), so the
        // receiver must apply the change for a frame it never saw before reading frame 6.
        let (mut sender, mut receiver) = transport_pair_rekeying_every(4);
        let start = Instant::now();
        for index in 0..3_u8 {
            let frame = sender.send(&[index]).unwrap();
            assert_eq!(receiver.receive(&frame).unwrap(), vec![vec![index]]);
        }
        for _ in 3..9 {
            sender.send(b"lost").unwrap();
        }
        let mut after = Vec::new();
        for index in 9..14_u8 {
            let frame = sender.send(&[index]).unwrap();
            assert!(receiver.receive(&frame).unwrap().is_empty());
            after.push(index);
        }
        let (messages, skipped) = receiver
            .skip_expired_gap(start + super::GAP_TIMEOUT + Duration::from_secs(1))
            .unwrap();
        assert_eq!(skipped, 6);
        assert_eq!(
            messages,
            after.iter().map(|index| vec![*index]).collect::<Vec<_>>()
        );
        assert!(!receiver.is_closed());
        // Later frames, in later key periods, still decrypt.
        for index in 20..30_u8 {
            let frame = sender.send(&[index]).unwrap();
            assert_eq!(receiver.receive(&frame).unwrap(), vec![vec![index]]);
        }
    }

    #[test]
    fn the_real_key_change_interval_is_crossed_without_a_problem() {
        // The default interval, not a shortened one: send a little past it both ways.
        let (mut sender, mut receiver) = transport_pair();
        assert_eq!(sender.rekey_interval, super::REKEY_INTERVAL);
        for index in 0..(super::REKEY_INTERVAL + 5) {
            let frame = sender.send(&index.to_be_bytes()).unwrap();
            let messages = receiver.receive(&frame).unwrap();
            assert_eq!(
                messages,
                vec![index.to_be_bytes().to_vec()],
                "message {index}"
            );
        }
    }

    #[test]
    fn a_key_change_means_old_ciphertext_does_not_open_with_the_new_key() {
        // A frame sent before the key change must not decrypt as if it came after it.
        let (mut sender, mut receiver) = transport_pair_rekeying_every(2);
        let first = sender.send(b"one").unwrap();
        let second = sender.send(b"two").unwrap();
        assert!(receiver.receive(&first).is_ok());
        assert!(receiver.receive(&second).is_ok());
        // Sequence 2 is in the next key period. Encrypt it, then claim it is sequence 0:
        // the receiver has moved on, so it is treated as an old duplicate and ignored.
        let third = sender.send(b"three").unwrap();
        let mut forged = third.clone();
        forged[..super::ENVELOPE_HEADER].copy_from_slice(&0_u64.to_be_bytes());
        assert!(receiver.receive(&forged).unwrap().is_empty());
        assert_eq!(receiver.receive(&third).unwrap(), vec![b"three".to_vec()]);
    }

    #[test]
    fn messages_of_different_lengths_produce_envelopes_of_the_same_length() {
        let (mut sender, mut receiver) = transport_pair();
        let lengths: Vec<usize> = [0_usize, 1, 2, 100, 200, 251]
            .iter()
            .map(|size| {
                let frame = sender.send(&vec![b'x'; *size]).unwrap();
                let received = receiver.receive(&frame).unwrap();
                assert_eq!(received, vec![vec![b'x'; *size]], "size {size} round trip");
                frame.len()
            })
            .collect();
        // Everything up to 252 bytes of message falls in the smallest class.
        assert!(
            lengths.iter().all(|length| *length == lengths[0]),
            "{lengths:?}"
        );
        assert_eq!(lengths[0], super::ENVELOPE_HEADER + 256 + 16);
    }

    #[test]
    fn padding_classes_are_the_documented_sizes_and_the_largest_message_fits() {
        let (mut sender, _receiver) = transport_pair();
        let class_of = |sender: &mut super::SessionTransport, size: usize| {
            sender.send(&vec![b'y'; size]).unwrap().len() - super::ENVELOPE_HEADER - 16
        };
        // The payload header is 4 bytes, so a message of `size` needs `size + 4` bytes.
        assert_eq!(class_of(&mut sender, 252), 256);
        assert_eq!(class_of(&mut sender, 253), 1024);
        assert_eq!(class_of(&mut sender, 1020), 1024);
        assert_eq!(class_of(&mut sender, 1021), 4096);
        assert_eq!(class_of(&mut sender, 4092), 4096);
        assert_eq!(class_of(&mut sender, 4093), 8176);
        // The largest message a frame can carry round trips and fills the envelope limit.
        let largest = super::ActiveChannel::MAX_MESSAGE;
        let (mut big_sender, mut big_receiver) = transport_pair();
        let frame = big_sender.send(&vec![7; largest]).unwrap();
        assert_eq!(frame.len(), super::MAX_ENVELOPE);
        assert_eq!(
            big_receiver.receive(&frame).unwrap(),
            vec![vec![7; largest]]
        );
        // One byte more cannot be sent at all.
        assert!(matches!(
            big_sender.send(&vec![7; largest + 1]),
            Err(HandshakeError::InvalidMessage)
        ));
    }

    /// A chat frame whose payload the sender chose byte for byte, as a peer that does not
    /// follow the padding rules would send. The receiver must decide what to accept.
    fn raw_chat_frame(payload: &[u8]) -> (ActiveChannel, Vec<u8>) {
        let (a, b) = exchange();
        let (mut a, b) = confirm_pair(a, b);
        let frame = super::encrypt(&mut a.transport, payload).unwrap();
        (b, frame)
    }

    /// `exchange` makes the sender the initiator, so its frames carry the initiator byte;
    /// the well-formed case below would fail if that were not so.
    fn chat_payload(length_field: u16, message: &[u8], total: usize, filler: u8) -> Vec<u8> {
        let mut payload = vec![super::FRAME_KIND_CHAT, Role::Initiator.byte()];
        payload.extend_from_slice(&length_field.to_be_bytes());
        payload.extend_from_slice(message);
        payload.resize(total, filler);
        payload
    }

    #[test]
    fn a_well_formed_padded_frame_is_accepted() {
        let (mut receiver, frame) = raw_chat_frame(&chat_payload(5, b"hello", 256, 0));
        assert_eq!(receiver.read_message(&frame).unwrap(), b"hello");
    }

    #[test]
    fn padding_that_is_not_all_zeros_is_rejected() {
        // Non-zero padding would let a peer smuggle bytes the length field does not show.
        for filler in [1_u8, 0xff] {
            let (mut receiver, frame) = raw_chat_frame(&chat_payload(5, b"hello", 256, filler));
            assert!(matches!(
                receiver.read_message(&frame),
                Err(HandshakeError::InvalidMessage)
            ));
        }
        // A single stray byte at the very end is enough to reject it.
        let mut payload = chat_payload(5, b"hello", 256, 0);
        *payload.last_mut().unwrap() = 1;
        let (mut receiver, frame) = raw_chat_frame(&payload);
        assert!(matches!(
            receiver.read_message(&frame),
            Err(HandshakeError::InvalidMessage)
        ));
    }

    #[test]
    fn a_payload_size_outside_the_padding_classes_is_rejected() {
        for total in [8_usize, 255, 257, 1000, 4097, 8000] {
            let (mut receiver, frame) = raw_chat_frame(&chat_payload(2, b"hi", total, 0));
            assert!(
                matches!(
                    receiver.read_message(&frame),
                    Err(HandshakeError::InvalidMessage)
                ),
                "payload of {total} bytes"
            );
        }
    }

    #[test]
    fn a_length_field_that_overruns_the_payload_is_rejected() {
        let (mut receiver, frame) = raw_chat_frame(&chat_payload(300, b"short", 256, 0));
        assert!(matches!(
            receiver.read_message(&frame),
            Err(HandshakeError::InvalidMessage)
        ));
    }

    #[test]
    fn a_frame_with_the_wrong_kind_or_the_wrong_sender_role_is_rejected() {
        let mut wrong_kind = chat_payload(2, b"hi", 256, 0);
        wrong_kind[0] = 9;
        let (mut receiver, frame) = raw_chat_frame(&wrong_kind);
        assert!(matches!(
            receiver.read_message(&frame),
            Err(HandshakeError::InvalidMessage)
        ));
        // A frame that claims to come from the receiver's own role is a reflection.
        let mut reflected = chat_payload(2, b"hi", 256, 0);
        reflected[1] = Role::Responder.byte();
        let (mut receiver, frame) = raw_chat_frame(&reflected);
        assert!(matches!(
            receiver.read_message(&frame),
            Err(HandshakeError::InvalidMessage)
        ));
    }

    #[test]
    fn a_frame_from_another_session_does_not_decrypt_and_ends_the_session() {
        // The envelope no longer names its session: a frame is attributed to a session by
        // the topic tag and the signature of the event that carried it, and by being
        // decryptable at all. A frame encrypted for some other session is not.
        let (mut sender, mut receiver) = transport_pair();
        let (mut stranger, _) = transport_pair();
        let foreign = stranger.send(b"hello").unwrap();
        assert!(matches!(
            receiver.receive(&foreign),
            Err(HandshakeError::Noise(_))
        ));
        assert!(
            receiver.is_closed(),
            "an undecryptable frame ends the session"
        );
        // The genuine frame can no longer be delivered once the session is closed.
        let genuine = sender.send(b"hello").unwrap();
        assert!(matches!(
            receiver.receive(&genuine),
            Err(HandshakeError::Closed)
        ));
    }

    #[test]
    fn out_of_window_frames_are_rejected_without_closing_the_session() {
        let (mut sender, mut receiver) = transport_pair();
        let mut far_future = sender.send(b"next").unwrap();
        far_future[..super::ENVELOPE_HEADER].copy_from_slice(&32_u64.to_be_bytes());
        assert!(matches!(
            receiver.receive(&far_future),
            Err(HandshakeError::OutsideReorderWindow)
        ));
        // The window check happens before any decryption, so nothing was consumed.
        let in_order = sender.send(b"after").unwrap();
        assert!(!receiver.is_closed());
        // `in_order` has sequence 1 and the receiver still expects 0: held, not lost.
        assert!(receiver.receive(&in_order).unwrap().is_empty());
    }

    #[test]
    fn an_envelope_too_short_or_too_long_is_rejected() {
        let (_sender, mut receiver) = transport_pair();
        let header_only = vec![0_u8; super::ENVELOPE_HEADER];
        assert!(matches!(
            receiver.receive(&header_only),
            Err(HandshakeError::InvalidEnvelope)
        ));
        let too_long = vec![0_u8; super::MAX_ENVELOPE + 1];
        assert!(matches!(
            receiver.receive(&too_long),
            Err(HandshakeError::InvalidEnvelope)
        ));
        assert!(!receiver.is_closed());
    }

    #[test]
    fn ciphertext_failure_closes_session_transport() {
        let (a, b) = exchange();
        let (a, b) = confirm_pair(a, b);
        let mut sender = super::SessionTransport::new(a);
        let mut receiver = super::SessionTransport::new(b);
        let mut tampered = sender.send(b"hello").unwrap();
        tampered[super::ENVELOPE_HEADER] ^= 1;
        assert!(receiver.receive(&tampered).is_err());
        assert!(receiver.is_closed());
        assert!(matches!(
            receiver.receive(&tampered),
            Err(HandshakeError::Closed)
        ));
    }

    #[test]
    fn both_users_see_the_same_short_code_in_two_groups_of_six_digits() {
        let (a, b) = exchange();
        let code = a.confirmation_code();
        assert_eq!(code, b.confirmation_code());
        let groups: Vec<_> = code.split(' ').collect();
        assert_eq!(groups.len(), 2, "{code}");
        for group in groups {
            assert_eq!(group.len(), 6, "{code}");
            assert!(group.bytes().all(|byte| byte.is_ascii_digit()), "{code}");
        }
        // A new session gives a different code.
        let (other, _) = exchange();
        assert_ne!(code, other.confirmation_code());
    }

    #[test]
    fn the_code_uses_the_whole_twelve_digit_range_not_a_smaller_one() {
        // The code is only worth its length if both groups really vary. Derive codes from
        // many different fingerprints and require that each group takes many values and
        // that high digits appear, which a code squeezed into a smaller range would not.
        let mut first_groups = std::collections::HashSet::new();
        let mut second_groups = std::collections::HashSet::new();
        let mut leading_digits = std::collections::HashSet::new();
        for index in 0_u32..2000 {
            let mut fingerprint = [0_u8; 32];
            let digest = <sha2::Sha256 as sha2::Digest>::digest(index.to_be_bytes());
            fingerprint.copy_from_slice(&digest);
            let code = super::confirmation_code(&fingerprint);
            let (first, second) = code.split_once(' ').unwrap();
            first_groups.insert(first.to_owned());
            second_groups.insert(second.to_owned());
            leading_digits.insert(first.as_bytes()[0]);
        }
        // With 2000 samples from 10^6 values, nearly all are distinct per group.
        assert!(
            first_groups.len() > 1900,
            "first group varies: {}",
            first_groups.len()
        );
        assert!(
            second_groups.len() > 1900,
            "second group varies: {}",
            second_groups.len()
        );
        assert_eq!(leading_digits.len(), 10, "every leading digit 0-9 occurs");
    }

    #[test]
    fn the_code_depends_on_both_random_values_and_on_the_transcript() {
        let hash = [7; 32];
        let (alice, bob) = ([1; 32], [2; 32]);
        let (first, second) = ([3; 16], [4; 16]);
        let base = super::fingerprint(&hash, Role::Initiator, (&alice, &first), (&bob, &second));
        // Both sides compute the same value from their own point of view.
        assert_eq!(
            base,
            super::fingerprint(&hash, Role::Responder, (&bob, &second), (&alice, &first))
        );
        let changed_initiator_nonce =
            super::fingerprint(&hash, Role::Initiator, (&alice, &[9; 16]), (&bob, &second));
        let changed_responder_nonce =
            super::fingerprint(&hash, Role::Initiator, (&alice, &first), (&bob, &[9; 16]));
        let changed_transcript =
            super::fingerprint(&[8; 32], Role::Initiator, (&alice, &first), (&bob, &second));
        let changed_identity =
            super::fingerprint(&hash, Role::Initiator, (&[5; 32], &first), (&bob, &second));
        for other in [
            changed_initiator_nonce,
            changed_responder_nonce,
            changed_transcript,
            changed_identity,
        ] {
            assert_ne!(base, other);
            assert_ne!(
                super::confirmation_code(&base),
                super::confirmation_code(&other)
            );
        }
    }

    #[test]
    fn a_value_that_does_not_open_the_commitment_is_rejected() {
        let (a_pending, _a_proof, b_pending, b_proof) = proofs_sent();
        // `a` has b's commitment. A reveal from anyone who did not make that commitment
        // must not be accepted, even though it is a well-formed frame from `b`'s transport.
        let (a_reveal_state, _a_reveal) = a_pending.receive_peer_proof(&b_proof, None).unwrap();
        let mut forged = b_pending;
        let mut reveal = vec![Role::Responder.byte()];
        reveal.extend_from_slice(&[0xAA; super::NONCE_SIZE]);
        let frame = super::encrypt(&mut forged.transport, &reveal).unwrap();
        // The proof was already consumed by the peer, so the transport counter lines up.
        assert!(matches!(
            a_reveal_state.receive_peer_reveal(&frame),
            Err(HandshakeError::CommitmentMismatch)
        ));
    }

    #[test]
    fn a_reveal_from_the_wrong_role_or_of_the_wrong_size_is_rejected() {
        for (role_byte, nonce_length) in [
            (Role::Initiator.byte(), 16),
            (Role::Responder.byte(), 15),
            (Role::Responder.byte(), 17),
        ] {
            let (a_pending, _a_proof, mut b_pending, b_proof) = proofs_sent();
            let (a_reveal_state, _) = a_pending.receive_peer_proof(&b_proof, None).unwrap();
            let mut reveal = vec![role_byte];
            reveal.extend(std::iter::repeat_n(1_u8, nonce_length));
            let frame = super::encrypt(&mut b_pending.transport, &reveal).unwrap();
            assert!(
                matches!(
                    a_reveal_state.receive_peer_reveal(&frame),
                    Err(HandshakeError::InvalidProof | HandshakeError::InvalidMessage)
                ),
                "role {role_byte}, nonce length {nonce_length}"
            );
        }
    }

    /// A proof frame from a responder that signs `signed_commitment` but puts
    /// `sent_commitment` in the frame. It is that responder's first frame, so the
    /// receiver's transport counter lines up.
    fn responder_proof_for(
        signed_commitment: &[u8; 32],
        sent_commitment: &[u8; 32],
    ) -> (super::IdentityPending, Vec<u8>) {
        let (a, b) = handshake_pair();
        let (receiver, _) = a.finish().unwrap().prove_identity(&identity()).unwrap();
        let mut sender = b.finish().unwrap();
        let signer = identity();
        let key = signer.public_key();
        let relay_key = super::generate_relay_keys()
            .unwrap()
            .public_key()
            .to_bytes();
        let signature = signer.sign(&super::identity_proof_input(
            &sender.hash,
            Role::Responder,
            &key,
            &relay_key,
            signed_commitment,
        ));
        let mut proof = vec![Role::Responder.byte()];
        proof.extend_from_slice(&key);
        proof.extend_from_slice(&relay_key);
        proof.extend_from_slice(sent_commitment);
        proof.extend_from_slice(&signature);
        assert_eq!(proof.len(), super::PROOF_SIZE);
        (
            receiver,
            super::encrypt(&mut sender.transport, &proof).unwrap(),
        )
    }

    #[test]
    fn the_commitment_is_signed_with_the_identity_so_it_cannot_be_swapped() {
        let signed = super::commitment(Role::Responder, &[1; super::NONCE_SIZE]);
        let other = super::commitment(Role::Responder, &[2; super::NONCE_SIZE]);
        // The commitment the signature covers is accepted.
        let (receiver, frame) = responder_proof_for(&signed, &signed);
        assert!(receiver.receive_peer_proof(&frame, None).is_ok());
        // The same proof carrying a different commitment is not, so a commitment cannot
        // be replaced in transit without the identity key.
        let (receiver, frame) = responder_proof_for(&signed, &other);
        assert!(matches!(
            receiver.receive_peer_proof(&frame, None),
            Err(HandshakeError::InvalidProof)
        ));
    }

    #[test]
    fn a_peer_on_protocol_version_two_cannot_complete_the_handshake() {
        // The prologue differs between versions, so the Noise transcript does not match.
        let mut current = Handshake::new(Role::Initiator).unwrap();
        let params = super::PATTERN.parse().unwrap();
        let keypair = snow::Builder::new(super::PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut previous = snow::Builder::new(params)
            .prologue(b"another-dimension-v2/noise-handshake/v2")
            .unwrap()
            .local_private_key(&keypair.private)
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buffer = [0; 128];
        let mut payload = [0; 128];
        let first = current.write().unwrap();
        // XX's first message carries no authenticated data, so the responder reads it
        // and the mismatch shows from the second message on.
        previous.read_message(&first, &mut payload).unwrap();
        let length = previous.write_message(&[], &mut buffer).unwrap();
        assert!(current.read(&buffer[..length]).is_err());
    }
}
