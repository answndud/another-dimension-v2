//! Minimal NIP-01 rendezvous and WebSocket adapter for Noise sessions.
//!
//! It publishes only kind-20000 ephemeral events. The relay still observes the
//! session tag, timing, size, and connection IP in direct mode. No relay URL or
//! Tor policy is selected here; callers must enforce those policies.

use crate::channel::{
    Handshake, HandshakeError, PendingChannel, Role, SessionTransport, VerificationPending,
};
use crate::identity::Identity;
use hkdf::Hkdf;
use nostr::prelude::{
    ClientMessage, Error as NostrError, EventBuilder, Filter, FinalizeEvent, Keys, Kind, PublicKey,
    RelayMessage, SecretKey, SingleLetterTag, SubscriptionId, Tag,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::io::Read;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::client::connect_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use zeroize::Zeroizing;

const EVENT_KIND: u16 = 20_000;
pub const DEFAULT_RELAY: &str = "wss://relay.damus.io";
const SUBSCRIPTION_ID: &str = "ad-v2-live";
const INVITE_PREFIX: &str = "ADI1-";
const INVITE_TOPIC_INFO: &[u8] = b"another-dimension-v2/invite-topic/v1";
const INVITE_KEY_INFO: &[u8] = b"another-dimension-v2/invite-relay-key/v1";
const INVITE_DOMAIN: &[u8] = b"another-dimension-v2/invite-code/v1";
const MAX_BOOTSTRAP_FRAME: usize = 256;
const MAX_RELAY_MESSAGE: usize = 16 * 1024;
const MAX_ENVELOPE: usize = 4 + 16 + 8 + 4096;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum RelayError {
    WebSocket(tungstenite::Error),
    Nostr(NostrError),
    Channel(HandshakeError),
    InvalidEndpoint,
    Io(io::Error),
    InvalidEvent,
    SubscriptionClosed(String),
    RelayRejected { event_id: String, reason: String },
    Disconnected,
    Cancelled,
}

impl From<tungstenite::Error> for RelayError {
    fn from(error: tungstenite::Error) -> Self {
        Self::WebSocket(error)
    }
}

impl From<io::Error> for RelayError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<NostrError> for RelayError {
    fn from(error: NostrError) -> Self {
        Self::Nostr(error)
    }
}

impl From<HandshakeError> for RelayError {
    fn from(error: HandshakeError) -> Self {
        Self::Channel(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelayUpdate {
    Messages(Vec<Vec<u8>>),
    Published { event_id: String },
    Ready,
}

pub struct RelaySession {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    transport: SessionTransport,
    keys: Keys,
    peer_author: PublicKey,
    topic: String,
    subscription: SubscriptionId,
}

impl RelaySession {
    /// Connects only to a TLS WebSocket endpoint and subscribes to this peer's
    /// signed ephemeral events for the current session.
    pub fn connect(endpoint: &str, transport: SessionTransport) -> Result<Self, RelayError> {
        Self::from_socket(open_socket(endpoint)?, transport)
    }

    fn from_socket(
        mut socket: WebSocket<MaybeTlsStream<TcpStream>>,
        transport: SessionTransport,
    ) -> Result<Self, RelayError> {
        let (keys, peer_author, session_tag) = transport.relay_credentials();
        let keys = keys.clone();
        let topic = hex(session_tag);
        let subscription = SubscriptionId::new(SUBSCRIPTION_ID);
        let filter = Filter::new()
            .kind(Kind::Custom(EVENT_KIND))
            .custom_tag(SingleLetterTag::LOWERCASE_T, topic.clone())
            .author(peer_author);
        let request = ClientMessage::req(subscription.clone(), vec![filter]);
        socket.send(Message::text(request.as_json()))?;

        Ok(Self {
            socket,
            transport,
            keys,
            peer_author,
            topic,
            subscription,
        })
    }

    /// Encrypts and publishes one live event. The returned identifier is the
    /// event id; relay acceptance arrives separately as `RelayUpdate::Published`.
    pub fn send(&mut self, message: &[u8]) -> Result<String, RelayError> {
        let envelope = self.transport.send(message)?;
        let event = EventBuilder::new(Kind::Custom(EVENT_KIND), hex(&envelope))
            .tag(Tag::custom("t", [self.topic.as_str()]))
            .finalize(&self.keys)?;
        let event_id = event.id.to_string();
        self.socket
            .send(Message::text(ClientMessage::event(event).as_json()))?;
        Ok(event_id)
    }

    /// Reads one WebSocket message, returning `None` when the polling timeout expires.
    pub fn poll(&mut self) -> Result<Option<RelayUpdate>, RelayError> {
        let message = match self.socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        match message {
            Message::Text(text) => match RelayMessage::from_json(text.as_str())? {
                RelayMessage::Event {
                    subscription_id,
                    event,
                } => {
                    if subscription_id.as_ref() != &self.subscription {
                        return Ok(None);
                    }
                    let event = event.as_ref();
                    if event.kind != Kind::Custom(EVENT_KIND)
                        || event.pubkey != self.peer_author
                        || event.verify().is_err()
                        || !has_tag(event, "t", &self.topic)
                    {
                        return Ok(None);
                    }
                    let envelope = decode_hex(&event.content).ok_or(RelayError::InvalidEvent)?;
                    let messages = self.transport.receive(&envelope)?;
                    if !messages.is_empty() {
                        return Ok(Some(RelayUpdate::Messages(messages)));
                    }
                }
                RelayMessage::Ok {
                    event_id,
                    status,
                    message,
                } => {
                    if status {
                        return Ok(Some(RelayUpdate::Published {
                            event_id: event_id.to_string(),
                        }));
                    }
                    return Err(RelayError::RelayRejected {
                        event_id: event_id.to_string(),
                        reason: message.to_string(),
                    });
                }
                RelayMessage::EndOfStoredEvents(subscription_id)
                    if subscription_id.as_ref() == &self.subscription =>
                {
                    return Ok(Some(RelayUpdate::Ready));
                }
                RelayMessage::Closed {
                    subscription_id,
                    message,
                } if subscription_id.as_ref() == &self.subscription => {
                    return Err(RelayError::SubscriptionClosed(message.to_string()));
                }
                _ => {}
            },
            Message::Ping(payload) => self.socket.send(Message::Pong(payload))?,
            Message::Close(_) => return Err(RelayError::Disconnected),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
        Ok(None)
    }

    pub fn receive(&mut self) -> Result<RelayUpdate, RelayError> {
        loop {
            if let Some(update) = self.poll()? {
                return Ok(update);
            }
        }
    }
}

fn open_socket(endpoint: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, RelayError> {
    if !endpoint.starts_with("wss://") || endpoint.contains('@') || endpoint.contains('#') {
        return Err(RelayError::InvalidEndpoint);
    }
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_RELAY_MESSAGE);
    config.max_frame_size = Some(MAX_RELAY_MESSAGE);
    let (mut socket, _) = connect_with_config(endpoint, Some(config), 0)?;
    match socket.get_mut() {
        MaybeTlsStream::Rustls(stream) => {
            stream.sock.set_read_timeout(Some(READ_TIMEOUT))?;
            stream.sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
        }
        _ => return Err(RelayError::InvalidEndpoint),
    }
    Ok(socket)
}

/// High-entropy bearer code used only to discover the first connection. Keep
/// it separate from the personal identity code and discard it after use.
pub struct InviteCode {
    secret: Zeroizing<[u8; 32]>,
    display: Zeroizing<String>,
}

impl InviteCode {
    pub fn generate() -> io::Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        File::open("/dev/urandom")?.read_exact(secret.as_mut())?;
        Ok(Self::from_secret(secret))
    }

    pub fn parse(code: &str) -> Option<Self> {
        let hex_code = code.strip_prefix(INVITE_PREFIX)?;
        if hex_code.len() != 64
            || !hex_code
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let mut secret = Zeroizing::new([0_u8; 32]);
        for (index, pair) in hex_code.as_bytes().chunks_exact(2).enumerate() {
            let nibble = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                _ => byte - b'a' + 10,
            };
            secret[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        Some(Self::from_secret(secret))
    }

    pub fn code(&self) -> &str {
        &self.display
    }

    fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let mut display = Zeroizing::new(String::with_capacity(INVITE_PREFIX.len() + 64));
        display.push_str(INVITE_PREFIX);
        display.push_str(&hex(secret.as_ref()));
        Self { secret, display }
    }

    fn relay_material(&self) -> Result<(String, Keys), RelayError> {
        let hkdf = Hkdf::<Sha256>::new(Some(INVITE_DOMAIN), self.secret.as_ref());
        let mut topic = [0_u8; 32];
        hkdf.expand(INVITE_TOPIC_INFO, &mut topic)
            .map_err(|_| RelayError::InvalidEvent)?;
        for counter in 0_u8..=u8::MAX {
            let mut info = Vec::with_capacity(INVITE_KEY_INFO.len() + 1);
            info.extend_from_slice(INVITE_KEY_INFO);
            info.push(counter);
            let mut bytes = Zeroizing::new([0_u8; 32]);
            hkdf.expand(&info, bytes.as_mut())
                .map_err(|_| RelayError::InvalidEvent)?;
            if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
                return Ok((hex(&topic), Keys::new(secret)));
            }
        }
        Err(RelayError::InvalidEvent)
    }
}

/// Initial rendezvous over NIP-01 ephemeral events. Room creator is responder;
/// entering the code is initiator. The code-derived event key authenticates
/// possession of the invite only; identity still requires the Noise proof and
/// human fingerprint comparison.
pub struct RelayRendezvous {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    topic: String,
    keys: Keys,
    role: Role,
    subscription: SubscriptionId,
    seen: BTreeSet<String>,
    published: BTreeSet<String>,
    attempt_tag: Option<String>,
    cancelled: Option<Arc<AtomicBool>>,
}

impl RelayRendezvous {
    pub fn create(endpoint: &str, invite: &InviteCode) -> Result<Self, RelayError> {
        Self::connect(endpoint, invite, Role::Responder)
    }

    pub fn join(endpoint: &str, invite: &InviteCode) -> Result<Self, RelayError> {
        Self::connect(endpoint, invite, Role::Initiator)
    }

    fn connect(endpoint: &str, invite: &InviteCode, role: Role) -> Result<Self, RelayError> {
        let mut socket = open_socket(endpoint)?;
        let (topic, keys) = invite.relay_material()?;
        let attempt_tag = match role {
            Role::Initiator => Some(random_hex(16)?),
            Role::Responder => None,
        };
        let subscription = SubscriptionId::new(SUBSCRIPTION_ID);
        let mut filter = Filter::new()
            .kind(Kind::Custom(EVENT_KIND))
            .custom_tag(SingleLetterTag::LOWERCASE_T, topic.clone())
            .custom_tag(SingleLetterTag::LOWERCASE_R, role_tag(role.peer()))
            .author(keys.public_key());
        if let Some(attempt) = &attempt_tag {
            filter = filter.custom_tag(SingleLetterTag::LOWERCASE_S, attempt.clone());
        }
        socket.send(Message::text(
            ClientMessage::req(subscription.clone(), vec![filter]).as_json(),
        ))?;
        Ok(Self {
            socket,
            topic,
            keys,
            role,
            subscription,
            seen: BTreeSet::new(),
            published: BTreeSet::new(),
            attempt_tag,
            cancelled: None,
        })
    }

    pub fn set_cancellation_token(&mut self, token: Arc<AtomicBool>) {
        self.cancelled = Some(token);
    }

    /// Exchanges all three Noise XX handshake messages over the rendezvous.
    pub fn complete_handshake(&mut self) -> Result<PendingChannel, RelayError> {
        let mut handshake = Handshake::new(self.role)?;
        match self.role {
            Role::Initiator => {
                self.publish_frame(&handshake.write()?)?;
                handshake.read(&self.receive_frame()?)?;
                self.publish_frame(&handshake.write()?)?;
            }
            Role::Responder => {
                handshake.read(&self.receive_frame()?)?;
                self.publish_frame(&handshake.write()?)?;
                handshake.read(&self.receive_frame()?)?;
            }
        }
        Ok(handshake.finish()?)
    }

    /// Exchanges the transcript-bound identity proof through the encrypted
    /// Noise transport. The returned fingerprint still needs human comparison.
    pub fn authenticate(
        &mut self,
        channel: PendingChannel,
        identity: &Identity,
        expected_peer: Option<[u8; 32]>,
    ) -> Result<VerificationPending, RelayError> {
        if channel.role() != self.role {
            return Err(HandshakeError::RoleMismatch.into());
        }
        let (pending, proof) = channel.prove_identity(identity)?;
        self.publish_frame(&proof)?;
        Ok(pending.receive_peer_proof(&self.receive_frame()?, expected_peer)?)
    }

    /// Call only after the user has compared the out-of-band fingerprint.
    /// Replaces the bootstrap subscription with the post-verification topic.
    pub fn confirm(
        mut self,
        verification: VerificationPending,
    ) -> Result<RelaySession, RelayError> {
        if verification.role() != self.role {
            return Err(HandshakeError::RoleMismatch.into());
        }
        let (pending, frame) = verification.confirm_after_user_check()?;
        self.publish_frame(&frame)?;
        let peer_frame = self.receive_frame()?;
        let active = pending.receive_peer_confirmation(&peer_frame)?;
        RelaySession::from_socket(self.socket, SessionTransport::new(active))
    }

    fn publish_frame(&mut self, frame: &[u8]) -> Result<(), RelayError> {
        if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME {
            return Err(RelayError::InvalidEvent);
        }
        let role = role_tag(self.role);
        let event = EventBuilder::new(Kind::Custom(EVENT_KIND), hex(frame))
            .tag(Tag::custom("t", [self.topic.as_str()]))
            .tag(Tag::custom("r", [role]))
            .tag(Tag::custom(
                "s",
                [self
                    .attempt_tag
                    .as_deref()
                    .ok_or(RelayError::InvalidEvent)?],
            ))
            .finalize(&self.keys)?;
        let event_id = event.id.to_string();
        self.published.insert(event_id);
        if self.published.len() > 16 {
            return Err(RelayError::InvalidEvent);
        }
        self.socket
            .send(Message::text(ClientMessage::event(event).as_json()))?;
        Ok(())
    }

    fn receive_frame(&mut self) -> Result<Vec<u8>, RelayError> {
        let expected_role = role_tag(self.role.peer());
        loop {
            if self
                .cancelled
                .as_ref()
                .is_some_and(|token| token.load(Ordering::SeqCst))
            {
                return Err(RelayError::Cancelled);
            }
            let incoming = match self.socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match incoming {
                Message::Text(text) => match RelayMessage::from_json(text.as_str())? {
                    RelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        if subscription_id.as_ref() != &self.subscription {
                            continue;
                        }
                        let event = event.as_ref();
                        let event_id = event.id.to_string();
                        if event.pubkey != self.keys.public_key()
                            || event.kind != Kind::Custom(EVENT_KIND)
                            || event.verify().is_err()
                            || tag_value(event, "t") != Some(self.topic.as_str())
                            || tag_value(event, "r") != Some(expected_role)
                        {
                            continue;
                        }
                        let Some(attempt) = tag_value(event, "s") else {
                            continue;
                        };
                        if !is_attempt_tag(attempt) {
                            continue;
                        }
                        match self.attempt_tag.as_deref() {
                            Some(expected) if expected != attempt => continue,
                            Some(_) => {}
                            None => self.attempt_tag = Some(attempt.to_owned()),
                        }
                        if !self.seen.insert(event_id) {
                            continue;
                        }
                        if self.seen.len() > 16 {
                            return Err(RelayError::InvalidEvent);
                        }
                        let frame = decode_hex(&event.content).ok_or(RelayError::InvalidEvent)?;
                        if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME {
                            return Err(RelayError::InvalidEvent);
                        }
                        return Ok(frame);
                    }
                    RelayMessage::Closed {
                        subscription_id,
                        message,
                    } if subscription_id.as_ref() == &self.subscription => {
                        return Err(RelayError::SubscriptionClosed(message.to_string()));
                    }
                    RelayMessage::Ok {
                        event_id,
                        status,
                        message,
                    } if self.published.remove(&event_id.to_string()) && !status => {
                        return Err(RelayError::RelayRejected {
                            event_id: event_id.to_string(),
                            reason: message.to_string(),
                        });
                    }
                    _ => {}
                },
                Message::Ping(payload) => self.socket.send(Message::Pong(payload))?,
                Message::Close(_) => return Err(RelayError::Disconnected),
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }
}

fn role_tag(role: Role) -> &'static str {
    match role {
        Role::Initiator => "i",
        Role::Responder => "r",
    }
}

fn has_tag(event: &nostr::prelude::Event, kind: &str, value: &str) -> bool {
    tag_value(event, kind) == Some(value)
}

fn tag_value<'a>(event: &'a nostr::prelude::Event, kind: &str) -> Option<&'a str> {
    let mut found = None;
    for tag in event.tags.iter() {
        let fields = tag.as_slice();
        if fields.first().is_some_and(|field| field == kind) {
            if fields.len() != 2 || found.is_some() {
                return None;
            }
            found = Some(fields[1].as_str());
        }
    }
    found
}

fn is_attempt_tag(tag: &str) -> bool {
    tag.len() == 32
        && tag
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_hex(bytes_len: usize) -> io::Result<String> {
    let mut bytes = Zeroizing::new(vec![0; bytes_len]);
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 || input.len() > MAX_ENVELOPE * 2 {
        return None;
    }
    let digit = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}
