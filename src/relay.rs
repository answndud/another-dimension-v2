//! Minimal NIP-01 rendezvous and WebSocket adapter for Noise sessions.
//!
//! It publishes only kind-20000 ephemeral events. The relay still observes the
//! session tag, timing, size, and connection IP in direct mode. Callers select
//! an optional loopback SOCKS5 proxy; proxy failures never fall back to direct.

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
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{client_tls_with_config, Message, WebSocket};
use zeroize::Zeroizing;

const EVENT_KIND: u16 = 20_000;
pub const DEFAULT_RELAY: &str = "wss://relay.primal.net";
const SUBSCRIPTION_ID: &str = "ad-v2-live";
const INVITE_PREFIX: &str = "ADI1-";
const INVITE_TOPIC_INFO: &[u8] = b"another-dimension-v2/invite-topic/v1";
const INVITE_KEY_INFO: &[u8] = b"another-dimension-v2/invite-relay-key/v1";
const INVITE_DOMAIN: &[u8] = b"another-dimension-v2/invite-code/v1";
const READY_REQUEST_PREFIX: &[u8] = b"\0AD2-READY-1:";
const READY_ACK_PREFIX: &[u8] = b"\0AD2-READY-ACK-1:";
const MAX_BOOTSTRAP_FRAME: usize = 256;
const MAX_RELAY_MESSAGE: usize = 16 * 1024;
const MAX_ENVELOPE: usize = 4 + 16 + 8 + 4096;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(15);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
const READY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum RelayError {
    WebSocket(tungstenite::Error),
    Nostr(NostrError),
    Channel(HandshakeError),
    InvalidEndpoint,
    Io(io::Error),
    InvalidEvent,
    TimedOut(&'static str),
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
    pub fn connect(
        endpoint: &str,
        transport: SessionTransport,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::from_socket(open_socket(endpoint, tor_socks)?, transport)
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
        wait_for_subscription(&mut socket, &subscription)?;

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

fn open_socket(
    endpoint: &str,
    tor_socks: Option<SocketAddr>,
) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, RelayError> {
    if !endpoint.starts_with("wss://") || endpoint.contains('@') || endpoint.contains('#') {
        return Err(RelayError::InvalidEndpoint);
    }
    ensure_tls_crypto_provider()?;
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_RELAY_MESSAGE);
    config.max_frame_size = Some(MAX_RELAY_MESSAGE);
    let request = endpoint.into_client_request()?;
    let host = request
        .uri()
        .host()
        .ok_or(RelayError::InvalidEndpoint)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = request.uri().port_u16().unwrap_or(443);
    let stream = if let Some(proxy) = tor_socks {
        if !proxy.ip().is_loopback() || proxy.port() == 0 {
            return Err(RelayError::InvalidEndpoint);
        }
        connect_socks5(proxy, &host, port)?
    } else {
        connect_tcp(&host, port)?
    };
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    let (mut socket, _) = client_tls_with_config(request, stream, Some(config), None).map_err(
        |error| match error {
            tungstenite::HandshakeError::Failure(error) => RelayError::WebSocket(error),
            tungstenite::HandshakeError::Interrupted(_) => {
                RelayError::Io(io::Error::other("blocking TLS handshake interrupted"))
            }
        },
    )?;
    match socket.get_mut() {
        MaybeTlsStream::Rustls(stream) => {
            stream.sock.set_read_timeout(Some(READ_TIMEOUT))?;
            stream.sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
        }
        _ => return Err(RelayError::InvalidEndpoint),
    }
    Ok(socket)
}

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, RelayError> {
    let addresses = (host, port).to_socket_addrs()?.collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(RelayError::Io(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "relay hostname did not resolve",
        )));
    }
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(RelayError::Io(last_error.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::TimedOut, "relay connection timed out")
    })))
}

fn connect_socks5(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream, RelayError> {
    let mut stream = TcpStream::connect_timeout(&proxy, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    stream.write_all(&[5, 1, 0])?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection)?;
    if selection != [5, 0] {
        return Err(RelayError::Io(io::Error::other(
            "SOCKS5 proxy rejected no-authentication mode",
        )));
    }
    let host = host.as_bytes();
    let host_len = u8::try_from(host.len()).map_err(|_| RelayError::InvalidEndpoint)?;
    stream.write_all(&[5, 1, 0, 3, host_len])?;
    stream.write_all(host)?;
    stream.write_all(&port.to_be_bytes())?;
    let mut response = [0; 4];
    stream.read_exact(&mut response)?;
    if response[0] != 5 || response[1] != 0 {
        return Err(RelayError::Io(io::Error::other(
            "SOCKS5 proxy could not connect to relay",
        )));
    }
    let bound_address_len = match response[3] {
        1 => 4,
        3 => {
            let mut length = [0];
            stream.read_exact(&mut length)?;
            length[0] as usize
        }
        4 => 16,
        _ => return Err(RelayError::Io(io::Error::other("invalid SOCKS5 response"))),
    };
    let mut bound_address = vec![0; bound_address_len + 2];
    stream.read_exact(&mut bound_address)?;
    Ok(stream)
}

fn ensure_tls_crypto_provider() -> Result<(), RelayError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(RelayError::Io(io::Error::other(
            "TLS crypto provider unavailable",
        )));
    }
    Ok(())
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
    pub fn create(
        endpoint: &str,
        invite: &InviteCode,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::connect(endpoint, invite, Role::Responder, tor_socks)
    }

    pub fn join(
        endpoint: &str,
        invite: &InviteCode,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::connect(endpoint, invite, Role::Initiator, tor_socks)
    }

    fn connect(
        endpoint: &str,
        invite: &InviteCode,
        role: Role,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        let mut socket = open_socket(endpoint, tor_socks)?;
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
        wait_for_subscription(&mut socket, &subscription)?;
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
        self.wait_for_peer_subscription()?;
        let mut handshake = Handshake::new(self.role)?;
        match self.role {
            Role::Initiator => {
                self.publish_frame(&handshake.write()?)?;
                handshake.read(&self.receive_frame("handshake response")?)?;
                self.publish_frame(&handshake.write()?)?;
            }
            Role::Responder => {
                handshake.read(&self.receive_frame("handshake initiation")?)?;
                self.publish_frame(&handshake.write()?)?;
                handshake.read(&self.receive_frame("handshake completion")?)?;
            }
        }
        Ok(handshake.finish()?)
    }

    fn wait_for_peer_subscription(&mut self) -> Result<(), RelayError> {
        let deadline = Instant::now() + RENDEZVOUS_TIMEOUT;
        let mut last_request = None;
        let mut pending_nonces = BTreeSet::new();
        loop {
            if self
                .cancelled
                .as_ref()
                .is_some_and(|token| token.load(Ordering::SeqCst))
            {
                return Err(RelayError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(RelayError::TimedOut("peer subscription"));
            }

            if self.role == Role::Initiator
                && last_request
                    .map(|last: Instant| last.elapsed() >= READY_RETRY_INTERVAL)
                    .unwrap_or(true)
            {
                let nonce = random_hex(12)?;
                let mut request = READY_REQUEST_PREFIX.to_vec();
                request.extend_from_slice(nonce.as_bytes());
                self.publish_frame(&request)?;
                pending_nonces.insert(nonce);
                last_request = Some(Instant::now());
            }

            if let Some(frame) = self.poll_frame()? {
                match self.role {
                    Role::Initiator => {
                        if let Some(nonce) = frame.strip_prefix(READY_ACK_PREFIX) {
                            if std::str::from_utf8(nonce)
                                .ok()
                                .is_some_and(|nonce| pending_nonces.contains(nonce))
                            {
                                return Ok(());
                            }
                        }
                    }
                    Role::Responder => {
                        if let Some(nonce) = frame.strip_prefix(READY_REQUEST_PREFIX) {
                            let mut acknowledgement = READY_ACK_PREFIX.to_vec();
                            acknowledgement.extend_from_slice(nonce);
                            self.publish_frame(&acknowledgement)?;
                            return Ok(());
                        }
                    }
                }
            }
        }
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
        Ok(pending.receive_peer_proof(&self.receive_frame("identity proof")?, expected_peer)?)
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
        let peer_frame = self.receive_frame("peer confirmation")?;
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

    fn receive_frame(&mut self, stage: &'static str) -> Result<Vec<u8>, RelayError> {
        let deadline = Instant::now() + RENDEZVOUS_TIMEOUT;
        loop {
            if self
                .cancelled
                .as_ref()
                .is_some_and(|token| token.load(Ordering::SeqCst))
            {
                return Err(RelayError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(RelayError::TimedOut(stage));
            }
            if let Some(frame) = self.poll_frame()? {
                if frame.starts_with(READY_REQUEST_PREFIX) || frame.starts_with(READY_ACK_PREFIX) {
                    continue;
                }
                return Ok(frame);
            }
        }
    }

    fn poll_frame(&mut self) -> Result<Option<Vec<u8>>, RelayError> {
        let expected_role = role_tag(self.role.peer());
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
                return Ok(None);
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
                        return Ok(None);
                    }
                    let event = event.as_ref();
                    let event_id = event.id.to_string();
                    if event.pubkey != self.keys.public_key()
                        || event.kind != Kind::Custom(EVENT_KIND)
                        || event.verify().is_err()
                        || tag_value(event, "t") != Some(self.topic.as_str())
                        || tag_value(event, "r") != Some(expected_role)
                    {
                        return Ok(None);
                    }
                    let Some(attempt) = tag_value(event, "s") else {
                        return Ok(None);
                    };
                    if !is_attempt_tag(attempt) {
                        return Ok(None);
                    }
                    match self.attempt_tag.as_deref() {
                        Some(expected) if expected != attempt => return Ok(None),
                        Some(_) => {}
                        None => self.attempt_tag = Some(attempt.to_owned()),
                    }
                    if !self.seen.insert(event_id) {
                        return Ok(None);
                    }
                    if self.seen.len() > 64 {
                        return Err(RelayError::InvalidEvent);
                    }
                    let frame = decode_hex(&event.content).ok_or(RelayError::InvalidEvent)?;
                    if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME {
                        return Err(RelayError::InvalidEvent);
                    }
                    Ok(Some(frame))
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
                } if self.published.remove(&event_id.to_string()) => {
                    if status {
                        Ok(None)
                    } else {
                        Err(RelayError::RelayRejected {
                            event_id: event_id.to_string(),
                            reason: message.to_string(),
                        })
                    }
                }
                _ => Ok(None),
            },
            Message::Ping(payload) => {
                self.socket.send(Message::Pong(payload))?;
                Ok(None)
            }
            Message::Close(_) => return Err(RelayError::Disconnected),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SubscriptionStatus {
    Pending,
    Ready,
    Closed(String),
}

fn subscription_status(
    text: &str,
    expected: &SubscriptionId,
) -> Result<SubscriptionStatus, RelayError> {
    Ok(match RelayMessage::from_json(text)? {
        RelayMessage::EndOfStoredEvents(subscription) if subscription.as_ref() == expected => {
            SubscriptionStatus::Ready
        }
        RelayMessage::Closed {
            subscription_id,
            message,
        } if subscription_id.as_ref() == expected => {
            SubscriptionStatus::Closed(message.to_string())
        }
        _ => SubscriptionStatus::Pending,
    })
}

fn wait_for_subscription(
    socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
    subscription: &SubscriptionId,
) -> Result<(), RelayError> {
    let deadline = Instant::now() + SUBSCRIPTION_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err(RelayError::TimedOut("relay subscription"));
        }
        let message = match socket.read() {
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
        match message {
            Message::Text(text) => match subscription_status(text.as_str(), subscription)? {
                SubscriptionStatus::Pending => {}
                SubscriptionStatus::Ready => return Ok(()),
                SubscriptionStatus::Closed(reason) => {
                    return Err(RelayError::SubscriptionClosed(reason));
                }
            },
            Message::Ping(payload) => socket.send(Message::Pong(payload))?,
            Message::Close(_) => return Err(RelayError::Disconnected),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
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

#[cfg(test)]
mod tests {
    use super::{
        subscription_status, InviteCode, RelayError, RelayRendezvous, RelayUpdate, Role,
        SubscriptionStatus,
    };
    use crate::identity::Identity;
    use nostr::prelude::SubscriptionId;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn tls_crypto_provider_is_initialized_before_network_use() {
        super::ensure_tls_crypto_provider().unwrap();
    }

    #[test]
    fn subscription_ready_and_closed_responses_are_matched_by_id() {
        let expected = SubscriptionId::new("ad-v2-live");
        assert_eq!(
            subscription_status(r#"["EOSE","ad-v2-live"]"#, &expected).unwrap(),
            SubscriptionStatus::Ready
        );
        assert_eq!(
            subscription_status(r#"["EOSE","other"]"#, &expected).unwrap(),
            SubscriptionStatus::Pending
        );
        assert_eq!(
            subscription_status(r#"["CLOSED","ad-v2-live","restricted"]"#, &expected).unwrap(),
            SubscriptionStatus::Closed("restricted".to_owned())
        );
    }

    #[test]
    fn socks_connection_sends_the_relay_hostname_to_the_proxy() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();

            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            let mut hostname = vec![0; request[4] as usize];
            stream.read_exact(&mut hostname).unwrap();
            assert_eq!(hostname, b"relay.example");
            let mut port = [0; 2];
            stream.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });

        let stream = super::connect_socks5(proxy, "relay.example", 443).unwrap();
        drop(stream);
        server.join().unwrap();
    }

    #[test]
    #[ignore = "live public relay end-to-end test"]
    fn live_relay_two_party_channel_roundtrip() {
        let abandoned_invite = InviteCode::generate().unwrap();
        let mut abandoned_join =
            RelayRendezvous::join("wss://relay.primal.net", &abandoned_invite, None).unwrap();
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        abandoned_join.set_cancellation_token(Arc::clone(&cancellation));
        let cancel_after_start = Arc::clone(&cancellation);
        let cancel_task = thread::spawn(move || {
            thread::sleep(Duration::from_millis(800));
            cancel_after_start.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(matches!(
            abandoned_join.complete_handshake(),
            Err(RelayError::Cancelled)
        ));
        cancel_task.join().unwrap();

        for _ in 0..2 {
            let invite = InviteCode::generate().unwrap();
            let invite_code = invite.code().to_string();
            let barrier = Arc::new(Barrier::new(2));
            let (initiator_tx, responder_rx) = mpsc::channel();
            let (responder_tx, initiator_rx) = mpsc::channel();
            let initiator_barrier = Arc::clone(&barrier);
            let responder_barrier = Arc::clone(&barrier);
            let initiator_code = invite_code.clone();
            let initiator = thread::spawn(move || {
                live_relay_party(
                    Role::Initiator,
                    initiator_code,
                    initiator_tx,
                    initiator_rx,
                    initiator_barrier,
                )
            });
            let responder = thread::spawn(move || {
                live_relay_party(
                    Role::Responder,
                    invite_code,
                    responder_tx,
                    responder_rx,
                    responder_barrier,
                )
            });
            initiator.join().unwrap();
            responder.join().unwrap();
        }
    }

    fn live_relay_party(
        role: Role,
        invite_code: String,
        fingerprint_tx: Sender<Vec<u8>>,
        fingerprint_rx: Receiver<Vec<u8>>,
        barrier: Arc<Barrier>,
    ) {
        let invite = InviteCode::parse(&invite_code).unwrap();
        let endpoint = "wss://relay.primal.net";
        let mut rendezvous = match role {
            Role::Initiator => RelayRendezvous::join(endpoint, &invite, None),
            Role::Responder => RelayRendezvous::create(endpoint, &invite, None),
        }
        .unwrap();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        rendezvous.set_cancellation_token(cancelled);
        let channel = rendezvous.complete_handshake().unwrap();
        let identity = Identity::create().unwrap().0;
        let verification = rendezvous.authenticate(channel, &identity, None).unwrap();
        let fingerprint = verification.fingerprint().to_vec();
        fingerprint_tx.send(fingerprint.clone()).unwrap();
        assert_eq!(
            fingerprint_rx
                .recv_timeout(Duration::from_secs(35))
                .unwrap(),
            fingerprint
        );
        let mut session = rendezvous.confirm(verification).unwrap();
        barrier.wait();
        let (send, expected) = match role {
            Role::Initiator => ("initiator message", "responder message"),
            Role::Responder => ("responder message", "initiator message"),
        };
        session.send(send.as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        let mut received = None;
        while Instant::now() < deadline {
            match session.poll().unwrap() {
                Some(RelayUpdate::Messages(messages)) => {
                    received = messages
                        .into_iter()
                        .find_map(|message| String::from_utf8(message).ok());
                    if received.is_some() {
                        break;
                    }
                }
                _ => thread::sleep(Duration::from_millis(100)),
            }
        }
        assert_eq!(received.as_deref(), Some(expected));
    }
}
