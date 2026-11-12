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
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
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
const INVITE_PREFIX: &str = "ADI3-";
const INVITE_TOPIC_INFO: &[u8] = b"another-dimension-v2/invite-topic/v2";
const INVITE_KEY_INFO: &[u8] = b"another-dimension-v2/invite-relay-key/v2";
const INVITE_DOMAIN: &[u8] = b"another-dimension-v2/invite-code/v2";
const READY_REQUEST_PREFIX: &[u8] = b"\0AD2-READY-1:";
const READY_ACK_PREFIX: &[u8] = b"\0AD2-READY-ACK-1:";
const MAX_BOOTSTRAP_FRAME: usize = 256;
const MAX_RELAY_MESSAGE: usize = 20 * 1024;
const MAX_ENVELOPE: usize = 4 + 16 + 8 + 8192;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(15);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
const READY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Validate a relay URL without resolving its host or making a network request.
/// The returned value is a comparison key: scheme/host case and the default
/// port are normalized so equivalent endpoints are detected as duplicates.
pub fn validate_relay_endpoint(endpoint: &str) -> Result<String, RelayError> {
    if endpoint.is_empty()
        || endpoint
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || endpoint.contains('@')
        || endpoint.contains('#')
    {
        return Err(RelayError::InvalidEndpoint);
    }
    let request = endpoint
        .into_client_request()
        .map_err(|_| RelayError::InvalidEndpoint)?;
    let uri = request.uri();
    if uri.scheme_str() != Some("wss") {
        return Err(RelayError::InvalidEndpoint);
    }
    let host = uri.host().ok_or(RelayError::InvalidEndpoint)?;
    if host.is_empty() {
        return Err(RelayError::InvalidEndpoint);
    }
    let authority = uri.authority().ok_or(RelayError::InvalidEndpoint)?.as_str();
    let explicit_port = if authority.starts_with('[') {
        let bracket_end = authority.find(']').ok_or(RelayError::InvalidEndpoint)?;
        let suffix = &authority[bracket_end + 1..];
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(RelayError::InvalidEndpoint)?,
            )
        }
    } else if let Some((host_part, port_part)) = authority.rsplit_once(':') {
        if host_part.contains(':') {
            return Err(RelayError::InvalidEndpoint);
        }
        Some(port_part)
    } else {
        None
    };
    let port = match explicit_port {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value
                .parse::<u16>()
                .map_err(|_| RelayError::InvalidEndpoint)?
        }
        Some(_) => return Err(RelayError::InvalidEndpoint),
        None => 443,
    };
    if port == 0 {
        return Err(RelayError::InvalidEndpoint);
    }
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err(RelayError::InvalidEndpoint);
    }
    let host = if let Ok(address) = host.parse::<IpAddr>() {
        address.to_string()
    } else {
        if host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(RelayError::InvalidEndpoint);
        }
        host.to_owned()
    };
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let port_part = if port == 443 {
        String::new()
    } else {
        format!(":{port}")
    };
    let path = uri.path_and_query().map_or("/", |value| value.as_str());
    Ok(format!("wss://{authority_host}{port_part}{path}"))
}

pub fn validate_relay_list(relays: &[String]) -> Result<Vec<String>, String> {
    if relays.is_empty() {
        return Err("relay 목록은 비어 있을 수 없습니다.".to_owned());
    }
    let mut normalized = BTreeSet::new();
    for (index, endpoint) in relays.iter().enumerate() {
        let key = validate_relay_endpoint(endpoint)
            .map_err(|_| format!("{}번째 relay 주소가 올바르지 않습니다.", index + 1))?;
        if !normalized.insert(key) {
            return Err(format!("{}번째 relay 주소가 중복됩니다.", index + 1));
        }
    }
    Ok(relays.to_vec())
}

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
    PendingPublishLimit,
    NoRelayAvailable,
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
    PublishUnknown { event_id: String },
    Ready,
}

trait RelayIo: Send {
    fn send_message(&mut self, message: Message) -> Result<(), RelayError>;
    fn read_message(&mut self) -> Result<Option<Message>, RelayError>;
}

struct WebSocketIo(WebSocket<MaybeTlsStream<TcpStream>>);

impl RelayIo for WebSocketIo {
    fn send_message(&mut self, message: Message) -> Result<(), RelayError> {
        self.0.send(message).map_err(RelayError::from)
    }

    fn read_message(&mut self) -> Result<Option<Message>, RelayError> {
        match self.0.read() {
            Ok(message) => Ok(Some(message)),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}

struct RelayLink {
    id: usize,
    io: Box<dyn RelayIo>,
    subscription: SubscriptionId,
    ready: bool,
    buffered: VecDeque<Message>,
}

impl RelayLink {
    fn new(id: usize, io: Box<dyn RelayIo>, subscription: SubscriptionId) -> Self {
        Self {
            id,
            io,
            subscription,
            ready: false,
            buffered: VecDeque::new(),
        }
    }

    fn read(&mut self) -> Result<Option<Message>, RelayError> {
        if let Some(message) = self.buffered.pop_front() {
            return Ok(Some(message));
        }
        self.io.read_message()
    }

    fn send_text(&mut self, text: &str) -> Result<(), RelayError> {
        self.io.send_message(Message::text(text.to_owned()))
    }
}

pub struct RelaySession {
    relays: Vec<RelayLink>,
    next_relay: usize,
    transport: SessionTransport,
    keys: Keys,
    peer_author: PublicKey,
    topic: String,
    seen: BTreeSet<String>,
    seen_order: VecDeque<String>,
    pending_publishes: HashMap<String, BTreeSet<usize>>,
    uncertain_publishes: BTreeSet<String>,
    publish_unknown: VecDeque<String>,
}

impl RelaySession {
    /// Connects only to a TLS WebSocket endpoint and subscribes to this peer's
    /// signed ephemeral events for the current session.
    pub fn connect(
        endpoint: &str,
        transport: SessionTransport,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        let link = RelayLink::new(
            0,
            Box::new(WebSocketIo(open_socket(endpoint, tor_socks)?)),
            SubscriptionId::new(SUBSCRIPTION_ID),
        );
        Self::from_links(vec![link], transport)
    }

    fn from_links(
        mut relays: Vec<RelayLink>,
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
        let text = request.as_json();
        let mut index = 0;
        while index < relays.len() {
            let close =
                serde_json::json!(["CLOSE", relays[index].subscription.to_string()]).to_string();
            // Buffered rendezvous events belong to the invite topic. Keep only
            // already-arrived events for this live topic; old EOSE/handshake
            // frames must not mark the replacement subscription ready.
            relays[index].buffered.retain(|message| {
                let Message::Text(text) = message else {
                    return true;
                };
                matches!(
                    RelayMessage::from_json(text.as_str()),
                    Ok(RelayMessage::Event { ref event, .. })
                        if event.kind == Kind::Custom(EVENT_KIND)
                            && event.pubkey == peer_author
                            && event.verify().is_ok()
                            && has_tag(event, "t", &topic)
                )
            });
            if relays[index].io.send_message(Message::text(close)).is_err()
                || relays[index]
                    .io
                    .send_message(Message::text(text.clone()))
                    .is_err()
            {
                relays.remove(index);
            } else {
                relays[index].subscription = subscription.clone();
                relays[index].ready = false;
                index += 1;
            }
        }
        wait_for_any_subscription(&mut relays, SUBSCRIPTION_TIMEOUT)?;

        Ok(Self {
            relays,
            next_relay: 0,
            transport,
            keys,
            peer_author,
            topic,
            seen: BTreeSet::new(),
            seen_order: VecDeque::new(),
            pending_publishes: HashMap::new(),
            uncertain_publishes: BTreeSet::new(),
            publish_unknown: VecDeque::new(),
        })
    }

    /// Encrypts and publishes one live event. The returned identifier is the
    /// event id; relay acceptance arrives separately as `RelayUpdate::Published`.
    pub fn send(&mut self, message: &[u8]) -> Result<String, RelayError> {
        if self.pending_publishes.len() >= 1024 {
            return Err(RelayError::PendingPublishLimit);
        }
        let envelope = self.transport.send(message)?;
        let event = EventBuilder::new(Kind::Custom(EVENT_KIND), hex(&envelope))
            .tag(Tag::custom("t", [self.topic.as_str()]))
            .finalize(&self.keys)?;
        let event_id = event.id.to_string();
        let text = ClientMessage::event(event).as_json();
        let mut awaiting = BTreeSet::new();
        let mut index = 0;
        while index < self.relays.len() {
            if self.relays[index].ready && self.relays[index].send_text(&text).is_err() {
                self.remove_relay(index);
            } else if self.relays[index].ready {
                awaiting.insert(self.relays[index].id);
                index += 1;
            } else {
                index += 1;
            }
        }
        if awaiting.is_empty() {
            return Err(RelayError::Disconnected);
        }
        self.pending_publishes.insert(event_id.clone(), awaiting);
        Ok(event_id)
    }

    /// Reads one WebSocket message, returning `None` when the polling timeout expires.
    pub fn poll(&mut self) -> Result<Option<RelayUpdate>, RelayError> {
        if let Some(event_id) = self.publish_unknown.pop_front() {
            return Ok(Some(RelayUpdate::PublishUnknown { event_id }));
        }
        if self.relays.is_empty() {
            return Err(RelayError::Disconnected);
        }
        let mut message = None;
        let mut attempts = self.relays.len();
        while attempts > 0 && !self.relays.is_empty() {
            let index = self.next_relay % self.relays.len();
            self.next_relay = (index + 1) % self.relays.len();
            attempts -= 1;
            match self.relays[index].read() {
                Ok(Some(incoming)) => {
                    message = Some((index, incoming));
                    break;
                }
                Ok(None) => {}
                Err(_) => {
                    self.remove_relay(index);
                    if self.relays.is_empty() {
                        return Err(RelayError::Disconnected);
                    }
                    self.next_relay = index % self.relays.len();
                }
            }
        }
        let Some((link_index, message)) = message else {
            return Ok(None);
        };
        match message {
            Message::Text(text) => match RelayMessage::from_json(text.as_str()) {
                Err(_) => return Ok(None),
                Ok(relay_message) => match relay_message {
                    RelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        if subscription_id.as_ref() != &self.relays[link_index].subscription {
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
                        let event_id = event.id.to_string();
                        if !self.seen.insert(event_id.clone()) {
                            return Ok(None);
                        }
                        self.seen_order.push_back(event_id);
                        while self.seen_order.len() > 4096 {
                            if let Some(expired) = self.seen_order.pop_front() {
                                self.seen.remove(&expired);
                            }
                        }
                        let envelope =
                            decode_hex(&event.content).ok_or(RelayError::InvalidEvent)?;
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
                            if self
                                .pending_publishes
                                .remove(&event_id.to_string())
                                .is_some()
                            {
                                self.uncertain_publishes.remove(&event_id.to_string());
                                return Ok(Some(RelayUpdate::Published {
                                    event_id: event_id.to_string(),
                                }));
                            }
                        } else if let Some(awaiting) =
                            self.pending_publishes.get_mut(&event_id.to_string())
                        {
                            awaiting.remove(&self.relays[link_index].id);
                            if awaiting.is_empty() {
                                self.pending_publishes.remove(&event_id.to_string());
                                if self.uncertain_publishes.remove(&event_id.to_string()) {
                                    return Ok(Some(RelayUpdate::PublishUnknown {
                                        event_id: event_id.to_string(),
                                    }));
                                }
                                return Err(RelayError::RelayRejected {
                                    event_id: event_id.to_string(),
                                    reason: message.to_string(),
                                });
                            }
                        }
                    }
                    RelayMessage::EndOfStoredEvents(subscription_id)
                        if subscription_id.as_ref() == &self.relays[link_index].subscription =>
                    {
                        self.relays[link_index].ready = true;
                        return Ok(Some(RelayUpdate::Ready));
                    }
                    RelayMessage::Closed {
                        subscription_id,
                        message,
                    } if subscription_id.as_ref() == &self.relays[link_index].subscription => {
                        self.remove_relay(link_index);
                        if self.relays.is_empty() {
                            return Err(RelayError::SubscriptionClosed(message.to_string()));
                        }
                    }
                    _ => {}
                },
            },
            Message::Ping(payload) => {
                if self.relays[link_index]
                    .io
                    .send_message(Message::Pong(payload))
                    .is_err()
                {
                    self.remove_relay(link_index);
                    if self.relays.is_empty() {
                        return Err(RelayError::Disconnected);
                    }
                }
            }
            Message::Close(_) => {
                self.remove_relay(link_index);
                if self.relays.is_empty() {
                    return Err(RelayError::Disconnected);
                }
            }
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
        Ok(None)
    }

    fn remove_relay(&mut self, index: usize) {
        let id = self.relays[index].id;
        self.relays.remove(index);
        self.remove_pending_relay(id);
        self.next_relay = 0;
    }

    fn remove_pending_relay(&mut self, relay_id: usize) {
        let mut expired = Vec::new();
        for (event_id, awaiting) in &mut self.pending_publishes {
            if awaiting.remove(&relay_id) {
                self.uncertain_publishes.insert(event_id.clone());
            }
            if awaiting.is_empty() {
                expired.push(event_id.clone());
            }
        }
        for event_id in expired {
            self.pending_publishes.remove(&event_id);
            self.uncertain_publishes.remove(&event_id);
            self.publish_unknown.push_back(event_id);
        }
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
    validate_relay_endpoint(endpoint)?;
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
    pub(crate) fn from_reconnect_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self::from_secret(secret)
    }
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
    relays: Vec<RelayLink>,
    next_relay: usize,
    topic: String,
    keys: Keys,
    role: Role,
    seen: BTreeSet<String>,
    attempt_tag: Option<String>,
    cancelled: Option<Arc<AtomicBool>>,
    timeout: Duration,
}

impl RelayRendezvous {
    pub fn create(
        endpoints: &[String],
        invite: &InviteCode,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::connect(endpoints, invite, Role::Responder, tor_socks)
    }

    pub fn join(
        endpoints: &[String],
        invite: &InviteCode,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::connect(endpoints, invite, Role::Initiator, tor_socks)
    }

    fn connect(
        endpoints: &[String],
        invite: &InviteCode,
        role: Role,
        tor_socks: Option<SocketAddr>,
    ) -> Result<Self, RelayError> {
        Self::connect_with(endpoints, invite, role, |endpoint| {
            open_socket(endpoint, tor_socks)
                .map(WebSocketIo)
                .map(|socket| Box::new(socket) as Box<dyn RelayIo>)
        })
    }

    fn connect_with<F>(
        endpoints: &[String],
        invite: &InviteCode,
        role: Role,
        mut open: F,
    ) -> Result<Self, RelayError>
    where
        F: FnMut(&str) -> Result<Box<dyn RelayIo>, RelayError>,
    {
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
        let mut relays = Vec::new();
        for (id, endpoint) in endpoints.iter().enumerate() {
            if validate_relay_endpoint(endpoint).is_err() {
                continue;
            }
            let Ok(io) = open(endpoint) else {
                continue;
            };
            let mut link = RelayLink::new(id, io, subscription.clone());
            if link
                .send_text(
                    &ClientMessage::req(subscription.clone(), vec![filter.clone()]).as_json(),
                )
                .is_ok()
            {
                relays.push(link);
            }
        }
        if relays.is_empty() {
            return Err(RelayError::NoRelayAvailable);
        }
        wait_for_any_subscription(&mut relays, SUBSCRIPTION_TIMEOUT)?;
        Ok(Self {
            relays,
            next_relay: 0,
            topic,
            keys,
            role,
            seen: BTreeSet::new(),
            attempt_tag,
            cancelled: None,
            timeout: RENDEZVOUS_TIMEOUT,
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
        let deadline = Instant::now() + self.timeout;
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
        RelaySession::from_links(self.relays, SessionTransport::new(active))
    }

    /// Establish a fresh relationship secret after both users have confirmed.
    /// This versioned exchange must only be used when both peers support it.
    pub fn confirm_with_contact(
        mut self,
        verification: VerificationPending,
    ) -> Result<(RelaySession, Zeroizing<[u8; 32]>), RelayError> {
        if verification.role() != self.role {
            return Err(HandshakeError::RoleMismatch.into());
        }
        let (pending, frame) = verification.confirm_after_user_check()?;
        self.publish_frame(&frame)?;
        let peer_frame = self.receive_frame("peer confirmation")?;
        let mut active = pending.receive_peer_confirmation(&peer_frame)?;
        let mut secret = Zeroizing::new([0; 32]);
        const OFFER: &[u8] = b"AD-CONTACT-OFFER-1";
        const ACK: &[u8] = b"AD-CONTACT-ACK-1";
        match self.role {
            Role::Responder => {
                File::open("/dev/urandom")?.read_exact(secret.as_mut())?;
                let mut offer = Zeroizing::new(Vec::from(OFFER));
                offer.extend_from_slice(secret.as_ref());
                self.publish_frame(&active.write_message(&offer)?)?;
                let reply = active.read_message(&self.receive_frame("contact acknowledgement")?)?;
                if reply != ACK {
                    return Err(RelayError::InvalidEvent);
                }
            }
            Role::Initiator => {
                let offer =
                    Zeroizing::new(active.read_message(&self.receive_frame("contact offer")?)?);
                if offer.len() != OFFER.len() + 32 || !offer.starts_with(OFFER) {
                    return Err(RelayError::InvalidEvent);
                }
                secret.copy_from_slice(&offer[OFFER.len()..]);
                self.publish_frame(&active.write_message(ACK)?)?;
            }
        }
        Ok((
            RelaySession::from_links(self.relays, SessionTransport::new(active))?,
            secret,
        ))
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
        let serialized = ClientMessage::event(event).as_json();
        if !self.relays.iter().any(|relay| relay.ready) {
            self.wait_until_relay_ready(self.timeout)?;
        }
        let mut delivered = false;
        let mut index = 0;
        while index < self.relays.len() {
            if self.relays[index].ready && self.relays[index].send_text(&serialized).is_err() {
                self.relays.remove(index);
                self.next_relay = 0;
            } else {
                delivered |= self.relays[index].ready;
                index += 1;
            }
        }
        if delivered {
            Ok(())
        } else {
            Err(RelayError::NoRelayAvailable)
        }
    }

    fn receive_frame(&mut self, stage: &'static str) -> Result<Vec<u8>, RelayError> {
        let deadline = Instant::now() + self.timeout;
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
        if self.relays.is_empty() {
            return Err(RelayError::NoRelayAvailable);
        }
        let mut attempts = self.relays.len();
        let mut received = None;
        while attempts > 0 && !self.relays.is_empty() {
            let index = self.next_relay % self.relays.len();
            self.next_relay = (index + 1) % self.relays.len();
            attempts -= 1;
            match self.relays[index].read() {
                Ok(Some(message)) => {
                    received = Some((index, message));
                    break;
                }
                Ok(None) => {}
                Err(_) => {
                    self.relays.remove(index);
                    self.next_relay = if self.relays.is_empty() {
                        0
                    } else {
                        index % self.relays.len()
                    };
                }
            }
        }
        let Some((link_index, incoming)) = received else {
            return if self.relays.is_empty() {
                Err(RelayError::NoRelayAvailable)
            } else {
                Ok(None)
            };
        };
        match incoming {
            Message::Text(text) => match RelayMessage::from_json(text.as_str()) {
                Err(_) => Ok(None),
                Ok(relay_message) => match relay_message {
                    RelayMessage::Event {
                        subscription_id,
                        event,
                    } => {
                        if subscription_id.as_ref() != &self.relays[link_index].subscription {
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
                    } if subscription_id.as_ref() == &self.relays[link_index].subscription => {
                        self.relays.remove(link_index);
                        self.next_relay = 0;
                        if self.relays.is_empty() {
                            return Err(RelayError::SubscriptionClosed(message.to_string()));
                        }
                        Ok(None)
                    }
                    RelayMessage::Ok { .. } => Ok(None),
                    RelayMessage::EndOfStoredEvents(subscription_id)
                        if subscription_id.as_ref() == &self.relays[link_index].subscription =>
                    {
                        self.relays[link_index].ready = true;
                        Ok(None)
                    }
                    _ => Ok(None),
                },
            },
            Message::Ping(payload) => {
                if self.relays[link_index]
                    .io
                    .send_message(Message::Pong(payload))
                    .is_err()
                {
                    self.relays.remove(link_index);
                    self.next_relay = 0;
                    if self.relays.is_empty() {
                        return Err(RelayError::NoRelayAvailable);
                    }
                }
                Ok(None)
            }
            Message::Close(_) => {
                self.relays.remove(link_index);
                self.next_relay = 0;
                if self.relays.is_empty() {
                    return Err(RelayError::NoRelayAvailable);
                }
                Ok(None)
            }
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => Ok(None),
        }
    }

    fn wait_until_relay_ready(&mut self, timeout: Duration) -> Result<(), RelayError> {
        let deadline = Instant::now() + timeout;
        while !self.relays.iter().any(|relay| relay.ready) {
            if self
                .cancelled
                .as_ref()
                .is_some_and(|token| token.load(Ordering::SeqCst))
            {
                return Err(RelayError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(RelayError::TimedOut("relay subscription"));
            }
            let Some((_index, incoming)) = self.poll_any_raw_message()? else {
                continue;
            };
            self.buffer_incoming(_index, incoming)?;
        }
        Ok(())
    }

    fn poll_any_raw_message(&mut self) -> Result<Option<(usize, Message)>, RelayError> {
        if self.relays.is_empty() {
            return Err(RelayError::NoRelayAvailable);
        }
        let mut attempts = self.relays.len();
        while attempts > 0 && !self.relays.is_empty() {
            let index = self.next_relay % self.relays.len();
            self.next_relay = (index + 1) % self.relays.len();
            attempts -= 1;
            match self.relays[index].io.read_message() {
                Ok(Some(message)) => return Ok(Some((index, message))),
                Ok(None) => {}
                Err(_) => {
                    self.relays.remove(index);
                    self.next_relay = if self.relays.is_empty() {
                        0
                    } else {
                        index % self.relays.len()
                    };
                }
            }
        }
        Ok(None)
    }

    fn buffer_incoming(&mut self, index: usize, incoming: Message) -> Result<(), RelayError> {
        match incoming {
            Message::Text(text) => {
                if let Ok(RelayMessage::EndOfStoredEvents(subscription)) =
                    RelayMessage::from_json(text.as_str())
                {
                    if subscription.as_ref() == &self.relays[index].subscription {
                        self.relays[index].ready = true;
                        return Ok(());
                    }
                }
                self.relays[index].buffered.push_back(Message::Text(text));
            }
            Message::Ping(payload) => {
                self.relays[index].io.send_message(Message::Pong(payload))?;
            }
            other => self.relays[index].buffered.push_back(other),
        }
        Ok(())
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

fn wait_for_any_subscription(
    relays: &mut Vec<RelayLink>,
    timeout: Duration,
) -> Result<(), RelayError> {
    let deadline = Instant::now() + timeout.min(SUBSCRIPTION_TIMEOUT);
    let mut first_ready_at: Option<Instant> = None;
    let mut next = 0;
    while relays.iter().any(|relay| !relay.ready) {
        if relays.is_empty() {
            return Err(RelayError::NoRelayAvailable);
        }
        if let Some(ready_at) = first_ready_at {
            if ready_at.elapsed() >= READ_TIMEOUT {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return if relays.iter().any(|relay| relay.ready) {
                Ok(())
            } else {
                Err(RelayError::TimedOut("relay subscription"))
            };
        }
        let index = next % relays.len();
        next = (index + 1) % relays.len();
        match relays[index].io.read_message() {
            Ok(Some(Message::Text(text))) => {
                match subscription_status(text.as_str(), &relays[index].subscription) {
                    Ok(SubscriptionStatus::Pending) => {
                        if buffer_subscription_message(&mut relays[index], Message::Text(text))
                            .is_err()
                        {
                            relays.remove(index);
                            next = 0;
                        }
                    }
                    Ok(SubscriptionStatus::Ready) => {
                        relays[index].ready = true;
                        first_ready_at.get_or_insert_with(Instant::now);
                    }
                    Ok(SubscriptionStatus::Closed(_)) | Err(_) => {
                        relays.remove(index);
                        next = 0;
                    }
                }
            }
            Ok(Some(Message::Ping(payload))) => {
                if relays[index]
                    .io
                    .send_message(Message::Pong(payload))
                    .is_err()
                {
                    relays.remove(index);
                    next = 0;
                }
            }
            Ok(Some(message)) => {
                if buffer_subscription_message(&mut relays[index], message).is_err() {
                    relays.remove(index);
                    next = 0;
                }
            }
            Ok(None) => {}
            Err(_) => {
                relays.remove(index);
                next = 0;
            }
        }
        std::thread::yield_now();
    }
    if relays.is_empty() {
        Err(RelayError::NoRelayAvailable)
    } else {
        Ok(())
    }
}

fn buffer_subscription_message(relay: &mut RelayLink, message: Message) -> Result<(), ()> {
    if relay.buffered.len() >= 64 {
        return Err(());
    }
    relay.buffered.push_back(message);
    Ok(())
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
        subscription_status, InviteCode, Message, RelayError, RelayRendezvous, RelayUpdate, Role,
        SubscriptionStatus,
    };
    use crate::identity::Identity;
    use nostr::prelude::SubscriptionId;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Default)]
    struct FakeRelayNetwork {
        state: Arc<Mutex<FakeRelayState>>,
        next_socket: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct FakeRelayState {
        subscriptions: HashMap<String, Vec<FakeSubscription>>,
        failed: BTreeSet<String>,
        malformed_subscriptions: BTreeSet<String>,
        closed_subscriptions: BTreeSet<String>,
        silent_subscriptions: BTreeSet<String>,
        overflowing_subscriptions: BTreeSet<String>,
        delayed_subscriptions: HashMap<String, Duration>,
        ack_modes: HashMap<String, FakeAckMode>,
        published: Vec<(String, String)>,
    }

    #[derive(Clone, Copy)]
    enum FakeAckMode {
        Accept,
        Reject,
        Silent,
    }

    #[derive(Clone)]
    struct FakeSubscription {
        socket_id: usize,
        subscription_id: String,
        filter: Value,
        sender: Sender<Message>,
    }

    struct FakeRelayIo {
        network: FakeRelayNetwork,
        endpoint: String,
        socket_id: usize,
        incoming: Receiver<Message>,
        sender: Sender<Message>,
    }

    impl FakeRelayNetwork {
        fn open(&self, endpoint: &str) -> Result<Box<dyn super::RelayIo>, RelayError> {
            if self.state.lock().unwrap().failed.contains(endpoint) {
                return Err(RelayError::Disconnected);
            }
            let (sender, incoming) = mpsc::channel();
            let socket_id = self.next_socket.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(FakeRelayIo {
                network: self.clone(),
                endpoint: endpoint.to_owned(),
                socket_id,
                incoming,
                sender,
            }))
        }

        fn fail(&self, endpoint: &str) {
            self.state
                .lock()
                .unwrap()
                .failed
                .insert(endpoint.to_owned());
        }

        fn with_subscription_failure(&self, endpoint: &str, malformed: bool, closed: bool) {
            let mut state = self.state.lock().unwrap();
            if malformed {
                state.malformed_subscriptions.insert(endpoint.to_owned());
            }
            if closed {
                state.closed_subscriptions.insert(endpoint.to_owned());
            }
        }

        fn set_ack_mode(&self, endpoint: &str, mode: FakeAckMode) {
            self.state
                .lock()
                .unwrap()
                .ack_modes
                .insert(endpoint.to_owned(), mode);
        }

        fn overflow_subscription_buffer(&self, endpoint: &str) {
            self.state
                .lock()
                .unwrap()
                .overflowing_subscriptions
                .insert(endpoint.to_owned());
        }

        fn delay_subscription(&self, endpoint: &str, delay: Duration) {
            self.state
                .lock()
                .unwrap()
                .delayed_subscriptions
                .insert(endpoint.to_owned(), delay);
        }

        fn published(&self) -> Vec<(String, String)> {
            self.state.lock().unwrap().published.clone()
        }
    }

    impl FakeRelayIo {
        fn is_failed(&self) -> bool {
            self.network
                .state
                .lock()
                .unwrap()
                .failed
                .contains(&self.endpoint)
        }

        fn event_matches(filter: &Value, event: &Value) -> bool {
            if filter
                .get("kinds")
                .and_then(Value::as_array)
                .is_some_and(|kinds| !kinds.iter().any(|kind| kind == &event["kind"]))
            {
                return false;
            }
            if filter
                .get("authors")
                .and_then(Value::as_array)
                .is_some_and(|authors| !authors.iter().any(|author| author == &event["pubkey"]))
            {
                return false;
            }
            filter.as_object().is_none_or(|fields| {
                fields
                    .iter()
                    .filter(|(key, _)| key.starts_with('#'))
                    .all(|(key, values)| {
                        let tag_name = &key[1..];
                        let Some(values) = values.as_array() else {
                            return false;
                        };
                        event["tags"].as_array().is_some_and(|tags| {
                            tags.iter().any(|tag| {
                                tag[0].as_str() == Some(tag_name)
                                    && values.iter().any(|value| value == &tag[1])
                            })
                        })
                    })
            })
        }

        fn send_text(&self, text: &str) -> Result<(), RelayError> {
            if self.is_failed() {
                return Err(RelayError::Disconnected);
            }
            let message: Value =
                serde_json::from_str(text).map_err(|_| RelayError::InvalidEvent)?;
            match message[0].as_str() {
                Some("REQ") => {
                    let subscription_id = message[1]
                        .as_str()
                        .ok_or(RelayError::InvalidEvent)?
                        .to_owned();
                    let filters = message[2]
                        .as_array()
                        .cloned()
                        .unwrap_or_else(|| vec![message[2].clone()]);
                    let mut state = self.network.state.lock().unwrap();
                    if state.malformed_subscriptions.contains(&self.endpoint) {
                        return self
                            .sender
                            .send(Message::text("not json"))
                            .map_err(|_| RelayError::Disconnected);
                    }
                    if state.closed_subscriptions.contains(&self.endpoint) {
                        return self
                            .sender
                            .send(Message::text(
                                serde_json::json!(["CLOSED", subscription_id, "test close"])
                                    .to_string(),
                            ))
                            .map_err(|_| RelayError::Disconnected);
                    }
                    let subscriptions = state
                        .subscriptions
                        .entry(self.endpoint.clone())
                        .or_default();
                    subscriptions.retain(|entry| {
                        entry.socket_id != self.socket_id
                            || entry.subscription_id != subscription_id
                    });
                    for filter in &filters {
                        subscriptions.push(FakeSubscription {
                            socket_id: self.socket_id,
                            subscription_id: subscription_id.clone(),
                            filter: filter.clone(),
                            sender: self.sender.clone(),
                        });
                    }
                    let delay = state.delayed_subscriptions.get(&self.endpoint).copied();
                    if state.overflowing_subscriptions.contains(&self.endpoint) {
                        for _ in 0..65 {
                            self.sender
                                .send(Message::Binary(vec![1].into()))
                                .map_err(|_| RelayError::Disconnected)?;
                        }
                    }
                    if state.silent_subscriptions.contains(&self.endpoint) {
                        return Ok(());
                    }
                    if let Some(delay) = delay {
                        let sender = self.sender.clone();
                        thread::spawn(move || {
                            thread::sleep(delay);
                            let _ = sender.send(Message::text(
                                serde_json::json!(["EOSE", subscription_id]).to_string(),
                            ));
                        });
                        return Ok(());
                    }
                    self.sender
                        .send(Message::text(
                            serde_json::json!(["EOSE", subscription_id]).to_string(),
                        ))
                        .map_err(|_| RelayError::Disconnected)
                }
                Some("CLOSE") => {
                    let Some(subscription_id) = message[1].as_str() else {
                        return Err(RelayError::InvalidEvent);
                    };
                    if let Some(subscriptions) = self
                        .network
                        .state
                        .lock()
                        .unwrap()
                        .subscriptions
                        .get_mut(&self.endpoint)
                    {
                        subscriptions.retain(|entry| {
                            entry.socket_id != self.socket_id
                                || entry.subscription_id != subscription_id
                        });
                    }
                    Ok(())
                }
                Some("EVENT") => {
                    let event = &message[1];
                    let event_id = event["id"]
                        .as_str()
                        .ok_or(RelayError::InvalidEvent)?
                        .to_owned();
                    let (recipients, ack_mode) = {
                        let mut state = self.network.state.lock().unwrap();
                        state
                            .published
                            .push((self.endpoint.clone(), event_id.clone()));
                        let recipients = state
                            .subscriptions
                            .get(&self.endpoint)
                            .into_iter()
                            .flatten()
                            .filter(|subscription| Self::event_matches(&subscription.filter, event))
                            .cloned()
                            .collect::<Vec<_>>();
                        let mode = state
                            .ack_modes
                            .get(&self.endpoint)
                            .copied()
                            .unwrap_or(FakeAckMode::Accept);
                        (recipients, mode)
                    };
                    for subscription in recipients {
                        let _ = subscription.sender.send(Message::text(
                            serde_json::json!(["EVENT", subscription.subscription_id, event])
                                .to_string(),
                        ));
                    }
                    match ack_mode {
                        FakeAckMode::Accept | FakeAckMode::Reject => {
                            let accepted = matches!(ack_mode, FakeAckMode::Accept);
                            let _ = self.sender.send(Message::text(
                                serde_json::json!([
                                    "OK",
                                    event_id,
                                    accepted,
                                    if accepted { "stored" } else { "rejected" }
                                ])
                                .to_string(),
                            ));
                        }
                        FakeAckMode::Silent => {}
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    impl super::RelayIo for FakeRelayIo {
        fn send_message(&mut self, message: Message) -> Result<(), RelayError> {
            match message {
                Message::Text(text) => self.send_text(text.as_str()),
                _ if self.is_failed() => Err(RelayError::Disconnected),
                _ => Ok(()),
            }
        }

        fn read_message(&mut self) -> Result<Option<Message>, RelayError> {
            if self.is_failed() {
                return Err(RelayError::Disconnected);
            }
            match self.incoming.recv_timeout(Duration::from_millis(2)) {
                Ok(message) => Ok(Some(message)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(RelayError::Disconnected),
            }
        }
    }

    fn fake_connected_party(
        network: FakeRelayNetwork,
        endpoints: Vec<String>,
        invite_code: String,
        role: Role,
        identity: Identity,
        expected_peer: Option<[u8; 32]>,
    ) -> Result<(super::RelaySession, zeroize::Zeroizing<[u8; 32]>), RelayError> {
        let invite = InviteCode::parse(&invite_code).ok_or(RelayError::InvalidEvent)?;
        let mut rendezvous =
            RelayRendezvous::connect_with(&endpoints, &invite, role, |endpoint| {
                network.open(endpoint)
            })?;
        rendezvous.timeout = Duration::from_secs(2);
        let channel = rendezvous.complete_handshake()?;
        let verification = rendezvous.authenticate(channel, &identity, expected_peer)?;
        if expected_peer.is_some() {
            rendezvous
                .confirm(verification)
                .map(|session| (session, zeroize::Zeroizing::new([0; 32])))
        } else {
            rendezvous.confirm_with_contact(verification)
        }
    }

    fn fake_session_pair(
        network: FakeRelayNetwork,
        endpoints_a: Vec<String>,
        endpoints_b: Vec<String>,
    ) -> (super::RelaySession, super::RelaySession) {
        let (identity_a, code_a) = Identity::create().unwrap();
        let (identity_b, code_b) = Identity::create().unwrap();
        let public_a = identity_a.public_key();
        let public_b = identity_b.public_key();
        let role_a = if public_a < public_b {
            Role::Responder
        } else {
            Role::Initiator
        };
        let role_b = if role_a == Role::Responder {
            Role::Initiator
        } else {
            Role::Responder
        };
        let invite = InviteCode::generate().unwrap();
        let invite_code = invite.code().to_owned();
        let network_a = network.clone();
        let code_a_for_worker = code_a.clone();
        let invite_code_a = invite_code.clone();
        let task_a = thread::spawn(move || {
            fake_connected_party(
                network_a,
                endpoints_a,
                invite_code_a,
                role_a,
                Identity::from_code(&code_a_for_worker).unwrap(),
                None,
            )
        });
        let code_b_for_worker = code_b.clone();
        let task_b = thread::spawn(move || {
            fake_connected_party(
                network,
                endpoints_b,
                invite_code,
                role_b,
                Identity::from_code(&code_b_for_worker).unwrap(),
                None,
            )
        });
        (
            task_a.join().unwrap().unwrap().0,
            task_b.join().unwrap().unwrap().0,
        )
    }

    #[test]
    fn subscriptions_isolate_bad_relays_and_report_exhaustion_and_buffer_overflow() {
        let invite = InviteCode::generate().unwrap();
        let code = invite.code().to_owned();
        let malformed = "wss://malformed.test".to_owned();
        let closed = "wss://closed.test".to_owned();
        let healthy = "wss://healthy.test".to_owned();
        let network = FakeRelayNetwork::default();
        network.with_subscription_failure(&malformed, true, false);
        network.with_subscription_failure(&closed, false, true);
        let invite_for_connect = InviteCode::parse(&code).unwrap();
        let rendezvous = RelayRendezvous::connect_with(
            &[malformed.clone(), closed.clone(), healthy.clone()],
            &invite_for_connect,
            Role::Initiator,
            |endpoint| network.open(endpoint),
        )
        .unwrap();
        assert_eq!(rendezvous.relays.len(), 1);
        assert_eq!(rendezvous.relays[0].id, 2);

        let all_bad = FakeRelayNetwork::default();
        all_bad.with_subscription_failure(&malformed, true, false);
        all_bad.with_subscription_failure(&closed, false, true);
        let invite_for_connect = InviteCode::parse(&code).unwrap();
        assert!(matches!(
            RelayRendezvous::connect_with(
                &[malformed, closed],
                &invite_for_connect,
                Role::Initiator,
                |endpoint| all_bad.open(endpoint),
            ),
            Err(RelayError::NoRelayAvailable)
        ));

        let flood = "wss://flood.test".to_owned();
        let network = FakeRelayNetwork::default();
        network.overflow_subscription_buffer(&flood);
        let invite_for_connect = InviteCode::parse(&code).unwrap();
        let rendezvous = RelayRendezvous::connect_with(
            &[flood, healthy],
            &invite_for_connect,
            Role::Initiator,
            |endpoint| network.open(endpoint),
        )
        .unwrap();
        assert_eq!(rendezvous.relays.len(), 1);
        assert_eq!(
            rendezvous.relays[0].id, 1,
            "overflowing route is explicitly dropped"
        );
    }

    #[test]
    fn subscription_wait_does_not_wait_for_late_eose_after_a_route_is_ready() {
        let network = FakeRelayNetwork::default();
        let slow = "wss://slow-eose.test";
        let ready = "wss://ready-eose.test";
        network.delay_subscription(slow, Duration::from_secs(2));
        let invite = InviteCode::generate().unwrap();
        let code = invite.code().to_owned();
        let invite = InviteCode::parse(&code).unwrap();
        let started = Instant::now();
        let rendezvous = RelayRendezvous::connect_with(
            &[slow.to_owned(), ready.to_owned()],
            &invite,
            Role::Initiator,
            |endpoint| network.open(endpoint),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(rendezvous.relays.iter().any(|relay| relay.ready));
    }

    #[test]
    fn lost_publish_path_and_pending_limit_have_explicit_results_without_sequence_gaps() {
        let relay_a = "wss://publish-a.test".to_owned();
        let relay_b = "wss://publish-b.test".to_owned();
        let network = FakeRelayNetwork::default();
        network.set_ack_mode(&relay_a, FakeAckMode::Silent);
        network.set_ack_mode(&relay_b, FakeAckMode::Reject);
        let (mut sender, receiver) = fake_session_pair(
            network.clone(),
            vec![relay_a.clone(), relay_b.clone()],
            vec![relay_b.clone(), relay_a.clone()],
        );
        let uncertain_id = sender.send(b"awaiting result").unwrap();
        network.fail(&relay_a);
        let rejected_id = sender.send(b"rejected on remaining route").unwrap();
        let mut unknown = None;
        let mut rejected = None;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && (unknown.is_none() || rejected.is_none()) {
            match sender.poll() {
                Ok(Some(RelayUpdate::PublishUnknown { event_id })) => unknown = Some(event_id),
                Ok(Some(RelayUpdate::Published { event_id })) => {
                    panic!("unexpected acceptance: {event_id}")
                }
                Err(RelayError::RelayRejected { event_id, .. }) => rejected = Some(event_id),
                Ok(Some(RelayUpdate::Messages(_))) | Ok(Some(RelayUpdate::Ready)) | Ok(None) => {}
                Err(error) => panic!("unexpected relay failure: {error:?}"),
            }
        }
        assert_eq!(unknown.as_deref(), Some(uncertain_id.as_str()));
        assert_eq!(rejected.as_deref(), Some(rejected_id.as_str()));
        drop(receiver);

        let network = FakeRelayNetwork::default();
        let (mut sender, mut receiver) = fake_session_pair(
            network,
            vec![relay_a.clone(), relay_b.clone()],
            vec![relay_b, relay_a],
        );
        for index in 0..1024 {
            sender
                .pending_publishes
                .insert(format!("pending-{index}"), BTreeSet::from([0]));
        }
        assert!(matches!(
            sender.send(b"must not consume sequence"),
            Err(RelayError::PendingPublishLimit)
        ));
        assert_eq!(sender.pending_publishes.len(), 1024);
        assert!(sender.pending_publishes.contains_key("pending-0"));
        assert!(sender.pending_publishes.contains_key("pending-1023"));
        sender.pending_publishes.clear();
        sender.send(b"first accepted sequence").unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut received = Vec::new();
        while Instant::now() < deadline && received.is_empty() {
            if let Some(RelayUpdate::Messages(messages)) = receiver.poll().unwrap() {
                received.extend(messages);
            }
        }
        assert_eq!(received, vec![b"first accepted sequence".to_vec()]);
    }

    #[test]
    fn multi_relay_handshake_session_failover_and_reconnect_use_shared_paths() {
        let network = FakeRelayNetwork::default();
        let (identity_a, code_a) = Identity::create().unwrap();
        let (identity_b, code_b) = Identity::create().unwrap();
        let invite = InviteCode::generate().unwrap();
        let invite_code = invite.code().to_owned();
        drop(invite);

        let relay_a = "wss://relay-a.test".to_owned();
        let relay_b = "wss://relay-b.test".to_owned();
        let relay_c = "wss://relay-c.test".to_owned();
        network.fail(&relay_c);
        let network_a = network.clone();
        let invite_a = invite_code.clone();
        let code_a_for_first = code_a.clone();
        let a_endpoints = vec![relay_a.clone(), relay_b.clone()];
        let task_a = thread::spawn(move || {
            fake_connected_party(
                network_a,
                a_endpoints,
                invite_a,
                Role::Initiator,
                identity_a,
                None,
            )
        });
        let network_b = network.clone();
        let code_b_for_first = code_b.clone();
        let b_endpoints = vec![relay_b.clone(), relay_c.clone()];
        let task_b = thread::spawn(move || {
            fake_connected_party(
                network_b,
                b_endpoints,
                invite_code,
                Role::Responder,
                identity_b,
                None,
            )
        });
        let (mut session_a, secret_a) = task_a.join().unwrap().unwrap();
        let (mut session_b, secret_b) = task_b.join().unwrap().unwrap();

        let event_id = session_a.send(b"first multi relay message").unwrap();
        let mut ack_count = 0;
        let mut received = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && (ack_count == 0 || received.is_empty()) {
            if let Some(RelayUpdate::Published { event_id: ack }) = session_a.poll().unwrap() {
                ack_count += usize::from(ack == event_id);
            }
            if let Some(RelayUpdate::Messages(messages)) = session_b.poll().unwrap() {
                received.extend(messages);
            }
        }
        for _ in 0..8 {
            if let Some(RelayUpdate::Published { event_id: ack }) = session_a.poll().unwrap() {
                ack_count += usize::from(ack == event_id);
            }
            if let Some(RelayUpdate::Messages(messages)) = session_b.poll().unwrap() {
                received.extend(messages);
            }
        }
        assert_eq!(ack_count, 1, "relay acknowledgements must be coalesced");
        assert_eq!(received, vec![b"first multi relay message".to_vec()]);

        let mirrored_event = network
            .published()
            .into_iter()
            .fold(
                HashMap::<String, BTreeSet<String>>::new(),
                |mut grouped, (relay, id)| {
                    grouped.entry(id).or_default().insert(relay);
                    grouped
                },
            )
            .into_values()
            .any(|relays| relays.contains(&relay_a) && relays.contains(&relay_b));
        assert!(
            mirrored_event,
            "bootstrap frames should use the same event on both relays"
        );

        network.fail(&relay_a);
        session_a.send(b"after one relay failed").unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut after_failure = Vec::new();
        while Instant::now() < deadline && after_failure.is_empty() {
            if let Some(RelayUpdate::Messages(messages)) = session_b.poll().unwrap() {
                after_failure.extend(messages);
            }
        }
        assert_eq!(after_failure, vec![b"after one relay failed".to_vec()]);

        network.fail(&relay_b);
        network.fail(&relay_c);
        assert!(matches!(session_a.poll(), Err(RelayError::Disconnected)));
        assert!(matches!(session_b.poll(), Err(RelayError::Disconnected)));
        drop(session_a);
        drop(session_b);
        assert_eq!(secret_a.as_ref(), secret_b.as_ref());

        let shared_secret: [u8; 32] = secret_a.as_ref().try_into().unwrap();
        let reconnect_code = reconnect_invite_for_test(shared_secret);
        let public_a = Identity::from_code(&code_a_for_first).unwrap().public_key();
        let public_b = Identity::from_code(&code_b_for_first).unwrap().public_key();
        let role_a = if public_a < public_b {
            Role::Responder
        } else {
            Role::Initiator
        };
        let role_b = if role_a == Role::Responder {
            Role::Initiator
        } else {
            Role::Responder
        };
        let reconnect_network = FakeRelayNetwork::default();
        let network_a = reconnect_network.clone();
        let reconnect_code_a = reconnect_code.clone();
        let reconnect_relays_a = vec![relay_a.clone(), relay_b.clone()];
        let reconnect_code_a_for_identity = code_a_for_first.clone();
        let task_a = thread::spawn(move || {
            fake_connected_party(
                network_a,
                reconnect_relays_a,
                reconnect_code_a,
                role_a,
                Identity::from_code(&reconnect_code_a_for_identity).unwrap(),
                Some(public_b),
            )
        });
        let network_b = reconnect_network.clone();
        let reconnect_relays_b = vec![relay_b, relay_a];
        let task_b = thread::spawn(move || {
            fake_connected_party(
                network_b,
                reconnect_relays_b,
                reconnect_code,
                role_b,
                Identity::from_code(&code_b_for_first).unwrap(),
                Some(public_a),
            )
        });
        let (mut reconnected_a, _) = task_a.join().unwrap().unwrap();
        let (mut reconnected_b, _) = task_b.join().unwrap().unwrap();
        reconnected_a
            .send(b"reconnected over shared relay set")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut reconnected_message = Vec::new();
        while Instant::now() < deadline && reconnected_message.is_empty() {
            if let Some(RelayUpdate::Messages(messages)) = reconnected_b.poll().unwrap() {
                reconnected_message.extend(messages);
            }
        }
        assert_eq!(
            reconnected_message,
            vec![b"reconnected over shared relay set".to_vec()]
        );
    }

    fn reconnect_invite_for_test(secret: [u8; 32]) -> String {
        InviteCode::from_reconnect_secret(zeroize::Zeroizing::new(secret))
            .code()
            .to_owned()
    }

    #[test]
    fn multi_relay_rendezvous_times_out_when_the_participants_share_no_relay() {
        let network = FakeRelayNetwork::default();
        let invite = InviteCode::generate().unwrap();
        let invite_code = invite.code().to_owned();
        let left_network = network.clone();
        let left_code = invite_code.clone();
        let left = thread::spawn(move || {
            let invite = InviteCode::parse(&left_code).unwrap();
            let mut rendezvous = RelayRendezvous::connect_with(
                &["wss://left-only.test".to_owned()],
                &invite,
                Role::Initiator,
                |endpoint| left_network.open(endpoint),
            )
            .unwrap();
            rendezvous.timeout = Duration::from_millis(120);
            rendezvous.complete_handshake()
        });
        let right_network = network.clone();
        let right = thread::spawn(move || {
            let invite = InviteCode::parse(&invite_code).unwrap();
            let mut rendezvous = RelayRendezvous::connect_with(
                &["wss://right-only.test".to_owned()],
                &invite,
                Role::Responder,
                |endpoint| right_network.open(endpoint),
            )
            .unwrap();
            rendezvous.timeout = Duration::from_millis(120);
            rendezvous.complete_handshake()
        });
        assert!(matches!(
            left.join().unwrap(),
            Err(RelayError::TimedOut("peer subscription"))
        ));
        assert!(matches!(
            right.join().unwrap(),
            Err(RelayError::TimedOut("peer subscription"))
        ));
    }

    #[test]
    fn relay_validation_is_local_and_normalizes_duplicate_endpoints() {
        assert_eq!(
            super::validate_relay_endpoint("wss://RELAY.Example").unwrap(),
            "wss://relay.example/"
        );
        assert_eq!(
            super::validate_relay_endpoint("wss://relay.example:443/").unwrap(),
            "wss://relay.example/"
        );
        for endpoint in [
            "",
            "ws://relay.example",
            "http://relay.example",
            "wss://user@relay.example",
            "wss://relay.example/#fragment",
            "wss://relay.example/a b",
            "wss://relay.example:0",
            "wss://relay.example:65536",
            "wss://relay.example:notaport",
            "wss://-invalid.example",
            "wss://bad_host.example",
        ] {
            assert!(
                super::validate_relay_endpoint(endpoint).is_err(),
                "accepted invalid endpoint: {endpoint}"
            );
        }
        assert!(super::validate_relay_list(&[]).is_err());
        assert!(super::validate_relay_list(&[
            "wss://relay.example".to_owned(),
            "wss://RELAY.EXAMPLE:443/".to_owned(),
        ])
        .is_err());
        assert!(super::validate_relay_endpoint("wss://no-such-host.invalid").is_ok());
    }

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
    fn invite_codes_mark_the_current_rendezvous_protocol_version() {
        let invite = InviteCode::generate().unwrap();
        assert!(invite.code().starts_with("ADI3-"));
        assert!(InviteCode::parse(invite.code()).is_some());
        let legacy = invite.code().replacen("ADI3-", "ADI2-", 1);
        assert!(InviteCode::parse(&legacy).is_none());
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
        let endpoints = vec!["wss://relay.primal.net".to_owned()];
        let mut abandoned_join =
            RelayRendezvous::join(&endpoints, &abandoned_invite, None).unwrap();
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
        let endpoints = vec!["wss://relay.primal.net".to_owned()];
        let mut rendezvous = match role {
            Role::Initiator => RelayRendezvous::join(&endpoints, &invite, None),
            Role::Responder => RelayRendezvous::create(&endpoints, &invite, None),
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
        let (mut session, secret) = rendezvous.confirm_with_contact(verification).unwrap();
        fingerprint_tx.send(secret.to_vec()).unwrap();
        assert_eq!(
            fingerprint_rx
                .recv_timeout(Duration::from_secs(35))
                .unwrap(),
            secret.as_ref()
        );
        barrier.wait();
        session.send(crate::PEER_HEARTBEAT_FRAME).unwrap();
        let heartbeat_deadline = Instant::now() + Duration::from_secs(15);
        let mut saw_peer_heartbeat = false;
        while Instant::now() < heartbeat_deadline {
            if let Some(RelayUpdate::Messages(messages)) = session.poll().unwrap() {
                saw_peer_heartbeat |= messages
                    .iter()
                    .any(|message| message.as_slice() == crate::PEER_HEARTBEAT_FRAME);
                if saw_peer_heartbeat {
                    break;
                }
            }
        }
        assert!(saw_peer_heartbeat);
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
        drop(session);
        fingerprint_tx.send(identity.public_key().to_vec()).unwrap();
        let peer_key: [u8; 32] = fingerprint_rx
            .recv_timeout(Duration::from_secs(35))
            .unwrap()
            .try_into()
            .unwrap();
        let invite = InviteCode::from_reconnect_secret(secret);
        let endpoints = vec!["wss://relay.primal.net".to_owned()];
        barrier.wait();
        let mut reconnect = if identity.public_key() < peer_key {
            RelayRendezvous::create(&endpoints, &invite, None)
        } else {
            RelayRendezvous::join(&endpoints, &invite, None)
        }
        .unwrap();
        let channel = reconnect.complete_handshake().unwrap();
        let verified = reconnect
            .authenticate(channel, &identity, Some(peer_key))
            .unwrap();
        let mut session = reconnect.confirm(verified).unwrap();
        barrier.wait();
        session.send(send.as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(35);
        let mut got = false;
        while Instant::now() < deadline {
            if let Some(RelayUpdate::Messages(messages)) = session.poll().unwrap() {
                if messages
                    .iter()
                    .any(|message| message == expected.as_bytes())
                {
                    got = true;
                    break;
                }
            }
        }
        assert!(got);
    }
}
