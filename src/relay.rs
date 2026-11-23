//! Minimal NIP-01 rendezvous and WebSocket adapter for Noise sessions.
//!
//! It publishes only kind-20000 ephemeral events. The relay still observes the
//! session tag, timing, size, and connection IP in direct mode. Callers select
//! an optional loopback SOCKS5 proxy; proxy failures never fall back to direct.

use crate::channel::MAX_ENVELOPE;
use crate::channel::{
    Handshake, HandshakeError, PendingChannel, Role, SessionTransport, VerificationPending,
};
use crate::identity::Identity;
use hkdf::Hkdf;
use nostr::prelude::{
    ClientMessage, Error as NostrError, EventBuilder, Filter, FinalizeEvent, Keys, Kind, PublicKey,
    RelayMessage, SecretKey, SingleLetterTag, SubscriptionId, Tag, Timestamp,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::collections::{HashMap, VecDeque};
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
const INVITE_PREFIX: &str = "ADI3-";
const INVITE_TOPIC_INFO: &[u8] = b"another-dimension-v2/invite-topic/v2";
const INVITE_KEY_INFO: &[u8] = b"another-dimension-v2/invite-relay-key/v2";
const INVITE_DOMAIN: &[u8] = b"another-dimension-v2/invite-code/v2";
/// A reconnect uses a long-lived secret, so the rendezvous topic and author key change
/// every epoch. Otherwise a relay could tell from the unchanging topic that the same two
/// people connect again and again. Both sides listen on the epochs around the current one
/// so that clocks that disagree a little, or a connection that straddles a boundary, still
/// meet.
const EPOCH_LENGTH_SECONDS: u64 = 6 * 60 * 60;
const EPOCH_INFO: &[u8] = b"another-dimension-v2/reconnect-epoch/v3";
/// An event older or newer than this is not accepted as part of a rendezvous. A relay
/// that stored an old event and replays it later is thereby ignored.
const MAX_EVENT_AGE_SECONDS: u64 = 5 * 60;
const READY_REQUEST_PREFIX: &[u8] = b"\0AD2-READY-1:";
const READY_ACK_PREFIX: &[u8] = b"\0AD2-READY-ACK-1:";
/// The largest frame exchanged while a session is being set up. These frames are padded
/// like chat messages, so the smallest size class plus its tag is the usual size and the
/// limit has to allow for it.
const MAX_BOOTSTRAP_FRAME: usize = crate::channel::SMALLEST_PADDED_FRAME;
const MAX_RELAY_MESSAGE: usize = 20 * 1024;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(15);
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a rendezvous waits for the peer to appear on the topic before giving up.
/// Cancelling ends it sooner. It only bounds the resources an abandoned invite holds.
const PEER_WAIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How long a person may take to compare the confirmation code and press confirm,
/// and how long to wait for the other person to do the same. The protocol timeout
/// above is far too short for people reading digits to each other.
pub(crate) const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
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
    /// Deriving a key failed: an internal error, not something a peer or relay sent.
    KeyDerivation,
    TimedOut(&'static str),
    SubscriptionClosed(String),
    RelayRejected {
        event_id: String,
        reason: String,
    },
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
    /// A hole in the sequence never filled, so the receiver moved past it. Relay events
    /// are not retransmitted, which means `count` messages from the peer may be lost.
    MessagesLost {
        count: u64,
    },
    Published {
        event_id: String,
    },
    PublishUnknown {
        event_id: String,
    },
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

/// What one round of reading the links produced.
struct LinkRead {
    /// The link that had a message, and the message.
    message: Option<(usize, Message)>,
    /// The ids of links that failed and were dropped, for the caller's own bookkeeping.
    dropped: Vec<usize>,
}

/// Reads one message from the next link that has one, trying each link at most once and
/// dropping a link whose read fails. `next_relay` keeps the round robin fair.
fn read_next_message(relays: &mut Vec<RelayLink>, next_relay: &mut usize) -> LinkRead {
    let mut dropped = Vec::new();
    let mut attempts = relays.len();
    while attempts > 0 && !relays.is_empty() {
        let index = *next_relay % relays.len();
        *next_relay = (index + 1) % relays.len();
        attempts -= 1;
        match relays[index].read() {
            Ok(Some(message)) => {
                return LinkRead {
                    message: Some((index, message)),
                    dropped,
                };
            }
            Ok(None) => {}
            Err(_) => {
                dropped.push(relays.remove(index).id);
                *next_relay = if relays.is_empty() {
                    0
                } else {
                    index % relays.len()
                };
            }
        }
    }
    LinkRead {
        message: None,
        dropped,
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
    /// A loss report that follows messages that were just delivered.
    pending_gap_update: Option<RelayUpdate>,
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
            new_subscription_id()?,
        );
        Self::from_links(vec![link], transport)
    }

    fn from_links(
        mut relays: Vec<RelayLink>,
        transport: SessionTransport,
    ) -> Result<Self, RelayError> {
        let (keys, peer_author, session_tag) = transport.relay_credentials();
        let keys = keys.clone();
        let topic = crate::hex::encode(session_tag);
        let subscription = new_subscription_id()?;
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
            pending_gap_update: None,
        })
    }

    /// Encrypts and publishes one live event. The returned identifier is the
    /// event id; relay acceptance arrives separately as `RelayUpdate::Published`.
    pub fn send(&mut self, message: &[u8]) -> Result<String, RelayError> {
        if self.pending_publishes.len() >= 1024 {
            return Err(RelayError::PendingPublishLimit);
        }
        let envelope = self.transport.send(message)?;
        let event = EventBuilder::new(Kind::Custom(EVENT_KIND), crate::hex::encode(&envelope))
            .tag(Tag::custom("t", [self.topic.as_str()]))
            .finalize(&self.keys)?;
        let event_id = event.id.to_string();
        let text = ClientMessage::event(event).as_json();
        let mut awaiting = BTreeSet::new();
        let mut index = 0;
        while index < self.relays.len() {
            // REQ is sent when each RelayLink is created. EOSE only marks the
            // end of historical results; it does not mean the subscription
            // becomes active. Publish to every subscribed socket so a late
            // EOSE on a shared relay cannot lose the first live message.
            if self.relays[index].send_text(&text).is_err() {
                self.remove_relay(index);
            } else {
                awaiting.insert(self.relays[index].id);
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
        // A hole is given up on by time, not by the arrival of more frames, so check it
        // on every poll even when nothing new came in.
        if let Some(update) = self.pending_gap_update.take() {
            return Ok(Some(update));
        }
        let (messages, skipped) = self.transport.skip_expired_gap(Instant::now())?;
        if skipped > 0 {
            if !messages.is_empty() {
                // Deliver what was held back first, and report the loss on the next poll.
                self.pending_gap_update = Some(RelayUpdate::MessagesLost { count: skipped });
                return Ok(Some(RelayUpdate::Messages(messages)));
            }
            return Ok(Some(RelayUpdate::MessagesLost { count: skipped }));
        }
        if self.relays.is_empty() {
            return Err(RelayError::Disconnected);
        }
        let read = read_next_message(&mut self.relays, &mut self.next_relay);
        for id in read.dropped {
            self.remove_pending_relay(id);
        }
        if self.relays.is_empty() {
            return Err(RelayError::Disconnected);
        }
        let Some((link_index, message)) = read.message else {
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

/// SOCKS5 method numbers (RFC 1928, RFC 1929).
const SOCKS_NO_AUTHENTICATION: u8 = 0;
const SOCKS_USERNAME_PASSWORD: u8 = 2;
const SOCKS_NO_ACCEPTABLE_METHOD: u8 = 0xff;

/// RFC 1929 username and password sub-negotiation with fresh random credentials. The
/// proxy is not asked to check them: for Tor they only select a circuit.
fn authenticate_socks5(stream: &mut TcpStream) -> Result<(), RelayError> {
    let user = random_hex(16)?;
    let password = Zeroizing::new(random_hex(16)?);
    let mut request = Zeroizing::new(Vec::with_capacity(3 + user.len() + password.len()));
    request.push(1);
    request.push(u8::try_from(user.len()).map_err(|_| RelayError::InvalidEndpoint)?);
    request.extend_from_slice(user.as_bytes());
    request.push(u8::try_from(password.len()).map_err(|_| RelayError::InvalidEndpoint)?);
    request.extend_from_slice(password.as_bytes());
    stream.write_all(&request)?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply)?;
    if reply != [1, 0] {
        return Err(RelayError::Io(io::Error::other(
            "SOCKS5 proxy rejected the credentials",
        )));
    }
    Ok(())
}

fn connect_socks5(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream, RelayError> {
    let mut stream = TcpStream::connect_timeout(&proxy, CONNECT_TIMEOUT)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECT_TIMEOUT))?;
    // Offer both methods. Tor puts streams with different credentials on different
    // circuits (IsolateSOCKSAuth), so every connection presents credentials of its own
    // and relays and sessions do not share a circuit. A proxy that needs none is fine.
    stream.write_all(&[5, 2, SOCKS_NO_AUTHENTICATION, SOCKS_USERNAME_PASSWORD])?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection)?;
    if selection[0] != 5 {
        return Err(RelayError::Io(io::Error::other("invalid SOCKS5 response")));
    }
    match selection[1] {
        SOCKS_NO_AUTHENTICATION => {}
        SOCKS_USERNAME_PASSWORD => authenticate_socks5(&mut stream)?,
        SOCKS_NO_ACCEPTABLE_METHOD => {
            return Err(RelayError::Io(io::Error::other(
                "SOCKS5 proxy accepts neither no authentication nor username and password",
            )))
        }
        _ => {
            return Err(RelayError::Io(io::Error::other(
                "SOCKS5 proxy chose an authentication method that was not offered",
            )))
        }
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
    /// A first-time invite is used once and keeps one topic. A reconnect secret is used
    /// again and again, so its topic follows the epoch.
    reconnect: bool,
}

impl InviteCode {
    pub(crate) fn from_reconnect_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let mut invite = Self::from_secret(secret);
        invite.reconnect = true;
        invite
    }
    pub fn generate() -> io::Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        crate::random::fill(secret.as_mut())?;
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
        push_secret_hex(&mut display, secret.as_ref());
        Self {
            secret,
            display,
            reconnect: false,
        }
    }

    /// The topic and event key for one epoch. A first-time invite ignores the epoch.
    fn relay_material_at(&self, epoch: u64) -> Result<(String, Keys), RelayError> {
        let hkdf = Hkdf::<Sha256>::new(Some(INVITE_DOMAIN), self.secret.as_ref());
        // Mixing the epoch into the key material changes both the topic and the key.
        let suffix: Vec<u8> = if self.reconnect {
            let mut suffix = EPOCH_INFO.to_vec();
            suffix.extend_from_slice(&epoch.to_be_bytes());
            suffix
        } else {
            Vec::new()
        };
        let mut topic = [0_u8; 32];
        let mut topic_info = INVITE_TOPIC_INFO.to_vec();
        topic_info.extend_from_slice(&suffix);
        hkdf.expand(&topic_info, &mut topic)
            .map_err(|_| RelayError::KeyDerivation)?;
        for counter in 0_u8..=u8::MAX {
            let mut info = Vec::with_capacity(INVITE_KEY_INFO.len() + suffix.len() + 1);
            info.extend_from_slice(INVITE_KEY_INFO);
            info.extend_from_slice(&suffix);
            info.push(counter);
            let mut bytes = Zeroizing::new([0_u8; 32]);
            hkdf.expand(&info, bytes.as_mut())
                .map_err(|_| RelayError::KeyDerivation)?;
            if let Ok(secret) = SecretKey::from_slice(bytes.as_ref()) {
                return Ok((crate::hex::encode(&topic), Keys::new(secret)));
            }
        }
        Err(RelayError::KeyDerivation)
    }

    /// The epoch a given Unix time falls in.
    fn epoch_of(unix_seconds: u64) -> u64 {
        unix_seconds / EPOCH_LENGTH_SECONDS
    }

    /// Topic and key used to publish at `unix_seconds`, plus every topic and key to listen
    /// on: the epochs before, at and after that time for a reconnect, just the one for a
    /// first-time invite. The publishing pair is always among the listening ones.
    fn rendezvous_at(&self, unix_seconds: u64) -> Result<(Vec<(String, Keys)>, usize), RelayError> {
        if !self.reconnect {
            return Ok((vec![self.relay_material_at(0)?], 0));
        }
        let current = Self::epoch_of(unix_seconds);
        let mut pairs = Vec::new();
        for epoch in [
            current.saturating_sub(1),
            current,
            current.saturating_add(1),
        ] {
            pairs.push(self.relay_material_at(epoch)?);
        }
        // `current - 1` and `current` coincide only at epoch 0, which no real clock is in.
        Ok((pairs, 1))
    }

    /// The topic and key used to publish right now. Only tests ask for a single pair.
    #[cfg(test)]
    fn relay_material(&self) -> Result<(String, Keys), RelayError> {
        let (mut pairs, publishing) = self.rendezvous_at(unix_now())?;
        Ok(pairs.swap_remove(publishing))
    }
}

/// Whether an event created at `created_at` is within the allowed distance of `now`, in
/// either direction (clocks differ, and an event may be stamped slightly ahead).
fn is_recent(created_at: u64, now: u64) -> bool {
    created_at.abs_diff(now) <= MAX_EVENT_AGE_SECONDS
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Initial rendezvous over NIP-01 ephemeral events. Room creator is responder;
/// entering the code is initiator. The code-derived event key authenticates
/// possession of the invite only; identity still requires the Noise proof and
/// human fingerprint comparison.
pub struct RelayRendezvous {
    relays: Vec<RelayLink>,
    next_relay: usize,
    /// Every topic and event key this rendezvous listens on: one for a first-time invite,
    /// the epochs around the current one for a reconnect. An event is accepted only if its
    /// author and its topic tag belong to the same pair.
    listen: Vec<(String, Keys)>,
    /// Which pair is used to publish.
    publish: usize,
    /// Current Unix time. A field so that a test can move the clock.
    clock: fn() -> u64,
    role: Role,
    seen: BTreeSet<String>,
    attempt_tag: Option<String>,
    cancelled: Option<Arc<AtomicBool>>,
    timeout: Duration,
    /// How long to wait for the peer to appear on the topic.
    peer_wait: Duration,
    /// How long to wait for the other person to confirm. Separate from `timeout`
    /// because a person needs far longer than a network round trip.
    confirmation_timeout: Duration,
    /// Frames that arrived while `keep_alive` was only servicing the connections, in
    /// arrival order. `receive_frame` hands them out before reading anything new.
    stashed: VecDeque<Vec<u8>>,
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
        let (listen, publish) = invite.rendezvous_at(unix_now())?;
        let attempt_tag = match role {
            Role::Initiator => Some(random_hex(16)?),
            Role::Responder => None,
        };
        let subscription = new_subscription_id()?;
        let mut filter = Filter::new()
            .kind(Kind::Custom(EVENT_KIND))
            .custom_tags(
                SingleLetterTag::LOWERCASE_T,
                listen.iter().map(|(topic, _)| topic.clone()),
            )
            .custom_tag(SingleLetterTag::LOWERCASE_R, role_tag(role.peer()))
            .authors(listen.iter().map(|(_, keys)| keys.public_key()));
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
            listen,
            publish,
            clock: unix_now,
            role,
            seen: BTreeSet::new(),
            attempt_tag,
            cancelled: None,
            timeout: RENDEZVOUS_TIMEOUT,
            peer_wait: PEER_WAIT_TIMEOUT,
            confirmation_timeout: CONFIRMATION_TIMEOUT,
            stashed: VecDeque::new(),
        })
    }

    fn confirmation_wait(&self) -> Duration {
        self.confirmation_timeout
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
        let mut last_request = None;
        let mut pending_nonces = BTreeSet::new();
        let deadline = Instant::now() + self.peer_wait;
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

    /// Exchanges the transcript-bound identity proof, then the committed random values
    /// behind the confirmation code, through the encrypted Noise transport. The code in
    /// the returned state still needs human comparison.
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
        // Our value is revealed only once the peer's commitment has arrived.
        let (pending, reveal) =
            pending.receive_peer_proof(&self.receive_frame("identity proof")?, expected_peer)?;
        self.publish_frame(&reveal)?;
        Ok(pending.receive_peer_reveal(&self.receive_frame("confirmation code")?)?)
    }

    /// Services the relay connections while a person decides. Without reads, a relay's
    /// pings go unanswered and it can drop an idle connection long before the user has
    /// finished comparing the code. A frame that arrives meanwhile, such as the peer's
    /// confirmation, is kept for `receive_frame` and not lost.
    pub fn keep_alive(&mut self) -> Result<(), RelayError> {
        if let Some(frame) = self.poll_frame()? {
            if !(frame.starts_with(READY_REQUEST_PREFIX) || frame.starts_with(READY_ACK_PREFIX)) {
                self.stashed.push_back(frame);
            }
        }
        Ok(())
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
        let peer_frame =
            self.receive_frame_within("peer confirmation", self.confirmation_wait())?;
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
        let peer_frame =
            self.receive_frame_within("peer confirmation", self.confirmation_wait())?;
        let mut active = pending.receive_peer_confirmation(&peer_frame)?;
        let mut secret = Zeroizing::new([0; 32]);
        const OFFER: &[u8] = b"AD-CONTACT-OFFER-1";
        const ACK: &[u8] = b"AD-CONTACT-ACK-1";
        match self.role {
            Role::Responder => {
                crate::random::fill(secret.as_mut())?;
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
        // The time is stamped here, from the same clock the receiver's freshness check
        // uses, so the two cannot drift apart or depend on a library default.
        let event = EventBuilder::new(Kind::Custom(EVENT_KIND), crate::hex::encode(frame))
            .custom_created_at(Timestamp::from_secs((self.clock)()))
            .tag(Tag::custom("t", [self.listen[self.publish].0.as_str()]))
            .tag(Tag::custom("r", [role]))
            .tag(Tag::custom(
                "s",
                [self
                    .attempt_tag
                    .as_deref()
                    .ok_or(RelayError::InvalidEvent)?],
            ))
            .finalize(&self.listen[self.publish].1)?;
        let serialized = ClientMessage::event(event).as_json();
        let mut delivered = false;
        let mut index = 0;
        while index < self.relays.len() {
            // All links already sent REQ during connect_with. Do not gate an
            // ephemeral rendezvous frame on EOSE: a late shared relay is
            // subscribed and can deliver this same event immediately.
            if self.relays[index].send_text(&serialized).is_err() {
                self.relays.remove(index);
                self.next_relay = 0;
            } else {
                delivered = true;
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
        self.receive_frame_within(stage, self.timeout)
    }

    fn receive_frame_within(
        &mut self,
        stage: &'static str,
        allowed: Duration,
    ) -> Result<Vec<u8>, RelayError> {
        if let Some(frame) = self.stashed.pop_front() {
            return Ok(frame);
        }
        let deadline = Instant::now() + allowed;
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
        let Some((link_index, incoming)) =
            read_next_message(&mut self.relays, &mut self.next_relay).message
        else {
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
                        // The author and the topic must belong to the same epoch. Checking them
                        // separately would accept an event signed for one epoch that names
                        // the topic of another.
                        let in_a_listened_pair = self.listen.iter().any(|(topic, keys)| {
                            event.pubkey == keys.public_key()
                                && tag_value(event, "t") == Some(topic.as_str())
                        });
                        if !in_a_listened_pair
                            || event.kind != Kind::Custom(EVENT_KIND)
                            || event.verify().is_err()
                            || tag_value(event, "r") != Some(expected_role)
                            // A relay can store an event and replay it later. Anything not
                            // recent is dropped before it can fix the attempt or fill `seen`.
                            || !is_recent(event.created_at.as_secs(), (self.clock)())
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
                        // Forget the oldest ids instead of giving up: an attacker who can
                        // publish to the topic must not be able to end the rendezvous.
                        while self.seen.len() > 64 {
                            if let Some(oldest) = self.seen.iter().next().cloned() {
                                self.seen.remove(&oldest);
                            }
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
}

#[derive(Debug, PartialEq, Eq)]
enum SubscriptionStatus {
    Pending,
    Ready,
    Closed(String),
    Stale,
}

fn subscription_status(
    text: &str,
    expected: &SubscriptionId,
) -> Result<SubscriptionStatus, RelayError> {
    Ok(match RelayMessage::from_json(text)? {
        RelayMessage::EndOfStoredEvents(subscription) => {
            if subscription.as_ref() == expected {
                SubscriptionStatus::Ready
            } else {
                SubscriptionStatus::Stale
            }
        }
        RelayMessage::Closed {
            subscription_id,
            message,
        } => {
            if subscription_id.as_ref() == expected {
                SubscriptionStatus::Closed(message.to_string())
            } else {
                SubscriptionStatus::Stale
            }
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
        if !relays.iter().any(|relay| relay.ready) {
            first_ready_at = None;
        } else if first_ready_at.is_some_and(|ready_at| ready_at.elapsed() >= READ_TIMEOUT) {
            return Ok(());
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
                    Ok(SubscriptionStatus::Stale) => {}
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
    crate::random::fill(&mut bytes)?;
    Ok(crate::hex::encode(&bytes))
}

/// A subscription id is sent to the relay in the clear, so it must not identify this
/// program: it is random hex with no fixed prefix.
fn new_subscription_id() -> Result<SubscriptionId, RelayError> {
    Ok(SubscriptionId::new(random_hex(16)?))
}

/// Appends the hex form of secret bytes to a string that is wiped when dropped, without
/// building an intermediate `String` that would be freed with the secret still in it.
fn push_secret_hex(target: &mut Zeroizing<String>, bytes: &[u8]) {
    crate::hex::push_encoded(target, bytes);
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    if input.len() > MAX_ENVELOPE * 2 {
        return None;
    }
    crate::hex::decode(input)
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
        close_after_eose: HashMap<String, Duration>,
        silent_subscriptions: BTreeSet<String>,
        overflowing_subscriptions: BTreeSet<String>,
        delayed_subscriptions: HashMap<String, (usize, Duration)>,
        request_counts: HashMap<(String, usize), usize>,
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

        fn close_after_eose(&self, endpoint: &str, delay: Duration) {
            self.state
                .lock()
                .unwrap()
                .close_after_eose
                .insert(endpoint.to_owned(), delay);
        }

        fn silence_subscription(&self, endpoint: &str) {
            self.state
                .lock()
                .unwrap()
                .silent_subscriptions
                .insert(endpoint.to_owned());
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

        fn delay_subscription(&self, endpoint: &str, request_number: usize, delay: Duration) {
            self.state
                .lock()
                .unwrap()
                .delayed_subscriptions
                .insert(endpoint.to_owned(), (request_number, delay));
        }

        fn delay_current_eose(&self, endpoint: &str, delay: Duration) {
            let subscriptions = self
                .state
                .lock()
                .unwrap()
                .subscriptions
                .get(endpoint)
                .cloned()
                .unwrap_or_default();
            thread::spawn(move || {
                thread::sleep(delay);
                for subscription in subscriptions {
                    let _ = subscription.sender.send(Message::text(
                        serde_json::json!(["EOSE", subscription.subscription_id]).to_string(),
                    ));
                }
            });
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
                    let request_count = state
                        .request_counts
                        .entry((self.endpoint.clone(), self.socket_id))
                        .or_default();
                    *request_count += 1;
                    let current_request = *request_count;
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
                    let delay = state.delayed_subscriptions.get(&self.endpoint).and_then(
                        |(request_number, delay)| {
                            (*request_number == current_request).then_some(*delay)
                        },
                    );
                    let close_delay = state.close_after_eose.get(&self.endpoint).copied();
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
                    if let Some(delay) = close_delay {
                        self.sender
                            .send(Message::text(
                                serde_json::json!(["EOSE", subscription_id]).to_string(),
                            ))
                            .map_err(|_| RelayError::Disconnected)?;
                        let sender = self.sender.clone();
                        thread::spawn(move || {
                            thread::sleep(delay);
                            let _ = sender.send(Message::text(
                                serde_json::json!(["CLOSED", subscription_id, "late close"])
                                    .to_string(),
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
        subscription_barrier: Option<Arc<Barrier>>,
    ) -> Result<(super::RelaySession, zeroize::Zeroizing<[u8; 32]>), RelayError> {
        fake_connected_party_after(
            network,
            endpoints,
            invite_code,
            role,
            identity,
            expected_peer,
            subscription_barrier,
            Duration::ZERO,
        )
    }

    /// Like `fake_connected_party`, but the user takes `thinking_time` to compare the
    /// code and press confirm, as a person reading digits over the phone would.
    #[allow(clippy::too_many_arguments)]
    fn fake_connected_party_after(
        network: FakeRelayNetwork,
        endpoints: Vec<String>,
        invite_code: String,
        role: Role,
        identity: Identity,
        expected_peer: Option<[u8; 32]>,
        subscription_barrier: Option<Arc<Barrier>>,
        thinking_time: Duration,
    ) -> Result<(super::RelaySession, zeroize::Zeroizing<[u8; 32]>), RelayError> {
        let invite = InviteCode::parse(&invite_code).ok_or(RelayError::InvalidEvent)?;
        let mut rendezvous =
            RelayRendezvous::connect_with(&endpoints, &invite, role, |endpoint| {
                network.open(endpoint)
            })?;
        rendezvous.timeout = Duration::from_secs(4);
        rendezvous.confirmation_timeout = Duration::from_secs(12);
        if let Some(barrier) = subscription_barrier {
            barrier.wait();
        }
        let channel = rendezvous.complete_handshake()?;
        let verification = rendezvous.authenticate(channel, &identity, expected_peer)?;
        // The person compares the code. The connection must stay usable meanwhile.
        let waited = Instant::now();
        while waited.elapsed() < thinking_time {
            rendezvous.keep_alive()?;
            thread::sleep(Duration::from_millis(50));
        }
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
                None,
            )
        });
        (
            task_a.join().unwrap().unwrap().0,
            task_b.join().unwrap().unwrap().0,
        )
    }

    /// What one user's side of a fake connection returns: the session and the secret
    /// the two users agreed on, or why it failed.
    type PartyResult = Result<(super::RelaySession, zeroize::Zeroizing<[u8; 32]>), RelayError>;

    /// Two users where one confirms at once and the other takes `late` to do so.
    fn confirm_with_delays(early: Duration, late: Duration) -> (PartyResult, PartyResult) {
        let network = FakeRelayNetwork::default();
        let endpoint = vec!["wss://relay.test".to_owned()];
        let invite = InviteCode::generate().unwrap();
        let invite_code = invite.code().to_owned();
        let (first, second) = (Identity::create().unwrap().0, Identity::create().unwrap().0);
        let first_is_responder = first.public_key() < second.public_key();
        let (first_role, second_role) = if first_is_responder {
            (Role::Responder, Role::Initiator)
        } else {
            (Role::Initiator, Role::Responder)
        };
        let barrier = Arc::new(Barrier::new(2));
        let (n1, e1, c1, b1) = (
            network.clone(),
            endpoint.clone(),
            invite_code.clone(),
            Arc::clone(&barrier),
        );
        let one = thread::spawn(move || {
            fake_connected_party_after(n1, e1, c1, first_role, first, None, Some(b1), early)
        });
        let two = thread::spawn(move || {
            fake_connected_party_after(
                network,
                endpoint,
                invite_code,
                second_role,
                second,
                None,
                Some(barrier),
                late,
            )
        });
        (one.join().unwrap(), two.join().unwrap())
    }

    #[test]
    fn a_user_who_confirms_much_later_than_the_peer_does_not_make_the_peer_time_out() {
        // The protocol timeout in these tests is 4 seconds. The slower person takes 6,
        // as someone reading twelve digits over the phone easily can.
        let (early, late) = confirm_with_delays(Duration::ZERO, Duration::from_secs(6));
        assert!(
            early.is_ok(),
            "the person who confirmed first must be able to wait for the other: {:?}",
            early.err()
        );
        assert!(late.is_ok(), "{:?}", late.err());
    }

    #[test]
    fn both_users_taking_a_long_time_to_confirm_still_connect() {
        // Both people read the code aloud and press confirm well after the protocol
        // timeout, at different moments.
        let (first, second) = confirm_with_delays(Duration::from_secs(5), Duration::from_secs(7));
        assert!(first.is_ok(), "{:?}", first.err());
        assert!(second.is_ok(), "{:?}", second.err());
    }

    #[test]
    fn waiting_for_the_other_person_ends_at_the_confirmation_limit() {
        // The wait is long but bounded: a peer who never confirms must not hold the
        // connection open forever. The limit is shortened here so the test is quick.
        let network = FakeRelayNetwork::default();
        let endpoint = vec!["wss://relay.test".to_owned()];
        let invite = InviteCode::generate().unwrap();
        let code = invite.code().to_owned();
        let (a, b) = (Identity::create().unwrap().0, Identity::create().unwrap().0);
        let a_is_responder = a.public_key() < b.public_key();
        let (a_role, b_role) = if a_is_responder {
            (Role::Responder, Role::Initiator)
        } else {
            (Role::Initiator, Role::Responder)
        };
        let barrier = Arc::new(Barrier::new(2));
        let impatient = {
            let (network, endpoint, code, barrier) = (
                network.clone(),
                endpoint.clone(),
                code.clone(),
                Arc::clone(&barrier),
            );
            thread::spawn(move || {
                let invite = InviteCode::parse(&code).unwrap();
                let mut rendezvous =
                    RelayRendezvous::connect_with(&endpoint, &invite, a_role, |e| network.open(e))
                        .unwrap();
                rendezvous.timeout = Duration::from_secs(4);
                rendezvous.confirmation_timeout = Duration::from_secs(2);
                barrier.wait();
                let channel = rendezvous.complete_handshake().unwrap();
                let verification = rendezvous.authenticate(channel, &a, None).unwrap();
                let started = Instant::now();
                let result = rendezvous.confirm(verification);
                (result.err(), started.elapsed())
            })
        };
        // The other person looks at the code and never presses confirm.
        let silent = thread::spawn(move || {
            let invite = InviteCode::parse(&code).unwrap();
            let mut rendezvous =
                RelayRendezvous::connect_with(&endpoint, &invite, b_role, |e| network.open(e))
                    .unwrap();
            rendezvous.timeout = Duration::from_secs(4);
            barrier.wait();
            let channel = rendezvous.complete_handshake().unwrap();
            let verification = rendezvous.authenticate(channel, &b, None).unwrap();
            thread::sleep(Duration::from_secs(4));
            drop(verification);
        });
        let (error, waited) = impatient.join().unwrap();
        silent.join().unwrap();
        assert!(
            matches!(error, Some(RelayError::TimedOut("peer confirmation"))),
            "{error:?}"
        );
        assert!(
            waited >= Duration::from_secs(2) && waited < Duration::from_secs(4),
            "waited {waited:?}: it must use the confirmation limit, not the protocol one"
        );
    }

    #[test]
    fn frames_that_arrive_while_a_person_decides_are_kept_in_order() {
        let network = FakeRelayNetwork::default();
        let endpoint = vec!["wss://relay.test".to_owned()];
        let invite = InviteCode::generate().unwrap();
        let mut rendezvous =
            RelayRendezvous::connect_with(&endpoint, &invite, Role::Initiator, |e| network.open(e))
                .unwrap();
        // Frames the peer sent while keep_alive was servicing the connection.
        rendezvous.stashed.push_back(vec![1]);
        rendezvous.stashed.push_back(vec![2]);
        rendezvous.timeout = Duration::from_millis(50);
        assert_eq!(rendezvous.receive_frame("first").unwrap(), vec![1]);
        assert_eq!(rendezvous.receive_frame("second").unwrap(), vec![2]);
        // With the stash empty it waits for the network and times out as before.
        assert!(matches!(
            rendezvous.receive_frame("third"),
            Err(RelayError::TimedOut("third"))
        ));
    }

    #[test]
    fn secret_hex_is_the_same_text_as_the_ordinary_hex() {
        let mut every_byte = Vec::new();
        for byte in 0..=255_u8 {
            every_byte.push(byte);
        }
        for bytes in [
            &[][..],
            &[0][..],
            &[0xff][..],
            &[0x0a, 0xb0][..],
            &every_byte[..],
        ] {
            let mut secret = zeroize::Zeroizing::new(String::new());
            super::push_secret_hex(&mut secret, bytes);
            assert_eq!(secret.as_str(), crate::hex::encode(bytes));
        }
        // Appending keeps what is already there, as the invite code display relies on.
        let mut prefixed = zeroize::Zeroizing::new(String::from("ADI3-"));
        super::push_secret_hex(&mut prefixed, &[1, 2, 3]);
        assert_eq!(prefixed.as_str(), "ADI3-010203");
    }

    #[test]
    fn an_invite_code_still_round_trips_after_the_display_is_built_without_a_temporary() {
        let invite = InviteCode::generate().unwrap();
        let shown = invite.code().to_owned();
        assert!(shown.starts_with("ADI3-"));
        assert_eq!(shown.len(), "ADI3-".len() + 64);
        let parsed = InviteCode::parse(&shown).unwrap();
        assert_eq!(parsed.code(), shown);
        assert_eq!(
            parsed.relay_material().unwrap().0,
            invite.relay_material().unwrap().0
        );
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

        let flicker = "wss://ready-then-closed.test".to_owned();
        let silent = "wss://still-pending.test".to_owned();
        let unstable = FakeRelayNetwork::default();
        unstable.close_after_eose(&flicker, Duration::from_millis(20));
        unstable.silence_subscription(&silent);
        let mut links = Vec::new();
        for (id, endpoint) in [flicker, silent].into_iter().enumerate() {
            let subscription = SubscriptionId::new(format!("test-sub-{id}"));
            let mut link =
                super::RelayLink::new(id, unstable.open(&endpoint).unwrap(), subscription.clone());
            let request = super::ClientMessage::req(subscription, vec![super::Filter::new()]);
            link.send_text(&request.as_json()).unwrap();
            links.push(link);
        }
        assert!(matches!(
            super::wait_for_any_subscription(&mut links, Duration::from_millis(350)),
            Err(RelayError::TimedOut("relay subscription"))
        ));

        let flood = "wss://flood.test".to_owned();
        let network = FakeRelayNetwork::default();
        network.overflow_subscription_buffer(&flood);
        // The healthy route must become ready only after the flooding route has been
        // read to overflow. Without this delay the outcome races with the grace period
        // that follows the first ready route and fails on a loaded machine.
        network.delay_subscription(&healthy, 1, Duration::from_millis(1500));
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
        network.delay_subscription(slow, 1, Duration::from_secs(2));
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

    /// Drains whatever a session has ready, so a test sees the updates in order.
    fn poll_until_quiet(session: &mut super::RelaySession) -> Vec<RelayUpdate> {
        let mut updates = Vec::new();
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline {
            match session.poll().unwrap() {
                Some(RelayUpdate::Ready) | None => {}
                Some(update) => updates.push(update),
            }
        }
        updates
    }

    #[test]
    fn a_hole_that_never_fills_is_reported_as_lost_messages_after_the_delivered_ones() {
        let network = FakeRelayNetwork::default();
        let relay = "wss://gap.test".to_owned();
        let (mut sender, mut receiver) =
            fake_session_pair(network, vec![relay.clone()], vec![relay]);
        // One message is sequenced but never published: it is lost in transit.
        sender.transport.send(b"lost in transit").unwrap();
        sender.send(b"after one").unwrap();
        sender.send(b"after two").unwrap();

        // Before the hole times out the receiver holds the two messages back.
        let early = poll_until_quiet(&mut receiver);
        assert!(
            early.is_empty(),
            "nothing is delivered across a hole yet: {early:?}"
        );

        // Pretend the hole has been open for the timeout. The receiver's clock is the real
        // one, so move the recorded start of the hole back instead of waiting.
        receiver
            .transport
            .age_gap_for_test(super::super::channel::GAP_TIMEOUT);
        let updates = poll_until_quiet(&mut receiver);
        let delivered: Vec<_> = updates
            .iter()
            .filter_map(|update| match update {
                RelayUpdate::Messages(messages) => Some(messages.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            delivered,
            vec![b"after one".to_vec(), b"after two".to_vec()]
        );
        let lost: Vec<_> = updates
            .iter()
            .filter_map(|update| match update {
                RelayUpdate::MessagesLost { count } => Some(*count),
                _ => None,
            })
            .collect();
        assert_eq!(lost, vec![1], "exactly one message was lost: {updates:?}");
        // The messages come first and the report follows, in that order.
        assert!(matches!(updates.first(), Some(RelayUpdate::Messages(_))));
        assert!(matches!(
            updates.last(),
            Some(RelayUpdate::MessagesLost { .. })
        ));
        // The report is made once, not on every later poll.
        assert!(poll_until_quiet(&mut receiver).is_empty());
    }

    #[test]
    fn a_gap_that_fills_in_time_reports_nothing_lost() {
        let network = FakeRelayNetwork::default();
        let relay = "wss://nogap.test".to_owned();
        let (mut sender, mut receiver) =
            fake_session_pair(network, vec![relay.clone()], vec![relay]);
        for index in 0..5_u8 {
            sender.send(&[index]).unwrap();
        }
        let updates = poll_until_quiet(&mut receiver);
        assert!(updates
            .iter()
            .all(|update| !matches!(update, RelayUpdate::MessagesLost { .. })));
        let delivered: Vec<u8> = updates
            .iter()
            .filter_map(|update| match update {
                RelayUpdate::Messages(messages) => Some(messages.clone()),
                _ => None,
            })
            .flatten()
            .map(|message| message[0])
            .collect();
        assert_eq!(delivered, vec![0, 1, 2, 3, 4]);
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
                Ok(Some(RelayUpdate::MessagesLost { count })) => {
                    panic!("a publish failure must not leave a gap, but {count} were lost")
                }
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
        let subscriptions_ready = Arc::new(Barrier::new(2));
        let subscriptions_ready_a = Arc::clone(&subscriptions_ready);
        let a_endpoints = vec![relay_a.clone(), relay_b.clone()];
        let task_a = thread::spawn(move || {
            fake_connected_party(
                network_a,
                a_endpoints,
                invite_a,
                Role::Initiator,
                identity_a,
                None,
                Some(subscriptions_ready_a),
            )
        });
        let network_b = network.clone();
        let code_b_for_first = code_b.clone();
        let subscriptions_ready_b = Arc::clone(&subscriptions_ready);
        let b_endpoints = vec![relay_b.clone(), relay_c.clone()];
        let task_b = thread::spawn(move || {
            fake_connected_party(
                network_b,
                b_endpoints,
                invite_code,
                Role::Responder,
                identity_b,
                None,
                Some(subscriptions_ready_b),
            )
        });
        let (mut session_a, secret_a) = task_a.join().unwrap().unwrap();
        let (mut session_b, secret_b) = task_b.join().unwrap().unwrap();
        // The live REQ is installed, but its EOSE is delayed. This separates
        // subscription availability from historical backlog completion.
        session_a
            .relays
            .iter_mut()
            .find(|relay| relay.id == 1)
            .unwrap()
            .ready = false;
        session_b
            .relays
            .iter_mut()
            .find(|relay| relay.id == 0)
            .unwrap()
            .ready = false;
        network.delay_current_eose(&relay_b, Duration::from_millis(500));
        assert!(
            !session_a
                .relays
                .iter()
                .find(|relay| relay.id == 1)
                .unwrap()
                .ready
        );
        assert!(
            !session_b
                .relays
                .iter()
                .find(|relay| relay.id == 0)
                .unwrap()
                .ready
        );

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

        session_a
            .send(b"second message after delayed common subscription")
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut second_received = Vec::new();
        while Instant::now() < deadline && second_received.is_empty() {
            if let Some(RelayUpdate::Messages(messages)) = session_b.poll().unwrap() {
                second_received.extend(messages);
            }
        }
        assert_eq!(
            second_received,
            vec![b"second message after delayed common subscription".to_vec()]
        );

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
                None,
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
                None,
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
    fn waiting_for_a_peer_that_never_comes_ends_at_the_deadline() {
        let network = FakeRelayNetwork::default();
        let invite = InviteCode::generate().unwrap();
        let mut rendezvous = RelayRendezvous::connect_with(
            &["wss://alone.test".to_owned()],
            &invite,
            Role::Initiator,
            |endpoint| network.open(endpoint),
        )
        .unwrap();
        rendezvous.peer_wait = Duration::from_millis(400);
        let started = Instant::now();
        assert!(matches!(
            rendezvous.complete_handshake().map(|_| ()),
            Err(RelayError::TimedOut("peer subscription"))
        ));
        assert!(started.elapsed() >= Duration::from_millis(400));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn rendezvous_waits_for_peer_subscription_until_cancelled() {
        let network = FakeRelayNetwork::default();
        let invite = InviteCode::generate().unwrap();
        let invite_code = invite.code().to_owned();
        let left_cancelled = Arc::new(AtomicBool::new(false));
        let right_cancelled = Arc::new(AtomicBool::new(false));
        let (result_sender, result_receiver) = mpsc::channel();
        let left_network = network.clone();
        let left_code = invite_code.clone();
        let left_token = Arc::clone(&left_cancelled);
        let left_result = result_sender.clone();
        let left = thread::spawn(move || {
            let invite = InviteCode::parse(&left_code).unwrap();
            let mut rendezvous = RelayRendezvous::connect_with(
                &["wss://left-only.test".to_owned()],
                &invite,
                Role::Initiator,
                |endpoint| left_network.open(endpoint),
            )
            .unwrap();
            rendezvous.set_cancellation_token(left_token);
            let result = rendezvous.complete_handshake().map(|_| ());
            left_result.send(result).unwrap();
        });
        let right_network = network.clone();
        let right_token = Arc::clone(&right_cancelled);
        let right_result = result_sender;
        let right = thread::spawn(move || {
            let invite = InviteCode::parse(&invite_code).unwrap();
            let mut rendezvous = RelayRendezvous::connect_with(
                &["wss://right-only.test".to_owned()],
                &invite,
                Role::Responder,
                |endpoint| right_network.open(endpoint),
            )
            .unwrap();
            rendezvous.set_cancellation_token(right_token);
            let result = rendezvous.complete_handshake().map(|_| ());
            right_result.send(result).unwrap();
        });
        assert!(matches!(
            result_receiver.recv_timeout(Duration::from_millis(250)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        left_cancelled.store(true, Ordering::SeqCst);
        right_cancelled.store(true, Ordering::SeqCst);
        let first = result_receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        let second = result_receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(matches!(first, Err(RelayError::Cancelled)));
        assert!(matches!(second, Err(RelayError::Cancelled)));
        left.join().unwrap();
        right.join().unwrap();
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
    fn relay_validation_handles_ip_literals_dots_and_length_limits() {
        // Equivalent spellings of one endpoint compare equal, which is what lets the
        // duplicate check work.
        let normalized = |endpoint| super::validate_relay_endpoint(endpoint).unwrap();
        assert_eq!(
            normalized("wss://relay.example./"),
            normalized("wss://relay.example")
        );
        assert_eq!(
            normalized("wss://[::1]"),
            normalized("wss://[0:0:0:0:0:0:0:1]:443/")
        );
        assert_eq!(
            normalized("wss://127.0.0.1"),
            normalized("wss://127.0.0.1:443")
        );
        assert_ne!(
            normalized("wss://relay.example"),
            normalized("wss://relay.example:8443")
        );
        assert_ne!(
            normalized("wss://relay.example/a"),
            normalized("wss://relay.example/b")
        );
        let long_label = "a".repeat(64);
        let long_host = format!("{}.example", "a".repeat(250));
        for endpoint in [
            "wss://:443",
            "wss://relay.example:",
            "wss://[::1",
            "wss://[::1]x",
            "wss://relay..example",
            "wss://relay.example-",
            "wss://relay-.example",
            "wss://relay.example:80:90",
            "wss://relay.example:-1",
            "wss://relay.example:+443",
            "wss://relay.example/\u{7f}",
            "wss://\u{e9}.example",
            &format!("wss://{long_label}.example"),
            &long_host,
        ] {
            assert!(
                super::validate_relay_endpoint(endpoint).is_err(),
                "accepted invalid endpoint: {endpoint}"
            );
        }
        let longest_label = "a".repeat(63);
        assert!(super::validate_relay_endpoint(&format!("wss://{longest_label}.example")).is_ok());
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
            SubscriptionStatus::Stale
        );
        assert_eq!(
            subscription_status(r#"["CLOSED","ad-v2-live","restricted"]"#, &expected).unwrap(),
            SubscriptionStatus::Closed("restricted".to_owned())
        );
    }

    /// Two rendezvous objects on one fake relay, one as each role, for tests of what a
    /// receiver accepts. `sender_clock` and `receiver_clock` are each side's idea of now.
    fn rendezvous_pair(
        invite: &InviteCode,
        sender_clock: fn() -> u64,
        receiver_clock: fn() -> u64,
    ) -> (RelayRendezvous, RelayRendezvous) {
        let network = FakeRelayNetwork::default();
        let endpoint = vec!["wss://epoch.test".to_owned()];
        let open = |network: &FakeRelayNetwork| {
            let network = network.clone();
            move |endpoint: &str| network.open(endpoint)
        };
        let mut sender =
            RelayRendezvous::connect_with(&endpoint, invite, Role::Initiator, open(&network))
                .unwrap();
        let mut receiver =
            RelayRendezvous::connect_with(&endpoint, invite, Role::Responder, open(&network))
                .unwrap();
        sender.clock = sender_clock;
        receiver.clock = receiver_clock;
        sender.timeout = Duration::from_millis(600);
        receiver.timeout = Duration::from_millis(600);
        // The responder takes the attempt tag from the first valid event, so give both
        // the same one in advance.
        receiver.attempt_tag = sender.attempt_tag.clone();
        (sender, receiver)
    }

    const NOW: u64 = 90 * super::EPOCH_LENGTH_SECONDS + 1000;
    fn now() -> u64 {
        NOW
    }
    fn five_minutes_and_a_second_ago() -> u64 {
        NOW - super::MAX_EVENT_AGE_SECONDS - 1
    }
    fn four_minutes_ago() -> u64 {
        NOW - 240
    }
    fn five_minutes_and_a_second_ahead() -> u64 {
        NOW + super::MAX_EVENT_AGE_SECONDS + 1
    }

    #[test]
    fn a_recent_event_is_accepted_even_if_the_clocks_differ_a_little() {
        let (mut sender, mut receiver) =
            rendezvous_pair(&reconnect_invite(), four_minutes_ago, now);
        sender.publish_frame(b"hello").unwrap();
        assert_eq!(receiver.receive_frame("test").unwrap(), b"hello");
    }

    #[test]
    fn an_event_older_than_the_window_is_ignored_as_a_replay() {
        let (mut sender, mut receiver) =
            rendezvous_pair(&reconnect_invite(), five_minutes_and_a_second_ago, now);
        sender.publish_frame(b"replayed").unwrap();
        // The event is genuine and correctly signed, but a relay could be replaying it.
        assert!(matches!(
            receiver.receive_frame("test"),
            Err(RelayError::TimedOut("test"))
        ));
    }

    #[test]
    fn an_event_dated_too_far_ahead_is_ignored_too() {
        let (mut sender, mut receiver) =
            rendezvous_pair(&reconnect_invite(), five_minutes_and_a_second_ahead, now);
        sender.publish_frame(b"from the future").unwrap();
        assert!(matches!(
            receiver.receive_frame("test"),
            Err(RelayError::TimedOut("test"))
        ));
    }

    #[test]
    fn replayed_events_cannot_fix_the_attempt_or_end_the_rendezvous() {
        // A relay replays many old events from this topic ahead of the genuine one. They
        // must not use up the receiver's bookkeeping or pin it to a stale attempt.
        let invite = reconnect_invite();
        let (mut replayer, mut receiver) =
            rendezvous_pair(&invite, five_minutes_and_a_second_ago, now);
        receiver.attempt_tag = None; // the responder learns the attempt from the first event
        receiver.timeout = Duration::from_secs(3);
        for index in 0..100_u8 {
            // Each replayed event is a different attempt.
            replayer.attempt_tag = Some(super::random_hex(16).unwrap());
            replayer.publish_frame(&[index, 1]).unwrap();
        }
        assert!(matches!(
            receiver.receive_frame("test"),
            Err(RelayError::TimedOut("test"))
        ));
        assert!(
            receiver.attempt_tag.is_none(),
            "no replayed event fixed the attempt"
        );
        assert!(receiver.seen.is_empty(), "no replayed event was remembered");
    }

    #[test]
    fn an_event_mixing_one_epochs_key_with_another_epochs_topic_is_ignored() {
        // Both the key and the topic are ones the receiver listens to, but they do not
        // belong together, so the event was not made by someone holding the secret's
        // material for any single epoch.
        let (mut sender, mut receiver) = rendezvous_pair(&reconnect_invite(), now, now);
        let other_topic = sender.listen[0].0.clone();
        sender.listen[sender.publish].0 = other_topic;
        sender.publish_frame(b"mixed").unwrap();
        assert!(matches!(
            receiver.receive_frame("test"),
            Err(RelayError::TimedOut("test"))
        ));
    }

    #[test]
    fn flooding_the_topic_with_valid_events_does_not_end_the_rendezvous() {
        let (mut sender, mut receiver) = rendezvous_pair(&reconnect_invite(), now, now);
        receiver.attempt_tag = sender.attempt_tag.clone();
        for index in 0..200_u32 {
            sender.publish_frame(&index.to_be_bytes()).unwrap();
        }
        // Reading far more than the 64 remembered ids is not an error.
        for index in 0..200_u32 {
            assert_eq!(receiver.receive_frame("test").unwrap(), index.to_be_bytes());
        }
        assert!(receiver.seen.len() <= 64);
    }

    #[test]
    fn subscription_ids_are_random_and_carry_no_program_marker() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let id = super::new_subscription_id().unwrap().to_string();
            // 16 random bytes in hex: nothing fixed for a relay operator to recognise.
            assert_eq!(id.len(), 32, "{id}");
            assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()), "{id}");
            assert!(!id.contains("ad-v2") && !id.contains("live"), "{id}");
            assert!(seen.insert(id), "a subscription id was repeated");
        }
    }

    fn reconnect_invite() -> InviteCode {
        InviteCode::from_reconnect_secret(zeroize::Zeroizing::new([7_u8; 32]))
    }

    fn key_of(pair: &(String, nostr::prelude::Keys)) -> nostr::prelude::PublicKey {
        pair.1.public_key()
    }

    #[test]
    fn a_reconnect_secret_lands_on_a_different_topic_and_key_in_each_epoch() {
        let invite = reconnect_invite();
        let epoch_a = invite.relay_material_at(1000).unwrap();
        let epoch_b = invite.relay_material_at(1001).unwrap();
        // A relay watching the topic or the author key cannot tie two epochs together.
        assert_ne!(epoch_a.0, epoch_b.0);
        assert_ne!(key_of(&epoch_a), key_of(&epoch_b));
        // Within one epoch both sides derive the same pair, which is how they meet.
        let again = invite.relay_material_at(1000).unwrap();
        assert_eq!(epoch_a.0, again.0);
        assert_eq!(key_of(&epoch_a), key_of(&again));
    }

    #[test]
    fn many_epochs_never_share_a_topic_or_a_key() {
        let invite = reconnect_invite();
        let mut topics = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        for epoch in 0..200_u64 {
            let (topic, pair_keys) = invite.relay_material_at(epoch).unwrap();
            assert!(topics.insert(topic), "epoch {epoch} repeated a topic");
            assert!(
                keys.insert(pair_keys.public_key()),
                "epoch {epoch} repeated a key"
            );
        }
    }

    #[test]
    fn different_reconnect_secrets_never_meet_in_the_same_epoch() {
        let first = reconnect_invite();
        let second = InviteCode::from_reconnect_secret(zeroize::Zeroizing::new([8_u8; 32]));
        let (a, b) = (
            first.relay_material_at(500).unwrap(),
            second.relay_material_at(500).unwrap(),
        );
        assert_ne!(a.0, b.0);
        assert_ne!(key_of(&a), key_of(&b));
    }

    #[test]
    fn a_first_time_invite_keeps_one_topic_whatever_the_time() {
        // An invite is used once. Giving it a lifetime would only make it fail when typed
        // in late, so it ignores the epoch.
        let invite = InviteCode::generate().unwrap();
        let early = invite.relay_material_at(1).unwrap();
        let late = invite.relay_material_at(9_999).unwrap();
        assert_eq!(early.0, late.0);
        assert_eq!(key_of(&early), key_of(&late));
        let (pairs, publishing) = invite.rendezvous_at(1_700_000_000).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(publishing, 0);
    }

    #[test]
    fn a_reconnect_listens_on_the_epochs_before_at_and_after_the_current_one() {
        let invite = reconnect_invite();
        let now = 50 * super::EPOCH_LENGTH_SECONDS + 123;
        let (pairs, publishing) = invite.rendezvous_at(now).unwrap();
        assert_eq!(pairs.len(), 3);
        // It publishes on the current epoch, which is the middle one.
        assert_eq!(pairs[publishing].0, invite.relay_material_at(50).unwrap().0);
        let listened: Vec<_> = pairs.iter().map(|pair| pair.0.clone()).collect();
        for epoch in [49, 50, 51] {
            assert!(
                listened.contains(&invite.relay_material_at(epoch).unwrap().0),
                "epoch {epoch}"
            );
        }
        assert!(!listened.contains(&invite.relay_material_at(48).unwrap().0));
        assert!(!listened.contains(&invite.relay_material_at(52).unwrap().0));
    }

    #[test]
    fn two_clocks_that_disagree_across_an_epoch_boundary_still_find_each_other() {
        // One side is just before the boundary, the other just after it. Each publishes on
        // its own current epoch and listens on the neighbours, so each hears the other.
        let invite = reconnect_invite();
        let boundary = 80 * super::EPOCH_LENGTH_SECONDS;
        let slow = invite.rendezvous_at(boundary - 30).unwrap();
        let fast = invite.rendezvous_at(boundary + 30).unwrap();
        let publishes_to =
            |side: &(Vec<(String, nostr::prelude::Keys)>, usize)| side.0[side.1].0.clone();
        let hears = |side: &(Vec<(String, nostr::prelude::Keys)>, usize), topic: &str| {
            side.0.iter().any(|pair| pair.0 == topic)
        };
        assert_ne!(
            publishes_to(&slow),
            publishes_to(&fast),
            "they do publish apart"
        );
        assert!(hears(&fast, &publishes_to(&slow)));
        assert!(hears(&slow, &publishes_to(&fast)));
    }

    #[test]
    fn clocks_more_than_one_epoch_apart_do_not_meet() {
        // The tolerance is a single epoch either way. Beyond it the sides are on topics the
        // other is not listening to, which is the cost of not reusing one topic.
        let invite = reconnect_invite();
        let early = invite
            .rendezvous_at(10 * super::EPOCH_LENGTH_SECONDS)
            .unwrap();
        let late = invite
            .rendezvous_at(13 * super::EPOCH_LENGTH_SECONDS)
            .unwrap();
        let topic = late.0[late.1].0.clone();
        assert!(!early.0.iter().any(|pair| pair.0 == topic));
    }

    #[test]
    fn invite_codes_mark_the_current_rendezvous_protocol_version() {
        let invite = InviteCode::generate().unwrap();
        assert!(invite.code().starts_with("ADI3-"));
        assert!(InviteCode::parse(invite.code()).is_some());
        let legacy = invite.code().replacen("ADI3-", "ADI2-", 1);
        assert!(InviteCode::parse(&legacy).is_none());
    }

    /// What a fake SOCKS5 proxy saw during one connection.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct SocksTranscript {
        offered_methods: Vec<u8>,
        credentials: Option<(Vec<u8>, Vec<u8>)>,
        hostname: Vec<u8>,
    }

    /// A one-connection SOCKS5 proxy. `choose` is the method the proxy selects from
    /// those offered (0 = no authentication, 2 = username and password, 0xff = none
    /// acceptable). It accepts any username and password.
    fn fake_socks_proxy(choose: u8) -> (std::net::SocketAddr, thread::JoinHandle<SocksTranscript>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut transcript = SocksTranscript::default();
            let mut head = [0; 2];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(head[0], 5);
            transcript.offered_methods = vec![0; head[1] as usize];
            stream.read_exact(&mut transcript.offered_methods).unwrap();
            stream.write_all(&[5, choose]).unwrap();
            if choose == 0xff {
                return transcript;
            }
            if choose == 2 {
                let mut version = [0; 2];
                stream.read_exact(&mut version).unwrap();
                assert_eq!(version[0], 1, "RFC 1929 sub-negotiation version");
                let mut user = vec![0; version[1] as usize];
                stream.read_exact(&mut user).unwrap();
                let mut password_length = [0];
                stream.read_exact(&mut password_length).unwrap();
                let mut password = vec![0; password_length[0] as usize];
                stream.read_exact(&mut password).unwrap();
                transcript.credentials = Some((user, password));
                stream.write_all(&[1, 0]).unwrap();
            }
            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            transcript.hostname = vec![0; request[4] as usize];
            stream.read_exact(&mut transcript.hostname).unwrap();
            let mut port = [0; 2];
            stream.read_exact(&mut port).unwrap();
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            transcript
        });
        (proxy, server)
    }

    #[test]
    fn socks_connection_offers_username_authentication_so_tor_can_isolate_circuits() {
        let (proxy, server) = fake_socks_proxy(2);
        drop(super::connect_socks5(proxy, "relay.example", 443).unwrap());
        let transcript = server.join().unwrap();
        assert!(transcript.offered_methods.contains(&2), "{transcript:?}");
        assert_eq!(transcript.hostname, b"relay.example");
        let (user, password) = transcript.credentials.expect("credentials were sent");
        // RFC 1929 allows 1 to 255 bytes; random hex is long enough to be unique.
        assert!(user.len() >= 16 && password.len() >= 16);
        assert!(user.iter().chain(&password).all(u8::is_ascii_hexdigit));
    }

    #[test]
    fn every_socks_connection_uses_credentials_of_its_own() {
        // Tor gives streams with different credentials different circuits, so two
        // relays, or two sessions, must never present the same ones.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5 {
            let (proxy, server) = fake_socks_proxy(2);
            drop(super::connect_socks5(proxy, "relay.example", 443).unwrap());
            let credentials = server.join().unwrap().credentials.unwrap();
            assert!(seen.insert(credentials), "credentials were reused");
        }
    }

    #[test]
    fn a_proxy_that_needs_no_authentication_still_works_and_gets_no_credentials() {
        let (proxy, server) = fake_socks_proxy(0);
        drop(super::connect_socks5(proxy, "relay.example", 443).unwrap());
        let transcript = server.join().unwrap();
        assert_eq!(transcript.credentials, None);
        assert_eq!(transcript.hostname, b"relay.example");
    }

    #[test]
    fn a_proxy_that_accepts_none_of_our_methods_is_an_error_not_a_direct_connection() {
        let (proxy, server) = fake_socks_proxy(0xff);
        let error = super::connect_socks5(proxy, "relay.example", 443).unwrap_err();
        assert!(format!("{error:?}").contains("authentication"), "{error:?}");
        assert_eq!(server.join().unwrap().hostname, Vec::<u8>::new());
    }

    #[test]
    fn a_proxy_that_rejects_the_credentials_is_an_error() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = [0; 2];
            stream.read_exact(&mut head).unwrap();
            let mut methods = vec![0; head[1] as usize];
            stream.read_exact(&mut methods).unwrap();
            stream.write_all(&[5, 2]).unwrap();
            let mut version = [0; 2];
            stream.read_exact(&mut version).unwrap();
            let mut rest = vec![0; version[1] as usize + 1];
            stream.read_exact(&mut rest).unwrap();
            let mut password = vec![0; *rest.last().unwrap() as usize];
            stream.read_exact(&mut password).unwrap();
            stream.write_all(&[1, 1]).unwrap();
        });
        let error = super::connect_socks5(proxy, "relay.example", 443).unwrap_err();
        assert!(format!("{error:?}").contains("rejected"), "{error:?}");
        server.join().unwrap();
    }

    #[test]
    fn socks_proxy_failure_never_falls_back_to_direct_relay_connection() {
        let relay_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        relay_listener.set_nonblocking(true).unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let (direct_seen_tx, direct_seen_rx) = mpsc::channel();
        let direct_probe = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match relay_listener.accept() {
                    Ok((stream, _)) => {
                        drop(stream);
                        let _ = direct_seen_tx.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            let _ = direct_seen_tx.send(false);
                            return;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        let _ = direct_seen_tx.send(false);
                        return;
                    }
                }
            }
        });

        let proxy_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy = proxy_listener.local_addr().unwrap();
        let proxy_server = thread::spawn(move || {
            let (mut stream, _) = proxy_listener.accept().unwrap();
            let mut greeting = [0; 4];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 0]).unwrap();

            let mut request = [0; 5];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 3]);
            let mut host = vec![0; request[4] as usize];
            stream.read_exact(&mut host).unwrap();
            assert_eq!(host, b"127.0.0.1");
            let mut port = [0; 2];
            stream.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), relay_address.port());
            stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        });

        let endpoint = format!("wss://127.0.0.1:{}", relay_address.port());
        assert!(super::open_socket(&endpoint, Some(proxy)).is_err());
        proxy_server.join().unwrap();
        assert!(!direct_seen_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        direct_probe.join().unwrap();
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
        // A person takes a while to compare the code. Run this against a real relay with
        // a long pause to check that `keep_alive` is enough to hold the connection open;
        // the in-memory relay in the other tests never sends pings, so it cannot show it.
        let pause = std::env::var("AD_LIVE_CONFIRM_PAUSE_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let paused = Instant::now();
        while paused.elapsed() < Duration::from_secs(pause) {
            rendezvous.keep_alive().unwrap();
            thread::sleep(Duration::from_millis(250));
        }
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
