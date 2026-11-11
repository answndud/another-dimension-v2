//! Minimal NIP-01 WebSocket adapter for one confirmed Noise session.
//!
//! It publishes only kind-20000 ephemeral events. The relay still observes the
//! session tag, timing, size, and connection IP in direct mode. No relay URL or
//! Tor policy is selected here; callers must enforce those policies.

use crate::channel::{HandshakeError, SessionTransport};
use nostr::prelude::{
    ClientMessage, Error as NostrError, EventBuilder, Filter, FinalizeEvent, Keys, Kind, PublicKey,
    RelayMessage, SingleLetterTag, SubscriptionId, Tag,
};
use std::io;
use std::net::TcpStream;
use std::time::Duration;
use tungstenite::client::connect_with_config;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

const EVENT_KIND: u16 = 20_000;
const SUBSCRIPTION_ID: &str = "ad-v2-live";
const MAX_RELAY_MESSAGE: usize = 16 * 1024;
const MAX_ENVELOPE: usize = 4 + 16 + 8 + 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

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
                stream.sock.set_write_timeout(Some(READ_TIMEOUT))?;
            }
            _ => return Err(RelayError::InvalidEndpoint),
        }

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

    /// Reads until a relevant relay update arrives. Authenticated channel
    /// errors close the Noise session; unrelated or invalidly signed events
    /// are ignored and never reach the message decoder.
    pub fn receive(&mut self) -> Result<RelayUpdate, RelayError> {
        loop {
            let message = self.socket.read()?;
            match message {
                Message::Text(text) => {
                    let relay_message = RelayMessage::from_json(text.as_str())?;
                    match relay_message {
                        RelayMessage::Event {
                            subscription_id,
                            event,
                        } => {
                            if subscription_id.as_ref() != &self.subscription {
                                continue;
                            }
                            let event = event.as_ref();
                            if event.kind != Kind::Custom(EVENT_KIND)
                                || event.pubkey != self.peer_author
                                || event.verify().is_err()
                                || !event.tags.iter().any(|tag| {
                                    let fields = tag.as_slice();
                                    fields.len() >= 2 && fields[0] == "t" && fields[1] == self.topic
                                })
                            {
                                continue;
                            }
                            let envelope =
                                decode_hex(&event.content).ok_or(RelayError::InvalidEvent)?;
                            let messages = self.transport.receive(&envelope)?;
                            if !messages.is_empty() {
                                return Ok(RelayUpdate::Messages(messages));
                            }
                        }
                        RelayMessage::Ok {
                            event_id,
                            status,
                            message,
                        } => {
                            if status {
                                return Ok(RelayUpdate::Published {
                                    event_id: event_id.to_string(),
                                });
                            }
                            return Err(RelayError::RelayRejected {
                                event_id: event_id.to_string(),
                                reason: message.to_string(),
                            });
                        }
                        RelayMessage::EndOfStoredEvents(subscription_id)
                            if subscription_id.as_ref() == &self.subscription =>
                        {
                            return Ok(RelayUpdate::Ready);
                        }
                        RelayMessage::Closed {
                            subscription_id,
                            message,
                        } if subscription_id.as_ref() == &self.subscription => {
                            return Err(RelayError::SubscriptionClosed(message.to_string()));
                        }
                        _ => {}
                    }
                }
                Message::Ping(payload) => self.socket.send(Message::Pong(payload))?,
                Message::Close(_) => return Err(RelayError::Disconnected),
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }
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
