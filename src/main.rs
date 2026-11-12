pub mod channel;
mod contacts;
pub mod history;
mod identity;
pub mod relay;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use identity::Identity;
use relay::{InviteCode, RelayError, RelayRendezvous, RelaySession, RelayUpdate, DEFAULT_RELAY};
use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, rename, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const PAGE: &[u8] = include_bytes!("../web/index.html");
const SCRIPT: &[u8] = include_bytes!("../web/app.js");
const REPROTECT_WORK_SCRIPT: &[u8] = include_bytes!("../web/reprotect-work.js");
const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 24 * 1024 * 1024;
const CHAT_CONTROL_PREFIX: &[u8] = b"[AD2-CONTROL/1] ";
const CODE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS: u8 = 5;
const PEER_HEARTBEAT_FRAME: &[u8] = &[0xff, b'A', b'D', b'2', b'-', b'H', b'B', b'2'];
const PEER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PEER_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_SYNC_RECORDS: usize = 100_000;
const MAX_SYNC_BYTES: usize = 64 * 1024 * 1024;
const SYNC_CHUNK_RECORDS: usize = 32;
const SYNC_CHUNK_BYTES: usize = 256 * 1024;
const RESTORE_PREVIEW_RECORDS: usize = 12;

struct State {
    code: String,
    issued: Instant,
    attempts: u8,
    sessions: Vec<String>,
    identity: Option<Arc<Identity>>,
    chats: HashMap<String, Arc<ChatOperation>>,
    tor_socks: Option<SocketAddr>,
    settings: AppSettings,
    notifications_enabled: Arc<AtomicBool>,
    last_notification: Arc<Mutex<Option<Instant>>>,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct AppSettings {
    tor_socks: Option<SocketAddr>,
    notifications: bool,
}

enum ChatCommand {
    Confirm,
    Send(String, Sender<()>),
    AcceptIdentityTransition(String, Sender<Result<(), String>>),
    RequestHistoryRestore(Sender<Result<(), String>>),
    ResolveHistoryRestore(bool, Sender<Result<(), String>>),
    Cancel,
}

struct ChatOperation {
    snapshot: Mutex<ChatSnapshot>,
    sender: Sender<ChatCommand>,
    cancelled: Arc<AtomicBool>,
}

struct ChatSnapshot {
    phase: &'static str,
    fingerprint: Option<String>,
    peer_id: Option<String>,
    error: Option<String>,
    storage_error: Option<String>,
    messages: Vec<ChatEntry>,
    relay_ack: Option<String>,
    pending_sends: usize,
    identity_transition: Option<Vec<String>>,
    history_restore_in_progress: bool,
    history_restore_offer: Vec<RestoreOfferEntry>,
    history_restore_offer_count: usize,
    history_restore_legacy_count: usize,
    history_restore_received: usize,
    history_restore_total: usize,
    history_restore_status: Option<String>,
    message_epoch: u64,
}

#[derive(Clone)]
struct ChatEntry {
    unix_time: u64,
    sender: &'static str,
    text: String,
}

#[derive(Clone)]
struct RestoreOfferEntry {
    unix_time: u64,
    sender: &'static str,
    text: String,
    signed: bool,
}

struct HistorySyncSender {
    request_id: String,
    messages: Vec<history::StoredMessage>,
    next_record: usize,
    awaiting_chunk: Option<usize>,
}

impl HistorySyncSender {
    fn new(request_id: String, messages: Vec<history::StoredMessage>) -> Self {
        Self {
            request_id,
            messages,
            next_record: 0,
            awaiting_chunk: None,
        }
    }

    fn next_chunk(&mut self) -> io::Result<Option<(usize, Vec<Vec<u8>>)>> {
        if self.awaiting_chunk.is_some() || self.next_record >= self.messages.len() {
            return Ok(None);
        }
        let chunk_index = self.next_record / SYNC_CHUNK_RECORDS;
        let mut frames = Vec::new();
        let mut bytes = 0usize;
        while self.next_record < self.messages.len() && frames.len() < SYNC_CHUNK_RECORDS {
            let frame = history::encode_transfer_chunk(
                &self.messages[self.next_record],
                &self.request_id,
                chunk_index,
            )?;
            if !frames.is_empty() && bytes.saturating_add(frame.len()) > SYNC_CHUNK_BYTES {
                break;
            }
            if frame.len() > SYNC_CHUNK_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "history record exceeds chunk limit",
                ));
            }
            bytes += frame.len();
            frames.push(frame);
            self.next_record += 1;
        }
        self.awaiting_chunk = Some(chunk_index);
        Ok(Some((chunk_index, frames)))
    }

    fn acknowledge(&mut self, request_id: &str, chunk_index: usize) -> io::Result<bool> {
        if request_id != self.request_id {
            return Ok(false);
        }
        if self.awaiting_chunk != Some(chunk_index) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate or out-of-order history chunk acknowledgment",
            ));
        }
        self.awaiting_chunk = None;
        Ok(self.next_record == self.messages.len())
    }
}

#[derive(Default)]
struct HistorySyncReceiver {
    request_id: Option<String>,
    total_records: usize,
    total_chunks: usize,
    next_chunk: usize,
    active_chunk: Option<(usize, usize, usize, usize)>,
    received_records: usize,
    received_bytes: usize,
}

impl HistorySyncReceiver {
    fn begin(
        &mut self,
        request_id: &str,
        total_records: usize,
        total_chunks: usize,
    ) -> io::Result<()> {
        if !valid_sync_request_id(request_id)
            || total_records > MAX_SYNC_RECORDS
            || total_chunks != total_records.div_ceil(SYNC_CHUNK_RECORDS)
            || self.request_id.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid history transfer start",
            ));
        }
        *self = Self {
            request_id: Some(request_id.to_owned()),
            total_records,
            total_chunks,
            ..Self::default()
        };
        Ok(())
    }

    fn begin_chunk(&mut self, request_id: &str, chunk: usize, count: usize) -> io::Result<()> {
        if self.request_id.as_deref() != Some(request_id)
            || self.active_chunk.is_some()
            || chunk != self.next_chunk
            || chunk >= self.total_chunks
            || count == 0
            || count > SYNC_CHUNK_RECORDS
            || count != (self.total_records - self.received_records).min(SYNC_CHUNK_RECORDS)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing, duplicate, or out-of-order history chunk",
            ));
        }
        self.active_chunk = Some((chunk, count, 0, 0));
        Ok(())
    }

    fn record(&mut self, request_id: &str, chunk: usize, bytes: usize) -> io::Result<()> {
        let Some((active_chunk, expected, received, chunk_bytes)) = self.active_chunk else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history record outside a chunk",
            ));
        };
        if self.request_id.as_deref() != Some(request_id)
            || chunk != active_chunk
            || received >= expected
            || chunk_bytes.saturating_add(bytes) > SYNC_CHUNK_BYTES
            || self.received_bytes.saturating_add(bytes) > MAX_SYNC_BYTES
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk size or sequence is invalid",
            ));
        }
        self.received_records += 1;
        self.received_bytes += bytes;
        self.active_chunk = Some((chunk, expected, received + 1, chunk_bytes + bytes));
        Ok(())
    }

    fn end_chunk(&mut self, request_id: &str, chunk: usize) -> io::Result<()> {
        let Some((expected_chunk, expected_records, received, _)) = self.active_chunk else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk end without a chunk",
            ));
        };
        if self.request_id.as_deref() != Some(request_id)
            || chunk != expected_chunk
            || received != expected_records
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history chunk end is out of order",
            ));
        }
        self.active_chunk = None;
        self.next_chunk += 1;
        Ok(())
    }

    fn finish(&self, request_id: &str, total_records: usize) -> io::Result<()> {
        if self.request_id.as_deref() != Some(request_id)
            || self.active_chunk.is_some()
            || total_records != self.total_records
            || self.received_records != self.total_records
            || self.next_chunk != self.total_chunks
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "history transfer is incomplete",
            ));
        }
        Ok(())
    }
}

fn valid_sync_request_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn send_next_history_chunk(
    session: &mut RelaySession,
    sync: &mut HistorySyncSender,
) -> io::Result<()> {
    let (chunk, frames) = sync.next_chunk()?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "history sender is already awaiting acknowledgment",
        )
    })?;
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-chunk-begin",
            "requestId": sync.request_id,
            "chunk": chunk,
            "count": frames.len(),
        })))
        .map_err(|error| io::Error::other(format!("{error:?}")))?;
    for frame in &frames {
        session
            .send(frame)
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
    }
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-chunk-end",
            "requestId": sync.request_id,
            "chunk": chunk,
        })))
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("{error:?}")))
}

fn send_history_sync_done(
    session: &mut RelaySession,
    request_id: &str,
    count: usize,
) -> io::Result<()> {
    session
        .send(&chat_control(serde_json::json!({
            "type": "history-sync-done",
            "requestId": request_id,
            "totalCount": count,
        })))
        .map(|_| ())
        .map_err(|error| io::Error::other(format!("{error:?}")))
}

fn chat_update(operation: &ChatOperation, update: impl FnOnce(&mut ChatSnapshot)) {
    if let Ok(mut snapshot) = operation.snapshot.lock() {
        update(&mut snapshot);
    }
}

fn submit_chat_message(sender: &Sender<ChatCommand>, text: String, timeout: Duration) -> bool {
    let (processed, result) = mpsc::channel();
    sender.send(ChatCommand::Send(text, processed)).is_ok() && result.recv_timeout(timeout).is_ok()
}

fn chat_control(value: serde_json::Value) -> Vec<u8> {
    let mut frame = CHAT_CONTROL_PREFIX.to_vec();
    frame.extend_from_slice(value.to_string().as_bytes());
    frame
}

fn parse_chat_control(message: &[u8]) -> Result<Option<serde_json::Value>, ()> {
    let Some(payload) = message.strip_prefix(CHAT_CONTROL_PREFIX) else {
        return Ok(None);
    };
    serde_json::from_slice(payload).map(Some).map_err(|_| ())
}

fn chat_entry(item: history::StoredMessage) -> ChatEntry {
    let is_identity_event = item.text.starts_with(history::IDENTITY_EVENT_PREFIX);
    let display_text = item
        .text
        .strip_prefix(history::IDENTITY_EVENT_PREFIX)
        .and_then(|value| {
            let mut parts = value.split(':');
            let kind = parts.next()?;
            let previous = parts.next()?;
            let current = parts.next()?;
            if previous.len() != 64 || current.len() != 64 {
                return None;
            }
            Some(match kind {
                "self" => format!(
                    "내 신원이 {}에서 {}로 변경되어 이 대화를 이어갑니다.",
                    &previous[..12],
                    &current[..12]
                ),
                "peer" => format!(
                    "상대 신원이 {}에서 {}로 변경되어 기존 기록을 연결했습니다.",
                    &previous[..12],
                    &current[..12]
                ),
                _ => return None,
            })
        });
    ChatEntry {
        unix_time: item.unix_time,
        sender: if is_identity_event {
            "신원 변경"
        } else {
            match item.sender {
                history::MessageSender::Me => "나",
                history::MessageSender::Other => "상대방",
            }
        },
        text: display_text.unwrap_or(item.text),
    }
}

fn identity_event(kind: &str, previous_id: &str, current_id: &str) -> history::StoredMessage {
    history::StoredMessage {
        unix_time: now_seconds(),
        sender: history::MessageSender::Me,
        text: format!(
            "{}{kind}:{previous_id}:{current_id}",
            history::IDENTITY_EVENT_PREFIX
        ),
        proof: None,
    }
}

fn identity_event_exists_for_previous(
    messages: &[history::StoredMessage],
    kind: &str,
    previous_id: &str,
    current_id: &str,
) -> bool {
    messages.iter().any(|message| {
        if message.sender != history::MessageSender::Me {
            return false;
        }
        let Some(marker) = message.text.strip_prefix(history::IDENTITY_EVENT_PREFIX) else {
            return false;
        };
        let mut fields = marker.split(':');
        fields.next() == Some(kind)
            && fields
                .next()
                .is_some_and(|id| id.eq_ignore_ascii_case(previous_id))
            && fields
                .next()
                .is_some_and(|id| id.eq_ignore_ascii_case(current_id))
    })
}

fn rejected_message(pending_events: &mut HashSet<String>, event_id: &str) -> bool {
    pending_events.remove(event_id)
}

#[cfg(test)]
mod send_tests {
    use super::*;

    #[test]
    fn identity_transition_control_and_history_marker_roundtrip() {
        let previous = "ab".repeat(32);
        let current = "cd".repeat(32);
        let frame = chat_control(serde_json::json!({
            "type": "identity-transition",
            "previousPeerIds": [previous],
        }));
        let control = parse_chat_control(&frame).unwrap().unwrap();
        assert_eq!(
            control["previousPeerIds"][0].as_str().unwrap(),
            "ab".repeat(32)
        );

        let event = identity_event("peer", &"ab".repeat(32), &current);
        assert!(identity_event_exists_for_previous(
            std::slice::from_ref(&event),
            "peer",
            &"ab".repeat(32),
            &current
        ));
        assert!(!identity_event_exists_for_previous(
            std::slice::from_ref(&event),
            "peer",
            &"ab".repeat(32),
            &"ef".repeat(32)
        ));
        let mut remote_marker = event.clone();
        remote_marker.sender = history::MessageSender::Other;
        assert!(!identity_event_exists_for_previous(
            std::slice::from_ref(&remote_marker),
            "peer",
            &"ab".repeat(32),
            &current
        ));
        let displayed = chat_entry(event);
        assert_eq!(displayed.sender, "신원 변경");
        assert!(displayed.text.contains("cdcdcdcdcdcd"));
    }

    #[test]
    fn history_sync_chunks_over_legacy_record_and_byte_limits_with_ack_backpressure() {
        let request_id = "ab".repeat(32);
        let messages: Vec<_> = (0..4_097)
            .map(|unix_time| history::StoredMessage {
                unix_time,
                sender: history::MessageSender::Me,
                text: "x".repeat(4_096),
                proof: None,
            })
            .collect();
        let total_bytes: usize = messages
            .iter()
            .enumerate()
            .map(|(index, item)| {
                history::encode_transfer_chunk(item, &request_id, index / SYNC_CHUNK_RECORDS)
                    .unwrap()
                    .len()
            })
            .sum();
        assert!(messages.len() > 4_096);
        assert!(total_bytes < MAX_SYNC_BYTES);
        assert!(total_bytes > 16 * 1024 * 1024);

        let mut sender = HistorySyncSender::new(request_id.clone(), messages);
        let mut receiver = HistorySyncReceiver::default();
        let chunk_count = 4_097_usize.div_ceil(SYNC_CHUNK_RECORDS);
        receiver.begin(&request_id, 4_097, chunk_count).unwrap();
        let mut received = 0;
        loop {
            let (chunk, frames) = sender.next_chunk().unwrap().unwrap();
            assert!(frames.len() <= SYNC_CHUNK_RECORDS);
            let chunk_bytes: usize = frames.iter().map(Vec::len).sum();
            assert!(chunk_bytes <= SYNC_CHUNK_BYTES);
            receiver
                .begin_chunk(&request_id, chunk, frames.len())
                .unwrap();
            for frame in frames {
                let (frame_id, frame_chunk, payload) =
                    history::transfer_chunk_metadata(&frame).unwrap();
                assert_eq!(frame_id, request_id);
                assert_eq!(frame_chunk, chunk);
                assert!(payload.starts_with(b"ADREC1"));
                receiver
                    .record(&request_id, frame_chunk, frame.len())
                    .unwrap();
            }
            receiver.end_chunk(&request_id, chunk).unwrap();
            received += 1;
            assert!(sender.acknowledge(&request_id, chunk + 1).is_err());
            assert!(!sender.acknowledge(&"cd".repeat(32), chunk).unwrap());
            let finished = sender.acknowledge(&request_id, chunk).unwrap();
            if finished {
                break;
            }
        }
        assert_eq!(received, chunk_count);
        receiver.finish(&request_id, 4_097).unwrap();
    }

    #[test]
    fn history_sync_receiver_rejects_missing_duplicate_and_out_of_order_chunks() {
        let request_id = "de".repeat(32);
        let mut receiver = HistorySyncReceiver::default();
        receiver.begin(&request_id, 33, 2).unwrap();
        assert!(receiver.begin_chunk(&request_id, 1, 1).is_err());
        receiver.begin_chunk(&request_id, 0, 32).unwrap();
        assert!(receiver.begin_chunk(&request_id, 0, 32).is_err());
        assert!(receiver.record(&"aa".repeat(32), 0, 1_000).is_err());
        assert!(receiver.record(&request_id, 1, 1_000).is_err());
        for _ in 0..31 {
            receiver.record(&request_id, 0, 1_000).unwrap();
        }
        assert!(receiver.end_chunk(&request_id, 0).is_err());
        assert!(receiver.finish(&request_id, 33).is_err());

        let mut retried = HistorySyncReceiver::default();
        let retry_id = "ef".repeat(32);
        retried.begin(&retry_id, 1, 1).unwrap();
        retried.begin_chunk(&retry_id, 0, 1).unwrap();
        assert!(retried.record(&request_id, 0, 1_000).is_err());
        assert!(retried.finish(&request_id, 1).is_err());
        retried.record(&retry_id, 0, 1_000).unwrap();
        retried.end_chunk(&retry_id, 0).unwrap();
        retried.finish(&retry_id, 1).unwrap();
    }

    #[test]
    fn queued_message_is_not_acknowledged_if_worker_exits() {
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let command = receiver.recv().unwrap();
            drop(command);
        });
        assert!(!submit_chat_message(
            &sender,
            "unsent".into(),
            Duration::from_secs(1)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn message_is_acknowledged_after_worker_processing() {
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            if let ChatCommand::Send(text, processed) = receiver.recv().unwrap() {
                assert_eq!(text, "hello");
                processed.send(()).unwrap();
            } else {
                panic!("expected message");
            }
        });
        assert!(submit_chat_message(
            &sender,
            "hello".into(),
            Duration::from_secs(1)
        ));
        worker.join().unwrap();
    }

    #[test]
    fn heartbeat_rejection_does_not_remove_pending_message() {
        let mut pending = HashSet::from(["message".to_owned()]);
        assert!(!rejected_message(&mut pending, "heartbeat"));
        assert!(pending.contains("message"));
        assert!(rejected_message(&mut pending, "message"));
    }
}

fn mark_chat_disconnected(operation: &ChatOperation, reason: &str, delivery_unknown: bool) {
    chat_update(operation, |snapshot| {
        snapshot.phase = "disconnected";
        if delivery_unknown {
            snapshot.relay_ack = Some("unknown".to_owned());
            snapshot.pending_sends = 0;
            snapshot.error = Some(format!(
                "{reason} 마지막 메시지의 전달 결과를 알 수 없습니다. 로컬 기록을 확인하고 다시 보낼 때는 중복 가능성을 고려하세요."
            ));
        } else {
            snapshot.error = Some(reason.to_owned());
        }
    });
}

fn relay_failure_message(error: &RelayError, phase: &str, using_tor: bool) -> String {
    match error {
        RelayError::Cancelled => "취소되었습니다.".to_owned(),
        RelayError::Channel(channel::HandshakeError::IdentityMismatch) => {
            "저장된 상대와 연결된 신원이 다릅니다. 연결을 중단했습니다. 별도 경로로 상대를 다시 확인하세요.".to_owned()
        }
        RelayError::TimedOut("relay subscription") => {
            "relay 구독이 제한 시간 안에 준비되지 않았습니다. relay 상태를 확인하고 다시 시도하세요."
                .to_owned()
        }
        RelayError::TimedOut(stage) => {
            let description = match *stage {
                "handshake initiation" | "handshake response" | "handshake completion" => {
                    "초대 상대 응답"
                }
                "identity proof" => "상대 신원 확인 응답",
                "peer confirmation" => "상대 확인 응답",
                "peer subscription" => "상대 relay 구독 준비",
                _ => "relay 응답",
            };
            format!("{description} 제한 시간이 지났습니다. 새 초대 코드로 다시 시도하세요.")
        }
        RelayError::SubscriptionClosed(_) => {
            "relay가 초대 구독을 닫았습니다. 다른 relay가 필요할 수 있습니다.".to_owned()
        }
        RelayError::RelayRejected { .. } => {
            "relay가 이벤트를 거부했습니다. relay 정책이나 연결을 확인하세요.".to_owned()
        }
        RelayError::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
            if using_tor {
                "Tor SOCKS 또는 TLS 응답 시간이 초과되었습니다. 직접 연결로 전환하지 않았습니다."
                    .to_owned()
            } else {
                "relay TCP/TLS 연결 시간이 초과되었습니다.".to_owned()
            }
        }
        _ => match phase {
            "connect" if using_tor => {
                "Tor SOCKS relay 연결에 실패했습니다. 직접 연결로 전환하지 않았습니다."
                    .to_owned()
            }
            "connect" => "relay TLS/WebSocket 연결에 실패했습니다.".to_owned(),
            "handshake" => "상대와 암호화 handshake를 완료하지 못했습니다.".to_owned(),
            "identity" => "상대 신원 증명을 확인하지 못했습니다. 새 초대 코드로 다시 시도하세요.".to_owned(),
            "confirmation" => "상대 확인 응답을 받지 못했습니다. 다시 연결하세요.".to_owned(),
            "chat" if using_tor => {
                "Tor 전용 relay 연결이 끊겼습니다. 직접 연결로 전환하지 않았습니다."
                    .to_owned()
            }
            _ => "relay 연결이 끊겼습니다.".to_owned(),
        },
    }
}

fn spawn_chat_worker(
    operation: Arc<ChatOperation>,
    commands: Receiver<ChatCommand>,
    role: RoleForChat,
    code: Zeroizing<String>,
    expected_peer: Option<[u8; 32]>,
    identity: Arc<Identity>,
    cancelled: Arc<AtomicBool>,
    tor_socks: Option<SocketAddr>,
    notifications_enabled: Arc<AtomicBool>,
    last_notification: Arc<Mutex<Option<Instant>>>,
) {
    thread::spawn(move || {
        let previous_identity_ids = match identity::previous_public_ids(&identity) {
            Ok(ids) => ids,
            Err(_) => {
                chat_update(&operation, |snapshot| {
                    snapshot.phase = "failed";
                    snapshot.error =
                        Some("이전 신원 기록을 읽지 못해 연결을 시작하지 않았습니다.".to_owned());
                });
                return;
            }
        };
        let result = (|| -> Result<(RelaySession, Option<history::History>, Vec<ChatEntry>, Option<String>, [u8; 32], String), String> {
            let invite = InviteCode::parse(&code).ok_or("초대 코드를 확인하세요.")?;
            let mut rendezvous = match role {
                RoleForChat::Create => RelayRendezvous::create(DEFAULT_RELAY, &invite, tor_socks),
                RoleForChat::Join => RelayRendezvous::join(DEFAULT_RELAY, &invite, tor_socks),
            }
            .map_err(|error| relay_failure_message(&error, "connect", tor_socks.is_some()))?;
            rendezvous.set_cancellation_token(Arc::clone(&cancelled));
            let channel = rendezvous
                .complete_handshake()
                .map_err(|error| relay_failure_message(&error, "handshake", tor_socks.is_some()))?;
            if operation.cancelled.load(Ordering::SeqCst) {
                return Err("취소되었습니다.".to_owned());
            }
            let verification = rendezvous
                .authenticate(channel, &identity, expected_peer)
                .map_err(|error| relay_failure_message(&error, "identity", tor_socks.is_some()))?;
            let fingerprint = encode_hex(verification.fingerprint());
            let peer_key = *verification.peer_public_key();
            let peer_id = encode_hex(verification.peer_public_key());
            chat_update(&operation, |snapshot| {
                snapshot.peer_id = Some(peer_id.clone());
                if expected_peer.is_some() { return; }
                snapshot.phase = "verification";
                snapshot.fingerprint = Some(fingerprint);
            });
            let verification = if expected_peer.is_some() { verification } else { loop {
                if operation.cancelled.load(Ordering::SeqCst) {
                    return Err("취소되었습니다.".to_owned());
                }
                match commands.recv_timeout(Duration::from_millis(250)) {
                    Ok(ChatCommand::Confirm) => break verification,
                    Ok(ChatCommand::Cancel) => return Err("취소되었습니다.".to_owned()),
                    Ok(ChatCommand::Send(_, _)) => {}
                    Ok(ChatCommand::AcceptIdentityTransition(_, result)) => {
                        let _ = result.send(Err("상대 기록 연결 요청을 처리할 수 없습니다.".to_owned()));
                    }
                    Ok(ChatCommand::RequestHistoryRestore(result)) => {
                        let _ = result.send(Err("상대 기록 복원은 연결 확인 후 사용할 수 있습니다.".to_owned()));
                    }
                    Ok(ChatCommand::ResolveHistoryRestore(_, result)) => {
                        let _ = result.send(Err("복원 제안을 처리할 수 없습니다.".to_owned()));
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return Err("취소되었습니다.".to_owned()),
                }
            }};
            chat_update(&operation, |snapshot| snapshot.phase = "confirming");
            let mut session = if expected_peer.is_some() {
                rendezvous.confirm(verification).map_err(|error| relay_failure_message(&error, "confirmation", tor_socks.is_some()))?
            } else {
            let (session, rendezvous_secret) = rendezvous
                .confirm_with_contact(verification)
                .map_err(|error| relay_failure_message(&error, "confirmation", tor_socks.is_some()))?;
            let directory = history::data_directory()
                .map_err(|_| "상대 확인 정보를 저장할 위치를 찾을 수 없습니다.".to_owned())?
                .join(identity.public_id()).join("verified-contacts");
            contacts::save_after_confirmation(&directory, &identity, &contacts::VerifiedContact { peer_key, rendezvous_secret })
                .map_err(|_| "상대 확인 정보를 저장하지 못했습니다. 기존 확인 기록을 확인하세요.".to_owned())?;
            session
            };
            let (history, entries, storage_error, pending_previous_ids) = match history::History::open(&identity, &peer_id) {
                Ok((history, stored, recovered_partial)) => {
                    let pending = previous_identity_ids
                        .iter()
                        .filter(|old_id| {
                            !identity_event_exists_for_previous(
                                &stored,
                                "self",
                                old_id,
                                &identity.public_id(),
                            )
                        })
                        .cloned()
                        .collect();
                    let entries = stored
                        .into_iter()
                        .map(chat_entry)
                        .collect();
                    let warning = recovered_partial
                        .then(|| "대화 기록의 마지막 불완전 항목을 제거했습니다.".to_owned());
                    (Some(history), entries, warning, pending)
                }
                Err(_) => (None, Vec::new(), Some("대화 기록을 열지 못했습니다. 이번 대화는 프로그램을 종료하면 사라질 수 있습니다.".to_owned()), previous_identity_ids.clone()),
            };
            if !pending_previous_ids.is_empty() {
                let announcement = chat_control(serde_json::json!({
                    "type": "identity-transition",
                    "previousPeerIds": pending_previous_ids,
                }));
                session.send(&announcement).map_err(|_| "신원 변경 안내를 상대에게 보내지 못했습니다.".to_owned())?;
            }
            Ok((session, history, entries, storage_error, peer_key, peer_id))
        })();

        let (mut session, mut history, peer_key, peer_id) = match result {
            Ok((session, history, messages, storage_error, peer_key, peer_id)) => {
                chat_update(&operation, |snapshot| {
                    snapshot.messages = messages;
                    snapshot.storage_error = storage_error;
                    snapshot.phase = "connected";
                });
                (session, history, peer_key, peer_id)
            }
            Err(error) => {
                chat_update(&operation, |snapshot| {
                    snapshot.phase = if operation.cancelled.load(Ordering::SeqCst) {
                        "closed"
                    } else {
                        snapshot.error = Some(error);
                        "failed"
                    };
                });
                return;
            }
        };
        let mut peer_transition_ids = Vec::<String>::new();
        let mut pending_events = HashSet::<String>::new();
        let mut pending_restore = Vec::<history::StoredMessage>::new();
        let mut restore_request_id = None::<String>;
        let mut restore_receiver = HistorySyncReceiver::default();
        let mut restore_local_aliases = Vec::<[u8; 32]>::new();
        let mut restore_peer_aliases = Vec::<[u8; 32]>::new();
        let mut restore_started_at = None::<Instant>;
        let mut outgoing_sync = None::<HistorySyncSender>;
        let mut outgoing_sync_started_at = None::<Instant>;
        let mut last_peer_activity = Instant::now();
        let mut last_heartbeat = Instant::now();

        while !operation.cancelled.load(Ordering::SeqCst) {
            let now = Instant::now();
            if restore_started_at
                .is_some_and(|started| now.duration_since(started) > Duration::from_secs(30))
            {
                restore_started_at = None;
                if let Some(request_id) = restore_request_id.take() {
                    let _ = session.send(&chat_control(serde_json::json!({
                        "type": "history-sync-cancel",
                        "requestId": request_id,
                        "reason": "receiver timeout",
                    })));
                }
                restore_receiver = HistorySyncReceiver::default();
                pending_restore.clear();
                chat_update(&operation, |snapshot| {
                    snapshot.history_restore_in_progress = false;
                    snapshot.history_restore_received = 0;
                    snapshot.history_restore_total = 0;
                    snapshot.history_restore_status = Some(
                        "상대 기록 응답 시간이 초과되었습니다. 로컬 기록은 변경하지 않았습니다."
                            .to_owned(),
                    );
                });
            }
            if outgoing_sync_started_at
                .is_some_and(|started| now.duration_since(started) > Duration::from_secs(30))
            {
                if let Some(sync) = outgoing_sync.take() {
                    let _ = session.send(&chat_control(serde_json::json!({
                        "type": "history-sync-failed",
                        "requestId": sync.request_id,
                        "reason": "다음 기록 묶음의 확인 응답이 시간 내 도착하지 않았습니다.",
                    })));
                }
                outgoing_sync_started_at = None;
            }
            if now.duration_since(last_peer_activity) >= PEER_HEARTBEAT_TIMEOUT {
                drop(history.take());
                mark_chat_disconnected(
                    &operation,
                    "상대 응답이 45초 동안 없어 연결을 종료했습니다.",
                    !pending_events.is_empty(),
                );
                return;
            }
            if now.duration_since(last_heartbeat) >= PEER_HEARTBEAT_INTERVAL {
                if session.send(PEER_HEARTBEAT_FRAME).is_err() {
                    drop(history.take());
                    mark_chat_disconnected(
                        &operation,
                        "relay 연결이 끊겼습니다.",
                        !pending_events.is_empty(),
                    );
                    return;
                }
                last_heartbeat = Instant::now();
            }
            loop {
                match commands.try_recv() {
                    Ok(ChatCommand::Send(text, processed)) => {
                        let entry = match history::sign_message(
                            &identity,
                            &peer_id,
                            now_seconds(),
                            text.clone(),
                        ) {
                            Ok(entry) => entry,
                            Err(_) => {
                                let _ = processed.send(());
                                chat_update(&operation, |snapshot| {
                                    snapshot.storage_error =
                                        Some("메시지에 발신 서명을 만들지 못했습니다.".to_owned())
                                });
                                continue;
                            }
                        };
                        let frame = match history::encode_signed_message(&entry) {
                            Ok(frame) => frame,
                            Err(_) => {
                                let _ = processed.send(());
                                chat_update(&operation, |snapshot| {
                                    snapshot.storage_error = Some(
                                        "서명된 메시지를 전송 형식으로 만들지 못했습니다."
                                            .to_owned(),
                                    )
                                });
                                continue;
                            }
                        };
                        match session.send(&frame) {
                            Ok(event_id) => {
                                pending_events.insert(event_id);
                                let save_error = match history.as_mut() {
                                    Some(history) => history.append(&entry).err(),
                                    None => Some(io::Error::other("history unavailable")),
                                };
                                if save_error.is_some() {
                                    history = None;
                                }
                                chat_update(&operation, |snapshot| {
                                    snapshot.messages.push(ChatEntry {
                                        unix_time: entry.unix_time,
                                        sender: "나",
                                        text,
                                    });
                                    snapshot.relay_ack = Some("pending".to_owned());
                                    snapshot.pending_sends = pending_events.len();
                                    if save_error.is_some() {
                                        snapshot.storage_error = Some("대화 기록을 저장하지 못했습니다. 프로그램을 종료하면 이 메시지를 잃을 수 있습니다.".to_owned());
                                    }
                                });
                                let _ = processed.send(());
                            }
                            Err(_) => {
                                let save_error = match history.as_mut() {
                                    Some(history) => history.append(&entry).err(),
                                    None => Some(io::Error::other("history unavailable")),
                                };
                                drop(history.take());
                                chat_update(&operation, |snapshot| {
                                    snapshot.phase = "disconnected";
                                    snapshot.messages.push(ChatEntry {
                                        unix_time: entry.unix_time,
                                        sender: "나",
                                        text,
                                    });
                                    snapshot.relay_ack = Some("unknown".to_owned());
                                    snapshot.pending_sends = 0;
                                    snapshot.error = Some(if save_error.is_some() {
                                        "메시지 전송 결과를 확인하지 못했고 기록 저장도 실패했습니다. 입력한 내용을 복사해 두세요.".to_owned()
                                    } else {
                                        "메시지를 로컬 기록에 보존했습니다. relay 전송 결과는 알 수 없으며 다시 보내면 중복될 수 있습니다.".to_owned()
                                    });
                                });
                                let _ = processed.send(());
                                return;
                            }
                        }
                    }
                    Ok(ChatCommand::Cancel) => {
                        operation.cancelled.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(ChatCommand::AcceptIdentityTransition(previous_peer_id, result)) => {
                        let linked = if peer_transition_ids.contains(&previous_peer_id) {
                            let current_peer_id = operation
                                .snapshot
                                .lock()
                                .ok()
                                .and_then(|snapshot| snapshot.peer_id.clone())
                                .unwrap_or_default();
                            let transition =
                                identity_event("peer", &previous_peer_id, &current_peer_id);
                            match history.as_mut() {
                                Some(current) => current
                                    .link_prior_identity(&identity, &previous_peer_id, transition)
                                    .map(|messages| {
                                        let entries =
                                            messages.into_iter().map(chat_entry).collect();
                                        chat_update(&operation, |snapshot| {
                                            snapshot.messages = entries;
                                            snapshot.identity_transition = None;
                                            snapshot.message_epoch =
                                                snapshot.message_epoch.wrapping_add(1);
                                        });
                                    })
                                    .map_err(|error| error.to_string()),
                                None => Err("현재 대화 기록을 사용할 수 없습니다.".to_owned()),
                            }
                        } else {
                            Err("상대가 알린 이전 대화를 찾을 수 없습니다.".to_owned())
                        };
                        if linked.is_ok() {
                            let frame = chat_control(serde_json::json!({
                                "type": "identity-linked",
                                "previousPeerId": previous_peer_id,
                            }));
                            if session.send(&frame).is_err() {
                                chat_update(&operation, |snapshot| {
                                    snapshot.storage_error = Some("기존 기록은 이 기기에 연결했지만 상대에게 변경 알림을 보내지 못했습니다.".to_owned());
                                });
                            }
                        }
                        let _ = result.send(linked.map(|_| ()));
                    }
                    Ok(ChatCommand::RequestHistoryRestore(result)) => {
                        if history.is_none() || restore_request_id.is_some() {
                            let _ = result
                                .send(Err("현재 기록을 읽을 수 없거나 복원이 이미 진행 중입니다."
                                    .to_owned()));
                            continue;
                        }
                        let request_id = match random_token() {
                            Ok(id) => id,
                            Err(_) => {
                                let _ = result
                                    .send(Err("복원 요청 ID를 만들지 못했습니다.".to_owned()));
                                continue;
                            }
                        };
                        let frame = chat_control(serde_json::json!({
                            "type": "history-sync-request",
                            "requestId": request_id,
                        }));
                        match session.send(&frame) {
                            Ok(_) => {
                                pending_restore.clear();
                                restore_request_id = Some(request_id);
                                restore_receiver = HistorySyncReceiver::default();
                                restore_started_at = Some(Instant::now());
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_in_progress = true;
                                    snapshot.history_restore_offer.clear();
                                    snapshot.history_restore_received = 0;
                                    snapshot.history_restore_total = 0;
                                    snapshot.history_restore_status = Some("상대 기록을 확인하고 있습니다. 아직 로컬 기록은 변경하지 않았습니다.".to_owned());
                                });
                                let _ = result.send(Ok(()));
                            }
                            Err(_) => {
                                let _ = result.send(Err(
                                    "상대에게 기록 복원을 요청하지 못했습니다.".to_owned(),
                                ));
                            }
                        }
                    }
                    Ok(ChatCommand::ResolveHistoryRestore(accept, result)) => {
                        let in_progress = restore_request_id.is_some();
                        let resolved = if accept {
                            match (history.as_mut(), operation.snapshot.lock().ok()) {
                                (Some(current), _) if !pending_restore.is_empty() => {
                                    match history::History::read_for_identity_copy(&identity, &peer_id) {
                                        Ok((existing, false)) => match history::merge_restored(&existing, &pending_restore) {
                                            Ok(merged) => current.replace(&merged).map(|_| {
                                                let restored_count = merged.len().saturating_sub(existing.len());
                                                chat_update(&operation, |snapshot| {
                                                    snapshot.messages = merged.into_iter().map(chat_entry).collect();
                                                    snapshot.message_epoch = snapshot.message_epoch.wrapping_add(1);
                                                    snapshot.history_restore_status = Some(format!("{restored_count}개 메시지를 복원했습니다. 서명이 없는 기존 형식 항목은 검증되지 않았습니다."));
                                                });
                                            }),
                                            Err(error) => Err(error),
                                        },
                                        Ok((_, true)) => Err(io::Error::other("current history has an incomplete record")),
                                        Err(error) => Err(error),
                                    }
                                }
                                _ => Err(io::Error::other("no pending history offer")),
                            }
                        } else {
                            if let Some(request_id) = restore_request_id.take() {
                                let _ = session.send(&chat_control(serde_json::json!({
                                    "type": "history-sync-cancel",
                                    "requestId": request_id,
                                    "reason": "user cancelled",
                                })));
                            }
                            restore_receiver = HistorySyncReceiver::default();
                            restore_started_at = None;
                            chat_update(&operation, |snapshot| {
                                snapshot.history_restore_status = Some(
                                    if in_progress {
                                        "기록 전송을 취소했습니다. 로컬 기록은 변경하지 않았습니다."
                                    } else {
                                        "복원을 거부했습니다. 로컬 기록은 변경하지 않았습니다."
                                    }
                                    .to_owned(),
                                )
                            });
                            Ok(())
                        };
                        pending_restore.clear();
                        chat_update(&operation, |snapshot| {
                            snapshot.history_restore_offer.clear();
                            snapshot.history_restore_offer_count = 0;
                            snapshot.history_restore_legacy_count = 0;
                            snapshot.history_restore_received = 0;
                            snapshot.history_restore_total = 0;
                        });
                        let _ = result.send(resolved.map_err(|error| error.to_string()));
                    }
                    Ok(ChatCommand::Confirm) => {}
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            if operation.cancelled.load(Ordering::SeqCst) {
                break;
            }
            match session.poll() {
                Ok(Some(RelayUpdate::Messages(messages))) => {
                    for message in messages {
                        if message == PEER_HEARTBEAT_FRAME {
                            last_peer_activity = Instant::now();
                            continue;
                        }
                        last_peer_activity = Instant::now();
                        if history::is_signed_message_frame(&message) {
                            let entry = match history::decode_signed_message(
                                &identity, &peer_id, &peer_key, &message,
                            ) {
                                Ok(entry) => entry,
                                Err(_) => {
                                    drop(history.take());
                                    mark_chat_disconnected(&operation, "상대 메시지의 발신 서명 또는 형식 검증에 실패했습니다. 기록은 가져오지 않았습니다.", false);
                                    return;
                                }
                            };
                            let save_error = match history.as_mut() {
                                Some(history) => history.append(&entry).err(),
                                None => Some(io::Error::other("history unavailable")),
                            };
                            if save_error.is_some() {
                                history = None;
                            }
                            chat_update(&operation, |snapshot| {
                                snapshot.messages.push(chat_entry(entry));
                                if save_error.is_some() {
                                    snapshot.storage_error =
                                        Some("메시지를 기록에 저장하지 못했습니다.".to_owned());
                                }
                            });
                            continue;
                        }
                        if history::is_transfer_frame(&message) {
                            let Ok((frame_request_id, chunk_index, payload)) =
                                history::transfer_chunk_metadata(&message)
                            else {
                                let request_id = restore_request_id.take();
                                pending_restore.clear();
                                restore_receiver = HistorySyncReceiver::default();
                                restore_started_at = None;
                                if let Some(request_id) = &request_id {
                                    let _ = session.send(&chat_control(serde_json::json!({
                                        "type": "history-sync-cancel", "requestId": request_id,
                                        "reason": "record missing chunk identity",
                                    })));
                                }
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_in_progress = false;
                                    snapshot.history_restore_received = 0;
                                    snapshot.history_restore_total = 0;
                                    snapshot.history_restore_status = Some("요청/묶음 ID가 없는 상대 기록 항목을 거부했습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                });
                                continue;
                            };
                            let Some(request_id) = restore_request_id.clone() else {
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_status = Some(
                                        "요청하지 않은 상대 기록 항목을 거부했습니다.".to_owned(),
                                    );
                                });
                                continue;
                            };
                            if frame_request_id != request_id {
                                // Delayed frames from cancelled or completed requests cannot alter a newer offer.
                                continue;
                            }
                            let decoded = history::decode_transfer_with_linked_keys(
                                &identity,
                                &peer_id,
                                &peer_key,
                                payload,
                                &restore_local_aliases,
                                &restore_peer_aliases,
                            )
                            .and_then(|entry| {
                                restore_receiver.record(&request_id, chunk_index, message.len())?;
                                Ok(entry)
                            });
                            match decoded {
                                Ok(entry) => {
                                    pending_restore.push(entry);
                                    restore_started_at = Some(Instant::now());
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_received =
                                            restore_receiver.received_records;
                                    });
                                }
                                Err(error) => {
                                    restore_request_id = None;
                                    restore_receiver = HistorySyncReceiver::default();
                                    restore_started_at = None;
                                    pending_restore.clear();
                                    let _ = session.send(&chat_control(serde_json::json!({
                                        "type": "history-sync-cancel",
                                        "requestId": request_id,
                                        "reason": error.to_string(),
                                    })));
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_received = 0;
                                        snapshot.history_restore_total = 0;
                                        snapshot.history_restore_status = Some(format!("상대 기록 검증에 실패했습니다: {error}. 확인 후 명시적으로 연결한 이전 신원만 허용됩니다. 로컬 기록은 변경하지 않았습니다."));
                                    });
                                }
                            }
                            continue;
                        }
                        let control = match parse_chat_control(&message) {
                            Ok(control) => control,
                            Err(()) => {
                                drop(history.take());
                                chat_update(&operation, |snapshot| {
                                    snapshot.phase = "disconnected";
                                    snapshot.error = Some(
                                        "상대의 내부 연결 안내 형식이 잘못되었습니다.".to_owned(),
                                    );
                                });
                                return;
                            }
                        };
                        if let Some(control) = control {
                            match control.get("type").and_then(serde_json::Value::as_str) {
                                Some("identity-transition") => {
                                    let Some(ids) = control
                                        .get("previousPeerIds")
                                        .and_then(serde_json::Value::as_array)
                                    else {
                                        drop(history.take());
                                        mark_chat_disconnected(
                                            &operation,
                                            "상대의 이전 신원 정보가 잘못되었습니다.",
                                            false,
                                        );
                                        return;
                                    };
                                    let mut parsed = Vec::new();
                                    for id in ids.iter().filter_map(serde_json::Value::as_str) {
                                        if history::decode_peer_id(id).is_err()
                                            || parsed.contains(&id.to_ascii_lowercase())
                                            || parsed.len() >= 32
                                        {
                                            drop(history.take());
                                            mark_chat_disconnected(
                                                &operation,
                                                "상대의 이전 신원 정보가 잘못되었습니다.",
                                                false,
                                            );
                                            return;
                                        }
                                        parsed.push(id.to_ascii_lowercase());
                                    }
                                    if parsed.len() != ids.len() {
                                        drop(history.take());
                                        mark_chat_disconnected(
                                            &operation,
                                            "상대의 이전 신원 정보가 잘못되었습니다.",
                                            false,
                                        );
                                        return;
                                    }
                                    let current_peer_id = operation
                                        .snapshot
                                        .lock()
                                        .ok()
                                        .and_then(|snapshot| snapshot.peer_id.clone())
                                        .unwrap_or_default();
                                    let mut pending = Vec::new();
                                    for old_id in parsed {
                                        if history::is_linked_peer_identity(
                                            &identity,
                                            &current_peer_id,
                                            &old_id,
                                        )
                                        .unwrap_or(false)
                                        {
                                            let ack = chat_control(serde_json::json!({
                                                "type": "identity-linked",
                                                "previousPeerId": old_id,
                                            }));
                                            let _ = session.send(&ack);
                                        } else {
                                            pending.push(old_id);
                                        }
                                    }
                                    peer_transition_ids = pending.clone();
                                    chat_update(&operation, |snapshot| {
                                        snapshot.identity_transition = Some(pending);
                                    });
                                }
                                Some("identity-linked") => {
                                    let Some(previous_id) = control
                                        .get("previousPeerId")
                                        .and_then(serde_json::Value::as_str)
                                        .map(str::to_ascii_lowercase)
                                    else {
                                        drop(history.take());
                                        mark_chat_disconnected(
                                            &operation,
                                            "상대의 신원 변경 응답이 잘못되었습니다.",
                                            false,
                                        );
                                        return;
                                    };
                                    if !previous_identity_ids.contains(&previous_id) {
                                        continue;
                                    }
                                    let entry =
                                        identity_event("self", &previous_id, &identity.public_id());
                                    match history.as_mut() {
                                        Some(current) => match current
                                            .append_system_once(&identity, entry.clone())
                                        {
                                            Ok(added) => {
                                                match history::record_linked_local_identity(
                                                    &identity,
                                                    &peer_id,
                                                    &previous_id,
                                                ) {
                                                    Ok(()) if added => {
                                                        chat_update(&operation, |snapshot| {
                                                            snapshot
                                                                .messages
                                                                .push(chat_entry(entry))
                                                        })
                                                    }
                                                    Ok(()) => {}
                                                    Err(error) => {
                                                        chat_update(&operation, |snapshot| {
                                                            snapshot.storage_error = Some(format!("이전 신원 연결 확인 정보를 저장하지 못했습니다. 재연결 후 다시 시도하세요: {error}"))
                                                        })
                                                    }
                                                }
                                            }
                                            Err(_) => chat_update(&operation, |snapshot| {
                                                snapshot.storage_error = Some(
                                                    "신원 변경 기록을 저장하지 못했습니다."
                                                        .to_owned(),
                                                )
                                            }),
                                        },
                                        None => chat_update(&operation, |snapshot| {
                                            snapshot.storage_error = Some(
                                                "신원 변경 기록을 저장하지 못했습니다.".to_owned(),
                                            )
                                        }),
                                    }
                                }
                                Some("history-sync-request") => {
                                    let Some(request_id) = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                    else {
                                        continue;
                                    };
                                    if !valid_sync_request_id(request_id) {
                                        continue;
                                    }
                                    if outgoing_sync.is_some() {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-failed", "requestId": request_id,
                                            "reason": "다른 기록 전송이 진행 중입니다.",
                                        })));
                                        continue;
                                    }
                                    let prepared = history::History::read_for_identity_copy(&identity, &peer_id)
                                        .map_err(|_| "현재 기록을 읽지 못했습니다.".to_owned())
                                        .and_then(|(messages, incomplete)| {
                                            if incomplete { return Err("기록 끝부분이 손상되어 전송하지 않았습니다.".to_owned()); }
                                            if messages.len() > MAX_SYNC_RECORDS { return Err("기록이 100,000개 메시지 제한을 넘어 전송하지 않았습니다.".to_owned()); }
                                            let mut total = 0usize;
                                            for (index, item) in messages.iter().enumerate() {
                                                let frame = history::encode_transfer_chunk(item, request_id, index / SYNC_CHUNK_RECORDS).map_err(|_| "기록 전송 형식을 만들지 못했습니다.".to_owned())?;
                                                total = total.saturating_add(frame.len());
                                                if total > MAX_SYNC_BYTES { return Err("기록이 64 MiB 동기화 한도를 넘어 전송하지 않았습니다.".to_owned()); }
                                            }
                                            Ok(messages)
                                        });
                                    let messages = match prepared {
                                        Ok(messages) => messages,
                                        Err(reason) => {
                                            let _ = session.send(&chat_control(serde_json::json!({
                                                "type": "history-sync-failed", "requestId": request_id, "reason": reason,
                                            })));
                                            continue;
                                        }
                                    };
                                    let total_count = messages.len();
                                    let total_chunks = total_count.div_ceil(SYNC_CHUNK_RECORDS);
                                    let mut sync =
                                        HistorySyncSender::new(request_id.to_owned(), messages);
                                    let begin = chat_control(serde_json::json!({
                                        "type": "history-sync-begin", "requestId": request_id,
                                        "totalCount": total_count, "chunkCount": total_chunks,
                                    }));
                                    let sent = session
                                        .send(&begin)
                                        .map(|_| ())
                                        .map_err(|error| io::Error::other(format!("{error:?}")))
                                        .and_then(|()| {
                                            if total_count == 0 {
                                                send_history_sync_done(
                                                    &mut session,
                                                    request_id,
                                                    total_count,
                                                )
                                            } else {
                                                send_next_history_chunk(&mut session, &mut sync)
                                            }
                                        });
                                    if sent.is_err() {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-failed", "requestId": request_id,
                                            "reason": "기록 묶음을 전송하지 못했습니다.",
                                        })));
                                    } else if total_count > 0 {
                                        outgoing_sync = Some(sync);
                                        outgoing_sync_started_at = Some(Instant::now());
                                    }
                                }
                                Some("history-sync-begin") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    let total_count = control
                                        .get("totalCount")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|count| usize::try_from(count).ok());
                                    let chunk_count = control
                                        .get("chunkCount")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|count| usize::try_from(count).ok());
                                    let started = total_count.zip(chunk_count).is_some_and(
                                        |(total, chunks)| {
                                            restore_receiver
                                                .begin(request_id, total, chunks)
                                                .is_ok()
                                        },
                                    );
                                    if !started {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-cancel", "requestId": request_id,
                                            "reason": "invalid transfer start",
                                        })));
                                        restore_request_id = None;
                                        restore_started_at = None;
                                        pending_restore.clear();
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some("상대 기록 제안의 시작 정보가 잘못되었습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                        });
                                    } else {
                                        let aliases = history::History::read_for_identity_copy(
                                            &identity, &peer_id,
                                        )
                                        .and_then(|(messages, incomplete)| {
                                            if incomplete {
                                                return Err(io::Error::other(
                                                    "current history has an incomplete record",
                                                ));
                                            }
                                            history::linked_identity_keys(
                                                &identity,
                                                &messages,
                                                &identity.public_id(),
                                                &peer_id,
                                                &previous_identity_ids,
                                            )
                                        });
                                        let Ok((local_aliases, peer_aliases)) = aliases else {
                                            let _ = session.send(&chat_control(serde_json::json!({
                                                "type": "history-sync-cancel", "requestId": request_id,
                                                "reason": "local identity-link history unavailable",
                                            })));
                                            restore_request_id = None;
                                            restore_receiver = HistorySyncReceiver::default();
                                            pending_restore.clear();
                                            chat_update(&operation, |snapshot| {
                                                snapshot.history_restore_in_progress = false;
                                                snapshot.history_restore_status = Some("이전 신원 연결 기록을 검증하지 못해 복원 제안을 거부했습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                            });
                                            continue;
                                        };
                                        restore_local_aliases = local_aliases;
                                        restore_peer_aliases = peer_aliases;
                                        pending_restore.clear();
                                        restore_started_at = Some(Instant::now());
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_total =
                                                restore_receiver.total_records;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_status = Some(format!("기록 묶음을 받는 중입니다: 0 / {}. 동의 전에는 로컬 기록을 변경하지 않습니다.", restore_receiver.total_records));
                                        });
                                    }
                                }
                                Some("history-sync-chunk-begin") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    let chunk = control
                                        .get("chunk")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|n| usize::try_from(n).ok());
                                    let count = control
                                        .get("count")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|n| usize::try_from(n).ok());
                                    let result = chunk
                                        .zip(count)
                                        .ok_or_else(|| io::Error::other("invalid chunk header"))
                                        .and_then(|(chunk, count)| {
                                            restore_receiver.begin_chunk(request_id, chunk, count)
                                        });
                                    if let Err(error) = result {
                                        restore_request_id = None;
                                        restore_receiver = HistorySyncReceiver::default();
                                        restore_started_at = None;
                                        pending_restore.clear();
                                        let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-cancel", "requestId": request_id, "reason": error.to_string() })));
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some(format!("기록 묶음 순서가 잘못되어 전송을 중단했습니다: {error}. 로컬 기록은 변경하지 않았습니다."));
                                        });
                                    }
                                }
                                Some("history-sync-chunk-end") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    let chunk = control
                                        .get("chunk")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|n| usize::try_from(n).ok());
                                    let result = chunk
                                        .ok_or_else(|| io::Error::other("invalid chunk index"))
                                        .and_then(|chunk| {
                                            restore_receiver.end_chunk(request_id, chunk)
                                        });
                                    if let Err(error) = result {
                                        restore_request_id = None;
                                        restore_receiver = HistorySyncReceiver::default();
                                        restore_started_at = None;
                                        pending_restore.clear();
                                        let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-cancel", "requestId": request_id, "reason": error.to_string() })));
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some(format!("기록 묶음이 완전하지 않아 전송을 중단했습니다: {error}. 로컬 기록은 변경하지 않았습니다."));
                                        });
                                    } else {
                                        restore_started_at = Some(Instant::now());
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-ack", "requestId": request_id, "chunk": chunk.unwrap(),
                                        })));
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_received =
                                                restore_receiver.received_records;
                                            snapshot.history_restore_status = Some(format!("기록 묶음을 받는 중입니다: {} / {}. 동의 전에는 로컬 기록을 변경하지 않습니다.", restore_receiver.received_records, restore_receiver.total_records));
                                        });
                                    }
                                }
                                Some("history-sync-ack") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    let chunk = control
                                        .get("chunk")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|n| usize::try_from(n).ok());
                                    let Some(sync) = outgoing_sync.as_mut() else {
                                        continue;
                                    };
                                    let result = chunk
                                        .ok_or_else(|| io::Error::other("invalid acknowledgment"))
                                        .and_then(|chunk| sync.acknowledge(request_id, chunk));
                                    match result {
                                        Ok(false) => {}
                                        Ok(true) => {
                                            let request_id = sync.request_id.clone();
                                            let total_count = sync.messages.len();
                                            if send_history_sync_done(
                                                &mut session,
                                                &request_id,
                                                total_count,
                                            )
                                            .is_ok()
                                            {
                                                outgoing_sync = None;
                                                outgoing_sync_started_at = None;
                                            }
                                        }
                                        Err(error) => {
                                            let request_id = sync.request_id.clone();
                                            let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-failed", "requestId": request_id, "reason": error.to_string() })));
                                            outgoing_sync = None;
                                            outgoing_sync_started_at = None;
                                        }
                                    }
                                    if let Some(sync) = outgoing_sync.as_mut() {
                                        if sync.awaiting_chunk.is_none() {
                                            if send_next_history_chunk(&mut session, sync).is_err()
                                            {
                                                let request_id = sync.request_id.clone();
                                                let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-failed", "requestId": request_id, "reason": "다음 기록 묶음을 전송하지 못했습니다." })));
                                                outgoing_sync = None;
                                                outgoing_sync_started_at = None;
                                            } else {
                                                outgoing_sync_started_at = Some(Instant::now());
                                            }
                                        }
                                    }
                                }
                                Some("history-sync-done") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    let count = control
                                        .get("totalCount")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|count| usize::try_from(count).ok());
                                    let received_count = restore_receiver.received_records;
                                    let declared_total = restore_receiver.total_records;
                                    let valid = count.is_some_and(|count| {
                                        restore_receiver.finish(request_id, count).is_ok()
                                    }) && restore_request_id.as_deref()
                                        == Some(request_id)
                                        && count == Some(pending_restore.len());
                                    restore_request_id = None;
                                    restore_started_at = None;
                                    restore_receiver = HistorySyncReceiver::default();
                                    if !valid {
                                        pending_restore.clear();
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some("상대 기록 제안이 완전하지 않아 아무 항목도 가져오지 않았습니다.".to_owned());
                                        });
                                        continue;
                                    }
                                    let offer = match history::History::read_for_identity_copy(
                                        &identity, &peer_id,
                                    )
                                    .and_then(|(existing, incomplete)| {
                                        if incomplete {
                                            return Err(io::Error::other(
                                                "current history is incomplete",
                                            ));
                                        }
                                        history::missing_restored(&existing, &pending_restore)
                                    }) {
                                        Ok(offer) => offer,
                                        Err(_) => {
                                            pending_restore.clear();
                                            chat_update(&operation, |snapshot| {
                                                snapshot.history_restore_in_progress = false;
                                                snapshot.history_restore_received = 0;
                                                snapshot.history_restore_total = 0;
                                                snapshot.history_restore_status = Some("기록 충돌 또는 로컬 기록 오류가 있어 복원 제안을 거부했습니다.".to_owned());
                                            });
                                            continue;
                                        }
                                    };
                                    pending_restore = offer;
                                    let signed_count = pending_restore
                                        .iter()
                                        .filter(|item| item.proof.is_some())
                                        .count();
                                    let legacy_count = pending_restore.len() - signed_count;
                                    let preview: Vec<_> = pending_restore
                                        .iter()
                                        .take(RESTORE_PREVIEW_RECORDS)
                                        .map(|item| RestoreOfferEntry {
                                            unix_time: item.unix_time,
                                            sender: if item.sender == history::MessageSender::Me {
                                                "나"
                                            } else {
                                                "상대방"
                                            },
                                            text: item.text.clone(),
                                            signed: item.proof.is_some(),
                                        })
                                        .collect();
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_legacy_count = legacy_count;
                                        snapshot.history_restore_offer_count =
                                            pending_restore.len();
                                        snapshot.history_restore_offer = preview;
                                        snapshot.history_restore_received = received_count;
                                        snapshot.history_restore_total = declared_total;
                                        snapshot.history_restore_status = Some(
                                            if pending_restore.is_empty() {
                                                "상대가 보낸 기록 중 새로 가져올 메시지가 없습니다."
                                                    .to_owned()
                                            } else {
                                                format!("서명 검증된 누락 {}개, 기존 서명 없는 기록 {}개를 찾았습니다. 동의 전에는 기록이 변경되지 않습니다.", signed_count, legacy_count)
                                            },
                                        );
                                    });
                                }
                                Some("history-sync-failed") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    restore_request_id = None;
                                    restore_receiver = HistorySyncReceiver::default();
                                    restore_started_at = None;
                                    pending_restore.clear();
                                    let reason = control
                                        .get("reason")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("상대가 기록을 전송하지 못했습니다.");
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_received = 0;
                                        snapshot.history_restore_total = 0;
                                        snapshot.history_restore_status = Some(format!(
                                            "{reason} 로컬 기록은 변경하지 않았습니다."
                                        ));
                                    });
                                }
                                Some("history-sync-cancel") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if outgoing_sync
                                        .as_ref()
                                        .is_some_and(|sync| sync.request_id == request_id)
                                    {
                                        outgoing_sync = None;
                                        outgoing_sync_started_at = None;
                                    }
                                    if restore_request_id.as_deref() == Some(request_id) {
                                        restore_request_id = None;
                                        restore_receiver = HistorySyncReceiver::default();
                                        restore_started_at = None;
                                        pending_restore.clear();
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some("상대가 기록 전송을 중단했습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                        });
                                    }
                                }
                                _ => {
                                    drop(history.take());
                                    mark_chat_disconnected(
                                        &operation,
                                        "알 수 없는 내부 연결 안내를 받았습니다.",
                                        false,
                                    );
                                    return;
                                }
                            }
                            continue;
                        }
                        match String::from_utf8(message) {
                            Ok(text) => {
                                let entry = history::StoredMessage {
                                    unix_time: now_seconds(),
                                    sender: history::MessageSender::Other,
                                    text,
                                    proof: None,
                                };
                                let save_error = match history.as_mut() {
                                    Some(history) => history.append(&entry).err(),
                                    None => Some(io::Error::other("history unavailable")),
                                };
                                if save_error.is_some() {
                                    history = None;
                                }
                                if notifications_enabled.load(Ordering::SeqCst)
                                    && should_send_notification(&last_notification)
                                {
                                    notify_incoming_message();
                                }
                                chat_update(&operation, |snapshot| {
                                    snapshot.messages.push(ChatEntry {
                                        unix_time: entry.unix_time,
                                        sender: "상대방",
                                        text: entry.text,
                                    });
                                    if save_error.is_some() {
                                        snapshot.storage_error = Some("대화 기록을 저장하지 못했습니다. 프로그램을 종료하면 이 메시지를 잃을 수 있습니다.".to_owned());
                                    }
                                });
                            }
                            Err(_) => {
                                drop(history.take());
                                chat_update(&operation, |snapshot| {
                                    snapshot.phase = "disconnected";
                                    snapshot.error =
                                        Some("상대 메시지 형식이 잘못되었습니다.".to_owned());
                                });
                                return;
                            }
                        }
                    }
                }
                Ok(Some(RelayUpdate::Published { event_id })) => {
                    if pending_events.remove(&event_id) {
                        chat_update(&operation, |snapshot| {
                            snapshot.relay_ack = Some("accepted".to_owned());
                            snapshot.pending_sends = pending_events.len();
                        });
                    }
                }
                Ok(Some(RelayUpdate::Ready)) | Ok(None) => {}
                Err(error) => {
                    drop(history.take());
                    chat_update(&operation, |snapshot| {
                        snapshot.phase = "disconnected";
                        if let RelayError::RelayRejected { event_id, .. } = &error {
                            let message_rejected = rejected_message(&mut pending_events, event_id);
                            if message_rejected && pending_events.is_empty() {
                                snapshot.relay_ack = Some("rejected".to_owned());
                                snapshot.pending_sends = 0;
                                snapshot.error = Some(
                                    "relay가 메시지 이벤트를 거부했습니다. 이 이벤트는 relay에 접수되지 않았습니다."
                                        .to_owned(),
                                );
                            } else if !pending_events.is_empty() {
                                snapshot.relay_ack = Some("unknown".to_owned());
                                snapshot.pending_sends = 0;
                                snapshot.error = Some("relay가 이벤트를 거부했습니다. 대기 중인 메시지의 전송 결과를 확인하지 못했습니다. 로컬 기록을 확인하고 다시 보내면 중복될 수 있습니다.".to_owned());
                            } else {
                                snapshot.error = Some(
                                    "relay가 연결 유지 이벤트를 거부해 연결이 끊겼습니다."
                                        .to_owned(),
                                );
                            }
                        } else if pending_events.is_empty() {
                            snapshot.error = Some(relay_failure_message(&error, "chat", false));
                        } else {
                            snapshot.relay_ack = Some("unknown".to_owned());
                            snapshot.pending_sends = 0;
                            snapshot.error = Some("relay 연결이 끊겨 마지막 메시지의 전송 결과를 확인하지 못했습니다. 로컬 기록에 보존되어 있으며 다시 보내면 중복될 수 있습니다.".to_owned());
                        }
                    });
                    return;
                }
            }
        }
        drop(history);
        chat_update(&operation, |snapshot| snapshot.phase = "closed");
    });
}

#[derive(Clone, Copy)]
enum RoleForChat {
    Create,
    Join,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn peer_chat_active(state: &State, peer_id: &str) -> bool {
    state.chats.values().any(|operation| {
        operation.snapshot.lock().is_ok_and(|snapshot| {
            snapshot
                .peer_id
                .as_deref()
                .is_some_and(|current| current.eq_ignore_ascii_case(peer_id))
                && !matches!(snapshot.phase, "closed" | "failed" | "disconnected")
        })
    })
}

fn any_chat_active(state: &State) -> bool {
    state.chats.values().any(|operation| {
        operation
            .snapshot
            .lock()
            .is_ok_and(|snapshot| !matches!(snapshot.phase, "closed" | "failed" | "disconnected"))
    })
}

fn respond_settings(stream: &mut TcpStream, state: &State) -> io::Result<()> {
    let active_mode = if state.tor_socks.is_some() {
        "tor"
    } else {
        "general"
    };
    let saved_mode = if state.settings.tor_socks.is_some() {
        "tor"
    } else {
        "general"
    };
    let payload = serde_json::json!({
        "activeMode": active_mode,
        "savedMode": saved_mode,
        "socks": state.settings.tor_socks.map(|address| address.to_string()),
        "activeSocks": state.tor_socks.map(|address| address.to_string()),
        "notifications": state.settings.notifications,
        "restartRequired": state.tor_socks != state.settings.tor_socks,
    })
    .to_string();
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        payload.as_bytes(),
    )
}

fn update_closed_chat_history(
    state: &State,
    peer_id: &str,
    messages: Option<&[history::StoredMessage]>,
) {
    for operation in state.chats.values() {
        if let Ok(mut snapshot) = operation.snapshot.lock() {
            if snapshot
                .peer_id
                .as_deref()
                .is_some_and(|current| current.eq_ignore_ascii_case(peer_id))
                && matches!(snapshot.phase, "closed" | "failed" | "disconnected")
            {
                snapshot.messages = messages
                    .unwrap_or_default()
                    .iter()
                    .cloned()
                    .map(chat_entry)
                    .collect();
            }
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn equal_token(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn issue_code(state: &mut State) -> io::Result<()> {
    state.code = random_token()?;
    state.issued = Instant::now();
    state.attempts = 0;
    println!("로컬 연결 코드: {}", state.code);
    println!("새 연결 코드를 발급하려면 Enter를 누르세요.");
    Ok(())
}

fn preferences_path() -> io::Result<PathBuf> {
    #[cfg(debug_assertions)]
    if std::env::var_os("ANOTHER_DIMENSION_DATA_DIR").is_some() {
        return Ok(history::data_directory()?.join("preferences.json"));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory is unavailable"))?;
    Ok(home
        .join("Library/Application Support/Another Dimension v2")
        .join("preferences.json"))
}

fn load_settings() -> io::Result<AppSettings> {
    let path = preferences_path()?;
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(AppSettings::default()),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "settings file is too large",
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "settings file is invalid"))?;
    let tor_socks = match value.get("torSocks") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(parse_loopback_socks(value)?),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "settings SOCKS address is invalid",
            ))
        }
    };
    let notifications = value
        .get("notifications")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Ok(AppSettings {
        tor_socks,
        notifications,
    })
}

fn save_settings(settings: &AppSettings) -> io::Result<()> {
    let path = preferences_path()?;
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("settings directory unavailable"))?;
    create_dir_all(directory)?;
    set_private_directory(directory)?;
    let contents = serde_json::to_vec(&serde_json::json!({
        "torSocks": settings.tor_socks.map(|address| address.to_string()),
        "notifications": settings.notifications,
    }))?;
    let temporary = path.with_extension(format!("{}.tmp", random_token()?));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_file(&file)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        rename(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

fn parse_loopback_socks(value: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = value.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS 주소는 127.0.0.1:9050 형식이어야 합니다.",
        )
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS 주소는 loopback과 유효한 포트만 허용합니다.",
        ));
    }
    Ok(address)
}

#[cfg(unix)]
fn set_private_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_file: &File) -> io::Result<()> {
    Ok(())
}

fn notify_incoming_message() {
    #[cfg(target_os = "macos")]
    {
        let _ = thread::Builder::new()
            .name("local-notification".to_owned())
            .spawn(|| {
                let _ = Command::new("/usr/bin/osascript")
                    .args([
                        "-e",
                        "display notification \"새 메시지가 도착했습니다\" with title \"Another Dimension\"",
                    ])
                    .status();
            });
    }
}

fn should_send_notification(last_notification: &Mutex<Option<Instant>>) -> bool {
    let Ok(mut last_notification) = last_notification.lock() else {
        return false;
    };
    let now = Instant::now();
    if last_notification.is_some_and(|last| now.duration_since(last) < Duration::from_secs(5)) {
        return false;
    }
    *last_notification = Some(now);
    true
}

fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len())?;
    stream.write_all(body)
}

fn reject(stream: &mut TcpStream, status: &str) -> io::Result<()> {
    respond(stream, status, "text/plain; charset=utf-8", b"")
}

fn handle(mut stream: TcpStream, expected_host: &str, state: &Arc<Mutex<State>>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0; 1024]);
    let header_end = loop {
        if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        let n = stream.read(buffer.as_mut())?;
        if n == 0 || request.len() + n > MAX_HEADER {
            return reject(&mut stream, "400 Bad Request");
        }
        request.extend_from_slice(&buffer[..n]);
    };
    if header_end > MAX_HEADER {
        return reject(&mut stream, "400 Bad Request");
    }
    let header = match std::str::from_utf8(&request[..header_end]) {
        Ok(value) => value,
        Err(_) => return reject(&mut stream, "400 Bad Request"),
    };
    let mut lines = header.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut host = None;
    let mut origin = None;
    let mut authorization = None;
    let mut length = None;
    let mut content_type = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return reject(&mut stream, "400 Bad Request");
        };
        let value = value.trim();
        let slot = if name.eq_ignore_ascii_case("host") {
            Some(&mut host)
        } else if name.eq_ignore_ascii_case("origin") {
            Some(&mut origin)
        } else if name.eq_ignore_ascii_case("authorization") {
            Some(&mut authorization)
        } else if name.eq_ignore_ascii_case("content-length") {
            Some(&mut length)
        } else if name.eq_ignore_ascii_case("content-type") {
            Some(&mut content_type)
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return reject(&mut stream, "400 Bad Request");
        } else {
            None
        };
        if let Some(slot) = slot {
            if slot.replace(value).is_some() {
                return reject(&mut stream, "400 Bad Request");
            }
        }
    }
    if host != Some(expected_host) {
        return reject(&mut stream, "400 Bad Request");
    }
    if first == "GET / HTTP/1.1" {
        return respond(&mut stream, "200 OK", "text/html; charset=utf-8", PAGE);
    }
    if first == "GET /app.js HTTP/1.1" {
        return respond(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            SCRIPT,
        );
    }
    if first == "GET /reprotect-work.js HTTP/1.1" {
        return respond(
            &mut stream,
            "200 OK",
            "text/javascript; charset=utf-8",
            REPROTECT_WORK_SCRIPT,
        );
    }
    if !matches!(
        first,
        "POST /api/connect HTTP/1.1"
            | "POST /api/session HTTP/1.1"
            | "POST /api/disconnect HTTP/1.1"
            | "POST /api/identity/create HTTP/1.1"
            | "POST /api/identity/login HTTP/1.1"
            | "POST /api/identity/replace HTTP/1.1"
            | "POST /api/identity/status HTTP/1.1"
            | "POST /api/identity/logout HTTP/1.1"
            | "POST /api/identity/add-code HTTP/1.1"
            | "POST /api/network/mode HTTP/1.1"
            | "POST /api/settings/get HTTP/1.1"
            | "POST /api/settings/save HTTP/1.1"
            | "POST /api/invite/create HTTP/1.1"
            | "POST /api/chat/create HTTP/1.1"
            | "POST /api/chat/join HTTP/1.1"
            | "POST /api/chat/reconnect HTTP/1.1"
            | "POST /api/chat/status HTTP/1.1"
            | "POST /api/chat/confirm HTTP/1.1"
            | "POST /api/chat/request-history-restore HTTP/1.1"
            | "POST /api/chat/resolve-history-restore HTTP/1.1"
            | "POST /api/chat/link-identity HTTP/1.1"
            | "POST /api/chat/cancel HTTP/1.1"
            | "POST /api/chat/send HTTP/1.1"
            | "POST /api/chat/messages HTTP/1.1"
            | "POST /api/history/list HTTP/1.1"
            | "POST /api/history/messages HTTP/1.1"
            | "POST /api/history/delete-messages HTTP/1.1"
            | "POST /api/history/delete-range HTTP/1.1"
            | "POST /api/history/delete-conversation HTTP/1.1"
            | "POST /api/history/export-backup HTTP/1.1"
            | "POST /api/history/export-backup-bundle HTTP/1.1"
            | "POST /api/history/import-backup HTTP/1.1"
            | "POST /api/history/reprotect-backup HTTP/1.1"
            | "POST /api/history/verify-backup HTTP/1.1"
            | "POST /api/contacts/export-backup HTTP/1.1"
            | "POST /api/contacts/import-backup HTTP/1.1"
    ) {
        return reject(&mut stream, "404 Not Found");
    }
    if origin != Some(format!("http://{expected_host}").as_str())
        || content_type != Some("text/plain;charset=UTF-8")
    {
        return reject(&mut stream, "403 Forbidden");
    }
    let body_len = match length.and_then(|value| value.parse::<usize>().ok()) {
        Some(value) if value <= MAX_BODY => value,
        _ => return reject(&mut stream, "400 Bad Request"),
    };
    let first = first.to_owned();
    let auth = authorization.map(str::to_owned);
    let mut body_buffer = Zeroizing::new([0; 8192]);
    while request.len() < header_end + body_len {
        let n = stream.read(body_buffer.as_mut())?;
        if n == 0 {
            return reject(&mut stream, "400 Bad Request");
        }
        request.extend_from_slice(&body_buffer[..n]);
    }
    if request.len() != header_end + body_len {
        return reject(&mut stream, "400 Bad Request");
    }
    let body = match std::str::from_utf8(&request[header_end..]) {
        Ok(value) => value,
        Err(_) => return reject(&mut stream, "400 Bad Request"),
    };
    let mut state = state
        .lock()
        .map_err(|_| io::Error::other("state unavailable"))?;
    if first == "POST /api/connect HTTP/1.1" {
        if state.code.is_empty()
            || state.issued.elapsed() >= CODE_LIFETIME
            || state.attempts >= MAX_ATTEMPTS
        {
            return reject(&mut stream, "403 Forbidden");
        }
        if !equal_token(body, &state.code) {
            state.attempts += 1;
            return reject(&mut stream, "403 Forbidden");
        }
        let token = random_token()?;
        state.code.clear();
        state.sessions.push(token.clone());
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            token.as_bytes(),
        );
    }
    let token = auth
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    let Some(index) = state
        .sessions
        .iter()
        .position(|item| equal_token(item, token))
    else {
        return reject(&mut stream, "401 Unauthorized");
    };
    if first == "POST /api/disconnect HTTP/1.1" {
        state.sessions.remove(index);
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    if first == "POST /api/network/mode HTTP/1.1" {
        if !body.is_empty() {
            return reject(&mut stream, "400 Bad Request");
        }
        return respond_settings(&mut stream, &state);
    }
    if first == "POST /api/settings/get HTTP/1.1" {
        if !body.is_empty() {
            return reject(&mut stream, "400 Bad Request");
        }
        return respond_settings(&mut stream, &state);
    }
    if first == "POST /api/settings/save HTTP/1.1" {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(mode) = value.get("mode").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let tor_socks = match mode {
            "general" => None,
            "tor" => {
                let Some(address) = value.get("socks").and_then(serde_json::Value::as_str) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                match parse_loopback_socks(address) {
                    Ok(address) => Some(address),
                    Err(_) => return reject(&mut stream, "400 Bad Request"),
                }
            }
            _ => return reject(&mut stream, "400 Bad Request"),
        };
        let Some(notifications) = value
            .get("notifications")
            .and_then(serde_json::Value::as_bool)
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        if tor_socks != state.tor_socks && any_chat_active(&state) {
            return reject(&mut stream, "409 Conflict");
        }
        let settings = AppSettings {
            tor_socks,
            notifications,
        };
        if save_settings(&settings).is_err() {
            return reject(&mut stream, "500 Internal Server Error");
        }
        state
            .notifications_enabled
            .store(notifications, Ordering::SeqCst);
        state.settings = settings;
        return respond_settings(&mut stream, &state);
    }
    if first == "POST /api/identity/add-code HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        if !body.is_empty() {
            return reject(&mut stream, "400 Bad Request");
        }
        let code = identity.create_access_code()?;
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            code.as_bytes(),
        );
    }
    if first == "POST /api/identity/replace HTTP/1.1" {
        if state.identity.is_none() {
            return reject(&mut stream, "401 Unauthorized");
        }
        if !body.is_empty() || any_chat_active(&state) {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(current) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let (replacement, code) = Identity::create()?;
        if current.copy_local_data_to(&replacement).is_err() {
            return reject(&mut stream, "500 Internal Server Error");
        }
        // Keep the old session active if the one-time code cannot be delivered.
        respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            code.as_bytes(),
        )?;
        state.identity = Some(Arc::new(replacement));
        return Ok(());
    }
    if first == "POST /api/invite/create HTTP/1.1" {
        if state.tor_socks != state.settings.tor_socks {
            return reject(&mut stream, "409 Conflict");
        }
        if state.identity.is_none() {
            return reject(&mut stream, "401 Unauthorized");
        }
        let invite = InviteCode::generate()?;
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            invite.code().as_bytes(),
        );
    }
    if matches!(
        first.as_str(),
        "POST /api/chat/create HTTP/1.1"
            | "POST /api/chat/join HTTP/1.1"
            | "POST /api/chat/reconnect HTTP/1.1"
    ) {
        if state.tor_socks != state.settings.tor_socks {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let (code, expected_peer, reconnect_role) = if first == "POST /api/chat/reconnect HTTP/1.1"
        {
            let Ok(peer) = history::decode_peer_id(body) else {
                return reject(&mut stream, "400 Bad Request");
            };
            if peer == identity.public_key() || peer_chat_active(&state, body) {
                return reject(&mut stream, "409 Conflict");
            }
            let directory = history::data_directory()?
                .join(identity.public_id())
                .join("verified-contacts");
            let contact = match contacts::load(&directory, &identity, peer) {
                Ok(contact) => contact,
                Err(_) => return reject(&mut stream, "404 Not Found"),
            };
            let invite = InviteCode::from_reconnect_secret(contact.rendezvous_secret);
            let role = if identity.public_key() < peer {
                RoleForChat::Create
            } else {
                RoleForChat::Join
            };
            (
                Zeroizing::new(invite.code().to_owned()),
                Some(peer),
                Some(role),
            )
        } else {
            if InviteCode::parse(body).is_none() {
                return reject(&mut stream, "400 Bad Request");
            }
            (Zeroizing::new(body.to_owned()), None, None)
        };
        let operation_id = random_token()?;
        let (sender, receiver) = mpsc::channel();
        let operation = Arc::new(ChatOperation {
            snapshot: Mutex::new(ChatSnapshot {
                phase: "connecting",
                fingerprint: None,
                peer_id: expected_peer.as_ref().map(|peer| encode_hex(peer)),
                error: None,
                storage_error: None,
                messages: Vec::new(),
                relay_ack: None,
                pending_sends: 0,
                identity_transition: None,
                history_restore_in_progress: false,
                history_restore_offer: Vec::new(),
                history_restore_offer_count: 0,
                history_restore_legacy_count: 0,
                history_restore_received: 0,
                history_restore_total: 0,
                history_restore_status: None,
                message_epoch: 0,
            }),
            sender,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let cancelled = Arc::clone(&operation.cancelled);
        let tor_socks = state.tor_socks;
        let notifications_enabled = Arc::clone(&state.notifications_enabled);
        let last_notification = Arc::clone(&state.last_notification);
        let role = reconnect_role.unwrap_or(if first == "POST /api/chat/create HTTP/1.1" {
            RoleForChat::Create
        } else {
            RoleForChat::Join
        });
        state
            .chats
            .insert(operation_id.clone(), Arc::clone(&operation));
        drop(state);
        spawn_chat_worker(
            operation,
            receiver,
            role,
            code,
            expected_peer,
            identity,
            cancelled,
            tor_socks,
            notifications_enabled,
            last_notification,
        );
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            operation_id.as_bytes(),
        );
    }
    if first == "POST /api/chat/status HTTP/1.1" {
        let Some(operation) = state.chats.get(body) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        let payload = serde_json::json!({
            "phase": snapshot.phase,
            "fingerprint": snapshot.fingerprint,
            "peerId": snapshot.peer_id,
            "error": snapshot.error,
            "storageError": snapshot.storage_error,
            "relayAck": snapshot.relay_ack,
            "pendingSends": snapshot.pending_sends,
            "identityTransition": snapshot.identity_transition,
            "historyRestoreInProgress": snapshot.history_restore_in_progress,
            "historyRestoreStatus": snapshot.history_restore_status,
            "historyRestoreLegacyCount": snapshot.history_restore_legacy_count,
            "historyRestoreOfferCount": snapshot.history_restore_offer_count,
            "historyRestoreReceived": snapshot.history_restore_received,
            "historyRestoreTotal": snapshot.history_restore_total,
            "historyRestoreOffer": snapshot.history_restore_offer.iter().map(|entry| serde_json::json!({
                "time": entry.unix_time,
                "sender": entry.sender,
                "text": entry.text,
                "signed": entry.signed
            })).collect::<Vec<_>>(),
            "messageEpoch": snapshot.message_epoch,
            "messageCount": snapshot.messages.len()
        })
        .to_string();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            payload.as_bytes(),
        );
    }
    if first == "POST /api/chat/confirm HTTP/1.1" {
        let Some(operation) = state.chats.get(body) else {
            return reject(&mut stream, "404 Not Found");
        };
        if operation.sender.send(ChatCommand::Confirm).is_err() {
            return reject(&mut stream, "409 Conflict");
        }
        return respond(
            &mut stream,
            "202 Accepted",
            "text/plain; charset=utf-8",
            b"ok",
        );
    }
    if first == "POST /api/chat/request-history-restore HTTP/1.1" {
        let Some(operation) = state.chats.get(body) else {
            return reject(&mut stream, "404 Not Found");
        };
        if !operation.snapshot.lock().is_ok_and(|snapshot| {
            snapshot.phase == "connected"
                && !snapshot.history_restore_in_progress
                && snapshot.history_restore_offer.is_empty()
        }) {
            return reject(&mut stream, "409 Conflict");
        }
        let (sender, receiver) = mpsc::channel();
        if operation
            .sender
            .send(ChatCommand::RequestHistoryRestore(sender))
            .is_err()
        {
            return reject(&mut stream, "409 Conflict");
        }
        return match receiver.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(())) => respond(
                &mut stream,
                "202 Accepted",
                "text/plain; charset=utf-8",
                b"ok",
            ),
            Ok(Err(error)) => respond(
                &mut stream,
                "409 Conflict",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            ),
            Err(_) => reject(&mut stream, "409 Conflict"),
        };
    }
    if first == "POST /api/chat/resolve-history-restore HTTP/1.1" {
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(operation_id) = payload
            .get("operationId")
            .and_then(serde_json::Value::as_str)
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(accept) = payload.get("accept").and_then(serde_json::Value::as_bool) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(operation) = state.chats.get(operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        if !operation.snapshot.lock().is_ok_and(|snapshot| {
            snapshot.phase == "connected"
                && if accept {
                    !snapshot.history_restore_offer.is_empty()
                        && !snapshot.history_restore_in_progress
                } else {
                    !snapshot.history_restore_offer.is_empty()
                        || snapshot.history_restore_in_progress
                }
        }) {
            return reject(&mut stream, "409 Conflict");
        }
        let (sender, receiver) = mpsc::channel();
        if operation
            .sender
            .send(ChatCommand::ResolveHistoryRestore(accept, sender))
            .is_err()
        {
            return reject(&mut stream, "409 Conflict");
        }
        return match receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok"),
            Ok(Err(error)) => respond(
                &mut stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            ),
            Err(_) => reject(&mut stream, "409 Conflict"),
        };
    }
    if first == "POST /api/chat/link-identity HTTP/1.1" {
        let Some((operation_id, previous_peer_id)) = body.split_once('\n') else {
            return reject(&mut stream, "400 Bad Request");
        };
        if history::decode_peer_id(previous_peer_id).is_err() {
            return reject(&mut stream, "400 Bad Request");
        }
        let previous_peer_id = previous_peer_id.to_ascii_lowercase();
        if peer_chat_active(&state, &previous_peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(operation) = state.chats.get(operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        if snapshot.phase != "connected"
            || !snapshot
                .identity_transition
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| id == &previous_peer_id))
        {
            return reject(&mut stream, "409 Conflict");
        }
        drop(snapshot);
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let contact_directory = history::data_directory()?
            .join(identity.public_id())
            .join("verified-contacts");
        let Ok(previous_peer_key) = history::decode_peer_id(&previous_peer_id) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if contacts::load(&contact_directory, identity, previous_peer_key).is_err() {
            return reject(&mut stream, "409 Conflict");
        }
        let (result_sender, result_receiver) = mpsc::channel();
        if operation
            .sender
            .send(ChatCommand::AcceptIdentityTransition(
                previous_peer_id,
                result_sender,
            ))
            .is_err()
        {
            return reject(&mut stream, "409 Conflict");
        }
        return match result_receiver.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok"),
            Ok(Err(error)) => respond(
                &mut stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            ),
            Err(_) => reject(&mut stream, "409 Conflict"),
        };
    }
    if first == "POST /api/chat/cancel HTTP/1.1" {
        let Some(operation) = state.chats.get(body) else {
            return reject(&mut stream, "404 Not Found");
        };
        operation.cancelled.store(true, Ordering::SeqCst);
        let _ = operation.sender.send(ChatCommand::Cancel);
        return respond(
            &mut stream,
            "202 Accepted",
            "text/plain; charset=utf-8",
            b"ok",
        );
    }
    if first == "POST /api/chat/send HTTP/1.1" {
        let Some((operation_id, text)) = body.split_once('\n') else {
            return reject(&mut stream, "400 Bad Request");
        };
        if text.trim().is_empty()
            || text.len() > 4078
            || text.as_bytes().starts_with(CHAT_CONTROL_PREFIX)
            || text
                .as_bytes()
                .starts_with(history::IDENTITY_EVENT_PREFIX.as_bytes())
            || text.contains('\0')
        {
            return reject(&mut stream, "400 Bad Request");
        }
        let Some(operation) = state.chats.get(operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        if snapshot.phase != "connected" {
            return reject(&mut stream, "409 Conflict");
        }
        drop(snapshot);
        if !submit_chat_message(&operation.sender, text.to_owned(), Duration::from_secs(10)) {
            return reject(&mut stream, "503 Service Unavailable");
        }
        return respond(
            &mut stream,
            "202 Accepted",
            "text/plain; charset=utf-8",
            b"ok",
        );
    }
    if first == "POST /api/chat/messages HTTP/1.1" {
        let Some((operation_id, cursor)) = body.split_once('\n') else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Ok(cursor) = cursor.parse::<usize>() else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(operation) = state.chats.get(operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        let messages: Vec<_> = snapshot
            .messages
            .iter()
            .skip(cursor)
            .map(|message| {
                serde_json::json!({
                    "time": message.unix_time,
                    "sender": message.sender,
                    "text": message.text
                })
            })
            .collect();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            serde_json::to_string(&messages)?.as_bytes(),
        );
    }
    if first == "POST /api/contacts/export-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(peer) = history::decode_peer_id(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let directory = history::data_directory()?
            .join(identity.public_id())
            .join("verified-contacts");
        let contact = match contacts::load(&directory, identity, peer) {
            Ok(contact) => contact,
            Err(_) => return reject(&mut stream, "404 Not Found"),
        };
        let backup = contacts::export_backup(identity, &contact)?;
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            BASE64.encode(backup).as_bytes(),
        );
    }
    if first == "POST /api/contacts/import-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        if any_chat_active(&state) {
            return reject(&mut stream, "409 Conflict");
        }
        if body.len() > 256 {
            return reject(&mut stream, "400 Bad Request");
        }
        let Ok(backup) = BASE64.decode(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let directory = history::data_directory()?
            .join(identity.public_id())
            .join("verified-contacts");
        let peer = match contacts::import_backup(&directory, identity, &backup) {
            Ok(peer) => peer,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return reject(&mut stream, "409 Conflict")
            }
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        let peer_id = encode_hex(&peer);
        if history::History::open(identity, &peer_id).is_err() {
            return reject(&mut stream, "500 Internal Server Error");
        }
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            peer_id.as_bytes(),
        );
    }
    if first == "POST /api/history/list HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let summaries = match history::History::list(identity) {
            Ok(summaries) => summaries,
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let directory = history::data_directory()?
            .join(identity.public_id())
            .join("verified-contacts");
        let verified: HashSet<_> = match contacts::list_known(&directory, identity) {
            Ok(contacts) => contacts
                .into_iter()
                .map(|contact| encode_hex(&contact.peer_key))
                .collect(),
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let payload: Vec<_> = summaries
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "peerId": item.peer_id,
                    "verified": verified.contains(&item.peer_id),
                    "messageCount": item.message_count,
                    "lastMessage": item.last_message
                })
            })
            .collect();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            serde_json::to_string(&payload)?.as_bytes(),
        );
    }
    if first == "POST /api/history/messages HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let (_, messages, _) = match history::History::open(identity, body) {
            Ok(history) => history,
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        let payload: Vec<_> = messages
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                serde_json::json!({
                    "index": index,
                    "time": item.unix_time,
                    "sender": chat_entry(item.clone()).sender,
                    "text": chat_entry(item).text
                })
            })
            .collect();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            serde_json::to_string(&payload)?.as_bytes(),
        );
    }
    if first == "POST /api/history/delete-messages HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peer_id) = payload.get("peerId").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if peer_chat_active(&state, peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(indices) = payload.get("indices").and_then(serde_json::Value::as_array) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if indices.is_empty() || indices.len() > 100_000 {
            return reject(&mut stream, "400 Bad Request");
        }
        let mut selected = HashSet::with_capacity(indices.len());
        for index in indices {
            let Some(index) = index.as_u64().and_then(|value| usize::try_from(value).ok()) else {
                return reject(&mut stream, "400 Bad Request");
            };
            selected.insert(index);
        }
        let (mut history, messages, _) = match history::History::open(identity, peer_id) {
            Ok(history) => history,
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        let kept: Vec<_> = messages
            .into_iter()
            .enumerate()
            .filter_map(|(index, item)| (!selected.contains(&index)).then_some(item))
            .collect();
        if let Err(_) = history.replace(&kept) {
            return reject(&mut stream, "500 Internal Server Error");
        }
        update_closed_chat_history(&state, peer_id, Some(&kept));
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    if first == "POST /api/history/delete-range HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let mut parts = body.split('\n');
        let peer_id = parts.next().unwrap_or("");
        let (Some(start), Some(end)) = (parts.next(), parts.next()) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if parts.next().is_some() || peer_chat_active(&state, peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
        let (Ok(start), Ok(end)) = (start.parse::<u64>(), end.parse::<u64>()) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if start > end {
            return reject(&mut stream, "400 Bad Request");
        }
        let (mut history, messages, _) = match history::History::open(identity, peer_id) {
            Ok(history) => history,
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        let kept = history::outside_time_range(&messages, start, end);
        if let Err(_) = history.replace(&kept) {
            return reject(&mut stream, "500 Internal Server Error");
        }
        update_closed_chat_history(&state, peer_id, Some(&kept));
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    if first == "POST /api/history/delete-conversation HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        if peer_chat_active(&state, body) {
            return reject(&mut stream, "409 Conflict");
        }
        if let Err(error) = history::History::delete_conversation(identity, body) {
            return respond(
                &mut stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                error.to_string().as_bytes(),
            );
        }
        update_closed_chat_history(&state, body, None);
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    if first == "POST /api/history/export-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peer_id) = payload.get("peerId").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let password = payload
            .get("password")
            .and_then(serde_json::Value::as_str)
            .filter(|password| !password.is_empty());
        if peer_chat_active(&state, peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
        let backup = match history::History::export_backup(identity, peer_id, password) {
            Ok(backup) => backup,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                return reject(&mut stream, "400 Bad Request");
            }
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            BASE64.encode(backup).as_bytes(),
        );
    }
    if first == "POST /api/history/export-backup-bundle HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peers) = payload.get("peerIds").and_then(serde_json::Value::as_array) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peer_ids) = peers
            .iter()
            .map(serde_json::Value::as_str)
            .collect::<Option<Vec<_>>>()
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        if peer_ids.iter().any(|peer| peer_chat_active(&state, peer)) {
            return reject(&mut stream, "409 Conflict");
        }
        let peer_ids: Vec<String> = peer_ids.into_iter().map(str::to_owned).collect();
        let backup = match history::History::export_backup_bundle(identity, &peer_ids) {
            Ok(backup) => backup,
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {
                return reject(&mut stream, "400 Bad Request")
            }
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            BASE64.encode(backup).as_bytes(),
        );
    }
    if first == "POST /api/history/import-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        if any_chat_active(&state) {
            return reject(&mut stream, "409 Conflict");
        }
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(encoded) = payload.get("backup").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let password = payload
            .get("password")
            .and_then(serde_json::Value::as_str)
            .filter(|password| !password.is_empty());
        let backup = match BASE64.decode(encoded) {
            Ok(backup) if backup.len() <= 16 * 1024 * 1024 => backup,
            _ => return reject(&mut stream, "400 Bad Request"),
        };
        if backup.starts_with(b"ADPACK1\0") {
            let restored = match history::History::import_backup_bundle(identity, &backup) {
                Ok(result) => result,
                Err(_) => return reject(&mut stream, "400 Bad Request"),
            };
            for (peer_id, _) in &restored {
                if let Ok((_, messages, _)) = history::History::open(identity, peer_id) {
                    update_closed_chat_history(&state, peer_id, Some(&messages));
                }
            }
            let payload = serde_json::json!({ "conversations": restored.iter().map(|(peer_id, count)| serde_json::json!({ "peerId": peer_id, "messageCount": count })).collect::<Vec<_>>() }).to_string();
            return respond(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                payload.as_bytes(),
            );
        }
        let (peer_id, count) = match history::History::import_backup(identity, &backup, password) {
            Ok(result) => result,
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        if let Ok((_, messages, _)) = history::History::open(identity, &peer_id) {
            update_closed_chat_history(&state, &peer_id, Some(&messages));
        }
        let payload = serde_json::json!({ "peerId": peer_id, "messageCount": count }).to_string();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            payload.as_bytes(),
        );
    }
    if first == "POST /api/history/reprotect-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(mut request) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(fields) = request.as_object_mut() else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(backup_text) = fields
            .remove("backup")
            .and_then(|value| value.as_str().map(str::to_owned))
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(previous_code) = fields
            .remove("previousCode")
            .and_then(|value| value.as_str().map(|value| Zeroizing::new(value.to_owned())))
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        let previous_password = fields
            .remove("previousPassword")
            .and_then(|value| value.as_str().map(|value| Zeroizing::new(value.to_owned())))
            .filter(|password| !password.is_empty());
        let replacement_password = fields
            .remove("replacementPassword")
            .and_then(|value| value.as_str().map(|value| Zeroizing::new(value.to_owned())))
            .filter(|password| !password.is_empty());
        if !fields.is_empty() {
            return reject(&mut stream, "400 Bad Request");
        }
        let Some(previous_identity) = Identity::from_code(&previous_code) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Ok(backup) = BASE64.decode(backup_text) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Ok(reprotected) = history::History::reprotect_backup(
            &previous_identity,
            identity,
            &backup,
            previous_password.as_deref().map(String::as_str),
            replacement_password.as_deref().map(String::as_str),
        ) else {
            return reject(&mut stream, "400 Bad Request");
        };
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            BASE64.encode(reprotected).as_bytes(),
        );
    }
    if first == "POST /api/history/verify-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let Ok(mut request) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(fields) = request.as_object_mut() else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(backup_text) = fields
            .remove("backup")
            .and_then(|value| value.as_str().map(str::to_owned))
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        let password = fields
            .remove("password")
            .and_then(|value| value.as_str().map(|value| Zeroizing::new(value.to_owned())))
            .filter(|password| !password.is_empty());
        if !fields.is_empty() {
            return reject(&mut stream, "400 Bad Request");
        }
        let Ok(backup) = BASE64.decode(backup_text) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Ok((peer_id, message_count)) = history::History::verify_backup(
            identity,
            &backup,
            password.as_deref().map(String::as_str),
        ) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let response =
            serde_json::json!({ "peerId": peer_id, "messageCount": message_count }).to_string();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            response.as_bytes(),
        );
    }
    match first.as_str() {
        "POST /api/identity/create HTTP/1.1" => {
            if state.identity.is_some() {
                return reject(&mut stream, "409 Conflict");
            }
            let (identity, code) = Identity::create()?;
            // Do not activate a new identity unless the response was written successfully.
            respond(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                code.as_bytes(),
            )?;
            state.identity = Some(Arc::new(identity));
            return Ok(());
        }
        "POST /api/identity/login HTTP/1.1" => {
            if state.identity.is_some() {
                return reject(&mut stream, "409 Conflict");
            }
            let Some(identity) = Identity::from_code(body) else {
                return reject(&mut stream, "400 Bad Request");
            };
            state.identity = Some(Arc::new(identity));
        }
        "POST /api/identity/status HTTP/1.1" => {
            let Some(identity) = state.identity.as_ref() else {
                return reject(&mut stream, "401 Unauthorized");
            };
            return respond(
                &mut stream,
                "200 OK",
                "text/plain; charset=utf-8",
                identity.public_id().as_bytes(),
            );
        }
        "POST /api/identity/logout HTTP/1.1" => {
            for operation in state.chats.values() {
                operation.cancelled.store(true, Ordering::SeqCst);
                let _ = operation.sender.send(ChatCommand::Cancel);
            }
            state.identity = None;
        }
        _ => {}
    }
    respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}

fn main() -> io::Result<()> {
    if std::env::args().nth(1).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "실행 옵션은 지원하지 않습니다. 연결 모드는 앱 설정에서 선택하세요.",
        ));
    }
    let settings = load_settings()?;
    let tor_socks = settings.tor_socks;
    let notifications_enabled = Arc::new(AtomicBool::new(settings.notifications));
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let state = Arc::new(Mutex::new(State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: Vec::new(),
        identity: None,
        chats: HashMap::new(),
        tor_socks,
        settings,
        notifications_enabled,
        last_notification: Arc::new(Mutex::new(None)),
    }));
    println!("http://{address}/");
    if let Some(proxy) = tor_socks {
        println!("Tor/SOCKS 전용 모드: {proxy}; 프록시 실패 시 직접 연결하지 않습니다.");
    } else {
        println!("일반 연결 모드");
    }
    {
        let mut state = state
            .lock()
            .map_err(|_| io::Error::other("state unavailable"))?;
        issue_code(&mut state)?;
    }
    let input_state = Arc::clone(&state);
    std::thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if line.is_err() {
                break;
            }
            if let Ok(mut state) = input_state.lock() {
                if let Err(error) = issue_code(&mut state) {
                    eprintln!("연결 코드 발급 오류: {error}");
                }
            }
        }
    });
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let _ = handle(stream, &address.to_string(), &state);
            }
            Err(error) => eprintln!("로컬 연결 오류: {error}"),
        }
    }
    Ok(())
}
