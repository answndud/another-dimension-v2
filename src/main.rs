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
const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 24 * 1024 * 1024;
const CHAT_CONTROL_PREFIX: &[u8] = b"[AD2-CONTROL/1] ";
const CODE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS: u8 = 5;
const PEER_HEARTBEAT_FRAME: &[u8] = &[0xff, b'A', b'D', b'2', b'-', b'H', b'B', b'2'];
const PEER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PEER_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

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
    AcceptIdentityTransition(String, Sender<bool>),
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
    message_epoch: u64,
}

#[derive(Clone)]
struct ChatEntry {
    unix_time: u64,
    sender: &'static str,
    text: String,
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
    }
}

fn identity_event_exists_for_previous(
    messages: &[history::StoredMessage],
    kind: &str,
    previous_id: &str,
) -> bool {
    messages.iter().any(|message| {
        let Some(marker) = message.text.strip_prefix(history::IDENTITY_EVENT_PREFIX) else {
            return false;
        };
        let mut fields = marker.split(':');
        fields.next() == Some(kind) && fields.next() == Some(previous_id)
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
            &"ab".repeat(32)
        ));
        let displayed = chat_entry(event);
        assert_eq!(displayed.sender, "신원 변경");
        assert!(displayed.text.contains("cdcdcdcdcdcd"));
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
        let result = (|| -> Result<(RelaySession, Option<history::History>, Vec<ChatEntry>, Option<String>), String> {
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
                        let _ = result.send(false);
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
                            !identity_event_exists_for_previous(&stored, "self", old_id)
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
            Ok((session, history, entries, storage_error))
        })();

        let (mut session, mut history) = match result {
            Ok((session, history, messages, storage_error)) => {
                chat_update(&operation, |snapshot| {
                    snapshot.messages = messages;
                    snapshot.storage_error = storage_error;
                    snapshot.phase = "connected";
                });
                (session, history)
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
        let mut last_peer_activity = Instant::now();
        let mut last_heartbeat = Instant::now();

        while !operation.cancelled.load(Ordering::SeqCst) {
            let now = Instant::now();
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
                    Ok(ChatCommand::Send(text, processed)) => match session.send(text.as_bytes()) {
                        Ok(event_id) => {
                            pending_events.insert(event_id);
                            let entry = history::StoredMessage {
                                unix_time: now_seconds(),
                                sender: history::MessageSender::Me,
                                text: text.clone(),
                            };
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
                            let entry = history::StoredMessage {
                                unix_time: now_seconds(),
                                sender: history::MessageSender::Me,
                                text: text.clone(),
                            };
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
                    },
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
                                    .is_ok(),
                                None => false,
                            }
                        } else {
                            false
                        };
                        if linked {
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
                        let _ = result.send(linked);
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
                                    let current_messages =
                                        history::History::open(&identity, &current_peer_id)
                                            .map(|(_, messages, _)| messages)
                                            .unwrap_or_default();
                                    let mut pending = Vec::new();
                                    for old_id in parsed {
                                        if identity_event_exists_for_previous(
                                            &current_messages,
                                            "peer",
                                            &old_id,
                                        ) {
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
                                            Ok(true) => chat_update(&operation, |snapshot| {
                                                snapshot.messages.push(chat_entry(entry))
                                            }),
                                            Ok(false) => {}
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
            Ok(true) => respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok"),
            _ => reject(&mut stream, "409 Conflict"),
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
        let kept: Vec<_> = messages
            .into_iter()
            .filter(|item| item.unix_time < start || item.unix_time > end)
            .collect();
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
        if history::History::delete_conversation(identity, body).is_err() {
            return reject(&mut stream, "500 Internal Server Error");
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
