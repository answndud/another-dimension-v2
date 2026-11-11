pub mod channel;
pub mod history;
mod identity;
pub mod relay;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use identity::Identity;
use relay::{InviteCode, RelayRendezvous, RelaySession, RelayUpdate, DEFAULT_RELAY};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
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
const CODE_LIFETIME: Duration = Duration::from_secs(300);
const MAX_ATTEMPTS: u8 = 5;

struct State {
    code: String,
    issued: Instant,
    attempts: u8,
    sessions: Vec<String>,
    identity: Option<Arc<Identity>>,
    chats: HashMap<String, Arc<ChatOperation>>,
}

enum ChatCommand {
    Confirm,
    Send(String),
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

fn spawn_chat_worker(
    operation: Arc<ChatOperation>,
    commands: Receiver<ChatCommand>,
    role: RoleForChat,
    code: Zeroizing<String>,
    identity: Arc<Identity>,
    cancelled: Arc<AtomicBool>,
) {
    thread::spawn(move || {
        let result = (|| -> Result<(RelaySession, Option<history::History>, Vec<ChatEntry>, Option<String>), String> {
            let invite = InviteCode::parse(&code).ok_or("초대 코드를 확인하세요.")?;
            let mut rendezvous = match role {
                RoleForChat::Create => RelayRendezvous::create(DEFAULT_RELAY, &invite),
                RoleForChat::Join => RelayRendezvous::join(DEFAULT_RELAY, &invite),
            }
            .map_err(|_| "relay에 연결하지 못했습니다.")?;
            rendezvous.set_cancellation_token(Arc::clone(&cancelled));
            let channel = rendezvous
                .complete_handshake()
                .map_err(|_| "상대와 handshake를 완료하지 못했습니다.")?;
            if operation.cancelled.load(Ordering::SeqCst) {
                return Err("취소되었습니다.".to_owned());
            }
            let verification = rendezvous
                .authenticate(channel, &identity, None)
                .map_err(|_| "상대 신원을 확인할 수 없습니다. 새 초대 코드로 다시 시도하세요.")?;
            let fingerprint = encode_hex(verification.fingerprint());
            let peer_id = encode_hex(verification.peer_public_key());
            chat_update(&operation, |snapshot| {
                snapshot.phase = "verification";
                snapshot.fingerprint = Some(fingerprint);
                snapshot.peer_id = Some(peer_id.clone());
            });
            let verification = loop {
                if operation.cancelled.load(Ordering::SeqCst) {
                    return Err("취소되었습니다.".to_owned());
                }
                match commands.recv_timeout(Duration::from_millis(250)) {
                    Ok(ChatCommand::Confirm) => break verification,
                    Ok(ChatCommand::Cancel) => return Err("취소되었습니다.".to_owned()),
                    Ok(ChatCommand::Send(_)) => {}
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return Err("취소되었습니다.".to_owned()),
                }
            };
            chat_update(&operation, |snapshot| snapshot.phase = "confirming");
            let session = rendezvous
                .confirm(verification)
                .map_err(|_| "상대 확인을 마치지 못했습니다. 다시 연결하세요.".to_owned())?;
            let (history, entries, storage_error) = match history::History::open(&identity, &peer_id) {
                Ok((history, stored, recovered_partial)) => {
                    let entries = stored
                        .into_iter()
                        .map(|item| ChatEntry {
                            unix_time: item.unix_time,
                            sender: match item.sender {
                                history::MessageSender::Me => "나",
                                history::MessageSender::Other => "상대방",
                            },
                            text: item.text,
                        })
                        .collect();
                    let warning = recovered_partial
                        .then(|| "대화 기록의 마지막 불완전 항목을 제거했습니다.".to_owned());
                    (Some(history), entries, warning)
                }
                Err(_) => (None, Vec::new(), Some("대화 기록을 열지 못했습니다. 이번 대화는 프로그램을 종료하면 사라질 수 있습니다.".to_owned())),
            };
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

        while !operation.cancelled.load(Ordering::SeqCst) {
            loop {
                match commands.try_recv() {
                    Ok(ChatCommand::Send(text)) => match session.send(text.as_bytes()) {
                        Ok(event_id) => {
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
                                snapshot.relay_ack = Some(format!("pending:{event_id}"));
                                if save_error.is_some() {
                                    snapshot.storage_error = Some("대화 기록을 저장하지 못했습니다. 프로그램을 종료하면 이 메시지를 잃을 수 있습니다.".to_owned());
                                }
                            });
                        }
                        Err(_) => {
                            drop(history.take());
                            chat_update(&operation, |snapshot| {
                                snapshot.phase = "disconnected";
                                snapshot.error = Some("메시지를 보낼 수 없습니다.".to_owned());
                            });
                            return;
                        }
                    },
                    Ok(ChatCommand::Cancel) => {
                        operation.cancelled.store(true, Ordering::SeqCst);
                        break;
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
                    chat_update(&operation, |snapshot| {
                        snapshot.relay_ack = Some(event_id);
                    });
                }
                Ok(Some(RelayUpdate::Ready)) | Ok(None) => {}
                Err(_) => {
                    drop(history.take());
                    chat_update(&operation, |snapshot| {
                        snapshot.phase = "disconnected";
                        snapshot.error = Some("relay 연결이 끊겼습니다.".to_owned());
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
                    .map(|item| ChatEntry {
                        unix_time: item.unix_time,
                        sender: match item.sender {
                            history::MessageSender::Me => "나",
                            history::MessageSender::Other => "상대방",
                        },
                        text: item.text.clone(),
                    })
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
            | "POST /api/identity/status HTTP/1.1"
            | "POST /api/identity/logout HTTP/1.1"
            | "POST /api/invite/create HTTP/1.1"
            | "POST /api/chat/create HTTP/1.1"
            | "POST /api/chat/join HTTP/1.1"
            | "POST /api/chat/status HTTP/1.1"
            | "POST /api/chat/confirm HTTP/1.1"
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
    if first == "POST /api/invite/create HTTP/1.1" {
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
        "POST /api/chat/create HTTP/1.1" | "POST /api/chat/join HTTP/1.1"
    ) {
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        if InviteCode::parse(body).is_none() {
            return reject(&mut stream, "400 Bad Request");
        }
        let operation_id = random_token()?;
        let (sender, receiver) = mpsc::channel();
        let operation = Arc::new(ChatOperation {
            snapshot: Mutex::new(ChatSnapshot {
                phase: "connecting",
                fingerprint: None,
                peer_id: None,
                error: None,
                storage_error: None,
                messages: Vec::new(),
                relay_ack: None,
            }),
            sender,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let cancelled = Arc::clone(&operation.cancelled);
        let role = if first == "POST /api/chat/create HTTP/1.1" {
            RoleForChat::Create
        } else {
            RoleForChat::Join
        };
        let code = Zeroizing::new(body.to_owned());
        state
            .chats
            .insert(operation_id.clone(), Arc::clone(&operation));
        drop(state);
        spawn_chat_worker(operation, receiver, role, code, identity, cancelled);
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
        if text.trim().is_empty() || text.len() > 4078 {
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
        if operation
            .sender
            .send(ChatCommand::Send(text.to_owned()))
            .is_err()
        {
            return reject(&mut stream, "409 Conflict");
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
    if first == "POST /api/history/list HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, "401 Unauthorized");
        };
        let summaries = match history::History::list(identity) {
            Ok(summaries) => summaries,
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let payload: Vec<_> = summaries
            .into_iter()
            .map(|item| {
                serde_json::json!({
                    "peerId": item.peer_id,
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
                    "sender": match item.sender {
                        history::MessageSender::Me => "나",
                        history::MessageSender::Other => "상대방",
                    },
                    "text": item.text
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
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let state = Arc::new(Mutex::new(State {
        code: String::new(),
        issued: Instant::now(),
        attempts: 0,
        sessions: Vec::new(),
        identity: None,
        chats: HashMap::new(),
    }));
    println!("http://{address}/");
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
