//! The chat worker thread and the operation state it shares with the API.

use super::*;

pub(crate) const CHAT_CONTROL_PREFIX: &[u8] = b"[AD2-CONTROL/1] ";

pub(crate) const PEER_HEARTBEAT_FRAME: &[u8] = &[0xff, b'A', b'D', b'2', b'-', b'H', b'B', b'2'];

pub(crate) const PEER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

pub(crate) const PEER_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

pub(crate) enum ChatCommand {
    Confirm,
    Send(String, Sender<Result<(), String>>),
    AcceptIdentityTransition(String, Sender<Result<(), String>>),
    RequestHistoryRestore(Sender<Result<(), String>>),
    ResolveHistoryRestore(bool),
    Cancel,
}

pub(crate) struct ChatOperation {
    pub(crate) owner_identity_id: String,
    pub(crate) history_state_lock: Mutex<()>,
    pub(crate) snapshot: Mutex<ChatSnapshot>,
    pub(crate) message_reader: Mutex<Option<MessagePageReader>>,
    pub(crate) sender: Sender<ChatCommand>,
    pub(crate) cancelled: Arc<AtomicBool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HistoryDeletionAction {
    Selected {
        version: String,
        indices: HashSet<usize>,
    },
    TimeRange {
        start: u64,
        end: u64,
    },
}

pub(crate) struct HistoryDeletionOperation {
    pub(crate) owner_identity_id: String,
    pub(crate) peer_id: String,
    pub(crate) request_body: String,
    pub(crate) snapshot: Mutex<HistoryDeletionSnapshot>,
}

pub(crate) struct HistoryDeletionSnapshot {
    pub(crate) state: &'static str,
    pub(crate) message_count: Option<u64>,
    pub(crate) error: Option<String>,
}

pub(crate) struct PendingMergeQueueNotice {
    pub(crate) operation: Arc<ChatOperation>,
    pub(crate) has_pending: Arc<AtomicBool>,
}

impl Drop for PendingMergeQueueNotice {
    fn drop(&mut self) {
        if self.has_pending.load(Ordering::SeqCst) {
            chat_update(&self.operation, |snapshot| {
                let detail = "연결 종료로 병합 중 임시 대기하던 수신 메시지를 기록에 반영하지 못했습니다. 상대 기록 복원을 다시 요청해 확인하세요.";
                snapshot.storage_error =
                    Some(append_error_detail(snapshot.storage_error.take(), detail));
                snapshot.error = Some(append_error_detail(snapshot.error.take(), detail));
            });
        }
    }
}

pub(crate) fn append_error_detail(previous: Option<String>, detail: &str) -> String {
    previous.map_or_else(
        || detail.to_owned(),
        |previous| format!("{previous} {detail}"),
    )
}

pub(crate) fn owned_chat_operation<'a>(
    state: &'a State,
    operation_id: &str,
) -> Option<&'a Arc<ChatOperation>> {
    let identity_id = state.identity.as_ref()?.public_id();
    let operation = state.chats.get(operation_id)?;
    (operation.owner_identity_id == identity_id).then_some(operation)
}

pub(crate) struct MessagePageReader {
    pub(crate) peer_id: String,
    pub(crate) epoch: u64,
    pub(crate) next_index: usize,
    pub(crate) reader: history::HistoryReader,
}

pub(crate) struct ChatSnapshot {
    pub(crate) phase: &'static str,
    pub(crate) fingerprint: Option<String>,
    /// Short code the two users compare. The full fingerprint stays available.
    pub(crate) confirmation_code: Option<String>,
    pub(crate) peer_id: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) storage_error: Option<String>,
    pub(crate) messages: Vec<ChatEntry>,
    pub(crate) message_count: usize,
    pub(crate) relay_ack: Option<String>,
    pub(crate) pending_sends: usize,
    pub(crate) identity_transition: Option<Vec<String>>,
    pub(crate) history_restore_in_progress: bool,
    pub(crate) history_restore_state: &'static str,
    pub(crate) history_restore_estimate_bytes: u64,
    pub(crate) history_restore_cleanup_error: Option<String>,
    pub(crate) history_restore_offer: Vec<RestoreOfferEntry>,
    pub(crate) history_restore_offer_count: usize,
    pub(crate) history_restore_legacy_count: usize,
    pub(crate) history_restore_received: usize,
    pub(crate) history_restore_total: usize,
    pub(crate) history_restore_status: Option<String>,
    pub(crate) message_epoch: u64,
}

#[derive(Clone)]
pub(crate) struct ChatEntry {
    pub(crate) unix_time: u64,
    pub(crate) sender: &'static str,
    pub(crate) text: String,
}

#[derive(Clone)]
pub(crate) struct RestoreOfferEntry {
    pub(crate) unix_time: u64,
    pub(crate) sender: &'static str,
    pub(crate) text: String,
    pub(crate) signed: bool,
}

/// Sender of entries that describe the connection itself. The page shows them apart from
/// messages and never counts them as signed or unsigned.
pub(crate) const SYSTEM_SENDER: &str = "시스템";

pub(crate) fn messages_lost_notice(count: u64) -> String {
    format!(
        "상대가 보낸 메시지 {count}개가 도착하지 않았을 수 있습니다. relay는 한 번 보낸 메시지를 다시 보내지 않아서 연결이 끊긴 사이의 메시지는 받을 수 없습니다. 상대에게 확인해 보세요."
    )
}

pub(crate) fn chat_update(operation: &ChatOperation, update: impl FnOnce(&mut ChatSnapshot)) {
    if let Ok(mut snapshot) = operation.snapshot.lock() {
        update(&mut snapshot);
    }
}

pub(crate) fn submit_chat_message(
    sender: &Sender<ChatCommand>,
    text: String,
    timeout: Duration,
) -> Result<(), String> {
    let (processed, result) = mpsc::channel();
    sender
        .send(ChatCommand::Send(text, processed))
        .map_err(|_| "채팅 작업자가 종료되었습니다.".to_owned())?;
    result.recv_timeout(timeout).map_err(|_| {
        "전송 결과를 확인할 수 없습니다. 입력을 보존하고 다시 보내기 전 기록을 확인하세요."
            .to_owned()
    })?
}

pub(crate) fn chat_control(value: serde_json::Value) -> Vec<u8> {
    let mut frame = CHAT_CONTROL_PREFIX.to_vec();
    frame.extend_from_slice(value.to_string().as_bytes());
    frame
}

pub(crate) fn parse_chat_control(message: &[u8]) -> Result<Option<serde_json::Value>, ()> {
    let Some(payload) = message.strip_prefix(CHAT_CONTROL_PREFIX) else {
        return Ok(None);
    };
    serde_json::from_slice(payload).map(Some).map_err(|_| ())
}

pub(crate) fn is_unframed_live_chat_message(message: &[u8]) -> bool {
    std::str::from_utf8(message).is_ok()
        && !history::is_signed_message_frame(message)
        && !history::is_transfer_frame(message)
        && matches!(parse_chat_control(message), Ok(None))
}

pub(crate) fn reject_unframed_live_chat_message(operation: &ChatOperation, message: &[u8]) -> bool {
    if !is_unframed_live_chat_message(message) {
        return false;
    }
    mark_chat_disconnected(
        operation,
        "서명되지 않은 일반 메시지를 받아 연결을 종료했습니다. 기록에는 저장하지 않았습니다.",
        false,
    );
    true
}

pub(crate) fn chat_entry(item: history::StoredMessage) -> ChatEntry {
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

pub(crate) fn read_chat_history_page(
    state: &mut Option<MessagePageReader>,
    identity: &Identity,
    peer_id: &str,
    epoch: u64,
    cursor: usize,
    expected_count: usize,
    limit: usize,
) -> io::Result<Vec<history::StoredMessage>> {
    let limit = limit.min(256);
    let reset = state.as_ref().is_none_or(|page| {
        page.peer_id != peer_id || page.epoch != epoch || page.next_index != cursor
    });
    if reset {
        let mut reader = history::History::reader_for_identity_copy(identity, peer_id)?;
        for _ in 0..cursor {
            if reader.next_record()?.is_none() {
                break;
            }
        }
        *state = Some(MessagePageReader {
            peer_id: peer_id.to_owned(),
            epoch,
            next_index: cursor,
            reader,
        });
    }
    let mut result = Vec::with_capacity(limit);
    if let Some(page) = state.as_mut() {
        while result.len() < limit {
            match page.reader.next_record()? {
                Some(message) => result.push(message),
                None => break,
            }
        }
    }
    if result.len() < limit && cursor.saturating_add(result.len()) < expected_count {
        let mut reader = history::History::reader_for_identity_copy(identity, peer_id)?;
        for _ in 0..cursor.saturating_add(result.len()) {
            if reader.next_record()?.is_none() {
                break;
            }
        }
        while result.len() < limit {
            match reader.next_record()? {
                Some(message) => result.push(message),
                None => break,
            }
        }
        if let Some(page) = state.as_mut() {
            page.reader = reader;
        }
    }
    if let Some(page) = state.as_mut() {
        page.next_index = cursor.saturating_add(result.len());
    }
    Ok(result)
}

pub(crate) fn identity_event(
    kind: &str,
    previous_id: &str,
    current_id: &str,
) -> history::StoredMessage {
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

pub(crate) fn rejected_message(pending_events: &mut HashSet<String>, event_id: &str) -> bool {
    pending_events.remove(event_id)
}

pub(crate) fn mark_chat_disconnected(
    operation: &ChatOperation,
    reason: &str,
    delivery_unknown: bool,
) {
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

pub(crate) fn relay_failure_message(error: &RelayError, phase: &str, using_tor: bool) -> String {
    match error {
        RelayError::Cancelled => "취소되었습니다.".to_owned(),
        RelayError::Channel(channel::HandshakeError::IdentityMismatch) => {
            "저장된 상대와 연결된 신원이 다릅니다. 연결을 중단했습니다. 별도 경로로 상대를 다시 확인하세요.".to_owned()
        }
        RelayError::NoRelayAvailable => {
            if using_tor {
                "Tor SOCKS를 통한 relay 연결을 사용할 수 없습니다. 직접 연결로 전환하지 않았습니다. 설정을 확인하고 다시 시도하세요.".to_owned()
            } else {
                "설정된 relay에 연결할 수 없습니다. 주소와 네트워크 상태를 확인하고 다시 시도하세요.".to_owned()
            }
        }
        RelayError::TimedOut("relay subscription") => {
            "공통으로 접근 가능한 relay에서 응답을 받지 못했습니다. relay 설정을 확인하고 다시 시도하세요."
                .to_owned()
        }
        RelayError::TimedOut("peer subscription") => {
            "공통 relay에서 상대를 제한 시간 안에 찾지 못했습니다. relay 설정을 확인하고 다시 시도하세요.".to_owned()
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

/// Everything `spawn_chat_worker` needs after a successful connection attempt.
pub(crate) type ConnectedChat = (
    RelaySession,
    Option<history::History>,
    Vec<ChatEntry>,
    usize,
    Option<String>,
    [u8; 32],
    String,
);

// TODO(PLAN 3.1): pass a config struct when the chat worker moves to its own module.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_chat_worker(
    operation: Arc<ChatOperation>,
    state_handle: Arc<Mutex<State>>,
    commands: Receiver<ChatCommand>,
    role: RoleForChat,
    code: Zeroizing<String>,
    expected_peer: Option<[u8; 32]>,
    identity: Arc<Identity>,
    cancelled: Arc<AtomicBool>,
    tor_socks: Option<SocketAddr>,
    relay_urls: Vec<String>,
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
        let result = (|| -> Result<ConnectedChat, String> {
            let invite = InviteCode::parse(&code).ok_or("초대 코드를 확인하세요.")?;
            let mut rendezvous = match role {
                RoleForChat::Create => RelayRendezvous::create(&relay_urls, &invite, tor_socks),
                RoleForChat::Join => RelayRendezvous::join(&relay_urls, &invite, tor_socks),
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
            let fingerprint = crate::hex::encode(verification.fingerprint());
            let confirmation_code = verification.confirmation_code();
            let peer_key = *verification.peer_public_key();
            let peer_id = crate::hex::encode(verification.peer_public_key());
            {
                let state = state_handle
                    .lock()
                    .map_err(|_| "local state unavailable".to_owned())?;
                if history_delete_active(&state, &identity.public_id(), &peer_id) {
                    return Err(
                        "해당 대화 기록을 삭제 중입니다. 삭제가 끝난 뒤 다시 연결하세요."
                            .to_owned(),
                    );
                }
                let mut snapshot = operation
                    .snapshot
                    .lock()
                    .map_err(|_| "chat state unavailable".to_owned())?;
                snapshot.peer_id = Some(peer_id.clone());
                if expected_peer.is_none() {
                    snapshot.phase = "verification";
                    snapshot.fingerprint = Some(fingerprint);
                    snapshot.confirmation_code = Some(confirmation_code);
                }
            }
            let verification = if expected_peer.is_some() {
                verification
            } else {
                // The person compares the code with the other person, which takes a while.
                // Keep answering the relays meanwhile, and give up after a limit instead of
                // holding the connection open for good.
                let waiting_since = Instant::now();
                loop {
                    if operation.cancelled.load(Ordering::SeqCst) {
                        return Err("취소되었습니다.".to_owned());
                    }
                    if waiting_since.elapsed() >= relay::CONFIRMATION_TIMEOUT {
                        return Err(
                            "확인 코드를 비교하는 시간이 지났습니다. 새 초대 코드로 다시 시작하세요."
                                .to_owned(),
                        );
                    }
                    rendezvous.keep_alive().map_err(|error| {
                        relay_failure_message(&error, "confirmation", tor_socks.is_some())
                    })?;
                    match commands.recv_timeout(Duration::from_millis(250)) {
                        Ok(ChatCommand::Confirm) => break verification,
                        Ok(ChatCommand::Cancel) => return Err("취소되었습니다.".to_owned()),
                        Ok(ChatCommand::Send(_, _)) => {}
                        Ok(ChatCommand::AcceptIdentityTransition(_, result)) => {
                            let _ = result
                                .send(Err("상대 기록 연결 요청을 처리할 수 없습니다.".to_owned()));
                        }
                        Ok(ChatCommand::RequestHistoryRestore(result)) => {
                            let _ =
                                result
                                    .send(Err("상대 기록 복원은 연결 확인 후 사용할 수 있습니다."
                                        .to_owned()));
                        }
                        Ok(ChatCommand::ResolveHistoryRestore(_)) => {}
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => {
                            return Err("취소되었습니다.".to_owned())
                        }
                    }
                }
            };
            chat_update(&operation, |snapshot| snapshot.phase = "confirming");
            let mut session = if expected_peer.is_some() {
                rendezvous.confirm(verification).map_err(|error| {
                    relay_failure_message(&error, "confirmation", tor_socks.is_some())
                })?
            } else {
                let (session, rendezvous_secret) = rendezvous
                    .confirm_with_contact(verification)
                    .map_err(|error| {
                        relay_failure_message(&error, "confirmation", tor_socks.is_some())
                    })?;
                let directory = contacts::directory_for(&identity)
                    .map_err(|_| "상대 확인 정보를 저장할 위치를 찾을 수 없습니다.".to_owned())?;
                contacts::save_after_confirmation(
                    &directory,
                    &identity,
                    &contacts::VerifiedContact {
                        peer_key,
                        rendezvous_secret,
                    },
                )
                .map_err(|_| {
                    "상대 확인 정보를 저장하지 못했습니다. 기존 확인 기록을 확인하세요.".to_owned()
                })?;
                session
            };
            let (history, entries, message_count, storage_error, pending_previous_ids) = match history::History::open_for_chat(&identity, &peer_id) {
                Ok((history, message_count, recovered_partial)) => {
                    let (pending, link_error) = match history::pending_local_identity_links(&identity, &peer_id, &previous_identity_ids) {
                        Ok(pending) => (pending, None),
                        Err(error) => (previous_identity_ids.clone(), Some(format!("이전 신원 연결 정보를 읽지 못했습니다. 재확인이 필요합니다: {error}"))),
                    };
                    let entries = Vec::new();
                    let warning = link_error
                        .or_else(|| history.integrity_warning().map(history_integrity_message))
                        .or_else(|| recovered_partial
                            .then(|| "대화 기록의 마지막 불완전 항목을 제거했습니다.".to_owned()));
                    (Some(history), entries, message_count, warning, pending)
                }
                Err(_) => (None, Vec::new(), 0, Some("대화 기록을 열지 못했습니다. 이번 대화는 프로그램을 종료하면 사라질 수 있습니다.".to_owned()), previous_identity_ids.clone()),
            };
            if !pending_previous_ids.is_empty() {
                let announcement = chat_control(serde_json::json!({
                    "type": "identity-transition",
                    "previousPeerIds": pending_previous_ids,
                }));
                session
                    .send(&announcement)
                    .map_err(|_| "신원 변경 안내를 상대에게 보내지 못했습니다.".to_owned())?;
            }
            Ok((
                session,
                history,
                entries,
                message_count,
                storage_error,
                peer_key,
                peer_id,
            ))
        })();

        let (mut session, mut history, peer_key, peer_id) = match result {
            Ok((session, history, messages, message_count, storage_error, peer_key, peer_id)) => {
                chat_update(&operation, |snapshot| {
                    snapshot.messages = messages;
                    snapshot.message_count = message_count;
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
        let mut pending_restore = None::<history::RestoreStaging>;
        let mut restore_request_id = None::<String>;
        let mut restore_receiver = HistorySyncReceiver::default();
        let mut restore_local_aliases = Vec::<[u8; 32]>::new();
        let mut restore_peer_aliases = Vec::<[u8; 32]>::new();
        let mut restore_started_at = None::<Instant>;
        let mut outgoing_sync = None::<HistorySyncSender>;
        let mut outgoing_sync_started_at = None::<Instant>;
        let mut merge_pending_messages = VecDeque::<history::StoredMessage>::new();
        let mut merge_pending_bytes = 0usize;
        let merge_queue_has_pending = Arc::new(AtomicBool::new(false));
        let _merge_queue_notice = PendingMergeQueueNotice {
            operation: Arc::clone(&operation),
            has_pending: Arc::clone(&merge_queue_has_pending),
        };
        let mut last_peer_activity = Instant::now();
        let mut last_heartbeat = Instant::now();

        while !operation.cancelled.load(Ordering::SeqCst) {
            let now = Instant::now();
            if !merge_pending_messages.is_empty() && !restore_merge_active(&operation) {
                match append_pending_restore_messages(
                    &operation,
                    &mut history,
                    &mut merge_pending_messages,
                    &mut merge_pending_bytes,
                    8,
                ) {
                    Ok(_) => {
                        merge_queue_has_pending
                            .store(!merge_pending_messages.is_empty(), Ordering::SeqCst);
                    }
                    Err(error) => {
                        chat_update(&operation, |snapshot| {
                            snapshot.storage_error = Some(format!(
                                "병합 중 받은 메시지를 로컬 기록에 저장하지 못했습니다. 연결을 다시 설정하고 상대 기록 복원을 재시도하세요: {error}"
                            ));
                            snapshot.error = snapshot.storage_error.clone();
                            snapshot.phase = "disconnected";
                        });
                        discard_restore_staging(&mut pending_restore, &operation);
                        return;
                    }
                }
            }
            if history_restore_work_timed_out(
                restore_started_at,
                restore_request_id.is_some(),
                pending_restore.is_some(),
                now,
            ) && try_reserve_history_restore_timeout(&operation)
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
                discard_restore_staging(&mut pending_restore, &operation);
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
                discard_restore_staging(&mut pending_restore, &operation);
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
                    discard_restore_staging(&mut pending_restore, &operation);
                    return;
                }
                last_heartbeat = Instant::now();
            }
            loop {
                match commands.try_recv() {
                    Ok(ChatCommand::Send(text, processed)) => {
                        if let Some(error) = restore_merge_send_error(&operation) {
                            let _ = processed.send(Err(error.to_owned()));
                            continue;
                        }
                        let entry = match history::sign_message(
                            &identity,
                            &peer_id,
                            now_seconds(),
                            text.clone(),
                        ) {
                            Ok(entry) => entry,
                            Err(_) => {
                                let _ = processed
                                    .send(Err("메시지 서명을 만들지 못했습니다.".to_owned()));
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
                                let _ = processed.send(Err(
                                    "서명 메시지를 전송 형식으로 만들지 못했습니다.".to_owned(),
                                ));
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
                                let _history_state_guard = operation
                                    .history_state_lock
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner());
                                let save_error = match history.as_mut() {
                                    Some(history) => history.append(&entry).err(),
                                    None => Some(io::Error::other("history unavailable")),
                                };
                                if save_error.is_some() {
                                    history = None;
                                }
                                chat_update(&operation, |snapshot| {
                                    snapshot.message_count =
                                        snapshot.message_count.saturating_add(1);
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
                                let _ = processed.send(Ok(()));
                            }
                            Err(RelayError::PendingPublishLimit) => {
                                let message = "relay 발행 확인 대기 한도에 도달했습니다. 기존 전송 확인이 처리된 뒤 다시 보내세요.".to_owned();
                                chat_update(&operation, |snapshot| {
                                    snapshot.error = Some(message.clone());
                                });
                                let _ = processed.send(Err(message));
                            }
                            Err(_) => {
                                let _history_state_guard = operation
                                    .history_state_lock
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner());
                                let save_error = match history.as_mut() {
                                    Some(history) => history.append(&entry).err(),
                                    None => Some(io::Error::other("history unavailable")),
                                };
                                drop(history.take());
                                chat_update(&operation, |snapshot| {
                                    snapshot.phase = "disconnected";
                                    snapshot.message_count =
                                        snapshot.message_count.saturating_add(1);
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
                                let _ = processed.send(Err("메시지 전송 결과를 알 수 없습니다. 입력을 보존하고 기록을 확인하세요.".to_owned()));
                                discard_restore_staging(&mut pending_restore, &operation);
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
                                            snapshot.message_count = snapshot.messages.len();
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
                            "type": "history-sync-estimate-request",
                            "requestId": request_id,
                        }));
                        match session.send(&frame) {
                            Ok(_) => {
                                discard_restore_staging(&mut pending_restore, &operation);
                                restore_request_id = Some(request_id);
                                restore_receiver = HistorySyncReceiver::default();
                                restore_started_at = Some(Instant::now());
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_in_progress = true;
                                    snapshot.history_restore_state = "estimating";
                                    snapshot.history_restore_offer.clear();
                                    snapshot.history_restore_offer_count = 0;
                                    snapshot.history_restore_received = 0;
                                    snapshot.history_restore_total = 0;
                                    snapshot.history_restore_estimate_bytes = 0;
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
                    Ok(ChatCommand::ResolveHistoryRestore(accept)) => {
                        let in_progress = restore_request_id.is_some();
                        let restore_state = operation
                            .snapshot
                            .lock()
                            .map(|snapshot| snapshot.history_restore_state)
                            .unwrap_or("failed");
                        if accept && restore_state == "transfer-queued" {
                            let request_id = restore_request_id.clone();
                            let sent =
                                request_id.is_some_and(|request_id| {
                                    session.send(&chat_control(serde_json::json!({
                                    "type": "history-sync-transfer", "requestId": request_id,
                                }))).is_ok()
                                });
                            if sent {
                                restore_started_at = Some(Instant::now());
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_state = "receiving";
                                    snapshot.history_restore_status = Some("전송 동의를 받았습니다. 서명과 발신자를 검증하며 암호화 임시 저장소에 받습니다.".to_owned());
                                });
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_status =
                                        Some("기록 전송을 시작했습니다.".to_owned());
                                });
                            } else {
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_state = "failed";
                                    snapshot.history_restore_in_progress = false;
                                    snapshot.history_restore_status =
                                        Some("기록 전송을 시작하지 못했습니다.".to_owned());
                                });
                            }
                            continue;
                        }
                        if accept && restore_state == "merge-queued" {
                            let Some(mut staging) = pending_restore.take() else {
                                chat_update(&operation, |snapshot| {
                                    snapshot.history_restore_state = "failed";
                                    snapshot.history_restore_in_progress = false;
                                    snapshot.history_restore_status =
                                        Some("복원 임시 저장소를 찾지 못했습니다.".to_owned());
                                });
                                continue;
                            };
                            let merge_identity = Arc::clone(&identity);
                            let merge_operation = Arc::clone(&operation);
                            let merge_peer_id = peer_id.clone();
                            chat_update(&operation, |snapshot| {
                                snapshot.history_restore_state = "merging";
                                snapshot.history_restore_in_progress = true;
                                snapshot.history_restore_status = Some("최종 병합 중입니다. 메시지 전송은 병합 완료 후 다시 시도해야 하며, 수신 메시지는 제한된 메모리 대기열에 보관한 뒤 기록에 반영합니다. heartbeat와 relay 수신은 계속 처리합니다. 연결 종료 뒤에도 병합 결과를 확인할 수 있습니다.".to_owned());
                            });
                            thread::spawn(move || {
                                let _history_state_guard = merge_operation
                                    .history_state_lock
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner());
                                let result = (|| -> io::Result<history::RestoreMergeSummary> {
                                    let (mut current, _, _) = history::History::open_for_chat(
                                        &merge_identity,
                                        &merge_peer_id,
                                    )?;
                                    current.merge_restore_staging(&merge_identity, &mut staging)
                                })();
                                let cleanup = staging.cleanup();
                                chat_update(&merge_operation, |snapshot| {
                                    snapshot.history_restore_in_progress = false;
                                    snapshot.history_restore_offer.clear();
                                    snapshot.history_restore_offer_count = 0;
                                    snapshot.history_restore_legacy_count = 0;
                                    snapshot.history_restore_received = 0;
                                    snapshot.history_restore_total = 0;
                                    match result {
                                        Ok(summary) => {
                                            snapshot.history_restore_state = "completed";
                                            snapshot.message_count =
                                                summary.total_count.min(usize::MAX as u64) as usize;
                                            snapshot.message_epoch =
                                                snapshot.message_epoch.wrapping_add(1);
                                            snapshot.history_restore_status = Some(match cleanup {
                                                Ok(()) => format!("{}개 메시지를 병합했습니다. 서명 없는 구형 메시지는 완전한 중복 판정이 불가능합니다.", summary.imported_count),
                                                Err(error) => {
                                                    snapshot.history_restore_cleanup_error = Some(error.to_string());
                                                    format!("{}개 메시지 병합은 완료됐지만 임시 저장소 정리에 실패했습니다: {error}", summary.imported_count)
                                                }
                                            });
                                        }
                                        Err(error) => {
                                            snapshot.history_restore_state = "failed";
                                            snapshot.history_restore_status = Some(match cleanup {
                                                Ok(()) => format!("기록 병합 실패: {error}"),
                                                Err(cleanup) => {
                                                    snapshot.history_restore_cleanup_error =
                                                        Some(cleanup.to_string());
                                                    format!("기록 병합 실패 ({error}); 임시 저장소 정리도 실패 ({cleanup})")
                                                }
                                            });
                                        }
                                    }
                                });
                            });
                            continue;
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
                            let mut result = Ok(());
                            if let Some(staging) = pending_restore.take() {
                                result = staging.cleanup();
                            }
                            chat_update(&operation, |snapshot| {
                                snapshot.history_restore_in_progress = false;
                                snapshot.history_restore_state =
                                    if result.is_ok() { "idle" } else { "failed" };
                                snapshot.history_restore_status = Some(match result {
                                    Ok(()) if in_progress => {
                                        "기록 전송을 취소했습니다. 로컬 기록은 변경하지 않았습니다."
                                            .to_owned()
                                    }
                                    Ok(()) => {
                                        "복원을 거부했습니다. 로컬 기록은 변경하지 않았습니다."
                                            .to_owned()
                                    }
                                    Err(error) => {
                                        format!("복원 임시 저장소 정리에 실패했습니다: {error}")
                                    }
                                });
                                snapshot.history_restore_offer.clear();
                                snapshot.history_restore_offer_count = 0;
                                snapshot.history_restore_legacy_count = 0;
                                snapshot.history_restore_received = 0;
                                snapshot.history_restore_total = 0;
                            });
                        }
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
                        if reject_unframed_live_chat_message(&operation, &message) {
                            drop(history.take());
                            discard_restore_staging(&mut pending_restore, &operation);
                            return;
                        }
                        if history::is_signed_message_frame(&message) {
                            let entry = match history::decode_signed_message(
                                &identity, &peer_id, &peer_key, &message,
                            ) {
                                Ok(entry) => entry,
                                Err(_) => {
                                    drop(history.take());
                                    mark_chat_disconnected(&operation, "상대 메시지의 발신 서명 또는 형식 검증에 실패했습니다. 기록은 가져오지 않았습니다.", false);
                                    discard_restore_staging(&mut pending_restore, &operation);
                                    return;
                                }
                            };
                            if notifications_enabled.load(Ordering::SeqCst)
                                && should_send_notification(&last_notification)
                            {
                                notify_incoming_message();
                            }
                            if queue_incoming_message(&operation, merge_pending_messages.len()) {
                                if queue_message_during_restore_merge(
                                    &mut merge_pending_messages,
                                    &mut merge_pending_bytes,
                                    entry,
                                )
                                .is_err()
                                {
                                    drop(history.take());
                                    chat_update(&operation, |snapshot| {
                                        snapshot.storage_error = Some(
                                            "기록 병합 중 수신 메시지 대기 한도를 초과했습니다. 새 메시지는 저장하지 못했으며 상대 기록 복원 후 대화를 다시 연결해 확인하세요.".to_owned(),
                                        );
                                        snapshot.error = snapshot.storage_error.clone();
                                        snapshot.phase = "disconnected";
                                    });
                                    discard_restore_staging(&mut pending_restore, &operation);
                                    return;
                                }
                                merge_queue_has_pending.store(true, Ordering::SeqCst);
                                continue;
                            }
                            let _history_state_guard = operation
                                .history_state_lock
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let save_error = match history.as_mut() {
                                Some(history) => history.append(&entry).err(),
                                None => Some(io::Error::other("history unavailable")),
                            };
                            if save_error.is_some() {
                                history = None;
                            }
                            chat_update(&operation, |snapshot| {
                                snapshot.message_count = snapshot.message_count.saturating_add(1);
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
                                discard_restore_staging(&mut pending_restore, &operation);
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
                            if !restore_transfer_allowed(&operation) {
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
                                pending_restore
                                    .as_mut()
                                    .ok_or_else(|| {
                                        io::Error::other("restore staging is unavailable")
                                    })?
                                    .append_verified(&entry)?;
                                Ok(entry)
                            });
                            match decoded {
                                Ok(_entry) => {
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
                                    discard_restore_staging(&mut pending_restore, &operation);
                                    let _ = session.send(&chat_control(serde_json::json!({
                                        "type": "history-sync-cancel",
                                        "requestId": request_id,
                                        "reason": error.to_string(),
                                    })));
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_state = "failed";
                                        snapshot.history_restore_state = "failed";
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
                                discard_restore_staging(&mut pending_restore, &operation);
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
                                        discard_restore_staging(&mut pending_restore, &operation);
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
                                            discard_restore_staging(
                                                &mut pending_restore,
                                                &operation,
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
                                        discard_restore_staging(&mut pending_restore, &operation);
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
                                        discard_restore_staging(&mut pending_restore, &operation);
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
                                Some("history-sync-estimate-request") => {
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
                                    let prepared = history::History::estimate_transfer(
                                        &identity, &peer_id, request_id,
                                    );
                                    let (reader, total_count, estimated_bytes) = match prepared {
                                        Ok(prepared) => prepared,
                                        Err(reason) => {
                                            let _ = session.send(&chat_control(serde_json::json!({
                                                "type": "history-sync-failed", "requestId": request_id, "reason": reason.to_string(),
                                            })));
                                            continue;
                                        }
                                    };
                                    outgoing_sync = Some(HistorySyncSender::new(
                                        request_id.to_owned(),
                                        reader,
                                        total_count,
                                    ));
                                    outgoing_sync_started_at = Some(Instant::now());
                                    let _ = session.send(&chat_control(serde_json::json!({
                                        "type": "history-sync-estimate", "requestId": request_id,
                                        "totalCount": total_count, "estimatedBytes": estimated_bytes,
                                    })));
                                }
                                Some("history-sync-transfer") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    let Some(sync) = outgoing_sync
                                        .as_mut()
                                        .filter(|sync| sync.request_id == request_id)
                                    else {
                                        continue;
                                    };
                                    let begin = chat_control(serde_json::json!({
                                        "type": "history-sync-begin", "requestId": request_id,
                                        "totalCount": sync.total_records,
                                    }));
                                    let sent = session
                                        .send(&begin)
                                        .map(|_| ())
                                        .map_err(|error| io::Error::other(format!("{error:?}")))
                                        .and_then(|()| {
                                            if sync.total_records == 0 {
                                                send_history_sync_done(&mut session, request_id, 0)
                                            } else {
                                                send_next_history_chunk(&mut session, sync)
                                            }
                                        });
                                    if sent.is_err() {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-failed", "requestId": request_id,
                                            "reason": "기록 묶음을 전송하지 못했습니다.",
                                        })));
                                        outgoing_sync = None;
                                        outgoing_sync_started_at = None;
                                    } else if sync.total_records == 0 {
                                        outgoing_sync = None;
                                        outgoing_sync_started_at = None;
                                    } else {
                                        outgoing_sync_started_at = Some(Instant::now());
                                    }
                                }
                                Some("history-sync-estimate") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    if !operation.snapshot.lock().is_ok_and(|snapshot| {
                                        snapshot.history_restore_state == "estimating"
                                    }) {
                                        continue;
                                    }
                                    let count = control
                                        .get("totalCount")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|n| usize::try_from(n).ok());
                                    let bytes = control
                                        .get("estimatedBytes")
                                        .and_then(serde_json::Value::as_u64);
                                    let Some((count, bytes)) = count.zip(bytes) else {
                                        restore_request_id = None;
                                        restore_started_at = None;
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_state = "failed";
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_state = "failed";
                                            snapshot.history_restore_status = Some(
                                                "상대 기록 예상치가 잘못되었습니다.".to_owned(),
                                            );
                                        });
                                        continue;
                                    };
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_state =
                                            "awaiting-transfer-consent";
                                        snapshot.history_restore_total = count;
                                        snapshot.history_restore_estimate_bytes = bytes;
                                        snapshot.history_restore_status = Some(format!("상대가 메시지 {count}개, 전송량 약 {bytes}바이트로 추정했습니다. 실제 수신량은 달라질 수 있습니다. 전송을 시작할까요?"));
                                    });
                                    restore_started_at = Some(Instant::now());
                                }
                                Some("history-sync-begin") => {
                                    let request_id = control
                                        .get("requestId")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or("");
                                    if restore_request_id.as_deref() != Some(request_id) {
                                        continue;
                                    }
                                    if !operation.snapshot.lock().is_ok_and(|snapshot| {
                                        snapshot.history_restore_state == "receiving"
                                    }) {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-cancel", "requestId": request_id,
                                            "reason": "transfer consent is required",
                                        })));
                                        continue;
                                    }
                                    let total_count = control
                                        .get("totalCount")
                                        .and_then(serde_json::Value::as_u64)
                                        .and_then(|count| usize::try_from(count).ok());
                                    let started = total_count.is_some_and(|total| {
                                        restore_receiver.begin(request_id, total).is_ok()
                                    });
                                    if !started {
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-cancel", "requestId": request_id,
                                            "reason": "invalid transfer start",
                                        })));
                                        restore_request_id = None;
                                        restore_started_at = None;
                                        discard_restore_staging(&mut pending_restore, &operation);
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_state = "failed";
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some("상대 기록 제안의 시작 정보가 잘못되었습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                        });
                                    } else {
                                        let aliases = history::linked_identity_keys(
                                            &identity,
                                            &[],
                                            &identity.public_id(),
                                            &peer_id,
                                            &previous_identity_ids,
                                        );
                                        let Ok((local_aliases, peer_aliases)) = aliases else {
                                            let _ = session.send(&chat_control(serde_json::json!({
                                                "type": "history-sync-cancel", "requestId": request_id,
                                                "reason": "local identity-link history unavailable",
                                            })));
                                            restore_request_id = None;
                                            restore_receiver = HistorySyncReceiver::default();
                                            discard_restore_staging(
                                                &mut pending_restore,
                                                &operation,
                                            );
                                            chat_update(&operation, |snapshot| {
                                                snapshot.history_restore_in_progress = false;
                                                snapshot.history_restore_status = Some("이전 신원 연결 기록을 검증하지 못해 복원 제안을 거부했습니다. 로컬 기록은 변경하지 않았습니다.".to_owned());
                                            });
                                            continue;
                                        };
                                        restore_local_aliases = local_aliases;
                                        restore_peer_aliases = peer_aliases;
                                        pending_restore = match history::RestoreStaging::create(
                                            &identity, &peer_id, request_id,
                                        ) {
                                            Ok(staging) => Some(staging),
                                            Err(error) => {
                                                let _ = session.send(&chat_control(serde_json::json!({
                                                    "type": "history-sync-cancel", "requestId": request_id,
                                                    "reason": error.to_string(),
                                                })));
                                                restore_request_id = None;
                                                restore_receiver = HistorySyncReceiver::default();
                                                restore_started_at = None;
                                                chat_update(&operation, |snapshot| {
                                                    snapshot.history_restore_in_progress = false;
                                                    snapshot.history_restore_state = "failed";
                                                    snapshot.history_restore_status = Some(format!("암호화 임시 저장소를 만들지 못했습니다: {error}"));
                                                });
                                                continue;
                                            }
                                        };
                                        restore_started_at = Some(Instant::now());
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_state = "receiving";
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
                                    if !operation.snapshot.lock().is_ok_and(|snapshot| {
                                        snapshot.history_restore_state == "receiving"
                                    }) {
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
                                        discard_restore_staging(&mut pending_restore, &operation);
                                        let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-cancel", "requestId": request_id, "reason": error.to_string() })));
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_state = "failed";
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
                                        discard_restore_staging(&mut pending_restore, &operation);
                                        let _ = session.send(&chat_control(serde_json::json!({ "type": "history-sync-cancel", "requestId": request_id, "reason": error.to_string() })));
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_state = "idle";
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some(format!("기록 묶음이 완전하지 않아 전송을 중단했습니다: {error}. 로컬 기록은 변경하지 않았습니다."));
                                        });
                                    } else if let Some(chunk) = chunk {
                                        restore_started_at = Some(Instant::now());
                                        let _ = session.send(&chat_control(serde_json::json!({
                                            "type": "history-sync-ack", "requestId": request_id, "chunk": chunk,
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
                                            let total_count = sync.total_records;
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
                                    if !operation.snapshot.lock().is_ok_and(|snapshot| {
                                        snapshot.history_restore_state == "receiving"
                                    }) {
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
                                        && count
                                            == pending_restore
                                                .as_ref()
                                                .map(|stage| stage.count() as usize);
                                    restore_request_id = None;
                                    restore_started_at = Some(Instant::now());
                                    restore_receiver = HistorySyncReceiver::default();
                                    if !valid {
                                        discard_restore_staging(&mut pending_restore, &operation);
                                        chat_update(&operation, |snapshot| {
                                            snapshot.history_restore_in_progress = false;
                                            snapshot.history_restore_state = "failed";
                                            snapshot.history_restore_received = 0;
                                            snapshot.history_restore_total = 0;
                                            snapshot.history_restore_status = Some("상대 기록 제안이 완전하지 않아 아무 항목도 가져오지 않았습니다.".to_owned());
                                        });
                                        continue;
                                    }
                                    let preview_result = (|| -> io::Result<(Vec<RestoreOfferEntry>, usize, usize)> {
                                        let stage = pending_restore.as_mut()
                                            .ok_or_else(|| io::Error::other("restore staging is unavailable"))?;
                                        stage.finish()?;
                                        stage.rewind()?;
                                        let mut preview = Vec::new();
                                        let mut signed_count = 0usize;
                                        let mut legacy_count = 0usize;
                                        while let Some(item) = stage.next_record()? {
                                            if item.proof.is_some() { signed_count += 1; } else { legacy_count += 1; }
                                            if preview.len() < RESTORE_PREVIEW_RECORDS {
                                                preview.push(RestoreOfferEntry {
                                                    unix_time: item.unix_time,
                                                    sender: if item.sender == history::MessageSender::Me { "나" } else { "상대방" },
                                                    text: item.text,
                                                    signed: item.proof.is_some(),
                                                });
                                            }
                                        }
                                        stage.rewind()?;
                                        Ok((preview, signed_count, legacy_count))
                                    })();
                                    let (preview, signed_count, legacy_count) = match preview_result
                                    {
                                        Ok(summary) => summary,
                                        Err(error) => {
                                            discard_restore_staging(
                                                &mut pending_restore,
                                                &operation,
                                            );
                                            chat_update(&operation, |snapshot| {
                                                snapshot.history_restore_in_progress = false;
                                                snapshot.history_restore_state = "failed";
                                                snapshot.history_restore_status = Some(format!(
                                                    "임시 기록을 검증하지 못했습니다: {}",
                                                    client_message("임시 기록 검증 오류", &error)
                                                ));
                                            });
                                            continue;
                                        }
                                    };
                                    let offer_count = pending_restore
                                        .as_ref()
                                        .map_or(0, |stage| stage.count() as usize);
                                    chat_update(&operation, |snapshot| {
                                        snapshot.history_restore_in_progress = false;
                                        snapshot.history_restore_state = "awaiting-merge-consent";
                                        snapshot.history_restore_legacy_count = legacy_count;
                                        snapshot.history_restore_offer_count = offer_count;
                                        snapshot.history_restore_offer = preview;
                                        snapshot.history_restore_received = received_count;
                                        snapshot.history_restore_total = declared_total;
                                        snapshot.history_restore_status = Some(
                                            if offer_count == 0 {
                                                "상대가 보낸 기록이 없습니다.".to_owned()
                                            } else {
                                                format!("전송된 메시지 {offer_count}개를 검증했습니다(서명 {signed_count}개, 기존 서명 없음 {legacy_count}개). 중복은 최종 병합 시 건너뜁니다. 동의 전에는 로컬 기록을 변경하지 않습니다.")
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
                                    discard_restore_staging(&mut pending_restore, &operation);
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
                                        discard_restore_staging(&mut pending_restore, &operation);
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
                                    discard_restore_staging(&mut pending_restore, &operation);
                                    return;
                                }
                            }
                            continue;
                        }
                        drop(history.take());
                        mark_chat_disconnected(
                            &operation,
                            "처리할 수 없는 채팅 프레임을 받아 연결을 종료했습니다.",
                            false,
                        );
                        discard_restore_staging(&mut pending_restore, &operation);
                        return;
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
                Ok(Some(RelayUpdate::PublishUnknown { event_id })) => {
                    if pending_events.remove(&event_id) {
                        chat_update(&operation, |snapshot| {
                            snapshot.relay_ack = Some("unknown".to_owned());
                            snapshot.pending_sends = pending_events.len();
                            snapshot.error = Some(
                                "relay 연결이 끊겨 메시지 접수 여부를 확인하지 못했습니다. 로컬 기록에 보존되어 있으며 다시 보내면 중복될 수 있습니다.".to_owned(),
                            );
                        });
                    }
                }
                Ok(Some(RelayUpdate::MessagesLost { count })) => {
                    // This is a fact about the connection, not part of the conversation, so
                    // it is shown in the chat but never written to the history.
                    chat_update(&operation, |snapshot| {
                        snapshot.message_count = snapshot.message_count.saturating_add(1);
                        snapshot.messages.push(ChatEntry {
                            unix_time: now_seconds(),
                            sender: SYSTEM_SENDER,
                            text: messages_lost_notice(count),
                        });
                    });
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
                    discard_restore_staging(&mut pending_restore, &operation);
                    return;
                }
            }
        }
        drop(history);
        chat_update(&operation, |snapshot| snapshot.phase = "closed");
    });
}

#[derive(Clone, Copy)]
pub(crate) enum RoleForChat {
    Create,
    Join,
}

pub(crate) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Replaces absolute file system paths in an error text with `…/<file name>`. The
/// directory layout of the user's machine does not belong in a response, while the
/// file name is still enough to find a temporary file by hand.
/// The notice shown when a conversation's log does not match what this program last
/// recorded for it. It says what was seen and what it does not prove.
pub(crate) fn history_integrity_message(warning: history::IntegrityWarning) -> String {
    match warning {
        history::IntegrityWarning::Truncated { recorded, found } => format!(
            "대화 기록 파일이 마지막으로 저장한 상태보다 짧습니다({recorded}개였는데 {found}개). 마지막 메시지가 사라졌을 수 있습니다."
        ),
        history::IntegrityWarning::UnknownGeneration => {
            "대화 기록 파일이 이 프로그램이 마지막으로 저장한 것과 다른 버전입니다. 이전 파일로 되돌려졌을 수 있습니다.".to_owned()
        }
        history::IntegrityWarning::AnchorUnreadable => {
            "대화 기록의 상태 정보를 읽지 못해 되돌림 여부를 확인할 수 없습니다.".to_owned()
        }
    }
}
