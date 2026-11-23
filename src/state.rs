//! Shared application state and the helpers that manage it.

use super::*;

pub(crate) const CODE_LIFETIME: Duration = Duration::from_secs(300);

pub(crate) const MAX_ATTEMPTS: u8 = 5;

pub(crate) struct State {
    pub(crate) code: String,
    pub(crate) issued: Instant,
    pub(crate) attempts: u8,
    pub(crate) sessions: SessionStore,
    pub(crate) identity: Option<Arc<Identity>>,
    pub(crate) chats: HashMap<String, Arc<ChatOperation>>,
    pub(crate) history_deletions: HashMap<String, Arc<HistoryDeletionOperation>>,
    pub(crate) active_history_deletions: HashSet<String>,
    /// True while a backup import runs outside the State lock. It blocks the same
    /// operations that an active chat or deletion would.
    pub(crate) history_import_active: bool,
    pub(crate) tor_socks: Option<SocketAddr>,
    pub(crate) active_relays: Vec<String>,
    pub(crate) settings: AppSettings,
    pub(crate) notifications_enabled: Arc<AtomicBool>,
    pub(crate) last_notification: Arc<Mutex<Option<Instant>>>,
}

pub(crate) fn peer_chat_active(state: &State, peer_id: &str) -> bool {
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

pub(crate) fn any_chat_active(state: &State) -> bool {
    state.chats.values().any(|operation| {
        operation
            .snapshot
            .lock()
            .is_ok_and(|snapshot| !matches!(snapshot.phase, "closed" | "failed" | "disconnected"))
    })
}

#[cfg(test)]
pub(crate) fn first_active_relay(relays: &[String]) -> &str {
    relays.first().map_or(DEFAULT_RELAY, String::as_str)
}

pub(crate) fn conversation_history_key(identity_id: &str, peer_id: &str) -> String {
    format!("{identity_id}:{}", peer_id.to_ascii_lowercase())
}

/// Whether history for this conversation is being changed: a deletion for it, or an
/// import (which can touch any conversation).
pub(crate) fn history_delete_active(state: &State, identity_id: &str, peer_id: &str) -> bool {
    state.history_import_active
        || state
            .active_history_deletions
            .contains(&conversation_history_key(identity_id, peer_id))
}

/// Clears `history_import_active` when the import ends, including by panic, so one
/// failed import cannot block chats until the next restart.
pub(crate) struct ImportGuard(pub(crate) Arc<Mutex<State>>);

impl Drop for ImportGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.history_import_active = false;
        }
    }
}

pub(crate) fn update_closed_chat_history(
    state: &State,
    identity_id: &str,
    peer_id: &str,
    message_count: u64,
) {
    for operation in state.chats.values() {
        if operation.owner_identity_id != identity_id {
            continue;
        }
        if let Ok(mut snapshot) = operation.snapshot.lock() {
            if snapshot
                .peer_id
                .as_deref()
                .is_some_and(|current| current.eq_ignore_ascii_case(peer_id))
                && matches!(snapshot.phase, "closed" | "failed" | "disconnected")
            {
                snapshot.messages.clear();
                snapshot.message_count = message_count.min(usize::MAX as u64) as usize;
                snapshot.message_epoch = snapshot.message_epoch.wrapping_add(1);
                if let Ok(mut reader) = operation.message_reader.lock() {
                    *reader = None;
                }
            }
        }
    }
}

pub(crate) fn queue_history_deletion(
    state: &mut State,
    state_handle: Arc<Mutex<State>>,
    operation_id: String,
    request_body: String,
    identity: Arc<Identity>,
    peer_id: String,
    action: HistoryDeletionAction,
) -> Result<(), &'static str> {
    let identity_id = identity.public_id().to_owned();
    if let Some(existing) = state.history_deletions.get(&operation_id) {
        return if existing.owner_identity_id == identity_id
            && existing.peer_id.eq_ignore_ascii_case(&peer_id)
            && existing.request_body == request_body
        {
            Ok(())
        } else {
            Err("deletion operation ID already exists")
        };
    }
    if state.history_import_active {
        return Err("a backup import is in progress");
    }
    let reservation_key = conversation_history_key(&identity_id, &peer_id);
    if state.active_history_deletions.contains(&reservation_key) {
        return Err("history deletion already in progress for this conversation");
    }
    if state.history_deletions.len() >= 256 {
        let completed: Vec<_> = state
            .history_deletions
            .iter()
            .filter_map(|(id, operation)| {
                operation
                    .snapshot
                    .lock()
                    .ok()
                    .filter(|snapshot| matches!(snapshot.state, "completed" | "failed"))
                    .map(|_| id.clone())
            })
            .take(state.history_deletions.len().saturating_sub(255))
            .collect();
        for id in completed {
            state.history_deletions.remove(&id);
        }
        if state.history_deletions.len() >= 256 {
            return Err("too many pending history deletion results");
        }
    }
    let operation = Arc::new(HistoryDeletionOperation {
        owner_identity_id: identity_id.clone(),
        peer_id: peer_id.clone(),
        request_body,
        snapshot: Mutex::new(HistoryDeletionSnapshot {
            state: "queued",
            message_count: None,
            error: None,
        }),
    });
    state
        .active_history_deletions
        .insert(reservation_key.clone());
    state
        .history_deletions
        .insert(operation_id, Arc::clone(&operation));
    #[cfg(test)]
    let test_data_directory = history::test_data_directory();
    // Lock order: reserve under State, release State before history I/O, then
    // reacquire State only after the conversation file lock has been released.
    thread::spawn(move || {
        #[cfg(test)]
        if let Some(path) = test_data_directory {
            history::set_test_data_directory(Some(path));
        }
        if let Ok(mut snapshot) = operation.snapshot.lock() {
            snapshot.state = "running";
        }
        let result = match action {
            HistoryDeletionAction::Selected { version, indices } => {
                history::History::delete_indices_if_version(&identity, &peer_id, &version, &indices)
            }
            HistoryDeletionAction::TimeRange { start, end } => {
                history::History::delete_time_range(&identity, &peer_id, start, end)
            }
        };
        if let Ok(mut state) = state_handle.lock() {
            if let Ok(summary) = &result {
                update_closed_chat_history(&state, &identity_id, &peer_id, summary.remaining_count);
            }
            state.active_history_deletions.remove(&reservation_key);
            if let Ok(mut snapshot) = operation.snapshot.lock() {
                match result {
                    Ok(summary) => {
                        snapshot.state = "completed";
                        snapshot.message_count = Some(summary.remaining_count);
                    }
                    Err(error) => {
                        snapshot.state = "failed";
                        snapshot.error = Some(client_message("기록 삭제 오류", &error));
                    }
                }
            }
        } else if let Ok(mut snapshot) = operation.snapshot.lock() {
            snapshot.state = "failed";
            snapshot.error = Some("history deletion result state unavailable".to_owned());
        }
        #[cfg(test)]
        history::set_test_data_directory(None);
    });
    Ok(())
}

/// Reads the optional `allowLegacy` request field. Only a literal `true` lets a
/// weak-format backup through; a missing field means "reject", and any other
/// type is a malformed request (`None`).
pub(crate) fn take_legacy_policy(
    fields: &mut serde_json::Map<String, serde_json::Value>,
) -> Option<history::LegacyBackupPolicy> {
    match fields.remove("allowLegacy") {
        None | Some(serde_json::Value::Bool(false)) => Some(history::LegacyBackupPolicy::Reject),
        Some(serde_json::Value::Bool(true)) => Some(history::LegacyBackupPolicy::Allow),
        Some(_) => None,
    }
}

/// Issues a fresh one-time connection code. Every existing session ends, so a
/// token that leaked earlier cannot outlive the pairing it came from.
pub(crate) fn issue_code(state: &mut State) -> io::Result<()> {
    state.code = random_token()?;
    state.issued = Instant::now();
    state.attempts = 0;
    state.sessions.revoke_all();
    println!("로컬 연결 코드: {}", state.code);
    println!("새 연결 코드를 발급하려면 Enter를 누르세요.");
    Ok(())
}
