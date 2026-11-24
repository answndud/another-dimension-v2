//! Invitation and live chat routes.

use super::*;

pub(crate) fn invite_create(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    _request: Request<'_>,
) -> io::Result<()> {
    if state.tor_socks != state.settings.tor_socks || state.active_relays != state.settings.relays {
        return reject(stream, "409 Conflict");
    }
    if state.identity.is_none() {
        return reject(stream, IDENTITY_REQUIRED);
    }
    let invite = InviteCode::generate()?;
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        invite.code().as_bytes(),
    )
}

pub(crate) fn chat_start(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request {
        first,
        body,
        state_handle,
        ..
    } = request;
    if state.tor_socks != state.settings.tor_socks
        || state.active_relays != state.settings.relays
        || state.history_import_active
    {
        return reject(stream, "409 Conflict");
    }
    let Some(identity) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let (code, expected_peer, reconnect_role) = if first == "POST /api/chat/reconnect HTTP/1.1" {
        let Ok(peer) = history::decode_peer_id(body) else {
            return reject(stream, "400 Bad Request");
        };
        if peer == identity.public_key()
            || peer_chat_active(&state, body)
            || history_delete_active(&state, &identity.public_id(), body)
        {
            return reject(stream, "409 Conflict");
        }
        let directory = contacts::directory_for(&identity)?;
        let contact = match contacts::load(&directory, &identity, peer) {
            Ok(contact) => contact,
            Err(_) => return reject(stream, "404 Not Found"),
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
            return reject(stream, "400 Bad Request");
        }
        (Zeroizing::new(body.to_owned()), None, None)
    };
    let operation_id = random_token()?;
    let (sender, receiver) = mpsc::channel();
    let operation = Arc::new(ChatOperation {
        owner_identity_id: identity.public_id().to_owned(),
        history_state_lock: Mutex::new(()),
        snapshot: Mutex::new(ChatSnapshot {
            phase: "connecting",
            fingerprint: None,
            confirmation_code: None,
            peer_id: expected_peer.as_ref().map(|peer| crate::hex::encode(peer)),
            error: None,
            storage_error: None,
            messages: Vec::new(),
            message_count: 0,
            relay_ack: None,
            pending_sends: 0,
            identity_transition: None,
            history_restore_in_progress: false,
            history_restore_state: "idle",
            history_restore_estimate_bytes: 0,
            history_restore_cleanup_error: None,
            history_restore_offer: Vec::new(),
            history_restore_offer_count: 0,
            history_restore_legacy_count: 0,
            history_restore_received: 0,
            history_restore_total: 0,
            history_restore_status: None,
            message_epoch: 0,
        }),
        message_reader: Mutex::new(None),
        sender,
        cancelled: Arc::new(AtomicBool::new(false)),
    });
    let cancelled = Arc::clone(&operation.cancelled);
    let tor_socks = state.tor_socks;
    let relay_urls = state.active_relays.clone();
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
        state_handle,
        receiver,
        role,
        code,
        expected_peer,
        identity,
        cancelled,
        tor_socks,
        relay_urls,
        notifications_enabled,
        last_notification,
    );
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        operation_id.as_bytes(),
    )
}

pub(crate) fn chat_status(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(operation) = owned_chat_operation(&state, body) else {
        return reject(stream, "404 Not Found");
    };
    let Ok(snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    let payload = serde_json::json!({
        "phase": snapshot.phase,
        "fingerprint": snapshot.fingerprint,
        "confirmationCode": snapshot.confirmation_code,
        "peerId": snapshot.peer_id,
        "error": snapshot.error,
        "storageError": snapshot.storage_error,
        "relayAck": snapshot.relay_ack,
        "pendingSends": snapshot.pending_sends,
        "identityTransition": snapshot.identity_transition,
        "historyRestoreInProgress": snapshot.history_restore_in_progress,
        "historyRestoreState": snapshot.history_restore_state,
        "historyRestoreEstimateBytes": snapshot.history_restore_estimate_bytes,
        "historyRestoreCleanupError": snapshot.history_restore_cleanup_error,
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
        "messageCount": snapshot.message_count
    })
    .to_string();
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        payload.as_bytes(),
    )
}

pub(crate) fn chat_confirm(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(operation) = owned_chat_operation(&state, body) else {
        return reject(stream, "404 Not Found");
    };
    if operation.sender.send(ChatCommand::Confirm).is_err() {
        return reject(stream, "409 Conflict");
    }
    respond(stream, "202 Accepted", "text/plain; charset=utf-8", b"ok")
}

pub(crate) fn chat_request_history_restore(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(operation) = owned_chat_operation(&state, body).cloned() else {
        return reject(stream, "404 Not Found");
    };
    drop(state);
    if !operation
        .snapshot
        .lock()
        .is_ok_and(|snapshot| history_restore_request_allowed(&snapshot))
    {
        return reject(stream, "409 Conflict");
    }
    let (sender, receiver) = mpsc::channel();
    if operation
        .sender
        .send(ChatCommand::RequestHistoryRestore(sender))
        .is_err()
    {
        return reject(stream, "409 Conflict");
    }
    match receiver.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(())) => respond(stream, "202 Accepted", "text/plain; charset=utf-8", b"ok"),
        Ok(Err(error)) => respond(
            stream,
            "409 Conflict",
            "text/plain; charset=utf-8",
            error.as_bytes(),
        ),
        Err(_) => reject(stream, "409 Conflict"),
    }
}

pub(crate) fn chat_resolve_history_restore(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(operation_id) = payload
        .get("operationId")
        .and_then(serde_json::Value::as_str)
    else {
        return reject(stream, "400 Bad Request");
    };
    let Some(accept) = payload.get("accept").and_then(serde_json::Value::as_bool) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(operation) = owned_chat_operation(&state, operation_id) else {
        return reject(stream, "404 Not Found");
    };
    let Ok(mut snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    match reserve_history_restore_resolution(&mut snapshot, accept) {
        Ok(_) => {}
        Err(_) => return reject(stream, "409 Conflict"),
    }
    drop(snapshot);
    if operation
        .sender
        .send(ChatCommand::ResolveHistoryRestore(accept))
        .is_err()
    {
        if let Ok(mut snapshot) = operation.snapshot.lock() {
            snapshot.history_restore_state = "failed";
            snapshot.history_restore_in_progress = false;
            snapshot.history_restore_status =
                Some("복원 요청을 작업자에게 전달하지 못했습니다.".to_owned());
        }
        return reject(stream, "409 Conflict");
    }
    respond(
        stream,
        "202 Accepted",
        "text/plain; charset=utf-8",
        b"accepted; poll /api/chat/status for the result",
    )
}

pub(crate) fn chat_link_identity(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some((operation_id, previous_peer_id)) = body.split_once('\n') else {
        return reject(stream, "400 Bad Request");
    };
    let Some(operation) = owned_chat_operation(&state, operation_id).cloned() else {
        return reject(stream, "404 Not Found");
    };
    if history::decode_peer_id(previous_peer_id).is_err() {
        return reject(stream, "400 Bad Request");
    }
    let previous_peer_id = previous_peer_id.to_ascii_lowercase();
    let identity = state.identity.as_ref().cloned();
    // Linking copies the previous conversation and then deletes it. A chat with that
    // peer or a deletion of its history must not be running, and the state stays locked
    // until the worker answers so that neither can start meanwhile, nor a second link.
    // This is the one wait on the worker that keeps the lock (see SF-022).
    if peer_chat_active(&state, &previous_peer_id)
        || identity.as_ref().is_some_and(|identity| {
            history_delete_active(&state, &identity.public_id(), &previous_peer_id)
        })
    {
        return reject(stream, "409 Conflict");
    }
    let Ok(snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    if snapshot.phase != "connected"
        || !snapshot
            .identity_transition
            .as_ref()
            .is_some_and(|ids| ids.iter().any(|id| id == &previous_peer_id))
    {
        return reject(stream, "409 Conflict");
    }
    drop(snapshot);
    let Some(identity) = identity else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let contact_directory = contacts::directory_for(&identity)?;
    let Ok(previous_peer_key) = history::decode_peer_id(&previous_peer_id) else {
        return reject(stream, "400 Bad Request");
    };
    if contacts::load(&contact_directory, &identity, previous_peer_key).is_err() {
        return reject(stream, "409 Conflict");
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
        return reject(stream, "409 Conflict");
    }
    match result_receiver.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok"),
        Ok(Err(error)) => respond(
            stream,
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            error.as_bytes(),
        ),
        Err(_) => reject(stream, "409 Conflict"),
    }
}

pub(crate) fn chat_cancel(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(operation) = owned_chat_operation(&state, body) else {
        return reject(stream, "404 Not Found");
    };
    let merge_accepted = operation
        .snapshot
        .lock()
        .is_ok_and(|snapshot| matches!(snapshot.history_restore_state, "merge-queued" | "merging"));
    if !merge_accepted {
        operation.cancelled.store(true, Ordering::SeqCst);
    }
    let _ = operation.sender.send(ChatCommand::Cancel);
    respond(stream, "202 Accepted", "text/plain; charset=utf-8", b"ok")
}

pub(crate) fn chat_send(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some((operation_id, text)) = body.split_once('\n') else {
        return reject(stream, "400 Bad Request");
    };
    if text.trim().is_empty()
        || text.len() > 4078
        || text.as_bytes().starts_with(CHAT_CONTROL_PREFIX)
        || text
            .as_bytes()
            .starts_with(history::IDENTITY_EVENT_PREFIX.as_bytes())
        || text.contains('\0')
    {
        return reject(stream, "400 Bad Request");
    }
    let Some(operation) = owned_chat_operation(&state, operation_id).cloned() else {
        return reject(stream, "404 Not Found");
    };
    // Waiting for the worker below can take seconds; nothing else may wait on the state.
    drop(state);
    let Ok(snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    if snapshot.phase != "connected" {
        return reject(stream, "409 Conflict");
    }
    if history_restore_is_merging(snapshot.history_restore_state) {
        return respond(
            stream,
            "409 Conflict",
            "text/plain; charset=utf-8",
            RESTORE_MERGE_SEND_REJECTION.as_bytes(),
        );
    }
    drop(snapshot);
    if let Err(error) =
        submit_chat_message(&operation.sender, text.to_owned(), Duration::from_secs(10))
    {
        let status = if error == RESTORE_MERGE_SEND_REJECTION {
            "409 Conflict"
        } else {
            "503 Service Unavailable"
        };
        return respond(
            stream,
            status,
            "text/plain; charset=utf-8",
            error.as_bytes(),
        );
    }
    respond(stream, "202 Accepted", "text/plain; charset=utf-8", b"ok")
}

pub(crate) fn chat_messages(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some((operation_id, cursor)) = body.split_once('\n') else {
        return reject(stream, "400 Bad Request");
    };
    let Ok(cursor) = cursor.parse::<usize>() else {
        return reject(stream, "400 Bad Request");
    };
    let Some(operation) = owned_chat_operation(&state, operation_id).cloned() else {
        return reject(stream, "404 Not Found");
    };
    let identity = state.identity.as_ref().cloned();
    let Ok(snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    let peer_id = snapshot.peer_id.clone();
    let epoch = snapshot.message_epoch;
    let message_count = snapshot.message_count;
    let fallback = snapshot
        .messages
        .iter()
        .skip(cursor)
        .take(256)
        .cloned()
        .collect::<Vec<_>>();
    drop(snapshot);
    drop(state);
    let messages: Vec<_> = if let (Some(identity), Some(peer_id)) = (identity, peer_id.as_deref()) {
        let Ok(mut reader_state) = operation.message_reader.lock() else {
            return reject(stream, "503 Service Unavailable");
        };
        match read_chat_history_page(
            &mut reader_state,
            &identity,
            peer_id,
            epoch,
            cursor,
            message_count,
            256,
        ) {
                Ok(page) => page.iter().map(|message| serde_json::json!({
                    "time": message.unix_time,
                    "sender": if message.sender == history::MessageSender::Me { "나" } else { "상대방" },
                    "text": message.text
                })).collect(),
                Err(_) => return reject(stream, "500 Internal Server Error"),
        }
    } else {
        fallback
            .iter()
            .map(|message| {
                serde_json::json!({
                    "time": message.unix_time, "sender": message.sender, "text": message.text
                })
            })
            .collect()
    };
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        serde_json::to_string(&messages)?.as_bytes(),
    )
}
