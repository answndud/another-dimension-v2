//! Request routing and the API handlers.

use super::*;

pub(crate) fn handle(
    mut stream: TcpStream,
    expected_host: &str,
    state: &Arc<Mutex<State>>,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Zeroizing::new(Vec::new());
    let header_end =
        match read_request_head(&mut stream, &mut request, Instant::now() + HEADER_DEADLINE) {
            Ok(end) => end,
            Err(error) => return reject(&mut stream, error.status()),
        };
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
        // A name with whitespace (for example "Host :") must not be silently ignored.
        if name.is_empty()
            || name
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return reject(&mut stream, "400 Bad Request");
        }
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
    if first == "GET /app.css HTTP/1.1" {
        return respond(&mut stream, "200 OK", "text/css; charset=utf-8", STYLESHEET);
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
            | "POST /api/history/delete-status HTTP/1.1"
            | "POST /api/history/delete-conversation HTTP/1.1"
            | "POST /api/history/backup-transfer HTTP/1.1"
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
    let body_len = match length
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<usize>().ok())
    {
        Some(value) if value <= MAX_BODY => value,
        _ => return reject(&mut stream, "400 Bad Request"),
    };
    let first = first.to_owned();
    let auth = authorization.map(str::to_owned);
    let mut body_buffer = Zeroizing::new([0; 8192]);
    let body_deadline = Instant::now() + BODY_DEADLINE;
    while request.len() < header_end + body_len {
        let n = match stream.read_within(body_buffer.as_mut(), body_deadline) {
            Ok(0) => return reject(&mut stream, "400 Bad Request"),
            Ok(n) => n,
            Err(error) => return reject(&mut stream, read_error(&error).status()),
        };
        request.extend_from_slice(&body_buffer[..n]);
    }
    if request.len() != header_end + body_len {
        return reject(&mut stream, "400 Bad Request");
    }
    let body = match std::str::from_utf8(&request[header_end..]) {
        Ok(value) => value,
        Err(_) => return reject(&mut stream, "400 Bad Request"),
    };
    let state_handle = Arc::clone(state);
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
        state.sessions.issue(token.clone(), Instant::now());
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
    if !state.sessions.authorize(token, Instant::now()) {
        return reject(&mut stream, "401 Unauthorized");
    }
    if first == "POST /api/disconnect HTTP/1.1" {
        state.sessions.revoke(token);
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
        let Some(relay_values) = value.get("relayUrls").and_then(serde_json::Value::as_array)
        else {
            return respond(
                &mut stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                b"relayUrls must be a non-empty array of wss URLs",
            );
        };
        let mut relays = Vec::with_capacity(relay_values.len());
        for relay_value in relay_values {
            let Some(relay_value) = relay_value.as_str() else {
                return respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    b"relayUrls must contain only strings",
                );
            };
            relays.push(relay_value.to_owned());
        }
        let relays = match relay::validate_relay_list(&relays) {
            Ok(relays) => relays,
            Err(error) => {
                return respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    error.as_bytes(),
                )
            }
        };
        let relay_changed = relays != state.settings.relays;
        if (tor_socks != state.tor_socks || relay_changed) && any_chat_active(&state) {
            return reject(&mut stream, "409 Conflict");
        }
        let settings = AppSettings {
            tor_socks,
            notifications,
            relays,
        };
        if let Err(error) = save_settings(&settings) {
            if error.kind() == io::ErrorKind::InvalidInput {
                return respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    client_message("요청 처리 오류", &error).as_bytes(),
                );
            }
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
            return reject(&mut stream, IDENTITY_REQUIRED);
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
            return reject(&mut stream, IDENTITY_REQUIRED);
        }
        if !body.is_empty()
            || any_chat_active(&state)
            || !state.active_history_deletions.is_empty()
            || state.history_import_active
        {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(current) = state.identity.as_ref() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
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
        if state.tor_socks != state.settings.tor_socks
            || state.active_relays != state.settings.relays
        {
            return reject(&mut stream, "409 Conflict");
        }
        if state.identity.is_none() {
            return reject(&mut stream, IDENTITY_REQUIRED);
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
        if state.tor_socks != state.settings.tor_socks
            || state.active_relays != state.settings.relays
            || state.history_import_active
        {
            return reject(&mut stream, "409 Conflict");
        }
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let (code, expected_peer, reconnect_role) = if first == "POST /api/chat/reconnect HTTP/1.1"
        {
            let Ok(peer) = history::decode_peer_id(body) else {
                return reject(&mut stream, "400 Bad Request");
            };
            if peer == identity.public_key()
                || peer_chat_active(&state, body)
                || history_delete_active(&state, &identity.public_id(), body)
            {
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
            owner_identity_id: identity.public_id().to_owned(),
            history_state_lock: Mutex::new(()),
            snapshot: Mutex::new(ChatSnapshot {
                phase: "connecting",
                fingerprint: None,
                confirmation_code: None,
                peer_id: expected_peer.as_ref().map(|peer| encode_hex(peer)),
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
        return respond(
            &mut stream,
            "200 OK",
            "text/plain; charset=utf-8",
            operation_id.as_bytes(),
        );
    }
    if first == "POST /api/chat/status HTTP/1.1" {
        let Some(operation) = owned_chat_operation(&state, body) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
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
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            payload.as_bytes(),
        );
    }
    if first == "POST /api/chat/confirm HTTP/1.1" {
        let Some(operation) = owned_chat_operation(&state, body) else {
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
        let Some(operation) = owned_chat_operation(&state, body) else {
            return reject(&mut stream, "404 Not Found");
        };
        if !operation
            .snapshot
            .lock()
            .is_ok_and(|snapshot| history_restore_request_allowed(&snapshot))
        {
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
        let Some(operation) = owned_chat_operation(&state, operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(mut snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        match reserve_history_restore_resolution(&mut snapshot, accept) {
            Ok(_) => {}
            Err(_) => return reject(&mut stream, "409 Conflict"),
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
            return reject(&mut stream, "409 Conflict");
        }
        return respond(
            &mut stream,
            "202 Accepted",
            "text/plain; charset=utf-8",
            b"accepted; poll /api/chat/status for the result",
        );
    }
    if first == "POST /api/chat/link-identity HTTP/1.1" {
        let Some((operation_id, previous_peer_id)) = body.split_once('\n') else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(operation) = owned_chat_operation(&state, operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        if history::decode_peer_id(previous_peer_id).is_err() {
            return reject(&mut stream, "400 Bad Request");
        }
        let previous_peer_id = previous_peer_id.to_ascii_lowercase();
        if peer_chat_active(&state, &previous_peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
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
            return reject(&mut stream, IDENTITY_REQUIRED);
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
        let Some(operation) = owned_chat_operation(&state, body) else {
            return reject(&mut stream, "404 Not Found");
        };
        let merge_accepted = operation.snapshot.lock().is_ok_and(|snapshot| {
            matches!(snapshot.history_restore_state, "merge-queued" | "merging")
        });
        if !merge_accepted {
            operation.cancelled.store(true, Ordering::SeqCst);
        }
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
        let Some(operation) = owned_chat_operation(&state, operation_id) else {
            return reject(&mut stream, "404 Not Found");
        };
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        if snapshot.phase != "connected" {
            return reject(&mut stream, "409 Conflict");
        }
        if history_restore_is_merging(snapshot.history_restore_state) {
            return respond(
                &mut stream,
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
                &mut stream,
                status,
                "text/plain; charset=utf-8",
                error.as_bytes(),
            );
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
        let Some(operation) = owned_chat_operation(&state, operation_id).cloned() else {
            return reject(&mut stream, "404 Not Found");
        };
        let identity = state.identity.as_ref().cloned();
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
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
        let messages: Vec<_> = if let (Some(identity), Some(peer_id)) =
            (identity, peer_id.as_deref())
        {
            let Ok(mut reader_state) = operation.message_reader.lock() else {
                return reject(&mut stream, "503 Service Unavailable");
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
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
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
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            serde_json::to_string(&messages)?.as_bytes(),
        );
    }
    if first == "POST /api/contacts/export-backup HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
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
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        if any_chat_active(&state)
            || !state.active_history_deletions.is_empty()
            || state.history_import_active
        {
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
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        drop(state);
        let summaries = match history::History::list(&identity) {
            Ok(summaries) => summaries,
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let directory = history::data_directory()?
            .join(identity.public_id())
            .join("verified-contacts");
        let verified: HashSet<_> = match contacts::list_known(&directory, &identity) {
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
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let Ok(request) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peer_id) = request.get("peerId").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let limit = request
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50);
        let Ok(limit) = usize::try_from(limit) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if limit == 0 || limit > 100 {
            return reject(&mut stream, "400 Bad Request");
        }
        let cursor = match request.get("cursor") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => {
                let Some(version) = value.get("version").and_then(serde_json::Value::as_str) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let (Some(offset), Some(index)) = (
                    value.get("offset").and_then(serde_json::Value::as_u64),
                    value.get("index").and_then(serde_json::Value::as_u64),
                ) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                Some(history::HistoryPageCursor {
                    version: version.to_owned(),
                    offset,
                    index,
                })
            }
        };
        let peer_id = peer_id.to_owned();
        drop(state);
        let page = match history::History::read_page(&identity, &peer_id, cursor.as_ref(), limit) {
            Ok(page) => page,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return reject(&mut stream, "409 Conflict")
            }
            Err(_) => return reject(&mut stream, "400 Bad Request"),
        };
        let payload = serde_json::json!({
            "version": page.version,
            "hasMore": page.next.is_some(),
            "nextCursor": page.next.map(|cursor| serde_json::json!({
                "version": cursor.version,
                "offset": cursor.offset,
                "index": cursor.index,
            })),
            "messages": page.entries.into_iter().map(|entry| {
                let item = entry.message;
                let signed = item.proof.is_some();
                serde_json::json!({
                    "index": entry.index,
                    "time": item.unix_time,
                    "sender": chat_entry(item.clone()).sender,
                    "text": chat_entry(item).text,
                    "signed": signed
                })
            }).collect::<Vec<_>>(),
        });
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            serde_json::to_string(&payload)?.as_bytes(),
        );
    }
    if first == "POST /api/history/delete-status HTTP/1.1" {
        let Some(identity_id) = state.identity.as_ref().map(|identity| identity.public_id()) else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let Some(operation) = state.history_deletions.get(body) else {
            return reject(&mut stream, "404 Not Found");
        };
        if operation.owner_identity_id != identity_id {
            return reject(&mut stream, "404 Not Found");
        }
        let Ok(snapshot) = operation.snapshot.lock() else {
            return reject(&mut stream, "503 Service Unavailable");
        };
        let payload = serde_json::json!({
            "state": snapshot.state,
            "peerId": operation.peer_id,
            "messageCount": snapshot.message_count,
            "error": snapshot.error,
        })
        .to_string();
        return respond(
            &mut stream,
            "200 OK",
            "application/json; charset=utf-8",
            payload.as_bytes(),
        );
    }
    if first == "POST /api/history/delete-messages HTTP/1.1" {
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(peer_id) = payload.get("peerId").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if history::decode_peer_id(peer_id).is_err() {
            return reject(&mut stream, "400 Bad Request");
        }
        if peer_chat_active(&state, peer_id) {
            return respond(
                &mut stream,
                "409 Conflict",
                "text/plain; charset=utf-8",
                b"disconnect the conversation and reload history before applying selection",
            );
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
        let Some(version) = payload.get("version").and_then(serde_json::Value::as_str) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(operation_id) = payload
            .get("operationId")
            .and_then(serde_json::Value::as_str)
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        if operation_id.is_empty() || operation_id.len() > 128 {
            return reject(&mut stream, "400 Bad Request");
        }
        let request_body = body.to_owned();
        let queued = queue_history_deletion(
            &mut state,
            Arc::clone(&state_handle),
            operation_id.to_owned(),
            request_body,
            identity,
            peer_id.to_owned(),
            HistoryDeletionAction::Selected {
                version: version.to_owned(),
                indices: selected,
            },
        );
        if let Err(error) = queued {
            return respond(
                &mut stream,
                "409 Conflict",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            );
        }
        drop(state);
        return respond(
            &mut stream,
            "202 Accepted",
            "application/json; charset=utf-8",
            serde_json::json!({"operationId": operation_id})
                .to_string()
                .as_bytes(),
        );
    }
    if first == "POST /api/history/delete-range HTTP/1.1" {
        let Some(identity) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let (Some(peer_id), Some(operation_id), Some(start), Some(end)) = (
            payload.get("peerId").and_then(serde_json::Value::as_str),
            payload
                .get("operationId")
                .and_then(serde_json::Value::as_str),
            payload.get("start").and_then(serde_json::Value::as_u64),
            payload.get("end").and_then(serde_json::Value::as_u64),
        ) else {
            return reject(&mut stream, "400 Bad Request");
        };
        if history::decode_peer_id(peer_id).is_err() {
            return reject(&mut stream, "400 Bad Request");
        }
        if operation_id.is_empty() || operation_id.len() > 128 {
            return reject(&mut stream, "400 Bad Request");
        }
        if peer_chat_active(&state, peer_id) {
            return reject(&mut stream, "409 Conflict");
        }
        if start > end {
            return reject(&mut stream, "400 Bad Request");
        }
        let request_body = body.to_owned();
        let queued = queue_history_deletion(
            &mut state,
            Arc::clone(&state_handle),
            operation_id.to_owned(),
            request_body,
            identity,
            peer_id.to_owned(),
            HistoryDeletionAction::TimeRange { start, end },
        );
        if let Err(error) = queued {
            return respond(
                &mut stream,
                "409 Conflict",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            );
        }
        drop(state);
        return respond(
            &mut stream,
            "202 Accepted",
            "application/json; charset=utf-8",
            serde_json::json!({"operationId": operation_id})
                .to_string()
                .as_bytes(),
        );
    }
    if first == "POST /api/history/delete-conversation HTTP/1.1" {
        let Some(identity) = state.identity.as_ref() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        if peer_chat_active(&state, body)
            || history_delete_active(&state, &identity.public_id(), body)
        {
            return reject(&mut stream, "409 Conflict");
        }
        if let Err(error) = history::History::delete_conversation(identity, body) {
            return respond(
                &mut stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                client_message("요청 처리 오류", &error).as_bytes(),
            );
        }
        update_closed_chat_history(&state, &identity.public_id(), body, 0);
        return respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok");
    }
    if first == "POST /api/history/backup-transfer HTTP/1.1" {
        // Owned, so the heavy actions below can release the State lock while they run.
        let Some(identity_owned) = state.identity.as_ref().cloned() else {
            return reject(&mut stream, IDENTITY_REQUIRED);
        };
        let identity = &identity_owned;
        let Ok(mut payload) = serde_json::from_str::<serde_json::Value>(body) else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(fields) = payload.as_object_mut() else {
            return reject(&mut stream, "400 Bad Request");
        };
        let Some(action) = fields
            .remove("action")
            .and_then(|v| v.as_str().map(str::to_owned))
        else {
            return reject(&mut stream, "400 Bad Request");
        };
        let transfer_dir = match history::History::backup_transfer_directory(identity) {
            Ok(path) => path,
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let transfer_owner = match history::History::backup_transfer_workspace_id(identity) {
            Ok(owner) => owner,
            Err(_) => return reject(&mut stream, "500 Internal Server Error"),
        };
        let new_transfer_id = || -> io::Result<String> {
            let entropy = random_token()?;
            Ok(format!(
                "{}{}",
                transfer_owner,
                &entropy[..64 - transfer_owner.len()]
            ))
        };
        let get_transfer_path = |id: &str| -> Option<PathBuf> {
            if id.len() != 64
                || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !id.to_ascii_lowercase().starts_with(&transfer_owner)
            {
                return None;
            }
            Some(transfer_dir.join(format!("{}.backup", id.to_ascii_lowercase())))
        };
        let response_json = |stream: &mut TcpStream, value: serde_json::Value| {
            let text = value.to_string();
            respond(
                stream,
                "200 OK",
                "application/json; charset=utf-8",
                text.as_bytes(),
            )
        };
        match action.as_str() {
            "export" | "bundle-export" => {
                let password = if action == "export" {
                    fields.remove("password").and_then(|v| {
                        v.as_str()
                            .filter(|s| !s.is_empty())
                            .map(|s| Zeroizing::new(s.to_owned()))
                    })
                } else {
                    None
                };
                let peer_ids: Vec<String> = if action == "export" {
                    let Some(peer) = fields
                        .remove("peerId")
                        .and_then(|v| v.as_str().map(str::to_owned))
                    else {
                        return reject(&mut stream, "400 Bad Request");
                    };
                    vec![peer]
                } else {
                    let Some(values) = fields.remove("peerIds").and_then(|v| v.as_array().cloned())
                    else {
                        return reject(&mut stream, "400 Bad Request");
                    };
                    let Some(peers) = values
                        .into_iter()
                        .map(|v| v.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                    else {
                        return reject(&mut stream, "400 Bad Request");
                    };
                    peers
                };
                if !fields.is_empty()
                    || peer_ids.iter().any(|peer| {
                        peer_chat_active(&state, peer)
                            || history_delete_active(&state, &identity.public_id(), peer)
                    })
                {
                    return reject(&mut stream, "409 Conflict");
                }
                // Export only reads history, so the State lock is not needed while it runs.
                drop(state);
                let id = match new_transfer_id() {
                    Ok(id) => id,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let mut created = false;
                let result = (|| -> io::Result<()> {
                    let (_, mut file) = history::History::create_backup_transfer_file(
                        identity,
                        &format!("{id}.backup"),
                    )?;
                    created = true;
                    if action == "export" {
                        history::History::export_backup_stream(
                            identity,
                            &peer_ids[0],
                            password.as_deref().map(String::as_str),
                            &mut file,
                        )?;
                    } else {
                        history::History::export_backup_bundle_stream(
                            identity, &peer_ids, &mut file,
                        )?;
                    }
                    file.flush()?;
                    file.sync_all()?;
                    Ok(())
                })();
                if let Err(error) = result {
                    if created {
                        let _ = std::fs::remove_file(&path);
                    }
                    let status = if error.kind() == io::ErrorKind::InvalidInput {
                        "400 Bad Request"
                    } else {
                        "500 Internal Server Error"
                    };
                    return respond(
                        &mut stream,
                        status,
                        "text/plain; charset=utf-8",
                        client_message("요청 처리 오류", &error).as_bytes(),
                    );
                }
                let size = match std::fs::metadata(&path) {
                    Ok(meta) => meta.len(),
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                return response_json(
                    &mut stream,
                    serde_json::json!({"transferId": id, "size": size}),
                );
            }
            "upload-start" => {
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                let id = match new_transfer_id() {
                    Ok(id) => id,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                let (_, _file) = match history::History::create_backup_transfer_file(
                    identity,
                    &format!("{id}.backup"),
                ) {
                    Ok(file) => file,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                return response_json(&mut stream, serde_json::json!({"transferId": id}));
            }
            "upload-chunk" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let Some(offset) = fields.remove("offset").and_then(|v| v.as_u64()) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let Some(encoded) = fields
                    .remove("data")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                let bytes = match BASE64.decode(encoded) {
                    Ok(bytes) if !bytes.is_empty() && bytes.len() <= 256 * 1024 => bytes,
                    _ => return reject(&mut stream, "400 Bad Request"),
                };
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let mut file = match crate::fsutil::private_options()
                    .read(true)
                    .append(true)
                    .open(path)
                {
                    Ok(file) => file,
                    Err(_) => return reject(&mut stream, "404 Not Found"),
                };
                if file
                    .metadata()
                    .map_or(true, |metadata| metadata.len() != offset)
                {
                    return reject(&mut stream, "409 Conflict");
                }
                if file.write_all(&bytes).and_then(|_| file.flush()).is_err() {
                    return reject(&mut stream, "507 Insufficient Storage");
                }
                return response_json(
                    &mut stream,
                    serde_json::json!({"offset": offset + bytes.len() as u64}),
                );
            }
            "read" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let Some(offset) = fields.remove("offset").and_then(|v| v.as_u64()) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let mut file = match File::open(path) {
                    Ok(file) => file,
                    Err(_) => return reject(&mut stream, "404 Not Found"),
                };
                let size = match file.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                if offset > size {
                    return reject(&mut stream, "416 Range Not Satisfiable");
                }
                if file.seek(io::SeekFrom::Start(offset)).is_err() {
                    return reject(&mut stream, "500 Internal Server Error");
                }
                let mut chunk = vec![0; 256 * 1024];
                let read = match file.read(&mut chunk) {
                    Ok(read) => read,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                chunk.truncate(read);
                return response_json(
                    &mut stream,
                    serde_json::json!({"transferId": id, "offset": offset, "size": size, "data": BASE64.encode(&chunk), "done": offset + read as u64 == size}),
                );
            }
            "import" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let password = fields
                    .remove("password")
                    .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                    .filter(|v| !v.is_empty());
                let Some(policy) = take_legacy_policy(fields) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                if !fields.is_empty()
                    || any_chat_active(&state)
                    || !state.active_history_deletions.is_empty()
                    || state.history_import_active
                {
                    return reject(&mut stream, "409 Conflict");
                }
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                // Reserve the import under the lock, then release it: a large import must
                // not freeze every other request. The reservation keeps chats, other
                // imports and deletions out until it ends (the guard also clears it on panic).
                state.history_import_active = true;
                drop(state);
                let _import_guard = ImportGuard(Arc::clone(&state_handle));
                let result = history::History::import_backup_file_with_policy(
                    identity,
                    &path,
                    password.as_deref().map(String::as_str),
                    policy,
                );
                let cleanup = std::fs::remove_file(&path);
                let restored = match (result, cleanup) {
                    (Ok(restored), Ok(())) => restored,
                    (Err(error), Ok(())) => {
                        return respond(
                            &mut stream,
                            "400 Bad Request",
                            "text/plain; charset=utf-8",
                            client_message("백업 가져오기 오류", &error).as_bytes(),
                        )
                    }
                    (Ok(_), Err(error)) => {
                        return respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain; charset=utf-8",
                            format!(
                                "backup import completed but temporary upload cleanup failed ({})",
                                client_message("백업 업로드 정리 오류", &error)
                            )
                            .as_bytes(),
                        )
                    }
                    (Err(error), Err(cleanup)) => {
                        return respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain; charset=utf-8",
                            format!(
                                "backup import failed ({}); temporary upload cleanup failed ({})",
                                client_message("백업 가져오기 오류", &error),
                                client_message("백업 업로드 정리 오류", &cleanup)
                            )
                            .as_bytes(),
                        )
                    }
                };
                {
                    let state = state_handle
                        .lock()
                        .map_err(|_| io::Error::other("state unavailable"))?;
                    for (peer_id, message_count, _) in &restored {
                        update_closed_chat_history(
                            &state,
                            &identity.public_id(),
                            peer_id,
                            *message_count as u64,
                        );
                    }
                }
                let response = if restored.len() == 1 {
                    let (peer_id, count, linked) = &restored[0];
                    serde_json::json!({"peerId": peer_id, "messageCount": count, "linkedIdentityRestored": linked})
                } else {
                    serde_json::json!({"conversations": restored.iter().map(|(peer_id,count,linked)| serde_json::json!({"peerId":peer_id,"messageCount":count,"linkedIdentityRestored":linked})).collect::<Vec<_>>()})
                };
                return response_json(&mut stream, response);
            }
            "verify" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let password = fields
                    .remove("password")
                    .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                    .filter(|v| !v.is_empty());
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                drop(state);
                return match history::History::verify_backup_file(
                    identity,
                    &path,
                    password.as_deref().map(String::as_str),
                ) {
                    Ok((peer_id, count)) => response_json(
                        &mut stream,
                        serde_json::json!({"peerId": peer_id, "messageCount": count}),
                    ),
                    Err(error) => respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain; charset=utf-8",
                        client_message("요청 처리 오류", &error).as_bytes(),
                    ),
                };
            }
            "reprotect" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let Some(previous_code) = fields
                    .remove("previousCode")
                    .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let previous_password = fields
                    .remove("previousPassword")
                    .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                    .filter(|v| !v.is_empty());
                let replacement_password = fields
                    .remove("replacementPassword")
                    .and_then(|v| v.as_str().map(|s| Zeroizing::new(s.to_owned())))
                    .filter(|v| !v.is_empty());
                let Some(policy) = take_legacy_policy(fields) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                drop(state);
                let Some(previous_identity) = Identity::from_code(&previous_code) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let Some(source_path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let output_id = match new_transfer_id() {
                    Ok(id) => id,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                let Some(output_path) = get_transfer_path(&output_id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                let (_, mut output) = match history::History::create_backup_transfer_file(
                    identity,
                    &format!("{output_id}.backup"),
                ) {
                    Ok(file) => file,
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                let result = history::History::reprotect_backup_file_with_policy(
                    &previous_identity,
                    identity,
                    &source_path,
                    &mut output,
                    previous_password.as_deref().map(String::as_str),
                    replacement_password.as_deref().map(String::as_str),
                    policy,
                );
                let result = result.and_then(|count| {
                    output.flush()?;
                    output.sync_all()?;
                    Ok(count)
                });
                drop(output);
                let cleanup_source = std::fs::remove_file(&source_path);
                let count = match (result, cleanup_source) {
                    (Ok(count), Ok(())) => count,
                    (Err(error), Ok(())) => {
                        let _ = std::fs::remove_file(&output_path);
                        return respond(
                            &mut stream,
                            "400 Bad Request",
                            "text/plain; charset=utf-8",
                            client_message("요청 처리 오류", &error).as_bytes(),
                        );
                    }
                    (Ok(_), Err(error)) => {
                        let _ = std::fs::remove_file(&output_path);
                        return respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain; charset=utf-8",
                            format!(
                                "reprotection completed but temporary upload cleanup failed ({})",
                                client_message("재보호 업로드 정리 오류", &error)
                            )
                            .as_bytes(),
                        );
                    }
                    (Err(error), Err(cleanup)) => {
                        let _ = std::fs::remove_file(&output_path);
                        return respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain; charset=utf-8",
                            format!(
                                "reprotection failed ({}); temporary upload cleanup failed ({})",
                                client_message("재보호 오류", &error),
                                client_message("재보호 업로드 정리 오류", &cleanup)
                            )
                            .as_bytes(),
                        );
                    }
                };
                let size = match std::fs::metadata(&output_path) {
                    Ok(meta) => meta.len(),
                    Err(_) => return reject(&mut stream, "500 Internal Server Error"),
                };
                return response_json(
                    &mut stream,
                    serde_json::json!({"transferId": output_id, "size": size, "messageCount": count}),
                );
            }
            "cleanup" => {
                let Some(id) = fields
                    .remove("transferId")
                    .and_then(|v| v.as_str().map(str::to_owned))
                else {
                    return reject(&mut stream, "400 Bad Request");
                };
                if !fields.is_empty() {
                    return reject(&mut stream, "400 Bad Request");
                }
                let Some(path) = get_transfer_path(&id) else {
                    return reject(&mut stream, "400 Bad Request");
                };
                return match std::fs::remove_file(path) {
                    Ok(()) => response_json(&mut stream, serde_json::json!({"ok": true})),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        response_json(&mut stream, serde_json::json!({"ok": true}))
                    }
                    Err(error) => respond(
                        &mut stream,
                        "500 Internal Server Error",
                        "text/plain; charset=utf-8",
                        client_message("요청 처리 오류", &error).as_bytes(),
                    ),
                };
            }
            _ => return reject(&mut stream, "400 Bad Request"),
        }
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
                return reject(&mut stream, IDENTITY_REQUIRED);
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
                let merge_accepted = operation.snapshot.lock().is_ok_and(|snapshot| {
                    matches!(snapshot.history_restore_state, "merge-queued" | "merging")
                });
                if !merge_accepted {
                    operation.cancelled.store(true, Ordering::SeqCst);
                }
                let _ = operation.sender.send(ChatCommand::Cancel);
            }
            state.identity = None;
            // Logging out ends every session, including this one, and prints a new
            // connection code. Otherwise a copied token would still work for the
            // next identity that logs in.
            issue_code(&mut state)?;
        }
        _ => {}
    }
    respond(&mut stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}
