//! Stored conversation routes.

use super::*;

pub(crate) fn history_list(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    _request: Request<'_>,
) -> io::Result<()> {
    let Some(identity) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    drop(state);
    let summaries = match history::History::list(&identity) {
        Ok(summaries) => summaries,
        Err(_) => return reject(stream, "500 Internal Server Error"),
    };
    let directory = contacts::directory_for(&identity)?;
    let verified: HashSet<_> = match contacts::list_known(&directory, &identity) {
        Ok(contacts) => contacts
            .into_iter()
            .map(|contact| crate::hex::encode(&contact.peer_key))
            .collect(),
        Err(_) => return reject(stream, "500 Internal Server Error"),
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
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        serde_json::to_string(&payload)?.as_bytes(),
    )
}

pub(crate) fn history_messages(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let Ok(request) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(peer_id) = request.get("peerId").and_then(serde_json::Value::as_str) else {
        return reject(stream, "400 Bad Request");
    };
    let limit = request
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(50);
    let Ok(limit) = usize::try_from(limit) else {
        return reject(stream, "400 Bad Request");
    };
    if limit == 0 || limit > 100 {
        return reject(stream, "400 Bad Request");
    }
    let cursor = match request.get("cursor") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let Some(version) = value.get("version").and_then(serde_json::Value::as_str) else {
                return reject(stream, "400 Bad Request");
            };
            let (Some(offset), Some(index)) = (
                value.get("offset").and_then(serde_json::Value::as_u64),
                value.get("index").and_then(serde_json::Value::as_u64),
            ) else {
                return reject(stream, "400 Bad Request");
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
            return reject(stream, "409 Conflict")
        }
        Err(_) => return reject(stream, "400 Bad Request"),
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
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        serde_json::to_string(&payload)?.as_bytes(),
    )
}

pub(crate) fn history_delete_status(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity_id) = state.identity.as_ref().map(|identity| identity.public_id()) else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let Some(operation) = state.history_deletions.get(body) else {
        return reject(stream, "404 Not Found");
    };
    if operation.owner_identity_id != identity_id {
        return reject(stream, "404 Not Found");
    }
    let Ok(snapshot) = operation.snapshot.lock() else {
        return reject(stream, "503 Service Unavailable");
    };
    let payload = serde_json::json!({
        "state": snapshot.state,
        "peerId": operation.peer_id,
        "messageCount": snapshot.message_count,
        "error": snapshot.error,
    })
    .to_string();
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        payload.as_bytes(),
    )
}

pub(crate) fn history_delete_messages(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request {
        body, state_handle, ..
    } = request;
    let Some(identity) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(peer_id) = payload.get("peerId").and_then(serde_json::Value::as_str) else {
        return reject(stream, "400 Bad Request");
    };
    if history::decode_peer_id(peer_id).is_err() {
        return reject(stream, "400 Bad Request");
    }
    if peer_chat_active(&state, peer_id) {
        return respond(
            stream,
            "409 Conflict",
            "text/plain; charset=utf-8",
            b"disconnect the conversation and reload history before applying selection",
        );
    }
    let Some(indices) = payload.get("indices").and_then(serde_json::Value::as_array) else {
        return reject(stream, "400 Bad Request");
    };
    if indices.is_empty() || indices.len() > 100_000 {
        return reject(stream, "400 Bad Request");
    }
    let mut selected = HashSet::with_capacity(indices.len());
    for index in indices {
        let Some(index) = index.as_u64().and_then(|value| usize::try_from(value).ok()) else {
            return reject(stream, "400 Bad Request");
        };
        selected.insert(index);
    }
    let Some(version) = payload.get("version").and_then(serde_json::Value::as_str) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(operation_id) = payload
        .get("operationId")
        .and_then(serde_json::Value::as_str)
    else {
        return reject(stream, "400 Bad Request");
    };
    if operation_id.is_empty() || operation_id.len() > 128 {
        return reject(stream, "400 Bad Request");
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
            stream,
            "409 Conflict",
            "text/plain; charset=utf-8",
            error.as_bytes(),
        );
    }
    drop(state);
    respond(
        stream,
        "202 Accepted",
        "application/json; charset=utf-8",
        serde_json::json!({"operationId": operation_id})
            .to_string()
            .as_bytes(),
    )
}

pub(crate) fn history_delete_range(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request {
        body, state_handle, ..
    } = request;
    let Some(identity) = state.identity.as_ref().cloned() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let (Some(peer_id), Some(operation_id), Some(start), Some(end)) = (
        payload.get("peerId").and_then(serde_json::Value::as_str),
        payload
            .get("operationId")
            .and_then(serde_json::Value::as_str),
        payload.get("start").and_then(serde_json::Value::as_u64),
        payload.get("end").and_then(serde_json::Value::as_u64),
    ) else {
        return reject(stream, "400 Bad Request");
    };
    if history::decode_peer_id(peer_id).is_err() {
        return reject(stream, "400 Bad Request");
    }
    if operation_id.is_empty() || operation_id.len() > 128 {
        return reject(stream, "400 Bad Request");
    }
    if peer_chat_active(&state, peer_id) {
        return reject(stream, "409 Conflict");
    }
    if start > end {
        return reject(stream, "400 Bad Request");
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
            stream,
            "409 Conflict",
            "text/plain; charset=utf-8",
            error.as_bytes(),
        );
    }
    drop(state);
    respond(
        stream,
        "202 Accepted",
        "application/json; charset=utf-8",
        serde_json::json!({"operationId": operation_id})
            .to_string()
            .as_bytes(),
    )
}

pub(crate) fn history_delete_conversation(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    if peer_chat_active(&state, body) || history_delete_active(&state, &identity.public_id(), body)
    {
        return reject(stream, "409 Conflict");
    }
    if let Err(error) = history::History::delete_conversation(identity, body) {
        return respond(
            stream,
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            client_message("요청 처리 오류", &error).as_bytes(),
        );
    }
    update_closed_chat_history(&state, &identity.public_id(), body, 0);
    respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}
