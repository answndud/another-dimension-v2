//! Connection code, session and identity routes.

use super::*;

pub(crate) fn identity_create(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    _request: Request<'_>,
) -> io::Result<()> {
    if state.identity.is_some() {
        return reject(stream, "409 Conflict");
    }
    let (identity, code) = Identity::create()?;
    // Do not activate a new identity unless the response was written successfully.
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        code.as_bytes(),
    )?;
    state.identity = Some(Arc::new(identity));
    Ok(())
}

pub(crate) fn identity_login(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    if state.identity.is_some() {
        return reject(stream, "409 Conflict");
    }
    let Some(identity) = Identity::from_code(body) else {
        return reject(stream, "400 Bad Request");
    };
    state.identity = Some(Arc::new(identity));
    respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}

pub(crate) fn identity_status(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    _request: Request<'_>,
) -> io::Result<()> {
    let Some(identity) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        identity.public_id().as_bytes(),
    )
}

pub(crate) fn identity_logout(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { token: _, .. } = request;
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
    // The snapshots of ended chats hold the plaintext of their messages. Nothing can
    // read them once the identity is gone, so they should not stay in memory.
    forget_finished_chats(&mut state);
    // Logging out ends every session, including this one, and prints a new
    // connection code. Otherwise a copied token would still work for the
    // next identity that logs in.
    issue_code(&mut state)?;
    respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}

pub(crate) fn identity_add_code(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    if !body.is_empty() {
        return reject(stream, "400 Bad Request");
    }
    let code = identity.create_access_code()?;
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        code.as_bytes(),
    )
}

pub(crate) fn identity_replace(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    if state.identity.is_none() {
        return reject(stream, IDENTITY_REQUIRED);
    }
    if !body.is_empty()
        || any_chat_active(&state)
        || !state.active_history_deletions.is_empty()
        || state.history_import_active
    {
        return reject(stream, "409 Conflict");
    }
    let Some(current) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let (replacement, code) = Identity::create()?;
    if current.copy_local_data_to(&replacement).is_err() {
        return reject(stream, "500 Internal Server Error");
    }
    // Keep the old session active if the one-time code cannot be delivered.
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        code.as_bytes(),
    )?;
    state.identity = Some(Arc::new(replacement));
    Ok(())
}

pub(crate) fn connect(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, token: _, .. } = request;
    if state.code.is_empty()
        || state.issued.elapsed() >= CODE_LIFETIME
        || state.attempts >= MAX_ATTEMPTS
    {
        return reject(stream, "403 Forbidden");
    }
    if !equal_token(body, &state.code) {
        state.attempts += 1;
        return reject(stream, "403 Forbidden");
    }
    let token = random_token()?;
    state.code.clear();
    state.sessions.issue(token.clone(), Instant::now());
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        token.as_bytes(),
    )
}

pub(crate) fn disconnect(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { token, .. } = request;
    state.sessions.revoke(token);
    respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}
