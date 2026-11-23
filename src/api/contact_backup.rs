//! Verified-contact backup routes.

use super::*;

pub(crate) fn contacts_export_backup(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    let Ok(peer) = history::decode_peer_id(body) else {
        return reject(stream, "400 Bad Request");
    };
    let directory = contacts::directory_for(identity)?;
    let contact = match contacts::load(&directory, identity, peer) {
        Ok(contact) => contact,
        Err(_) => return reject(stream, "404 Not Found"),
    };
    let backup = contacts::export_backup(identity, &contact)?;
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        BASE64.encode(backup).as_bytes(),
    )
}

pub(crate) fn contacts_import_backup(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Some(identity) = state.identity.as_ref() else {
        return reject(stream, IDENTITY_REQUIRED);
    };
    if any_chat_active(&state)
        || !state.active_history_deletions.is_empty()
        || state.history_import_active
    {
        return reject(stream, "409 Conflict");
    }
    if body.len() > 256 {
        return reject(stream, "400 Bad Request");
    }
    let Ok(backup) = BASE64.decode(body) else {
        return reject(stream, "400 Bad Request");
    };
    let directory = contacts::directory_for(identity)?;
    let peer = match contacts::import_backup(&directory, identity, &backup) {
        Ok(peer) => peer,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return reject(stream, "409 Conflict")
        }
        Err(_) => return reject(stream, "400 Bad Request"),
    };
    let peer_id = crate::hex::encode(&peer);
    if history::History::open(identity, &peer_id).is_err() {
        return reject(stream, "500 Internal Server Error");
    }
    respond(
        stream,
        "200 OK",
        "text/plain; charset=utf-8",
        peer_id.as_bytes(),
    )
}
