//! Request routing: one table maps every (method, path) to its handler.
//!
//! A request line that names a known path with another method gets 405, and any other
//! gets 404. The handlers live in the sibling modules, one group per area.

mod account;
mod backup_transfer;
mod chat;
mod contact_backup;
mod conversations;
mod preferences;

use super::*;
use account::*;
use backup_transfer::*;
use chat::*;
use contact_backup::*;
use conversations::*;
use preferences::*;
use std::sync::MutexGuard;

/// What a handler is given besides the connection and the locked state.
pub(crate) struct Request<'a> {
    /// The request line, for the handlers that serve more than one path.
    pub(crate) first: &'a str,
    pub(crate) body: &'a str,
    /// The bearer token, or an empty string when none was sent.
    pub(crate) token: &'a str,
    pub(crate) state_handle: Arc<Mutex<State>>,
}

type Handler = fn(&mut TcpStream, MutexGuard<'_, State>, Request<'_>) -> io::Result<()>;

pub(crate) enum Target {
    Asset {
        content_type: &'static str,
        body: &'static [u8],
    },
    Api {
        handler: Handler,
        /// Whether a live session token is required. Only the connection code
        /// exchange is open without one.
        session: bool,
    },
}

pub(crate) struct Route {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) target: Target,
}

#[rustfmt::skip]
pub(crate) const ROUTES: &[Route] = &[
    Route { method: "GET", path: "/", target: Target::Asset { content_type: "text/html; charset=utf-8", body: PAGE } },
    Route { method: "GET", path: "/app.css", target: Target::Asset { content_type: "text/css; charset=utf-8", body: STYLESHEET } },
    Route { method: "GET", path: "/app.js", target: Target::Asset { content_type: "text/javascript; charset=utf-8", body: SCRIPT } },
    Route { method: "GET", path: "/reprotect-work.js", target: Target::Asset { content_type: "text/javascript; charset=utf-8", body: REPROTECT_WORK_SCRIPT } },
    Route { method: "POST", path: "/api/chat/cancel", target: Target::Api { handler: chat_cancel, session: true } },
    Route { method: "POST", path: "/api/chat/confirm", target: Target::Api { handler: chat_confirm, session: true } },
    Route { method: "POST", path: "/api/chat/create", target: Target::Api { handler: chat_start, session: true } },
    Route { method: "POST", path: "/api/chat/join", target: Target::Api { handler: chat_start, session: true } },
    Route { method: "POST", path: "/api/chat/link-identity", target: Target::Api { handler: chat_link_identity, session: true } },
    Route { method: "POST", path: "/api/chat/messages", target: Target::Api { handler: chat_messages, session: true } },
    Route { method: "POST", path: "/api/chat/reconnect", target: Target::Api { handler: chat_start, session: true } },
    Route { method: "POST", path: "/api/chat/request-history-restore", target: Target::Api { handler: chat_request_history_restore, session: true } },
    Route { method: "POST", path: "/api/chat/resolve-history-restore", target: Target::Api { handler: chat_resolve_history_restore, session: true } },
    Route { method: "POST", path: "/api/chat/send", target: Target::Api { handler: chat_send, session: true } },
    Route { method: "POST", path: "/api/chat/status", target: Target::Api { handler: chat_status, session: true } },
    Route { method: "POST", path: "/api/connect", target: Target::Api { handler: connect, session: false } },
    Route { method: "POST", path: "/api/contacts/export-backup", target: Target::Api { handler: contacts_export_backup, session: true } },
    Route { method: "POST", path: "/api/contacts/import-backup", target: Target::Api { handler: contacts_import_backup, session: true } },
    Route { method: "POST", path: "/api/disconnect", target: Target::Api { handler: disconnect, session: true } },
    Route { method: "POST", path: "/api/history/backup-transfer", target: Target::Api { handler: history_backup_transfer, session: true } },
    Route { method: "POST", path: "/api/history/delete-conversation", target: Target::Api { handler: history_delete_conversation, session: true } },
    Route { method: "POST", path: "/api/history/delete-messages", target: Target::Api { handler: history_delete_messages, session: true } },
    Route { method: "POST", path: "/api/history/delete-range", target: Target::Api { handler: history_delete_range, session: true } },
    Route { method: "POST", path: "/api/history/delete-status", target: Target::Api { handler: history_delete_status, session: true } },
    Route { method: "POST", path: "/api/history/list", target: Target::Api { handler: history_list, session: true } },
    Route { method: "POST", path: "/api/history/messages", target: Target::Api { handler: history_messages, session: true } },
    Route { method: "POST", path: "/api/identity/add-code", target: Target::Api { handler: identity_add_code, session: true } },
    Route { method: "POST", path: "/api/identity/create", target: Target::Api { handler: identity_create, session: true } },
    Route { method: "POST", path: "/api/identity/login", target: Target::Api { handler: identity_login, session: true } },
    Route { method: "POST", path: "/api/identity/logout", target: Target::Api { handler: identity_logout, session: true } },
    Route { method: "POST", path: "/api/identity/replace", target: Target::Api { handler: identity_replace, session: true } },
    Route { method: "POST", path: "/api/identity/status", target: Target::Api { handler: identity_status, session: true } },
    Route { method: "POST", path: "/api/invite/create", target: Target::Api { handler: invite_create, session: true } },
    Route { method: "POST", path: "/api/network/mode", target: Target::Api { handler: network_mode, session: true } },
    Route { method: "POST", path: "/api/session", target: Target::Api { handler: session_check, session: true } },
    Route { method: "POST", path: "/api/settings/get", target: Target::Api { handler: settings_get, session: true } },
    Route { method: "POST", path: "/api/settings/save", target: Target::Api { handler: settings_save, session: true } },
];

/// Finds the route for a request line, or the status to refuse it with.
fn find_route(request_line: &str) -> Result<&'static Route, &'static str> {
    let Some((method, rest)) = request_line.split_once(' ') else {
        return Err("404 Not Found");
    };
    let Some((path, "HTTP/1.1")) = rest.rsplit_once(' ') else {
        return Err("404 Not Found");
    };
    if let Some(route) = ROUTES
        .iter()
        .find(|route| route.method == method && route.path == path)
    {
        return Ok(route);
    }
    if ROUTES.iter().any(|route| route.path == path) {
        Err("405 Method Not Allowed")
    } else {
        Err("404 Not Found")
    }
}

fn session_check(
    stream: &mut TcpStream,
    _state: MutexGuard<'_, State>,
    _request: Request<'_>,
) -> io::Result<()> {
    respond(stream, "200 OK", "text/plain; charset=utf-8", b"ok")
}

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
    let route = match find_route(first) {
        Ok(route) => route,
        Err(status) => return reject(&mut stream, status),
    };
    let (handler, session_required) = match route.target {
        Target::Asset { content_type, body } => {
            return respond(&mut stream, "200 OK", content_type, body);
        }
        Target::Api { handler, session } => (handler, session),
    };
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
    let mut state_guard = state
        .lock()
        .map_err(|_| io::Error::other("state unavailable"))?;
    let token = auth
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if session_required && !state_guard.sessions.authorize(token, Instant::now()) {
        return reject(&mut stream, "401 Unauthorized");
    }
    handler(
        &mut stream,
        state_guard,
        Request {
            first: &first,
            body,
            token,
            state_handle,
        },
    )
}
