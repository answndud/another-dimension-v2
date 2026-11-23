//! Network and preference routes.

use super::*;

pub(crate) fn network_mode(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    if !body.is_empty() {
        return reject(stream, "400 Bad Request");
    }
    respond_settings(stream, &state)
}

pub(crate) fn settings_get(
    stream: &mut TcpStream,
    state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    if !body.is_empty() {
        return reject(stream, "400 Bad Request");
    }
    respond_settings(stream, &state)
}

pub(crate) fn settings_save(
    stream: &mut TcpStream,
    mut state: MutexGuard<'_, State>,
    request: Request<'_>,
) -> io::Result<()> {
    let Request { body, .. } = request;
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return reject(stream, "400 Bad Request");
    };
    let Some(mode) = value.get("mode").and_then(serde_json::Value::as_str) else {
        return reject(stream, "400 Bad Request");
    };
    let tor_socks = match mode {
        "general" => None,
        "tor" => {
            let Some(address) = value.get("socks").and_then(serde_json::Value::as_str) else {
                return reject(stream, "400 Bad Request");
            };
            match parse_loopback_socks(address) {
                Ok(address) => Some(address),
                Err(_) => return reject(stream, "400 Bad Request"),
            }
        }
        _ => return reject(stream, "400 Bad Request"),
    };
    let Some(notifications) = value
        .get("notifications")
        .and_then(serde_json::Value::as_bool)
    else {
        return reject(stream, "400 Bad Request");
    };
    let Some(relay_values) = value.get("relayUrls").and_then(serde_json::Value::as_array) else {
        return respond(
            stream,
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"relayUrls must be a non-empty array of wss URLs",
        );
    };
    let mut relays = Vec::with_capacity(relay_values.len());
    for relay_value in relay_values {
        let Some(relay_value) = relay_value.as_str() else {
            return respond(
                stream,
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
                stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                error.as_bytes(),
            )
        }
    };
    let relay_changed = relays != state.settings.relays;
    if (tor_socks != state.tor_socks || relay_changed) && any_chat_active(&state) {
        return reject(stream, "409 Conflict");
    }
    let settings = AppSettings {
        tor_socks,
        notifications,
        relays,
    };
    if let Err(error) = save_settings(&settings) {
        if error.kind() == io::ErrorKind::InvalidInput {
            return respond(
                stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                client_message("요청 처리 오류", &error).as_bytes(),
            );
        }
        return reject(stream, "500 Internal Server Error");
    }
    state
        .notifications_enabled
        .store(notifications, Ordering::SeqCst);
    state.settings = settings;
    respond_settings(stream, &state)
}
