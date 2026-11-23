//! User preferences and the small platform helpers around them.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppSettings {
    pub(crate) tor_socks: Option<SocketAddr>,
    pub(crate) notifications: bool,
    pub(crate) relays: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            tor_socks: None,
            notifications: false,
            relays: vec![DEFAULT_RELAY.to_owned()],
        }
    }
}

pub(crate) fn respond_settings(stream: &mut TcpStream, state: &State) -> io::Result<()> {
    let active_mode = if state.tor_socks.is_some() {
        "tor"
    } else {
        "general"
    };
    let saved_mode = if state.settings.tor_socks.is_some() {
        "tor"
    } else {
        "general"
    };
    let relay_restart_required = state.active_relays != state.settings.relays;
    let payload = serde_json::json!({
        "activeMode": active_mode,
        "savedMode": saved_mode,
        "savedRelays": &state.settings.relays,
        "activeRelays": &state.active_relays,
        "activeRelay": state.active_relays.first(),
        "relayRestartRequired": relay_restart_required,
        "socks": state.settings.tor_socks.map(|address| address.to_string()),
        "activeSocks": state.tor_socks.map(|address| address.to_string()),
        "notifications": state.settings.notifications,
        "restartRequired": state.tor_socks != state.settings.tor_socks || relay_restart_required,
    })
    .to_string();
    respond(
        stream,
        "200 OK",
        "application/json; charset=utf-8",
        payload.as_bytes(),
    )
}

pub(crate) fn preferences_path() -> io::Result<PathBuf> {
    Ok(history::data_directory()?.join("preferences.json"))
}

pub(crate) fn load_settings() -> io::Result<AppSettings> {
    load_settings_from_path(&preferences_path()?)
}

pub(crate) const MAX_SETTINGS_BYTES: usize = 4096;

pub(crate) fn load_settings_from_path(path: &std::path::Path) -> io::Result<AppSettings> {
    let bytes = match crate::fsutil::read_regular_file(path, MAX_SETTINGS_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(AppSettings::default()),
        Err(error) => return Err(error),
    };
    let contents = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "settings file is invalid"))?;
    let value: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "settings file is invalid"))?;
    let tor_socks = match value.get("torSocks") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(parse_loopback_socks(value)?),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "settings SOCKS address is invalid",
            ))
        }
    };
    let notifications = value
        .get("notifications")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let relays = match value.get("relayUrls") {
        None => vec![DEFAULT_RELAY.to_owned()],
        Some(serde_json::Value::Array(values)) => {
            let mut relays = Vec::with_capacity(values.len());
            for value in values {
                let Some(value) = value.as_str() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "settings relay list contains a non-string address",
                    ));
                };
                relays.push(value.to_owned());
            }
            relay::validate_relay_list(&relays)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "settings relay list is invalid",
            ))
        }
    };
    Ok(AppSettings {
        tor_socks,
        notifications,
        relays,
    })
}

pub(crate) fn save_settings(settings: &AppSettings) -> io::Result<()> {
    save_settings_to_path(&preferences_path()?, settings)
}

pub(crate) fn save_settings_to_path(
    path: &std::path::Path,
    settings: &AppSettings,
) -> io::Result<()> {
    let relays = relay::validate_relay_list(&settings.relays)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::other("settings directory unavailable"))?;
    crate::fsutil::create_private_dir_all(directory)?;
    set_private_directory(directory)?;
    let contents = serde_json::to_vec(&serde_json::json!({
        "torSocks": settings.tor_socks.map(|address| address.to_string()),
        "notifications": settings.notifications,
        "relayUrls": relays,
    }))?;
    if contents.len() > MAX_SETTINGS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "settings file is too large",
        ));
    }
    let temporary = path.with_extension(format!("{}.tmp", random_token()?));
    let result = (|| {
        let mut file = crate::fsutil::private_options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        set_private_file(&file)?;
        file.write_all(&contents)?;
        file.sync_all()?;
        crate::fsutil::rename_durable(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

pub(crate) fn parse_loopback_socks(value: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = value.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS 주소는 127.0.0.1:9050 형식이어야 합니다.",
        )
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS 주소는 loopback과 유효한 포트만 허용합니다.",
        ));
    }
    Ok(address)
}

#[cfg(unix)]
pub(crate) fn set_private_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn set_private_directory(_path: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub(crate) fn set_private_file(_file: &File) -> io::Result<()> {
    Ok(())
}

pub(crate) fn notify_incoming_message() {
    #[cfg(target_os = "macos")]
    {
        let _ = thread::Builder::new()
            .name("local-notification".to_owned())
            .spawn(|| {
                let _ = Command::new("/usr/bin/osascript")
                    .args([
                        "-e",
                        "display notification \"새 메시지가 도착했습니다\" with title \"Another Dimension\"",
                    ])
                    .status();
            });
    }
}

pub(crate) fn should_send_notification(last_notification: &Mutex<Option<Instant>>) -> bool {
    let Ok(mut last_notification) = last_notification.lock() else {
        return false;
    };
    let now = Instant::now();
    if last_notification.is_some_and(|last| now.duration_since(last) < Duration::from_secs(5)) {
        return false;
    }
    *last_notification = Some(now);
    true
}
