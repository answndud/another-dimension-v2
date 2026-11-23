//! Where the application keeps its data.

use super::*;

/// Where the application keeps its data.
///
/// `ANOTHER_DIMENSION_DATA_DIR` overrides the default in every build, but only for a
/// directory that is safe to put secrets in (see `checked_data_directory`). Otherwise
/// a debug build on macOS uses `chat-data/` in the source tree, and every other build
/// uses the per-user data location of the platform. A path is never taken from the
/// machine the binary was built on.
pub(crate) fn data_directory() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(path) = TEST_DATA_DIRECTORY.with(|directory| directory.borrow().clone()) {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("ANOTHER_DIMENSION_DATA_DIR") {
        return checked_data_directory(PathBuf::from(path));
    }
    default_data_directory()
}

pub(crate) fn default_data_directory() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        macos_data_directory(
            &home_dir()?,
            cfg!(debug_assertions),
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory is unavailable"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Another Dimension v2"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "APPDATA is not set"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(path).join("another-dimension-v2"));
        }
        home_dir().map(|home| home.join(".local/share/another-dimension-v2"))
    }
}

/// The macOS location: the source tree in a debug build (convenient while developing),
/// the per-user Application Support folder otherwise.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn macos_data_directory(
    home: &std::path::Path,
    debug_build: bool,
    manifest_directory: &std::path::Path,
) -> Option<PathBuf> {
    if debug_build {
        Some(manifest_directory.join("chat-data"))
    } else if home.as_os_str().is_empty() {
        None
    } else {
        Some(home.join("Library/Application Support/Another Dimension v2"))
    }
}

/// Accepts a data directory chosen by the user only if it is safe to keep secrets in:
/// an absolute path without `..`, not a symbolic link, and, if it already exists, a
/// directory owned by this user that nobody else can enter. Permissions are not
/// changed here. Pointing the variable at a shared directory such as the home
/// directory must fail, not quietly lock the user out of it.
pub(crate) fn checked_data_directory(path: PathBuf) -> io::Result<PathBuf> {
    let invalid = |message: &str| io::Error::new(io::ErrorKind::InvalidInput, message.to_owned());
    if !path.is_absolute() {
        return Err(invalid("data directory must be absolute"));
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(invalid("data directory must not contain '..'"));
    }
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        // Not created yet: it will be created private.
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() {
        return Err(invalid("data directory must not be a symbolic link"));
    }
    if !metadata.is_dir() {
        return Err(invalid("data directory exists but is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(invalid("data directory must be owned by the current user"));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid(
                "data directory must not be accessible by other users (run chmod 700 on it)",
            ));
        }
    }
    Ok(path)
}

/// A message for the terminal when an earlier run kept data somewhere else: a release
/// build no longer reads the source tree's `chat-data/`, so existing conversations
/// there would otherwise seem to have disappeared. Nothing is moved automatically.
pub(crate) fn legacy_data_warning(
    current: &std::path::Path,
    legacy: &std::path::Path,
) -> Option<String> {
    if current == legacy {
        return None;
    }
    let has_data = std::fs::read_dir(legacy)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false);
    has_data.then(|| {
        format!(
            "이전 위치에 대화 데이터가 있습니다: {legacy}\n\
             이 실행은 다른 위치를 사용합니다: {current}\n\
             이전 데이터를 계속 쓰려면 ANOTHER_DIMENSION_DATA_DIR={legacy} 를 지정해 실행하세요(그 폴더는 chmod 700 이어야 합니다).",
            legacy = legacy.display(),
            current = current.display(),
        )
    })
}

/// The source tree's `chat-data/` directory, where debug builds on macOS keep data and
/// where earlier versions kept it for every build.
pub(crate) fn source_tree_data_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("chat-data")
}

#[cfg(test)]
pub(crate) fn set_test_data_directory(path: Option<PathBuf>) {
    TEST_DATA_DIRECTORY.with(|directory| *directory.borrow_mut() = path);
}

#[cfg(test)]
pub(crate) fn test_data_directory() -> Option<PathBuf> {
    TEST_DATA_DIRECTORY.with(|directory| directory.borrow().clone())
}

pub(crate) fn home_dir() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "home directory is unavailable"))
}

#[cfg(unix)]
pub(crate) fn set_private_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
pub(crate) fn set_private_directory(_: &std::path::Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(crate) fn set_private_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub(crate) fn set_private_file(_: &File) -> io::Result<()> {
    Ok(())
}
