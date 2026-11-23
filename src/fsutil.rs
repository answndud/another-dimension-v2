//! File system helpers for data that must stay private and survive a crash.
//!
//! * Files and directories are created with owner-only permissions from the start,
//!   so there is no moment at which they exist with the default umask.
//! * A rename is followed by a flush of the directory entry. Flushing a file's
//!   contents is not enough: until the directory itself reaches the disk, a crash
//!   can bring back the old file after a write that was reported as successful.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::path::Path;

/// `OpenOptions` for files only the owner may read (mode 0600 on Unix). The mode is
/// applied when the file is created. It does nothing for a file that already exists,
/// so callers that reopen old files still tighten them with `set_private_file`.
pub(crate) fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Like `create_dir_all`, but every directory it creates, including missing parents,
/// is owner-only (mode 0700 on Unix).
pub(crate) fn create_private_dir_all(path: impl AsRef<Path>) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Flushes a directory's entries to disk.
#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    // On macOS the standard library's `sync_all` issues F_FULLFSYNC.
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Flushes the directory that holds `path`, after a file was created or linked there.
/// Best effort like `rename_durable`: the change already happened, so a failure is
/// logged and not returned.
pub(crate) fn sync_parent(path: impl AsRef<Path>) {
    let path = path.as_ref();
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => Path::new(".").to_owned(),
    };
    if let Err(error) = sync_dir(&directory) {
        eprintln!("디렉터리 동기화 실패 ({}): {error}", directory.display());
    }
}

/// Renames `from` to `to`, then flushes the directory (or directories) that changed.
///
/// The rename has already taken effect when the flush runs, so a failed flush is
/// logged and not returned: reporting an error for an operation that happened would
/// leave callers cleaning up a state that no longer exists.
pub(crate) fn rename_durable(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    let (from, to) = (from.as_ref(), to.as_ref());
    fs::rename(from, to)?;
    let directory_of = |path: &Path| match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        _ => Path::new(".").to_owned(),
    };
    let (to_directory, from_directory) = (directory_of(to), directory_of(from));
    if let Err(error) = sync_dir(&to_directory) {
        eprintln!("디렉터리 동기화 실패 ({}): {error}", to_directory.display());
    }
    if from_directory != to_directory {
        if let Err(error) = sync_dir(&from_directory) {
            eprintln!(
                "디렉터리 동기화 실패 ({}): {error}",
                from_directory.display()
            );
        }
    }
    Ok(())
}

/// `umask` is process-wide, so tests that change it must not overlap.
#[cfg(all(test, unix))]
static UMASK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `body` with a permissive umask, the situation in which a file created
/// without an explicit mode ends up readable by others.
#[cfg(all(test, unix))]
pub(crate) fn with_permissive_umask<T>(body: impl FnOnce() -> T) -> T {
    let _guard = UMASK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: umask only changes this process's file creation mask.
    let previous = unsafe { libc::umask(0) };
    let result = body();
    // SAFETY: as above; restores the previous mask.
    unsafe { libc::umask(previous) };
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ad2-fsutil-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn files_are_private_from_the_moment_they_are_created() {
        let directory = scratch("file");
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("secret");
        with_permissive_umask(|| {
            private_options()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
        });
        assert_eq!(mode(&path), 0o600, "a permissive umask must not widen it");
        // A plain OpenOptions under the same umask is world readable, which is the
        // window this helper closes.
        let plain = directory.join("plain");
        with_permissive_umask(|| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&plain)
                .unwrap();
        });
        assert_eq!(mode(&plain), 0o666);
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn every_missing_directory_is_private() {
        let root = scratch("dirs");
        let nested = root
            .join("chat-data")
            .join("identity")
            .join("verified-contacts");
        with_permissive_umask(|| create_private_dir_all(&nested).unwrap());
        for path in [
            &root,
            &root.join("chat-data"),
            &root.join("chat-data").join("identity"),
            &nested,
        ] {
            assert_eq!(mode(path), 0o700, "{}", path.display());
        }
        // Creating it again is not an error, and does not loosen anything.
        create_private_dir_all(&nested).unwrap();
        assert_eq!(mode(&nested), 0o700);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rename_replaces_the_target_and_removes_the_source() {
        let directory = scratch("rename");
        fs::create_dir_all(&directory).unwrap();
        let (from, to) = (directory.join("new"), directory.join("old"));
        fs::write(&to, b"old contents").unwrap();
        fs::write(&from, b"new contents").unwrap();
        rename_durable(&from, &to).unwrap();
        assert_eq!(fs::read(&to).unwrap(), b"new contents");
        assert!(!from.exists());
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn rename_across_directories_and_of_directories_works() {
        let root = scratch("across");
        let (left, right) = (root.join("left"), root.join("right"));
        fs::create_dir_all(&left).unwrap();
        fs::create_dir_all(&right).unwrap();
        fs::write(left.join("file"), b"data").unwrap();
        rename_durable(left.join("file"), right.join("file")).unwrap();
        assert_eq!(fs::read(right.join("file")).unwrap(), b"data");
        rename_durable(&right, root.join("moved")).unwrap();
        assert_eq!(fs::read(root.join("moved").join("file")).unwrap(), b"data");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn syncing_a_parent_never_fails_the_caller() {
        let directory = scratch("parent");
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, b"data").unwrap();
        sync_parent(&file);
        // A parent that does not exist is logged, not a panic or an error.
        sync_parent(directory.join("gone").join("file"));
        sync_parent("file-in-the-current-directory");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_missing_source_is_an_error_and_leaves_the_target_alone() {
        let directory = scratch("missing");
        fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target");
        fs::write(&target, b"keep").unwrap();
        let error = rename_durable(directory.join("absent"), &target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(&target).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&directory);
    }

    /// The production part of a source file: everything outside its test modules.
    fn production_part(source: &str) -> String {
        let mut text = source.to_owned();
        // A test module sits at column 0 and ends at the next closing brace at column 0.
        while let Some(start) = text
            .find("\nmod send_tests {")
            .or_else(|| text.find("\nmod tests {"))
            .or_else(|| text.find("\npub(crate) mod tests {"))
        {
            let end = text[start + 1..]
                .find("\n}\n")
                .map_or(text.len(), |offset| start + 1 + offset + 3);
            text.replace_range(start..end, "");
        }
        text
    }

    fn calls_outside_the_helpers(source: &str) -> Vec<String> {
        let mut problems = Vec::new();
        for (number, line) in production_part(source).lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("OpenOptions::new()") {
                problems.push(format!("line {}: OpenOptions::new()", number + 1));
            }
            for (needle, allowed_prefix) in [("create_dir_all(", "private_"), ("rename(", "")] {
                for (index, _) in code.match_indices(needle) {
                    let before = &code[..index];
                    if !allowed_prefix.is_empty() && before.ends_with(allowed_prefix) {
                        continue;
                    }
                    problems.push(format!("line {}: {needle}", number + 1));
                }
            }
        }
        problems
    }

    #[test]
    fn production_code_creates_and_replaces_files_through_the_helpers() {
        for (name, source) in [
            ("history.rs", include_str!("history.rs")),
            ("contacts.rs", include_str!("contacts.rs")),
            ("identity.rs", include_str!("identity.rs")),
            ("main.rs", include_str!("main.rs")),
        ] {
            let problems = calls_outside_the_helpers(source);
            assert!(
                problems.is_empty(),
                "{name} bypasses fsutil (private_options, create_private_dir_all, rename_durable): {problems:?}"
            );
        }
    }

    #[test]
    fn the_guard_notices_a_direct_call() {
        let bad = "fn f() {\n    let o = OpenOptions::new();\n    create_dir_all(p);\n    fs::rename(a, b);\n}\n";
        assert_eq!(calls_outside_the_helpers(bad).len(), 3);
        let good = "fn f() {\n    crate::fsutil::private_options();\n    crate::fsutil::create_private_dir_all(p);\n    crate::fsutil::rename_durable(a, b);\n}\n";
        assert!(calls_outside_the_helpers(good).is_empty());
        // Code inside a test module is not production code.
        let tested =
            "fn f() {}\nmod tests {\n    fn t() { OpenOptions::new(); rename(a, b); }\n}\n";
        assert!(calls_outside_the_helpers(tested).is_empty());
    }
}
