//! Randomness from the operating system.
//!
//! Every key, nonce, salt and token in the program comes from here, so there is a
//! single place that decides how random bytes are produced. It does not open a
//! device file, which keeps it portable and avoids a file descriptor per call.

use std::io;

/// Fills `buffer` with bytes from the operating system's random number generator.
pub(crate) fn fill(buffer: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buffer)
        .map_err(|error| io::Error::other(format!("random number generator unavailable: {error}")))
}

#[cfg(test)]
mod tests {
    use super::fill;

    #[test]
    fn fills_the_whole_buffer_with_different_bytes_each_time() {
        let (mut first, mut second) = ([0_u8; 32], [0_u8; 32]);
        fill(&mut first).unwrap();
        fill(&mut second).unwrap();
        assert_ne!(first, [0_u8; 32]);
        assert_ne!(first, second);
        // The tail of a long buffer is filled too, not only a prefix.
        let mut long = vec![0_u8; 4096];
        fill(&mut long).unwrap();
        assert!(long[2048..].iter().any(|byte| *byte != 0));
    }

    #[test]
    fn an_empty_buffer_is_fine() {
        fill(&mut []).unwrap();
    }

    #[test]
    fn no_module_opens_the_random_device_directly() {
        let device = concat!("/dev/", "urandom");
        for (name, source) in [
            ("main.rs", include_str!("main.rs")),
            ("history/mod.rs", include_str!("history/mod.rs")),
            ("history/log.rs", include_str!("history/log.rs")),
            (
                "history/conversations.rs",
                include_str!("history/conversations.rs"),
            ),
            ("history/index.rs", include_str!("history/index.rs")),
            ("history/staging.rs", include_str!("history/staging.rs")),
            ("history/paths.rs", include_str!("history/paths.rs")),
            ("history/wire.rs", include_str!("history/wire.rs")),
            (
                "history/linked_keys.rs",
                include_str!("history/linked_keys.rs"),
            ),
            (
                "history/transfer_workspace.rs",
                include_str!("history/transfer_workspace.rs"),
            ),
            (
                "history/backup/mod.rs",
                include_str!("history/backup/mod.rs"),
            ),
            (
                "history/backup/legacy.rs",
                include_str!("history/backup/legacy.rs"),
            ),
            (
                "history/backup/stream.rs",
                include_str!("history/backup/stream.rs"),
            ),
            (
                "history/backup/bundle.rs",
                include_str!("history/backup/bundle.rs"),
            ),
            ("relay.rs", include_str!("relay.rs")),
            ("channel.rs", include_str!("channel.rs")),
            ("identity.rs", include_str!("identity.rs")),
            ("contacts.rs", include_str!("contacts.rs")),
            ("session.rs", include_str!("session.rs")),
            ("anchor.rs", include_str!("anchor.rs")),
            ("hex.rs", include_str!("hex.rs")),
            ("http.rs", include_str!("http.rs")),
            ("state.rs", include_str!("state.rs")),
            ("settings.rs", include_str!("settings.rs")),
            ("api/mod.rs", include_str!("api/mod.rs")),
            ("api/account.rs", include_str!("api/account.rs")),
            (
                "api/backup_transfer.rs",
                include_str!("api/backup_transfer.rs"),
            ),
            ("api/chat.rs", include_str!("api/chat.rs")),
            (
                "api/contact_backup.rs",
                include_str!("api/contact_backup.rs"),
            ),
            ("api/conversations.rs", include_str!("api/conversations.rs")),
            ("api/preferences.rs", include_str!("api/preferences.rs")),
            ("chat_worker.rs", include_str!("chat_worker.rs")),
            ("history_sync.rs", include_str!("history_sync.rs")),
            ("restore.rs", include_str!("restore.rs")),
        ] {
            assert!(
                !source.contains(device),
                "{name} reads randomness from a device file; use crate::random::fill"
            );
        }
    }
}
