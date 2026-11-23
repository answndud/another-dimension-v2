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
            ("history.rs", include_str!("history.rs")),
            ("relay.rs", include_str!("relay.rs")),
            ("channel.rs", include_str!("channel.rs")),
            ("identity.rs", include_str!("identity.rs")),
            ("contacts.rs", include_str!("contacts.rs")),
            ("session.rs", include_str!("session.rs")),
            ("anchor.rs", include_str!("anchor.rs")),
        ] {
            assert!(
                !source.contains(device),
                "{name} reads randomness from a device file; use crate::random::fill"
            );
        }
    }
}
