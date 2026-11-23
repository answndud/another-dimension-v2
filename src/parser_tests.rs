//! Property tests for the parsers that read input from outside the process: the HTTP
//! request head, invitation and access codes, the settings file and relay URLs.
//!
//! These feed arbitrary and mutated input and check that nothing panics and that what is
//! accepted is in its canonical form. They are not coverage-guided fuzzing (see
//! docs/testing.md); the backup parsers have their own in `history/tests.rs`.

use super::*;
use proptest::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Hands out a request a few bytes at a time, like a slow client.
struct Trickle {
    data: Vec<u8>,
    position: usize,
    chunk: usize,
}

impl ReadWithin for Trickle {
    fn read_within(&mut self, buffer: &mut [u8], _deadline: Instant) -> io::Result<usize> {
        let count = self
            .chunk
            .min(buffer.len())
            .min(self.data.len() - self.position);
        buffer[..count].copy_from_slice(&self.data[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

fn read_head(data: &[u8], chunk: usize) -> (Result<usize, RequestReadError>, Vec<u8>) {
    let mut stream = Trickle {
        data: data.to_vec(),
        position: 0,
        chunk,
    };
    let mut request = Vec::new();
    let result = read_request_head(
        &mut stream,
        &mut request,
        Instant::now() + Duration::from_secs(5),
    );
    (result, request)
}

/// Mutates `text` with one of: replace a character, delete one, insert one, truncate.
fn mutations(text: String) -> impl Strategy<Value = String> {
    let length = text.chars().count().max(1);
    (0_usize..4, 0..length, any::<char>()).prop_map(move |(kind, at, character)| {
        let mut characters: Vec<char> = text.chars().collect();
        let at = at.min(characters.len().saturating_sub(1));
        match kind {
            0 if !characters.is_empty() => characters[at] = character,
            1 if !characters.is_empty() => {
                characters.remove(at);
            }
            2 => characters.insert(at.min(characters.len()), character),
            _ => characters.truncate(at),
        }
        characters.into_iter().collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn the_request_head_reader_returns_the_first_blank_line_however_the_bytes_arrive(
        head in proptest::collection::vec(any::<u8>(), 0..20_000),
        chunk in 1_usize..3000,
    ) {
        let (result, request) = read_head(&head, chunk);
        if let Ok(end) = result {
            prop_assert!(end <= MAX_HEADER);
            prop_assert!(request[..end].ends_with(b"\r\n\r\n"));
            let earlier = request[..end - 4].windows(4).any(|part| part == b"\r\n\r\n");
            prop_assert!(!earlier, "stopped after the first blank line, not before");
        }
        // The outcome does not depend on how the bytes were split into reads.
        let (other, _) = read_head(&head, 1);
        prop_assert_eq!(result.is_ok(), other.is_ok());
        if let (Ok(a), Ok(b)) = (result, other) {
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn a_head_with_a_blank_line_inside_the_limit_is_always_accepted(
        mut line in "[ -~]{0,200}",
        chunk in 1_usize..64,
    ) {
        line.push_str("\r\n\r\n");
        let (result, _) = read_head(line.as_bytes(), chunk);
        prop_assert!(result.is_ok());
    }

    #[test]
    fn arbitrary_text_is_never_a_valid_invite_unless_it_round_trips(text in ".{0,200}") {
        if let Some(invite) = InviteCode::parse(&text) {
            prop_assert_eq!(invite.code(), text.as_str());
        }
    }

    #[test]
    fn a_mutated_invite_never_panics_and_only_accepts_its_canonical_form(
        mutated in mutations(InviteCode::generate().unwrap().code().to_owned()),
    ) {
        if let Some(invite) = InviteCode::parse(&mutated) {
            prop_assert_eq!(invite.code(), mutated.as_str());
        }
    }

    #[test]
    fn a_mutated_access_code_never_panics(
        mutated in mutations(Identity::create().unwrap().1.to_string()),
    ) {
        let _ = Identity::from_code(&mutated);
    }

    #[test]
    fn arbitrary_text_is_never_an_access_code(text in ".{0,300}") {
        prop_assert!(Identity::from_code(&text).is_none());
    }

    #[test]
    fn relay_endpoints_never_panic_and_normalize_to_a_fixed_point(text in "\\PC{0,120}") {
        if let Ok(key) = relay::validate_relay_endpoint(&text) {
            // The comparison key is itself a valid endpoint with the same key.
            prop_assert_eq!(relay::validate_relay_endpoint(&key).unwrap(), key);
        }
    }

    #[test]
    fn the_settings_file_loader_never_panics_on_any_content(
        content in proptest::collection::vec(any::<u8>(), 0..6000),
    ) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ad2-settings-prop-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, &content).unwrap();
        let loaded = load_settings_from_path(&path);
        let _ = std::fs::remove_file(&path);
        if let Ok(settings) = loaded {
            // Whatever was accepted can be saved and loaded back unchanged.
            let again = std::env::temp_dir().join(format!(
                "ad2-settings-prop-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            save_settings_to_path(&again, &settings).unwrap();
            let reloaded = load_settings_from_path(&again);
            let _ = std::fs::remove_file(&again);
            let reloaded = reloaded.unwrap();
            prop_assert_eq!(reloaded.relays, settings.relays);
            prop_assert_eq!(reloaded.tor_socks, settings.tor_socks);
            prop_assert_eq!(reloaded.notifications, settings.notifications);
        }
    }
}
