//! Lowercase hexadecimal, in one place.
//!
//! Decoding accepts lowercase digits only, so two spellings of the same bytes cannot
//! both be valid and compare as different identifiers.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Appends the hex form of `bytes` to `target`, without an intermediate `String`, so a
/// caller holding secret bytes in a wiped string never leaves a copy behind.
pub(crate) fn push_encoded(target: &mut String, bytes: &[u8]) {
    target.reserve(bytes.len() * 2);
    for byte in bytes {
        target.push(DIGITS[(byte >> 4) as usize] as char);
        target.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    push_encoded(&mut result, bytes);
    result
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Decodes an even-length string of lowercase hex digits.
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?))
        .collect()
}

/// Decodes exactly `N` bytes of lowercase hex.
pub(crate) fn decode_array<const N: usize>(input: &str) -> Option<[u8; N]> {
    if input.len() != N * 2 {
        return None;
    }
    let mut output = [0; N];
    for (slot, pair) in output.iter_mut().zip(input.as_bytes().chunks_exact(2)) {
        *slot = digit(pair[0])? << 4 | digit(pair[1])?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips_every_byte_value() {
        let bytes: Vec<u8> = (0..=255).collect();
        let text = encode(&bytes);
        assert_eq!(text.len(), 512);
        assert!(text.starts_with("000102") && text.ends_with("fdfeff"));
        assert_eq!(decode(&text), Some(bytes));
        assert_eq!(encode(&[]), "");
        assert_eq!(decode(""), Some(Vec::new()));
    }

    #[test]
    fn decoding_rejects_uppercase_odd_length_and_non_hex() {
        for bad in ["AB", "aB", "abc", "0g", " 1", "1 ", "é1", "0x"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_fixed_size_decode_checks_the_length_exactly() {
        assert_eq!(decode_array::<2>("0aff"), Some([0x0a, 0xff]));
        assert_eq!(decode_array::<2>("0af"), None);
        assert_eq!(decode_array::<2>("0aff00"), None);
        assert_eq!(decode_array::<2>("0aFf"), None);
    }

    #[test]
    fn pushing_appends_without_disturbing_what_is_there() {
        let mut target = String::from("ab");
        push_encoded(&mut target, &[0x01, 0xfe]);
        assert_eq!(target, "ab01fe");
    }
}
