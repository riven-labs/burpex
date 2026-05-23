//! UTF-16 decoding helpers.

pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn decode_utf16be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Try both byte orders and return the one that looks more like real text.
pub fn decode_utf16_best_effort(bytes: &[u8]) -> String {
    if bytes.len() < 2 {
        return String::new();
    }
    let le = decode_utf16le(bytes);
    let be = decode_utf16be(bytes);
    if printable_ratio(&le) >= printable_ratio(&be) {
        le
    } else {
        be
    }
}

fn printable_ratio(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let total = s.chars().count() as f32;
    // Heavily reward ASCII; mildly reward other printable scripts. The
    // intent is to pick the byte order that yields recognisable text, not
    // a coincidentally-valid CJK reading of ASCII bytes.
    let score: f32 = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || matches!(c, ' ' | '\n' | '\r' | '\t') {
                1.0
            } else if c.is_control() {
                0.0
            } else {
                0.25
            }
        })
        .sum();
    score / total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_utf16le_ascii() {
        let bytes = b"h\x00i\x00";
        assert_eq!(decode_utf16le(bytes), "hi");
    }

    #[test]
    fn decodes_utf16be_ascii() {
        let bytes = b"\x00h\x00i";
        assert_eq!(decode_utf16be(bytes), "hi");
    }

    #[test]
    fn best_effort_picks_correct_endianness() {
        assert_eq!(
            decode_utf16_best_effort(b"\x00h\x00e\x00l\x00l\x00o"),
            "hello"
        );
        assert_eq!(
            decode_utf16_best_effort(b"h\x00e\x00l\x00l\x00o\x00"),
            "hello"
        );
    }
}
