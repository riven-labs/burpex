//! Classify a frame payload by sniffing its first bytes.
//!
//! The frame has already been located by the container walker — this is
//! type dispatch on already-trusted bytes, not a content search.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    HttpRequest,
    HttpResponse,
    Utf16Text,
    Utf8Text,
    Json,
    SmallId,
    StateBlob,
    Empty,
    Unknown,
}

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

pub fn classify(payload: &[u8]) -> Kind {
    if payload.is_empty() {
        return Kind::Empty;
    }
    if payload.len() <= 8 {
        return Kind::SmallId;
    }
    if payload.starts_with(b"HTTP/") {
        return Kind::HttpResponse;
    }
    for m in METHODS {
        if payload.starts_with(m) && has_request_line(payload) {
            return Kind::HttpRequest;
        }
    }
    if is_utf16_text(payload) {
        return Kind::Utf16Text;
    }
    if looks_like_state_blob(payload) {
        return Kind::StateBlob;
    }

    let trimmed = trim_ws(payload);
    if let Some(c) = trimmed.first() {
        if (*c == b'{' || *c == b'[') && looks_like_json(trimmed) {
            return Kind::Json;
        }
    }
    if is_mostly_printable(payload) {
        return Kind::Utf8Text;
    }
    Kind::Unknown
}

fn has_request_line(payload: &[u8]) -> bool {
    let end = payload.len().min(8192);
    let line_end = payload[..end]
        .iter()
        .position(|&b| b == b'\n' || b == b'\r');
    let line = match line_end {
        Some(p) => &payload[..p],
        None => return false,
    };
    let needle = b" HTTP/";
    line.windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + needle.len() < line.len())
        .unwrap_or(false)
}

fn is_utf16_text(p: &[u8]) -> bool {
    if p.len() < 16 {
        return false;
    }
    let n = (p.len() / 2).min(512);
    let mut le_ok = 0usize;
    let mut be_ok = 0usize;
    for i in 0..n {
        let a = p[i * 2];
        let b = p[i * 2 + 1];
        if b == 0 && is_text_ascii(a) {
            le_ok += 1;
        }
        if a == 0 && is_text_ascii(b) {
            be_ok += 1;
        }
    }
    le_ok.max(be_ok) * 5 >= n * 4
}

fn is_text_ascii(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r') || (0x20..=0x7e).contains(&b)
}

fn is_mostly_printable(p: &[u8]) -> bool {
    let n = p.len().min(512);
    let ok = p[..n].iter().filter(|&&b| is_text_ascii(b)).count();
    ok * 10 >= n * 9
}

fn trim_ws(p: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < p.len() && matches!(p[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    &p[i..]
}

fn looks_like_json(p: &[u8]) -> bool {
    let cap = p.len().min(1024 * 1024);
    let open = p[0];
    let close = if open == b'{' { b'}' } else { b']' };
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for &b in &p[..cap] {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            if b == b'"' {
                in_str = true;
            } else if b == open {
                depth += 1;
            } else if b == close {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
        }
    }
    false
}

/// State blob: large, binary, but holding a lot of UTF-16BE ASCII runs.
/// Burp's target/scope/sitemap/issues all serialize into this shape.
fn looks_like_state_blob(p: &[u8]) -> bool {
    if p.len() < 256 {
        return false;
    }
    let cap = p.len().min(8192);
    let mut runs = 0;
    let mut i = 0;
    while i + 8 <= cap {
        if p[i] == 0
            && is_text_ascii(p[i + 1])
            && p[i + 2] == 0
            && is_text_ascii(p[i + 3])
            && p[i + 4] == 0
            && is_text_ascii(p[i + 5])
            && p[i + 6] == 0
            && is_text_ascii(p[i + 7])
        {
            runs += 1;
            i += 8;
        } else {
            i += 1;
        }
    }
    runs >= 4
}

/// Pull every UTF-16BE ASCII run out of a buffer.
pub fn extract_utf16be_strings(p: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= p.len() {
        if p[i] == 0 && is_text_ascii(p[i + 1]) {
            let mut chars = Vec::new();
            while i + 2 <= p.len() && p[i] == 0 && is_text_ascii(p[i + 1]) {
                chars.push(p[i + 1]);
                i += 2;
            }
            if chars.len() >= min_chars {
                if let Ok(s) = std::str::from_utf8(&chars) {
                    out.push(s.to_string());
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Pull every printable ASCII run out of a buffer.
pub fn extract_ascii_strings(p: &[u8], min_chars: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = Vec::new();
    for &b in p {
        if is_text_ascii(b) {
            run.push(b);
        } else {
            if run.len() >= min_chars {
                if let Ok(s) = std::str::from_utf8(&run) {
                    out.push(s.to_string());
                }
            }
            run.clear();
        }
    }
    if run.len() >= min_chars {
        if let Ok(s) = std::str::from_utf8(&run) {
            out.push(s.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_http_request() {
        let req = b"GET /foo HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(classify(req), Kind::HttpRequest);
    }

    #[test]
    fn classifies_http_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi";
        assert_eq!(classify(resp), Kind::HttpResponse);
    }

    #[test]
    fn classifies_short_payload_as_smallid() {
        assert_eq!(classify(&[1, 2, 3, 4]), Kind::SmallId);
    }

    #[test]
    fn empty_payload() {
        assert_eq!(classify(&[]), Kind::Empty);
    }

    #[test]
    fn classifies_json() {
        let j = br#"{"a":1,"b":[2,3],"c":"hi"}xxxxxxxxxxxx"#;
        assert_eq!(classify(j), Kind::Json);
    }

    #[test]
    fn extracts_utf16be_strings() {
        // "hello" in UTF-16BE + junk + "world"
        let mut buf = vec![];
        for c in b"hello" {
            buf.extend_from_slice(&[0, *c]);
        }
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        for c in b"world" {
            buf.extend_from_slice(&[0, *c]);
        }
        let strings = extract_utf16be_strings(&buf, 3);
        assert!(strings.contains(&"hello".to_string()));
        assert!(strings.contains(&"world".to_string()));
    }

    #[test]
    fn extracts_ascii_strings() {
        let buf = b"\x00\x00\x00hello\x00world\x00\x00mini";
        let strings = extract_ascii_strings(buf, 4);
        assert_eq!(strings, vec!["hello", "world", "mini"]);
    }
}
