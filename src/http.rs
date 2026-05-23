//! Parse an HTTP request or response sitting in a frame payload.
//!
//! Bodies are de-chunked when needed and decompressed for the common
//! encodings (gzip / deflate / br). Binary bodies come back as base64
//! so callers don't get garbled strings.

use serde::Serialize;

#[derive(Debug, Serialize, Default, Clone)]
pub struct HttpMessage {
    /// "request" or "response".
    pub kind: &'static str,
    /// Byte offset in the file where the message payload starts.
    pub offset: usize,
    pub raw_len: usize,
    pub http_version: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Vec<(String, String)>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub transfer_encoding: Option<String>,
    pub content_length: Option<u64>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<String>,
    /// UTF-8 preview of the (decoded) body — present for text content.
    pub body_preview: Option<String>,
    /// Base64 preview of the (decoded) body — present for binary content.
    pub body_preview_base64: Option<String>,
    pub body_decoded: bool,
    pub body_decoded_len: Option<usize>,
    pub body_offset: Option<usize>,
    pub body_len: usize,
}

const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Parse `payload` as an HTTP message. Returns `None` if it doesn't look
/// like one. `frame_offset` is the absolute byte offset for diagnostics.
pub fn parse(payload: &[u8], frame_offset: usize, body_cap: usize) -> Option<HttpMessage> {
    let head_end = find_header_terminator(payload)?;
    let head = decode_head(&payload[..head_end]);

    let sep = if head.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines = head.split(sep);
    let first_line = lines.next()?.to_string();

    let body_start =
        head_end + header_terminator_len(&payload[..(head_end + 4).min(payload.len())]);
    let body_avail = payload.len() - body_start;

    let mut msg = HttpMessage::default();
    msg.offset = frame_offset;

    if first_line.starts_with("HTTP/") {
        msg.kind = "response";
        let mut parts = first_line.splitn(3, ' ');
        let ver = parts.next()?;
        let code = parts.next()?;
        let reason = parts.next().unwrap_or("").to_string();
        msg.http_version = Some(ver.trim_start_matches("HTTP/").to_string());
        msg.status = code.parse().ok();
        if !reason.is_empty() {
            msg.reason = Some(reason);
        }
    } else if METHODS
        .iter()
        .any(|m| first_line.starts_with(m) && first_line.as_bytes().get(m.len()) == Some(&b' '))
    {
        msg.kind = "request";
        let mut parts = first_line.splitn(3, ' ');
        let method = parts.next()?.to_string();
        let target = parts.next()?.to_string();
        let ver = parts.next().unwrap_or("HTTP/1.1");
        msg.method = Some(method);
        msg.http_version = Some(ver.trim_start_matches("HTTP/").to_string());
        if let Some((path, q)) = target.split_once('?') {
            msg.path = Some(path.to_string());
            for kv in q.split('&') {
                let pair = kv
                    .split_once('=')
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap_or_else(|| (kv.to_string(), String::new()));
                msg.query.push(pair);
            }
        } else {
            msg.path = Some(target);
        }
    } else {
        return None;
    }

    parse_headers(&head, sep, &mut msg);

    let body_len = msg
        .content_length
        .map(|n| (n as usize).min(body_avail))
        .unwrap_or(body_avail);

    if body_len > 0 {
        msg.body_offset = Some(frame_offset + body_start);
        msg.body_len = body_len;
        let raw = &payload[body_start..body_start + body_len];

        let dechunked = match msg.transfer_encoding.as_deref() {
            Some(v) if v.to_ascii_lowercase().contains("chunked") => dechunk(raw),
            _ => raw.to_vec(),
        };

        let (decoded, ok) = match msg
            .content_encoding
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
        {
            Some(enc) => decode_encoded(&dechunked, &enc),
            None => (dechunked, true),
        };
        msg.body_decoded = ok;
        msg.body_decoded_len = Some(decoded.len());

        let take = decoded.len().min(body_cap);
        if take > 0 {
            let slice = &decoded[..take];
            write_body_preview(&mut msg, slice);
        }
    }

    msg.raw_len = body_start + body_len;
    Some(msg)
}

fn parse_headers(head: &str, sep: &str, msg: &mut HttpMessage) {
    // Skip the request/status line, then iterate the rest.
    let mut iter = head.split(sep);
    let _ = iter.next();
    for line in iter {
        if line.is_empty() {
            continue;
        }
        let (k, v) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        let k = k.trim().to_string();
        let v = v.trim().to_string();
        match k.to_ascii_lowercase().as_str() {
            "host" => msg.host = Some(v.clone()),
            "content-type" => msg.content_type = Some(v.clone()),
            "content-length" => msg.content_length = v.parse().ok(),
            "content-encoding" => msg.content_encoding = Some(v.clone()),
            "transfer-encoding" => msg.transfer_encoding = Some(v.clone()),
            "cookie" | "set-cookie" => msg.cookies.push(v.clone()),
            _ => {}
        }
        msg.headers.push((k, v));
    }
}

fn write_body_preview(msg: &mut HttpMessage, slice: &[u8]) {
    let text_kind = is_text_content(msg.content_type.as_deref());
    if msg.content_type.is_none() {
        if let Ok(s) = std::str::from_utf8(slice) {
            if mostly_printable(s) {
                msg.body_preview = Some(s.to_string());
                return;
            }
        }
        msg.body_preview_base64 = Some(b64(slice));
    } else if text_kind {
        msg.body_preview = Some(decode_text_lossy(slice));
    } else {
        msg.body_preview_base64 = Some(b64(slice));
    }
}

fn b64(slice: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(slice)
}

fn find_header_terminator(p: &[u8]) -> Option<usize> {
    if p.len() >= 4 {
        if let Some(i) = p.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(i);
        }
    }
    p.windows(2).position(|w| w == b"\n\n")
}

fn header_terminator_len(p: &[u8]) -> usize {
    if p.ends_with(b"\r\n\r\n") {
        4
    } else {
        2
    }
}

fn decode_head(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| c as char).collect(),
    }
}

fn dechunk(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut i = 0;
    while i < buf.len() {
        let nl = match buf[i..].iter().position(|&b| b == b'\n') {
            Some(p) => i + p,
            None => break,
        };
        let line = buf[i..nl].strip_suffix(b"\r").unwrap_or(&buf[i..nl]);
        let hex = line.split(|&b| b == b';').next().unwrap_or(line);
        let sz = match std::str::from_utf8(hex)
            .ok()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
        {
            Some(n) => n,
            None => break,
        };
        i = nl + 1;
        if sz == 0 {
            break;
        }
        let end = i + sz;
        if end > buf.len() {
            break;
        }
        out.extend_from_slice(&buf[i..end]);
        i = end;
        if buf.get(i) == Some(&b'\r') {
            i += 1;
        }
        if buf.get(i) == Some(&b'\n') {
            i += 1;
        }
    }
    out
}

fn decode_encoded(buf: &[u8], enc: &str) -> (Vec<u8>, bool) {
    let layers: Vec<&str> = enc
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let mut cur = buf.to_vec();
    for layer in layers.iter().rev() {
        let result = match layer.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => decode_gzip(&cur),
            "deflate" => decode_deflate(&cur),
            "br" => decode_brotli(&cur),
            "identity" | "none" | "" => Some(cur.clone()),
            _ => None,
        };
        match result {
            Some(v) => cur = v,
            None => return (cur, false),
        }
    }
    (cur, true)
}

fn decode_gzip(buf: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(buf)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn decode_deflate(buf: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    if flate2::read::ZlibDecoder::new(buf)
        .read_to_end(&mut out)
        .is_ok()
        && !out.is_empty()
    {
        return Some(out);
    }
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(buf)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn decode_brotli(buf: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::with_capacity(buf.len() * 4);
    brotli::Decompressor::new(buf, 4096)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn is_text_content(ct: Option<&str>) -> bool {
    let ct = match ct {
        Some(s) => s.to_ascii_lowercase(),
        None => return true,
    };
    let base = ct.split(';').next().unwrap_or(&ct).trim().to_string();
    if base.starts_with("text/") {
        return true;
    }
    matches!(
        base.as_str(),
        "application/json"
            | "application/x-www-form-urlencoded"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/javascript"
            | "application/x-javascript"
            | "application/ld+json"
            | "application/graphql"
            | "application/csp-report"
            | "application/manifest+json"
            | "application/vnd.api+json"
            | "image/svg+xml"
    ) || base.ends_with("+json")
        || base.ends_with("+xml")
}

fn mostly_printable(s: &str) -> bool {
    let n = s.chars().take(512).count().max(1);
    let ok = s
        .chars()
        .take(512)
        .filter(|c| c.is_ascii_graphic() || matches!(*c, ' ' | '\n' | '\r' | '\t') || !c.is_ascii())
        .count();
    ok * 10 >= n * 9
}

fn decode_text_lossy(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b
            .iter()
            .map(|&x| {
                if (0x20..=0x7e).contains(&x) || matches!(x, b'\n' | b'\r' | b'\t') {
                    x as char
                } else {
                    '.'
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_get() {
        let buf = b"GET /foo?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let m = parse(buf, 0, 0).unwrap();
        assert_eq!(m.kind, "request");
        assert_eq!(m.method.as_deref(), Some("GET"));
        assert_eq!(m.path.as_deref(), Some("/foo"));
        assert_eq!(m.host.as_deref(), Some("example.com"));
        assert_eq!(
            m.query,
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn parses_a_response_with_body() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let m = parse(buf, 0, 1024).unwrap();
        assert_eq!(m.kind, "response");
        assert_eq!(m.status, Some(200));
        assert_eq!(m.body_len, 5);
        assert_eq!(m.body_preview.as_deref(), Some("hello"));
    }

    #[test]
    fn binary_body_gets_base64() {
        let body = [0u8, 1, 2, 3, 0xff, 0xfe];
        let mut buf: Vec<u8> = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\n\r\n".to_vec();
        buf.extend_from_slice(&body);
        let m = parse(&buf, 0, 1024).unwrap();
        assert!(m.body_preview.is_none());
        assert!(m.body_preview_base64.is_some());
    }

    #[test]
    fn gzip_body_gets_decoded() {
        use std::io::Write;
        let plaintext = b"the quick brown fox";
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(plaintext).unwrap();
        let gz = enc.finish().unwrap();
        let mut buf: Vec<u8> = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            gz.len()
        )
        .into_bytes();
        buf.extend_from_slice(&gz);
        let m = parse(&buf, 0, 4096).unwrap();
        assert!(m.body_decoded);
        assert_eq!(m.body_decoded_len, Some(plaintext.len()));
        assert_eq!(m.body_preview.as_deref(), Some("the quick brown fox"));
    }

    #[test]
    fn dechunks_chunked_body() {
        let chunked = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut buf: Vec<u8> =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        buf.extend_from_slice(chunked);
        let m = parse(&buf, 0, 1024).unwrap();
        // dechunk → "hello world"
        assert_eq!(m.body_decoded_len, Some(11));
        assert_eq!(m.body_preview.as_deref(), Some("hello world"));
    }
}
