//! Group framed records into HTTP transactions.
//!
//! Each exchange in Burp's history is a cluster of frames at one offset:
//!
//! ```text
//!   [4-byte id]    transaction id
//!   [4-byte id]    secondary id (connection / parent)
//!   [request]
//!   [response]
//!   [path]         sitemap key (ASCII or UTF-16BE)
//! ```
//!
//! Some entries are missing the response (in-flight or aborted) or have
//! extra metadata wedged in. The walker stitches what it can and leaves
//! the rest as `None`.

use serde::Serialize;

use crate::classify::{classify, Kind};
use crate::file::ProjectFile;
use crate::frame::{Frame, FrameIter};
use crate::http::{self, HttpMessage};

#[derive(Debug, Serialize, Default, Clone)]
pub struct Transaction {
    /// Absolute byte offset of the request frame's payload in the file.
    pub offset: usize,
    pub transaction_id: Option<u32>,
    pub secondary_id: Option<u32>,
    pub sitemap_path: Option<String>,
    pub request: Option<HttpMessage>,
    pub response: Option<HttpMessage>,
}

impl Transaction {
    /// `true` if both a request and a response landed in the cluster.
    pub fn is_paired(&self) -> bool {
        self.request.is_some() && self.response.is_some()
    }

    /// Convenience: the request URL as `scheme://host/path?query`. Returns
    /// `None` if the request isn't present.
    pub fn request_url(&self) -> Option<String> {
        let req = self.request.as_ref()?;
        let host = req.host.as_deref()?;
        let path = req.path.as_deref().unwrap_or("/");
        // assume https (Burp doesn't store the scheme inside the message)
        let mut url = format!("https://{}{}", host, path);
        if !req.query.is_empty() {
            url.push('?');
            for (i, (k, v)) in req.query.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                url.push_str(k);
                url.push('=');
                url.push_str(v);
            }
        }
        Some(url)
    }
}

/// Walk the file, emitting one [`Transaction`] per request found. Recurses
/// into state blobs. Return `false` from `cb` to stop early.
pub fn for_each_transaction<F: FnMut(Transaction) -> bool>(
    pf: &ProjectFile,
    body_cap: usize,
    mut cb: F,
) {
    let buf = pf.bytes();
    let mut stop = false;
    let iter = FrameIter::new(buf).min_inner(1).max_inner(64 * 1024 * 1024);
    walk(buf, iter, 0, body_cap, &mut cb, &mut stop, 0);
}

fn walk<'a, F: FnMut(Transaction) -> bool>(
    slice: &'a [u8],
    iter: FrameIter<'a>,
    base_offset: usize,
    body_cap: usize,
    cb: &mut F,
    stop: &mut bool,
    depth: u32,
) {
    let frames: Vec<_> = iter.collect();
    let mut i = 0;
    while i < frames.len() {
        if *stop {
            return;
        }
        let f = frames[i];
        let payload = f.payload(slice);

        match classify(payload) {
            Kind::HttpRequest => {
                let mut txn = Transaction::default();
                txn.offset = base_offset + f.payload_start();
                let ids = collect_ids_backward(&frames, slice, i);
                txn.transaction_id = ids.first().copied();
                txn.secondary_id = ids.get(1).copied();

                if let Some(req) = http::parse(payload, txn.offset, body_cap) {
                    txn.request = Some(req);
                }

                // Look ahead a few frames for the response and the path.
                let mut j = i + 1;
                while j < frames.len() && j <= i + 4 {
                    let nf = frames[j];
                    let np = nf.payload(slice);
                    match classify(np) {
                        Kind::HttpResponse if txn.response.is_none() => {
                            if let Some(resp) =
                                http::parse(np, base_offset + nf.payload_start(), body_cap)
                            {
                                txn.response = Some(resp);
                            }
                            j += 1;
                        }
                        Kind::Utf8Text | Kind::Utf16Text if txn.sitemap_path.is_none() => {
                            if let Some(p) = extract_path(np) {
                                txn.sitemap_path = Some(p);
                            }
                            j += 1;
                            break;
                        }
                        Kind::HttpRequest => break, // next cluster starts here
                        _ => j += 1,
                    }
                }

                if !cb(txn) {
                    *stop = true;
                    return;
                }
                i = j.max(i + 1);
            }
            Kind::StateBlob if depth < 4 => {
                let max = if depth == 0 {
                    64 * 1024 * 1024
                } else {
                    32 * 1024 * 1024
                };
                let inner = FrameIter::new(payload).min_inner(8).max_inner(max);
                walk(
                    payload,
                    inner,
                    base_offset + f.payload_start(),
                    body_cap,
                    cb,
                    stop,
                    depth + 1,
                );
                i += 1;
            }
            _ => i += 1,
        }
    }
}

fn collect_ids_backward(frames: &[Frame], slice: &[u8], req_idx: usize) -> Vec<u32> {
    let mut ids = Vec::new();
    for back in 1..=4 {
        if back > req_idx {
            break;
        }
        let pay = frames[req_idx - back].payload(slice);
        if pay.len() != 4 {
            break;
        }
        ids.push(u32::from_be_bytes([pay[0], pay[1], pay[2], pay[3]]));
    }
    ids
}

fn extract_path(payload: &[u8]) -> Option<String> {
    if payload.len() < 4096
        && payload.iter().all(|&b| (0x20..=0x7e).contains(&b))
        && payload.first() == Some(&b'/')
    {
        return Some(std::str::from_utf8(payload).ok()?.to_string());
    }
    if payload.len() >= 2 && payload.len() % 2 == 0 {
        let mut s = String::new();
        for pair in payload.chunks_exact(2) {
            if pair[0] != 0 || !(0x20..=0x7e).contains(&pair[1]) {
                return None;
            }
            s.push(pair[1] as char);
        }
        if s.starts_with('/') {
            return Some(s);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_path_ascii() {
        assert_eq!(extract_path(b"/api/v1/foo"), Some("/api/v1/foo".into()));
        assert_eq!(extract_path(b"not-a-path"), None);
    }

    #[test]
    fn extract_path_utf16be() {
        let path: Vec<u8> = "/foo/bar".bytes().flat_map(|c| [0u8, c]).collect();
        assert_eq!(extract_path(&path), Some("/foo/bar".into()));
    }

    #[test]
    fn request_url_assembly() {
        let mut req = HttpMessage::default();
        req.kind = "request";
        req.host = Some("example.com".into());
        req.path = Some("/foo".into());
        req.query = vec![("a".into(), "1".into()), ("b".into(), "2".into())];
        let txn = Transaction {
            request: Some(req),
            ..Transaction::default()
        };
        assert_eq!(
            txn.request_url().as_deref(),
            Some("https://example.com/foo?a=1&b=2")
        );
    }
}
