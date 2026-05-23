//! Whole-file extraction. Walks the frame tree, classifies each payload,
//! and rolls everything up into a single `Findings` struct.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::classify::{classify, extract_ascii_strings, extract_utf16be_strings, Kind};
use crate::file::ProjectFile;
use crate::frame::FrameIter;
use crate::header::Header;
use crate::http;
use crate::project::{summarize, ProjectSummary, StateBlobMeta};
use crate::text::decode_utf16_best_effort;

#[derive(Debug, Serialize)]
pub struct FrameRecord {
    pub offset: usize,
    pub size: u32,
    pub kind: Kind,
    pub preview: String,
}

#[derive(Debug, Serialize)]
pub struct ConfigBlob {
    pub offset: usize,
    pub size: u32,
    pub encoding: &'static str,
    pub text: String,
}

#[derive(Debug, Serialize, Default)]
pub struct StateBlobOut {
    pub offset: usize,
    pub size: u32,
    pub strings_utf16be: Vec<String>,
    pub strings_ascii: Vec<String>,
}

#[derive(Debug, Serialize, Default)]
pub struct Findings {
    pub file: String,
    pub size: usize,
    pub header: Option<Header>,
    pub stats: Stats,
    pub hosts: BTreeMap<String, u64>,
    pub status_codes: BTreeMap<u16, u64>,
    pub methods: BTreeMap<String, u64>,
    pub content_types: BTreeMap<String, u64>,
    pub project: ProjectSummary,
    pub state_blob_index: Vec<StateBlobMeta>,
    pub http_messages: Vec<http::HttpMessage>,
    pub config_blobs: Vec<ConfigBlob>,
    pub state_blobs: Vec<StateBlobOut>,
    pub other_text: Vec<ConfigBlob>,
    pub json_blobs: Vec<ConfigBlob>,
    pub unknown_frames: Vec<FrameRecord>,
}

#[derive(Debug, Serialize, Default)]
pub struct Stats {
    pub total_frames: u64,
    pub bytes_in_frames: u64,
    pub bytes_in_gaps: u64,
    pub requests: u64,
    pub responses: u64,
    pub utf16_blobs: u64,
    pub state_blobs: u64,
    pub json_blobs: u64,
    pub small_ids: u64,
    pub unknown: u64,
}

pub struct Options {
    pub body_cap: usize,
    pub include_unknown: bool,
    pub include_other_text: bool,
    pub max_frames: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            body_cap: 64 * 1024,
            include_unknown: false,
            include_other_text: true,
            max_frames: None,
        }
    }
}

pub fn extract(pf: &ProjectFile, opts: &Options) -> Findings {
    let buf = pf.bytes();
    let mut f = Findings::default();
    f.file = pf.path.display().to_string();
    f.size = pf.size();
    f.header = Header::parse(buf);

    let mut bytes_in_frames: u64 = 0;
    let mut frame_count: u64 = 0;

    let iter = FrameIter::new(buf).min_inner(1).max_inner(MAX_INNER_TOP);
    walk_frames(
        buf,
        iter,
        0,
        opts,
        &mut f,
        &mut bytes_in_frames,
        &mut frame_count,
        0,
    );

    f.stats.total_frames = frame_count;
    f.stats.bytes_in_frames = bytes_in_frames;
    f.stats.bytes_in_gaps = (pf.size() as u64).saturating_sub(bytes_in_frames);

    // Re-read each state blob payload from the file to summarize its role
    // (scanner config, issues, scope, etc) without holding extra copies
    // during the main walk.
    let blob_payloads: Vec<(usize, u32, Vec<u8>)> = f
        .state_blobs
        .iter()
        .map(|b| {
            let end = b.offset + b.size as usize;
            let payload = if end <= buf.len() {
                buf[b.offset..end].to_vec()
            } else {
                Vec::new()
            };
            (b.offset, b.size, payload)
        })
        .collect();
    let (metas, summary) = summarize(&blob_payloads);
    f.state_blob_index = metas;
    f.project = summary;

    f
}

const MAX_INNER_TOP: u32 = 64 * 1024 * 1024;
const MAX_INNER_DEEP: u32 = 32 * 1024 * 1024;

fn walk_frames<'a>(
    slice: &'a [u8],
    iter: FrameIter<'a>,
    base_offset: usize,
    opts: &Options,
    f: &mut Findings,
    bytes_in_frames: &mut u64,
    frame_count: &mut u64,
    depth: u32,
) {
    for frame in iter {
        if let Some(cap) = opts.max_frames {
            if *frame_count >= cap {
                return;
            }
        }
        *frame_count += 1;
        *bytes_in_frames += frame.outer as u64;

        let payload_abs_offset = base_offset + frame.payload_start();
        let payload = frame.payload(slice);

        let kind = classify(payload);
        match kind {
            Kind::HttpRequest | Kind::HttpResponse => {
                if let Some(m) = http::parse(payload, payload_abs_offset, opts.body_cap) {
                    if m.kind == "request" {
                        f.stats.requests += 1;
                        if let Some(ref h) = m.host {
                            *f.hosts.entry(h.clone()).or_default() += 1;
                        }
                        if let Some(ref meth) = m.method {
                            *f.methods.entry(meth.clone()).or_default() += 1;
                        }
                    } else {
                        f.stats.responses += 1;
                        if let Some(s) = m.status {
                            *f.status_codes.entry(s).or_default() += 1;
                        }
                    }
                    if let Some(ref ct) = m.content_type {
                        let base = ct
                            .split(';')
                            .next()
                            .unwrap_or(ct)
                            .trim()
                            .to_ascii_lowercase();
                        *f.content_types.entry(base).or_default() += 1;
                    }
                    f.http_messages.push(m);
                }
            }
            Kind::Utf16Text => {
                f.stats.utf16_blobs += 1;
                let text = decode_utf16_best_effort(payload);
                f.config_blobs.push(ConfigBlob {
                    offset: payload_abs_offset,
                    size: frame.inner,
                    encoding: "utf-16",
                    text,
                });
            }
            Kind::Json => {
                f.stats.json_blobs += 1;
                let s = std::str::from_utf8(payload).unwrap_or("").to_string();
                f.json_blobs.push(ConfigBlob {
                    offset: payload_abs_offset,
                    size: frame.inner,
                    encoding: "utf-8",
                    text: s,
                });
            }
            Kind::Utf8Text => {
                if opts.include_other_text {
                    let s = std::str::from_utf8(payload).unwrap_or("").to_string();
                    f.other_text.push(ConfigBlob {
                        offset: payload_abs_offset,
                        size: frame.inner,
                        encoding: "utf-8",
                        text: s,
                    });
                }
            }
            Kind::StateBlob => {
                f.stats.state_blobs += 1;
                let u16s = extract_utf16be_strings(payload, 4);
                let asciis = extract_ascii_strings(payload, 6);
                for s in u16s.iter().chain(asciis.iter()) {
                    if let Some(h) = host_from_string(s) {
                        *f.hosts.entry(h).or_default() += 1;
                    }
                }
                f.state_blobs.push(StateBlobOut {
                    offset: payload_abs_offset,
                    size: frame.inner,
                    strings_utf16be: u16s,
                    strings_ascii: asciis,
                });
                // State blobs hold their own framed stream — proxy history,
                // sitemap entries, scan issues. Recurse.
                if depth < 4 {
                    let inner_iter = FrameIter::new(payload)
                        .min_inner(8)
                        .max_inner(max_inner_for_depth(depth));
                    walk_frames(
                        payload,
                        inner_iter,
                        payload_abs_offset,
                        opts,
                        f,
                        bytes_in_frames,
                        frame_count,
                        depth + 1,
                    );
                }
            }
            Kind::SmallId => {
                f.stats.small_ids += 1;
            }
            Kind::Empty => {}
            Kind::Unknown => {
                f.stats.unknown += 1;
                if opts.include_unknown {
                    f.unknown_frames.push(FrameRecord {
                        offset: payload_abs_offset.saturating_sub(8),
                        size: frame.outer,
                        kind: Kind::Unknown,
                        preview: hex_preview(payload, 64),
                    });
                }
            }
        }
    }
}

fn max_inner_for_depth(depth: u32) -> u32 {
    if depth == 0 {
        MAX_INNER_TOP
    } else {
        MAX_INNER_DEEP
    }
}

/// Streaming HTTP walker. Calls `cb` for every decoded request/response
/// found anywhere in the file, recursing into state blobs. Return `false`
/// from `cb` to stop early.
pub fn for_each_http<F: FnMut(http::HttpMessage) -> bool>(
    pf: &ProjectFile,
    body_cap: usize,
    mut cb: F,
) {
    let buf = pf.bytes();
    let iter = FrameIter::new(buf).min_inner(8).max_inner(64 * 1024 * 1024);
    let mut stop = false;
    walk_for_http(buf, iter, 0, body_cap, &mut cb, &mut stop, 0);
}

fn walk_for_http<'a, F: FnMut(http::HttpMessage) -> bool>(
    slice: &'a [u8],
    iter: FrameIter<'a>,
    base_offset: usize,
    body_cap: usize,
    cb: &mut F,
    stop: &mut bool,
    depth: u32,
) {
    for frame in iter {
        if *stop {
            return;
        }
        let payload_abs_offset = base_offset + frame.payload_start();
        let payload = frame.payload(slice);
        let kind = classify(payload);
        match kind {
            Kind::HttpRequest | Kind::HttpResponse => {
                if let Some(m) = http::parse(payload, payload_abs_offset, body_cap) {
                    if !cb(m) {
                        *stop = true;
                        return;
                    }
                }
            }
            Kind::StateBlob if depth < 4 => {
                let inner = FrameIter::new(payload)
                    .min_inner(8)
                    .max_inner(max_inner_for_depth(depth));
                walk_for_http(
                    payload,
                    inner,
                    payload_abs_offset,
                    body_cap,
                    cb,
                    stop,
                    depth + 1,
                );
            }
            _ => {}
        }
    }
}

fn host_from_string(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
    {
        let end = rest.find('/').unwrap_or(rest.len());
        let host = &rest[..end];
        if is_hostlike(host) {
            return Some(host.to_string());
        }
    }
    if is_hostlike(s) && !s.contains(' ') {
        return Some(s.to_string());
    }
    None
}

fn is_hostlike(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    let body = h.split(':').next().unwrap_or(h);
    if !body.contains('.') {
        return false;
    }
    let labels: Vec<&str> = body.split('.').collect();
    let all_ok = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !all_ok {
        return false;
    }
    if labels.len() == 4 && labels.iter().all(|l| l.parse::<u8>().is_ok()) {
        return true;
    }
    let tld = labels.last().copied().unwrap_or("");
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

fn hex_preview(p: &[u8], n: usize) -> String {
    use std::fmt::Write;
    let n = p.len().min(n);
    let mut s = String::with_capacity(n * 3);
    for (i, b) in p[..n].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_url() {
        assert_eq!(
            host_from_string("https://example.com/foo"),
            Some("example.com".into())
        );
        assert_eq!(
            host_from_string("http://a.b.example.com:8080"),
            Some("a.b.example.com:8080".into())
        );
    }

    #[test]
    fn host_from_bare_hostname() {
        assert_eq!(host_from_string("api.fun.xyz"), Some("api.fun.xyz".into()));
        assert_eq!(host_from_string("1.2.3.4"), Some("1.2.3.4".into()));
    }

    #[test]
    fn host_rejects_garbage() {
        assert_eq!(host_from_string("just-words"), None); // no dot
        assert_eq!(host_from_string("ends.with.123"), None); // numeric TLD
        assert_eq!(host_from_string(""), None);
        assert_eq!(host_from_string("with spaces.com"), None);
        assert_eq!(host_from_string("-leading.dash"), None); // dash leading
    }
}
