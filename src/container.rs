//! File-level layout.
//!
//! ```text
//!   [ fixed header, 256 bytes ]      magic + version + used_size + schema directory
//!   [ extended header, ~24-50 KB ]   schema tables + project-wide strings
//!   [ frame run ] [ trailer ] ...
//!   [ zero-padded tail up to EOF ]
//! ```
//!
//! `used_size` (header offset 0x38) divides live data from the pre-allocated
//! zero tail.

use serde::Serialize;

use crate::file::ProjectFile;
use crate::frame::FrameIter;
use crate::header::Header;

#[derive(Debug, Serialize)]
pub struct Layout {
    pub file_size: u64,
    pub used_size: u64,
    pub tail_zero_bytes: u64,
    pub tail_zero_verified: bool,
    pub header_run: Section,
    pub frame_runs: Vec<Section>,
    pub trailers: Vec<Section>,
    pub gap_count: u64,
    pub gap_bytes: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct Section {
    pub offset: u64,
    pub end: u64,
    pub size: u64,
    pub note: String,
}

pub fn analyze(pf: &ProjectFile) -> Layout {
    let buf = pf.bytes();
    let n = buf.len() as u64;
    let used = Header::parse(buf).map(|h| h.used_size).unwrap_or(n);

    // Confirm the tail past used_size is all zero.
    let tail_start = (used as usize).min(buf.len());
    let tail = &buf[tail_start..];
    let tail_zero = tail.iter().all(|&b| b == 0);

    // Walk top-level frames to identify contiguous runs.
    let mut runs: Vec<(u64, u64, u64)> = Vec::new();
    let mut cur_start: Option<u64> = None;
    let mut cur_end: u64 = 0;
    let mut cur_count: u64 = 0;
    let used_clamp = used.min(n);
    let active = &buf[..used_clamp as usize];

    for f in FrameIter::new(active)
        .min_inner(1)
        .max_inner(64 * 1024 * 1024)
    {
        let start = f.offset as u64;
        let end = (f.offset + f.outer as usize) as u64;
        match cur_start {
            None => {
                cur_start = Some(start);
                cur_end = end;
                cur_count = 1;
            }
            Some(_) if start == cur_end => {
                cur_end = end;
                cur_count += 1;
            }
            Some(s) => {
                runs.push((s, cur_end, cur_count));
                cur_start = Some(start);
                cur_end = end;
                cur_count = 1;
            }
        }
    }
    if let Some(s) = cur_start {
        runs.push((s, cur_end, cur_count));
    }

    // The "header_run" is everything before the first frame.
    let first_frame_start = runs.first().map(|r| r.0).unwrap_or(used_clamp);
    let header_run = Section {
        offset: 0,
        end: first_frame_start,
        size: first_frame_start,
        note: format!(
            "fixed header (256B) + extended header & schema tables up to first frame run"
        ),
    };

    let frame_runs: Vec<Section> = runs
        .iter()
        .map(|(s, e, c)| Section {
            offset: *s,
            end: *e,
            size: e - s,
            note: format!("{} contiguous frames", c),
        })
        .collect();

    // Trailers: the bytes between consecutive runs (and between last run and used_size).
    let mut trailers = Vec::new();
    let mut gap_count = 0u64;
    let mut gap_bytes = 0u64;
    let mut cursor = first_frame_start;
    for (s, e, _) in &runs {
        if *s > cursor {
            let gap = s - cursor;
            gap_count += 1;
            gap_bytes += gap;
            trailers.push(Section {
                offset: cursor,
                end: *s,
                size: gap,
                note: classify_gap(&buf[cursor as usize..*s as usize]),
            });
        }
        cursor = *e;
    }
    if cursor < used_clamp {
        let gap = used_clamp - cursor;
        gap_count += 1;
        gap_bytes += gap;
        trailers.push(Section {
            offset: cursor,
            end: used_clamp,
            size: gap,
            note: classify_gap(&buf[cursor as usize..used_clamp as usize]),
        });
    }

    Layout {
        file_size: n,
        used_size: used,
        tail_zero_bytes: n.saturating_sub(used),
        tail_zero_verified: tail_zero,
        header_run,
        frame_runs,
        trailers,
        gap_count,
        gap_bytes,
    }
}

fn classify_gap(buf: &[u8]) -> String {
    if buf.is_empty() {
        return "empty".into();
    }
    if buf.len() == 1 {
        return "1-byte alignment pad".into();
    }
    // Section trailers carry a u64 0xff sentinel and a 4-byte txn id.
    let has_sentinel = buf.windows(8).any(|w| w == [0xff; 8]);
    let utf16_runs = count_utf16be_ascii(buf);
    if has_sentinel && buf.len() < 8192 {
        "trailer (back-pointer + 0xff sentinel + txn id)".into()
    } else if utf16_runs >= 8 {
        format!("schema or strings block ({} utf-16be runs)", utf16_runs)
    } else if buf.iter().all(|&b| b == 0) {
        "zero padding".into()
    } else {
        format!(
            "unclassified ({} bytes, {} utf-16be runs)",
            buf.len(),
            utf16_runs
        )
    }
}

fn count_utf16be_ascii(buf: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i + 8 <= buf.len() {
        let mut j = i;
        let mut chars = 0;
        while j + 2 <= buf.len() && buf[j] == 0 && (0x20..=0x7e).contains(&buf[j + 1]) {
            chars += 1;
            j += 2;
        }
        if chars >= 4 {
            count += 1;
            i = j;
        } else {
            i += 1;
        }
    }
    count
}
