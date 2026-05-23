//! Frame detection.
//!
//! A frame is `[outer:u32 BE][inner:u32 BE][payload:inner]` where
//! `outer == inner + 8`. That 8-byte signature is the only thing the
//! walker matches on — no content sniffing here, just structure.

use crate::file::ProjectFile;

#[derive(Debug, Clone, Copy)]
pub struct Frame {
    /// Byte offset of the 8-byte header.
    pub offset: usize,
    /// Outer length (always `inner + 8`).
    pub outer: u32,
    /// Payload length.
    pub inner: u32,
}

impl Frame {
    #[inline]
    pub fn payload_start(&self) -> usize {
        self.offset + 8
    }
    #[inline]
    pub fn payload_end(&self) -> usize {
        self.offset + self.outer as usize
    }
    #[inline]
    pub fn payload<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[self.payload_start()..self.payload_end()]
    }
}

/// Sliding-window iterator over every valid frame in a slice.
///
/// Frames in a Burp file aren't aligned to a fixed boundary, so the walker
/// advances one byte at a time looking for the signature. On a match it
/// jumps past the frame's outer length unless `overlap(true)` is set.
pub struct FrameIter<'a> {
    buf: &'a [u8],
    pos: usize,
    min_inner: u32,
    max_inner: u32,
    allow_overlap: bool,
}

impl<'a> FrameIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            min_inner: 1,
            max_inner: u32::MAX / 2,
            allow_overlap: false,
        }
    }
    pub fn min_inner(mut self, v: u32) -> Self {
        self.min_inner = v;
        self
    }
    pub fn max_inner(mut self, v: u32) -> Self {
        self.max_inner = v;
        self
    }
    pub fn overlap(mut self, yes: bool) -> Self {
        self.allow_overlap = yes;
        self
    }
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        let buf = self.buf;
        let n = buf.len();
        while self.pos + 8 <= n {
            let i = self.pos;
            let outer = u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
            let inner = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
            if outer == inner.wrapping_add(8)
                && inner >= self.min_inner
                && inner <= self.max_inner
                && (i + outer as usize) <= n
            {
                let f = Frame {
                    offset: i,
                    outer,
                    inner,
                };
                self.pos = if self.allow_overlap {
                    i + 1
                } else {
                    i + outer as usize
                };
                return Some(f);
            }
            self.pos = i + 1;
        }
        None
    }
}

/// Shortcut: iterate frames over the whole `ProjectFile`.
pub fn iter_frames(pf: &ProjectFile) -> FrameIter<'_> {
    FrameIter::new(pf.bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(payload: &[u8]) -> Vec<u8> {
        let inner = payload.len() as u32;
        let outer = inner + 8;
        let mut v = Vec::with_capacity(outer as usize);
        v.extend_from_slice(&outer.to_be_bytes());
        v.extend_from_slice(&inner.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn finds_a_single_frame() {
        let buf = make_frame(b"hello");
        let frames: Vec<_> = FrameIter::new(&buf).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].inner, 5);
        assert_eq!(frames[0].payload(&buf), b"hello");
    }

    #[test]
    fn finds_three_back_to_back() {
        let mut buf = Vec::new();
        for s in [b"aaaa".as_ref(), b"bbbbbb", b"cc"] {
            buf.extend(make_frame(s));
        }
        let frames: Vec<_> = FrameIter::new(&buf).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].payload(&buf), b"aaaa");
        assert_eq!(frames[1].payload(&buf), b"bbbbbb");
        assert_eq!(frames[2].payload(&buf), b"cc");
    }

    #[test]
    fn min_inner_filter_works() {
        let mut buf = Vec::new();
        for s in [b"ab".as_ref(), b"abcdef"] {
            buf.extend(make_frame(s));
        }
        let frames: Vec<_> = FrameIter::new(&buf).min_inner(4).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].inner, 6);
    }

    #[test]
    fn ignores_invalid_pair_when_outer_mismatches() {
        // outer != inner + 8 should not match
        let mut buf = vec![];
        buf.extend(&0xeeu32.to_be_bytes());
        buf.extend(&0x10u32.to_be_bytes());
        buf.extend(vec![0u8; 0x10]);
        let frames: Vec<_> = FrameIter::new(&buf).collect();
        assert!(frames.is_empty());
    }
}
