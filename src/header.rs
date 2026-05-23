use serde::Serialize;

/// Magic bytes at offset 0 of every Burp project file.
pub const MAGIC: [u8; 4] = [0x66, 0x85, 0x82, 0x80];

/// Fixed prelude at the start of a project file. The first 256 bytes hold
/// magic, version, timestamps, the `used_size` boundary, and a schema
/// directory describing the extended header that follows.
#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub magic_ok: bool,
    pub magic_hex: String,
    pub version: u32,
    pub field_08: [u8; 4],
    pub field_0c_a: u16,
    pub field_0c_b: u16,
    pub timestamp_raw: u64,
    pub max_int64: i64,
    /// Byte offset of the end of live data — bytes past this are zero-padded
    /// pre-allocated capacity.
    pub used_size: u64,
    pub field_40: u64,
    pub field_48: u64,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 0x50 {
            return None;
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut f08 = [0u8; 4];
        f08.copy_from_slice(&buf[0x08..0x0c]);
        Some(Self {
            magic_ok: magic == MAGIC,
            magic_hex: hex(&magic),
            version,
            field_08: f08,
            field_0c_a: u16::from_be_bytes([buf[0x0c], buf[0x0d]]),
            field_0c_b: u16::from_be_bytes([buf[0x0e], buf[0x0f]]),
            timestamp_raw: u64::from_be_bytes(buf[0x10..0x18].try_into().unwrap()),
            max_int64: i64::from_be_bytes(buf[0x30..0x38].try_into().unwrap()),
            used_size: u64::from_be_bytes(buf[0x38..0x40].try_into().unwrap()),
            field_40: u64::from_be_bytes(buf[0x40..0x48].try_into().unwrap()),
            field_48: u64::from_be_bytes(buf[0x48..0x50].try_into().unwrap()),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_buffers() {
        assert!(Header::parse(&[]).is_none());
        assert!(Header::parse(&[0u8; 32]).is_none());
    }

    #[test]
    fn parses_full_header() {
        let mut buf = vec![0u8; 0x80];
        buf[..4].copy_from_slice(&MAGIC);
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[0x38..0x40].copy_from_slice(&12345u64.to_be_bytes());
        let h = Header::parse(&buf).unwrap();
        assert!(h.magic_ok);
        assert_eq!(h.version, 1);
        assert_eq!(h.used_size, 12345);
    }
}
