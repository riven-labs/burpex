use anyhow::{Context, Result};
use memmap2::Mmap;
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::header::MAGIC;

/// A `.burp` file opened read-only via mmap.
pub struct ProjectFile {
    pub path: PathBuf,
    pub mmap: Mmap,
    pub is_burp: bool,
}

impl ProjectFile {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let f = File::open(&path).with_context(|| format!("opening {}", path.display()))?;
        let mmap = unsafe { Mmap::map(&f).with_context(|| format!("mmap {}", path.display()))? };
        let is_burp = mmap.len() >= 4 && &mmap[..4] == MAGIC;
        Ok(Self {
            path,
            mmap,
            is_burp,
        })
    }

    #[inline]
    pub fn bytes(&self) -> &[u8] {
        &self.mmap
    }
    #[inline]
    pub fn size(&self) -> usize {
        self.mmap.len()
    }
}
