//! Read a Burp Suite project file and turn it into something a pipeline
//! can use: HTTP transactions, scan issues, scope, hosts, anything that
//! was in the project.
//!
//! ```no_run
//! use burpex::BurpProject;
//!
//! let proj = BurpProject::open("Polymarket_Funxyz.burp")?;
//! for txn in proj.transactions().with_body_cap(8 * 1024).iter() {
//!     if let (Some(req), Some(resp)) = (&txn.request, &txn.response) {
//!         println!("{} {} -> {}", req.method.as_deref().unwrap_or("?"),
//!                                 req.path.as_deref().unwrap_or("?"),
//!                                 resp.status.unwrap_or(0));
//!     }
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod classify;
pub mod container;
pub mod extract;
pub mod file;
pub mod frame;
pub mod header;
pub mod http;
pub mod project;
pub mod text;
pub mod transaction;

pub use classify::{classify, Kind};
pub use container::Layout;
pub use extract::{extract, Findings, Options};
pub use file::ProjectFile;
pub use frame::{Frame, FrameIter};
pub use header::Header;
pub use http::HttpMessage;
pub use project::{BlobRole, ProjectSummary, ScanIssue, StateBlobMeta};
pub use transaction::Transaction;

use anyhow::Result;
use std::path::Path;

/// A Burp Suite project file opened for read.
///
/// Holds an mmap of the file, so creating one is cheap and querying it
/// repeatedly is cheap too. Drop it when done.
pub struct BurpProject {
    file: ProjectFile,
}

impl BurpProject {
    /// Open a `.burp` file. Fails if the file can't be read or mapped.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self {
            file: ProjectFile::open(path)?,
        })
    }

    /// Path the project was opened from.
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// File size in bytes (the whole mmap, including the zero-padded tail).
    pub fn size(&self) -> usize {
        self.file.size()
    }

    /// Decoded fixed header. `None` if the file is too short to hold one.
    pub fn header(&self) -> Option<Header> {
        Header::parse(self.file.bytes())
    }

    /// Whether the magic bytes at the start of the file match Burp's.
    pub fn is_valid(&self) -> bool {
        self.file.is_burp
    }

    /// File-level layout: header span, frame runs, trailers, zero tail.
    pub fn layout(&self) -> Layout {
        container::analyze(&self.file)
    }

    /// Run the full extraction pass and return a single `Findings` value
    /// with everything decoded — HTTP messages, project summary, issues.
    ///
    /// This loads the whole result into memory. For huge files use
    /// [`Self::transactions`] or [`Self::http_messages`] instead.
    pub fn extract(&self) -> Findings {
        self.extract_with(&Options::default())
    }

    /// Same as [`Self::extract`] but with custom options.
    pub fn extract_with(&self, opts: &Options) -> Findings {
        extract(&self.file, opts)
    }

    /// Stream HTTP transactions (request + response + sitemap path).
    pub fn transactions(&self) -> TransactionStream<'_> {
        TransactionStream {
            proj: self,
            body_cap: 64 * 1024,
        }
    }

    /// Stream individual HTTP messages without grouping into transactions.
    pub fn http_messages(&self) -> HttpStream<'_> {
        HttpStream {
            proj: self,
            body_cap: 64 * 1024,
        }
    }

    /// Iterator over every framed record in the file. Low-level; useful
    /// for reverse-engineering or for tools that want the raw container.
    pub fn frames(&self) -> FrameIter<'_> {
        FrameIter::new(self.file.bytes()).min_inner(1)
    }

    /// Borrow the underlying [`ProjectFile`] for raw access.
    pub fn project_file(&self) -> &ProjectFile {
        &self.file
    }
}

/// Builder + iterator for HTTP transactions.
pub struct TransactionStream<'a> {
    proj: &'a BurpProject,
    body_cap: usize,
}

impl<'a> TransactionStream<'a> {
    /// Cap on bytes kept per HTTP body preview. Default 64 KiB.
    pub fn with_body_cap(mut self, n: usize) -> Self {
        self.body_cap = n;
        self
    }

    /// Walk the file with a callback. Return `false` from `f` to stop early.
    pub fn for_each<F: FnMut(Transaction) -> bool>(self, f: F) {
        transaction::for_each_transaction(&self.proj.file, self.body_cap, f);
    }

    /// Collect every transaction into a `Vec`.
    pub fn collect(self) -> Vec<Transaction> {
        let mut out = Vec::new();
        self.for_each(|t| {
            out.push(t);
            true
        });
        out
    }

    /// Adapt to a `std::iter::Iterator` by collecting first.
    ///
    /// Streaming as a true `Iterator` would require self-referential state;
    /// since most callers want either a callback or the whole set, the
    /// `Vec` adapter is the practical answer.
    pub fn iter(self) -> std::vec::IntoIter<Transaction> {
        self.collect().into_iter()
    }
}

/// Builder + iterator for HTTP messages (request OR response, ungrouped).
pub struct HttpStream<'a> {
    proj: &'a BurpProject,
    body_cap: usize,
}

impl<'a> HttpStream<'a> {
    pub fn with_body_cap(mut self, n: usize) -> Self {
        self.body_cap = n;
        self
    }

    pub fn for_each<F: FnMut(HttpMessage) -> bool>(self, f: F) {
        extract::for_each_http(&self.proj.file, self.body_cap, f);
    }

    pub fn collect(self) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        self.for_each(|m| {
            out.push(m);
            true
        });
        out
    }

    pub fn iter(self) -> std::vec::IntoIter<HttpMessage> {
        self.collect().into_iter()
    }

    /// Yield only requests.
    pub fn requests(self) -> impl Iterator<Item = HttpMessage> {
        self.iter().filter(|m| m.kind == "request")
    }

    /// Yield only responses.
    pub fn responses(self) -> impl Iterator<Item = HttpMessage> {
        self.iter().filter(|m| m.kind == "response")
    }
}
