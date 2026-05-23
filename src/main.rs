use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use burpex::{classify::classify, extract::Options, frame::iter_frames, BurpProject, Kind};

#[derive(Parser)]
#[command(
    name = "burpex",
    version,
    about = "Pull everything useful out of a Burp Suite project file."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Header, frame stats, top hosts/methods/statuses, project summary.
    Info { file: PathBuf },

    /// File layout: header span, frame runs, trailers, zero tail.
    Layout { file: PathBuf },

    /// One JSON line per frame (offset, size, kind, head).
    Walk {
        file: PathBuf,
        #[arg(long)]
        limit: Option<u64>,
        #[arg(long)]
        kind: Option<String>,
        #[arg(long, default_value_t = 0)]
        min_size: u32,
    },

    /// One JSON line per HTTP message.
    Http {
        file: PathBuf,
        #[arg(long, default_value_t = 65536)]
        body_cap: usize,
        #[arg(long)]
        limit: Option<u64>,
    },

    /// One JSON line per HTTP transaction (request + response + sitemap path).
    Transactions {
        file: PathBuf,
        #[arg(long, default_value_t = 65536)]
        body_cap: usize,
        #[arg(long)]
        limit: Option<u64>,
    },

    /// Full extraction to a single JSON document.
    Extract {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
        #[arg(long, default_value_t = 65536)]
        body_cap: usize,
        #[arg(long, default_value_t = false)]
        include_unknown: bool,
        #[arg(long, default_value_t = false)]
        no_text: bool,
        #[arg(long, default_value_t = false)]
        pretty: bool,
    },

    /// Dump every text/JSON/state-blob payload as a file under <out>/.
    Blobs {
        file: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Info { file } => cmd_info(&file),
        Cmd::Layout { file } => cmd_layout(&file),
        Cmd::Walk {
            file,
            limit,
            kind,
            min_size,
        } => cmd_walk(&file, limit, kind, min_size),
        Cmd::Http {
            file,
            body_cap,
            limit,
        } => cmd_http(&file, body_cap, limit),
        Cmd::Transactions {
            file,
            body_cap,
            limit,
        } => cmd_transactions(&file, body_cap, limit),
        Cmd::Extract {
            file,
            out,
            body_cap,
            include_unknown,
            no_text,
            pretty,
        } => cmd_extract(
            &file,
            out.as_deref(),
            body_cap,
            include_unknown,
            !no_text,
            pretty,
        ),
        Cmd::Blobs { file, out } => cmd_blobs(&file, &out),
    }
}

fn cmd_info(path: &Path) -> Result<()> {
    let proj = BurpProject::open(path)?;
    let f = proj.extract_with(&Options {
        include_unknown: false,
        include_other_text: false,
        ..Default::default()
    });

    let summary = serde_json::json!({
        "file": proj.path().display().to_string(),
        "size": proj.size(),
        "header": proj.header(),
        "stats": f.stats,
        "top_hosts": take_top(&f.hosts, 20),
        "top_methods": &f.methods,
        "top_status_codes": &f.status_codes,
        "top_content_types": take_top(&f.content_types, 20),
        "state_blob_index": &f.state_blob_index,
        "project": {
            "project_id_candidates": &f.project.project_id_candidates,
            "scope_includes": &f.project.scope_includes,
            "scope_excludes": &f.project.scope_excludes,
            "file_extension_filters": &f.project.file_extension_filters,
            "live_tasks": &f.project.live_tasks,
            "scanner_parameter_names_count": f.project.scanner_parameter_names.len(),
            "issues_count": f.project.issues.len(),
            "affected_urls_count": f.project.affected_urls.len(),
            "flagged_cookies_count": f.project.flagged_cookies.len(),
            "leaked_emails_count": f.project.leaked_emails.len(),
            "leaked_card_numbers_count": f.project.leaked_card_numbers.len(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn cmd_layout(path: &Path) -> Result<()> {
    let proj = BurpProject::open(path)?;
    println!("{}", serde_json::to_string_pretty(&proj.layout())?);
    Ok(())
}

fn cmd_walk(
    path: &Path,
    limit: Option<u64>,
    kind_filter: Option<String>,
    min_size: u32,
) -> Result<()> {
    let proj = BurpProject::open(path)?;
    let buf = proj.project_file().bytes();
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut shown: u64 = 0;
    for frame in iter_frames(proj.project_file()).min_inner(1) {
        if frame.inner < min_size {
            continue;
        }
        let payload = frame.payload(buf);
        let k = classify(payload);
        let k_str = kind_to_str(&k);
        if let Some(ref want) = kind_filter {
            if k_str != *want {
                continue;
            }
        }
        let head = ascii_preview(payload, 80);
        writeln!(
            out,
            "{{\"offset\":{},\"size\":{},\"kind\":\"{}\",\"head\":{}}}",
            frame.offset,
            frame.inner,
            k_str,
            serde_json::to_string(&head).unwrap()
        )?;
        shown += 1;
        if let Some(cap) = limit {
            if shown >= cap {
                break;
            }
        }
    }
    Ok(())
}

fn cmd_http(path: &Path, body_cap: usize, limit: Option<u64>) -> Result<()> {
    let proj = BurpProject::open(path)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut n: u64 = 0;
    burpex::extract::for_each_http(proj.project_file(), body_cap, |m| {
        if serde_json::to_writer(&mut out, &m).is_err() {
            return false;
        }
        if out.write_all(b"\n").is_err() {
            return false;
        }
        n += 1;
        limit.map(|cap| n < cap).unwrap_or(true)
    });
    Ok(())
}

fn cmd_transactions(path: &Path, body_cap: usize, limit: Option<u64>) -> Result<()> {
    let proj = BurpProject::open(path)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut n: u64 = 0;
    burpex::transaction::for_each_transaction(proj.project_file(), body_cap, |t| {
        if serde_json::to_writer(&mut out, &t).is_err() {
            return false;
        }
        if out.write_all(b"\n").is_err() {
            return false;
        }
        n += 1;
        limit.map(|cap| n < cap).unwrap_or(true)
    });
    Ok(())
}

fn cmd_extract(
    path: &Path,
    out: Option<&Path>,
    body_cap: usize,
    include_unknown: bool,
    include_other_text: bool,
    pretty: bool,
) -> Result<()> {
    let proj = BurpProject::open(path)?;
    let f = proj.extract_with(&Options {
        body_cap,
        include_unknown,
        include_other_text,
        ..Default::default()
    });
    let writer: Box<dyn Write> = match out {
        Some(p) => Box::new(BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => Box::new(BufWriter::new(std::io::stdout().lock())),
    };
    if pretty {
        serde_json::to_writer_pretty(writer, &f)?;
    } else {
        serde_json::to_writer(writer, &f)?;
    }
    Ok(())
}

fn cmd_blobs(path: &Path, out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    let proj = BurpProject::open(path)?;
    let buf = proj.project_file().bytes();
    let mut idx = 0u64;
    for frame in iter_frames(proj.project_file()).min_inner(8) {
        let payload = frame.payload(buf);
        let k = classify(payload);
        let (ext, bytes): (&str, Vec<u8>) = match k {
            Kind::Utf16Text => (
                "txt",
                burpex::text::decode_utf16_best_effort(payload).into_bytes(),
            ),
            Kind::Json => ("json", payload.to_vec()),
            Kind::Utf8Text => ("txt", payload.to_vec()),
            Kind::StateBlob => ("bin", payload.to_vec()),
            _ => continue,
        };
        let name = format!(
            "{:08}_0x{:08x}_{}.{}",
            idx,
            frame.payload_start(),
            kind_to_str(&k),
            ext
        );
        std::fs::write(out_dir.join(name), &bytes)?;
        idx += 1;
    }
    println!("wrote {} blobs to {}", idx, out_dir.display());
    Ok(())
}

// ---- helpers --------------------------------------------------------------

fn kind_to_str(k: &Kind) -> String {
    serde_json::to_string(k)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

fn take_top<V: Clone + Ord + std::fmt::Debug + serde::Serialize>(
    m: &std::collections::BTreeMap<impl ToString + Ord + Clone, V>,
    n: usize,
) -> Vec<(String, V)> {
    let mut v: Vec<_> = m.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(n);
    v
}

fn ascii_preview(p: &[u8], n: usize) -> String {
    let n = p.len().min(n);
    let mut s = String::with_capacity(n);
    for &b in &p[..n] {
        match b {
            0x20..=0x7e => s.push(b as char),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            _ => s.push('.'),
        }
    }
    s
}
