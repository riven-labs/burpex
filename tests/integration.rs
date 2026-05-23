//! Integration tests against the bundled `test.burp` sample.
//!
//! The sample lives at the repo root (one level above the crate). Tests
//! that need it look for it relative to `CARGO_MANIFEST_DIR`. If the file
//! isn't present the tests skip rather than fail — keeps `cargo test`
//! working in fresh checkouts that haven't pulled the binary fixture.

use std::path::PathBuf;

use burpex::BurpProject;

fn sample_path() -> Option<PathBuf> {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let p = here.parent()?.join("test.burp");
    p.exists().then_some(p)
}

macro_rules! sample_or_skip {
    () => {
        match sample_path() {
            Some(p) => p,
            None => {
                eprintln!("skipping: test.burp not found alongside crate");
                return;
            }
        }
    };
}

#[test]
fn opens_a_real_project() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).expect("open");
    assert!(proj.is_valid(), "magic bytes should match");
    assert!(proj.size() > 0);
}

#[test]
fn header_has_used_size_within_file() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    let h = proj.header().expect("header");
    assert!(h.magic_ok);
    assert!(h.used_size as usize <= proj.size());
}

#[test]
fn layout_marks_tail_as_zero() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    let layout = proj.layout();
    assert!(
        layout.tail_zero_verified,
        "tail past used_size should be zero-padded"
    );
    assert!(!layout.frame_runs.is_empty());
}

#[test]
fn finds_http_messages() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    let n = proj.http_messages().with_body_cap(0).collect().len();
    assert!(n > 0, "expected to find some HTTP messages, got {}", n);
}

#[test]
fn transactions_match_request_count() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    let txns = proj.transactions().with_body_cap(0).collect();
    let requests = txns.iter().filter(|t| t.request.is_some()).count();
    assert_eq!(
        txns.len(),
        requests,
        "every transaction should at least have a request"
    );
    assert!(txns.len() > 0);
}

#[test]
fn extract_summary_has_stats() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    let f = proj.extract();
    assert!(f.stats.total_frames > 0);
    // bytes_in_frames is summed across all depths (state blobs hold nested
    // frames, so bytes get counted at every level they appear). It's an
    // upper bound on coverage rather than a tight equality with file size.
    assert!(f.stats.bytes_in_frames > 0);
    assert!(!f.hosts.is_empty());
    assert!(f.stats.requests > 0);
}

#[test]
fn request_url_is_buildable_when_host_present() {
    let p = sample_or_skip!();
    let proj = BurpProject::open(&p).unwrap();
    for t in proj
        .transactions()
        .with_body_cap(0)
        .collect()
        .into_iter()
        .take(50)
    {
        if let Some(url) = t.request_url() {
            assert!(url.starts_with("https://"));
            assert!(url.contains('/'));
        }
    }
}
