//! Pull every transaction out of a Burp project and write a curl-replayable
//! script. Shows the streaming library API.
//!
//! Run with:
//!     cargo run --release --example replay_targets -- path/to/project.burp

use std::env;

use burpex::BurpProject;

fn main() -> anyhow::Result<()> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: replay_targets <file.burp>"))?;
    let proj = BurpProject::open(&path)?;

    let mut count = 0;
    proj.transactions().with_body_cap(0).for_each(|t| {
        if let Some(url) = t.request_url() {
            let method = t
                .request
                .as_ref()
                .and_then(|r| r.method.as_deref())
                .unwrap_or("GET");
            println!("curl -k -X {} {:?}", method, url);
            count += 1;
        }
        true
    });
    eprintln!("emitted {} curl lines", count);
    Ok(())
}
