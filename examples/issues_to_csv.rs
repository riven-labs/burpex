//! Dump scan issues out of a Burp project as CSV. Shows pulling the
//! project summary out via the library.
//!
//!     cargo run --release --example issues_to_csv -- path/to/project.burp

use std::env;

use burpex::BurpProject;

fn main() -> anyhow::Result<()> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: issues_to_csv <file.burp>"))?;
    let proj = BurpProject::open(&path)?;
    let f = proj.extract();

    println!("severity,confidence,url,path,excerpt");
    for issue in &f.project.issues {
        let excerpt = issue
            .title_or_excerpt
            .replace('"', "\"\"")
            .replace('\n', " ");
        println!(
            "{:?},{:?},{:?},{:?},{:?}",
            issue.severity.as_deref().unwrap_or(""),
            issue.confidence.as_deref().unwrap_or(""),
            issue.url.as_deref().unwrap_or(""),
            issue.path.as_deref().unwrap_or(""),
            excerpt,
        );
    }
    eprintln!(
        "\n{} issues, {} flagged cookies, {} leaked emails, {} card numbers",
        f.project.issues.len(),
        f.project.flagged_cookies.len(),
        f.project.leaked_emails.len(),
        f.project.leaked_card_numbers.len(),
    );
    Ok(())
}
