//! Decode the project's state blobs into typed sections.
//!
//! Burp packs proxy history, scope, settings, scan tasks and scan issues
//! into a few large state blobs. The container around them isn't fully
//! known yet, so this module:
//!
//!  - classifies each blob by sentinel strings it contains;
//!  - pulls record-shaped strings out (scope rules, issues, cookies, ...).
//!
//! Strings inside a blob carry a 1-byte type tag (`t` = text, `d` = rule,
//! `s` = short, ...). We strip those when slicing.

use serde::Serialize;

use crate::classify::extract_utf16be_strings;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlobRole {
    ScannerConfig,
    Issues,
    Scope,
    LiveTasks,
    Sitemap,
    Unknown,
}

#[derive(Debug, Serialize, Default)]
pub struct ProjectSummary {
    pub project_id_candidates: Vec<String>,
    pub scope_includes: Vec<String>,
    pub scope_excludes: Vec<String>,
    pub scope_rules_raw: Vec<String>,
    pub file_extension_filters: Vec<String>,
    pub live_tasks: Vec<String>,
    pub scanner_parameter_names: Vec<String>,
    pub issues: Vec<ScanIssue>,
    pub affected_urls: Vec<String>,
    pub flagged_cookies: Vec<String>,
    pub leaked_emails: Vec<String>,
    pub leaked_card_numbers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StateBlobMeta {
    pub offset: usize,
    pub size: u32,
    pub role: BlobRole,
    pub first_token: String,
    pub string_count: usize,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct ScanIssue {
    pub title_or_excerpt: String,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub url: Option<String>,
    pub path: Option<String>,
}

/// Walk a set of state-blob payloads and produce a typed summary.
pub fn summarize(blobs: &[(usize, u32, Vec<u8>)]) -> (Vec<StateBlobMeta>, ProjectSummary) {
    let mut metas = Vec::new();
    let mut sum = ProjectSummary::default();

    for (off, size, payload) in blobs {
        let strings = extract_utf16be_strings(payload, 3);
        let role = classify_blob(&strings);
        let first_token = strings.first().cloned().unwrap_or_default();
        metas.push(StateBlobMeta {
            offset: *off,
            size: *size,
            role,
            first_token: trim_to(&first_token, 80),
            string_count: strings.len(),
        });
        match role {
            BlobRole::ScannerConfig => harvest_scanner_config(&strings, &mut sum),
            BlobRole::Issues => harvest_issues(&strings, &mut sum),
            BlobRole::Scope => harvest_scope(&strings, &mut sum),
            BlobRole::LiveTasks => harvest_live_tasks(&strings, &mut sum),
            BlobRole::Sitemap | BlobRole::Unknown => harvest_loose_signals(&strings, &mut sum),
        }
    }

    for v in [
        &mut sum.scope_includes,
        &mut sum.scope_excludes,
        &mut sum.scope_rules_raw,
        &mut sum.file_extension_filters,
        &mut sum.live_tasks,
        &mut sum.scanner_parameter_names,
        &mut sum.affected_urls,
        &mut sum.flagged_cookies,
        &mut sum.leaked_emails,
        &mut sum.leaked_card_numbers,
        &mut sum.project_id_candidates,
    ] {
        dedup_inplace(v);
    }

    (metas, sum)
}

fn classify_blob(strings: &[String]) -> BlobRole {
    // Issue blobs are the only ones that carry CSP/XSS finding prose.
    let issue_sentinels: &[&str] = &[
        "form hijacking",
        "Cross-site scripting",
        "unsafe-inline",
        "unsafe-eval",
        "Content Security Policy",
        "Severity",
        "Confidence",
        "SQL injection",
        "Cross-origin",
        "Open redirection",
    ];
    if strings
        .iter()
        .any(|s| issue_sentinels.iter().any(|n| s.contains(n)))
    {
        return BlobRole::Issues;
    }

    // Scanner config has recognisable parameter name lists.
    let scanner_sentinels: &[&str] = &[
        "__viewstate",
        "__eventargument",
        "__eventvalidation",
        "jsessionid",
        "PHPSESSID",
        "cftoken",
        "cfid",
    ];
    let scanner_hits = strings
        .iter()
        .filter(|s| scanner_sentinels.iter().any(|n| s.eq_ignore_ascii_case(n)))
        .count();
    if scanner_hits >= 3 {
        return BlobRole::ScannerConfig;
    }

    // Live tasks: " Proxy (all traffic)", " Audit checks - passive".
    if strings
        .iter()
        .any(|s| s.contains("Proxy (all traffic)") || s.contains("Audit checks"))
    {
        return BlobRole::LiveTasks;
    }

    // Scope rule blobs hold `return true;` / `return false;` expressions
    // tagged with 'd' prefixes.
    if strings
        .iter()
        .any(|s| s.contains("return true;") || s.contains("return false;"))
    {
        return BlobRole::Scope;
    }

    // Fallback: many hostnames, no other signal — call it sitemap-ish.
    if strings.iter().filter(|s| is_hostname(s)).count() >= 10 {
        return BlobRole::Sitemap;
    }

    BlobRole::Unknown
}

fn harvest_scanner_config(strings: &[String], out: &mut ProjectSummary) {
    for s in strings {
        if looks_like_param_name(s) {
            out.scanner_parameter_names.push(s.clone());
        }
        harvest_loose_signals_one(s, out);
    }
}

fn harvest_issues(strings: &[String], out: &mut ProjectSummary) {
    let mut current = ScanIssue {
        title_or_excerpt: String::new(),
        severity: None,
        confidence: None,
        url: None,
        path: None,
    };

    for s in strings {
        if let Some(sev) = parse_severity(s) {
            current.severity = Some(sev);
        }
        if let Some(conf) = parse_confidence(s) {
            current.confidence = Some(conf);
        }
        if is_url(s) && current.url.is_none() {
            current.url = Some(s.clone());
        }
        if is_path(s) && current.path.is_none() {
            current.path = Some(s.clone());
        }
        if is_issue_text(s) {
            // Each chunk of issue prose closes the previous issue.
            if !current.title_or_excerpt.is_empty() || current.url.is_some() {
                out.issues.push(current.clone());
                current = ScanIssue::default();
            }
            current.title_or_excerpt = trim_to(s, 240);
        }
        harvest_loose_signals_one(s, out);
    }
    if !current.title_or_excerpt.is_empty() || current.url.is_some() {
        out.issues.push(current);
    }
}

fn harvest_scope(strings: &[String], out: &mut ProjectSummary) {
    for s in strings {
        if s.contains("return true;") {
            out.scope_includes
                .push(s.trim_start_matches(['d', 's', 't', ' ']).to_string());
            out.scope_rules_raw.push(s.clone());
        } else if s.contains("return false;") {
            out.scope_excludes
                .push(s.trim_start_matches(['d', 's', 't', ' ']).to_string());
            out.scope_rules_raw.push(s.clone());
        }
        if let Some(exts) = parse_extension_list(s) {
            out.file_extension_filters.push(exts);
        }
        harvest_loose_signals_one(s, out);
    }
}

fn harvest_live_tasks(strings: &[String], out: &mut ProjectSummary) {
    for s in strings {
        if s.contains("Proxy (all traffic)") || s.contains("Audit checks") {
            out.live_tasks.push(s.trim().to_string());
        }
        harvest_loose_signals_one(s, out);
    }
}

fn harvest_loose_signals(strings: &[String], out: &mut ProjectSummary) {
    for s in strings {
        harvest_loose_signals_one(s, out);
    }
}

fn harvest_loose_signals_one(s: &str, out: &mut ProjectSummary) {
    if is_url(s) {
        out.affected_urls.push(s.clone_to_string_or_self());
    }
    if let Some(c) = parse_cookie_finding(s) {
        out.flagged_cookies.push(c);
    }
    if let Some(e) = parse_email(s) {
        out.leaked_emails.push(e);
    }
    if let Some(p) = parse_card_number(s) {
        out.leaked_card_numbers.push(p);
    }
    if is_project_id_like(s) {
        out.project_id_candidates.push(s.trim().to_string());
    }
}

trait CloneToStringOrSelf {
    fn clone_to_string_or_self(&self) -> String;
}
impl CloneToStringOrSelf for str {
    fn clone_to_string_or_self(&self) -> String {
        self.to_string()
    }
}
impl CloneToStringOrSelf for String {
    fn clone_to_string_or_self(&self) -> String {
        self.clone()
    }
}

fn parse_severity(s: &str) -> Option<String> {
    let candidates = [
        "Severity: High",
        "Severity: Medium",
        "Severity: Low",
        "Severity: Information",
        "High",
        "Medium",
        "Low",
        "Information",
    ];
    for c in candidates {
        if s.contains(c) {
            return Some(c.to_string());
        }
    }
    None
}
fn parse_confidence(s: &str) -> Option<String> {
    for c in [
        "Confidence: Certain",
        "Confidence: Firm",
        "Confidence: Tentative",
    ] {
        if s.contains(c) {
            return Some(c.to_string());
        }
    }
    None
}

fn is_url(s: &str) -> bool {
    let t = s.trim_start_matches([' ', 't', 'd', 's', 'b', 'e']);
    t.starts_with("http://") || t.starts_with("https://")
}

fn is_path(s: &str) -> bool {
    let t = s.trim();
    if !t.starts_with('/') {
        return false;
    }
    if t.len() < 2 || t.len() > 4096 {
        return false;
    }
    !t.contains(' ') && !t.contains('<')
}

fn is_issue_text(s: &str) -> bool {
    // Issue prose has HTML markup and is long.
    s.contains("</p>")
        || s.contains("<p>")
        || s.contains("<code>")
        || s.contains("<b>")
        || (s.len() > 80
            && (s.contains("policy") || s.contains("vulnerab") || s.contains("attacker")))
}

fn parse_cookie_finding(s: &str) -> Option<String> {
    // Burp tags unrecognised cookies as "Other: <name>"
    if let Some(rest) = s.strip_prefix("Other: ") {
        let name = rest.trim();
        if !name.is_empty() && name.len() < 128 && !name.contains(' ') {
            return Some(name.to_string());
        }
    }
    None
}

fn parse_email(s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(at) = t.find('@') {
        let local = &t[..at];
        let dom = &t[at + 1..];
        if !local.is_empty()
            && local
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
            && dom.contains('.')
            && dom.len() <= 253
            && dom
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && t.len() <= 254
        {
            return Some(t.to_string());
        }
    }
    None
}

fn parse_card_number(s: &str) -> Option<String> {
    // 13-19 digit run that passes Luhn.
    let t = s.trim();
    if t.len() < 13 || t.len() > 19 {
        return None;
    }
    if !t.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if luhn(t) {
        Some(t.to_string())
    } else {
        None
    }
}

fn luhn(s: &str) -> bool {
    let mut sum = 0u32;
    for (i, c) in s.chars().rev().enumerate() {
        let mut d = c.to_digit(10).unwrap_or(0);
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

fn is_project_id_like(s: &str) -> bool {
    // 8-char base36 ID Burp uses: e.g. "xp6q26jc"
    s.len() == 8
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_digit())
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

fn looks_like_param_name(s: &str) -> bool {
    if s.len() > 64 {
        return false;
    }
    let t = s.trim();
    !t.is_empty()
        && !t.contains(' ')
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*' | ':'))
}

fn parse_extension_list(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches(['d', 's', 't', 'b']);
    let parts: Vec<&str> = t.split(',').collect();
    if parts.len() < 3 {
        return None;
    }
    if !parts.iter().all(|p| {
        let p = p.trim();
        !p.is_empty() && p.len() <= 8 && p.chars().all(|c| c.is_ascii_alphabetic())
    }) {
        return None;
    }
    Some(t.to_string())
}

fn is_hostname(s: &str) -> bool {
    let t = s.trim().trim_start_matches([' ', 't', 'd', 's']);
    if !t.contains('.') || t.len() > 253 || t.is_empty() {
        return false;
    }
    t.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn trim_to(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    s[..end].to_string()
}

fn dedup_inplace<T: Ord + Clone>(v: &mut Vec<T>) {
    v.sort();
    v.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luhn_validates_card_numbers() {
        assert!(luhn("4242424242424242")); // a test Visa
        assert!(luhn("5555555555554444")); // a test Mastercard
        assert!(!luhn("1234567890123456"));
    }

    #[test]
    fn extracts_email() {
        assert_eq!(
            parse_email("user@example.com"),
            Some("user@example.com".into())
        );
        assert_eq!(
            parse_email(" tag-with+plus@a.b "),
            Some("tag-with+plus@a.b".into())
        );
        assert_eq!(parse_email("not an email"), None);
        assert_eq!(parse_email("missing-at-symbol.com"), None);
    }

    #[test]
    fn parses_cookie_finding() {
        assert_eq!(parse_cookie_finding("Other: SIDCC"), Some("SIDCC".into()));
        assert_eq!(
            parse_cookie_finding("Other: __Secure-1PSIDCC"),
            Some("__Secure-1PSIDCC".into())
        );
        assert_eq!(parse_cookie_finding("Severity: High"), None);
    }

    #[test]
    fn parses_severity_and_confidence() {
        assert_eq!(
            parse_severity("Severity: High"),
            Some("Severity: High".into())
        );
        assert_eq!(
            parse_confidence("Confidence: Firm"),
            Some("Confidence: Firm".into())
        );
    }

    #[test]
    fn classifies_issues_blob() {
        let strings = vec![
            "unsafe-inline allowed".into(),
            "Content Security Policy".into(),
        ];
        assert_eq!(classify_blob(&strings), BlobRole::Issues);
    }

    #[test]
    fn classifies_scanner_config_blob() {
        let strings: Vec<String> = ["__viewstate", "__eventargument", "PHPSESSID", "jsessionid"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(classify_blob(&strings), BlobRole::ScannerConfig);
    }
}
