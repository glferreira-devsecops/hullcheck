//! Rendering: a human report, a machine-readable JSON document, and the triage
//! prompt that hands the findings to a coding agent. JSON is emitted by hand so
//! the tool keeps zero dependencies.

use crate::finding::{Finding, Lane};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROMPTBOOK_URL: &str = "https://www.rettecnologia.org/promptbook";

/// Count findings in a lane.
fn count(findings: &[Finding], lane: Lane) -> usize {
    findings.iter().filter(|f| f.lane == lane).count()
}

/// The human-facing report.
pub fn render_text(findings: &[Finding], scanned_files: usize, root: &str) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "hullcheck {VERSION}  ·  {scanned_files} files scanned  ·  {root}\n"
    ));
    s.push_str("read-only, no network. evidence is quoted by file and line.\n\n");

    if findings.is_empty() {
        s.push_str("No signals from these rules. That is not a clean bill of health:\n");
        s.push_str("these are a handful of common misconfigurations, not a full audit.\n\n");
        s.push_str(&footer());
        return s;
    }

    s.push_str(&format!(
        "Fix Now {}   Monitor {}   Validate Manually {}   Unverified {}\n\n",
        count(findings, Lane::FixNow),
        count(findings, Lane::Monitor),
        count(findings, Lane::Validate),
        count(findings, Lane::Unverified),
    ));

    for lane in Lane::ALL {
        let lane_findings: Vec<&Finding> = findings.iter().filter(|f| f.lane == lane).collect();
        if lane_findings.is_empty() {
            continue;
        }
        s.push_str(&format!("## {}\n\n", lane.title()));
        for f in lane_findings {
            s.push_str(&format!("{}:{}  {}\n", f.file, f.line, f.title));
            s.push_str(&format!("    {}\n", f.quote));
            s.push_str(&format!("    why: {}\n", f.impact));
            s.push_str(&format!("    fix: {}\n\n", f.fix));
        }
    }

    s.push_str(&footer());
    s
}

/// The closing block: how to read the lanes, the triage prompt, and the link.
fn footer() -> String {
    let mut s = String::new();
    s.push_str(
        "Lanes: Fix Now = safe to correct now. Monitor = depends on config outside the repo.\n",
    );
    s.push_str("Validate Manually = touches login, data, billing, uploads, admin or AI tools; a human confirms.\n");
    s.push_str(
        "This tool does not test third parties, write exploits, or prove your app is secure.\n\n",
    );
    s.push_str("Hand the findings to your agent with this prompt:\n");
    s.push_str(
        "  \"For each hullcheck finding, open the quoted file:line, confirm the issue is real,\n",
    );
    s.push_str(
        "   then propose the smallest safe fix and a test that fails before it. Do not change\n",
    );
    s.push_str("   anything you cannot confirm from the file.\"\n\n");
    s.push_str(&format!(
        "Full review kit (13 skills, auth/uploads/AI/LGPD/threat model): {PROMPTBOOK_URL}\n"
    ));
    s
}

/// The machine-readable report. Stable key order; safe JSON string escaping.
pub fn render_json(findings: &[Finding], scanned_files: usize) -> String {
    let mut s = String::new();
    s.push_str("{\n");
    s.push_str(&format!(
        "  \"tool\": \"hullcheck\",\n  \"version\": \"{VERSION}\",\n"
    ));
    s.push_str(&format!("  \"scannedFiles\": {scanned_files},\n"));
    s.push_str("  \"summary\": {\n");
    s.push_str(&format!(
        "    \"fixNow\": {},\n",
        count(findings, Lane::FixNow)
    ));
    s.push_str(&format!(
        "    \"monitor\": {},\n",
        count(findings, Lane::Monitor)
    ));
    s.push_str(&format!(
        "    \"validate\": {},\n",
        count(findings, Lane::Validate)
    ));
    s.push_str(&format!(
        "    \"unverified\": {}\n",
        count(findings, Lane::Unverified)
    ));
    s.push_str("  },\n");
    s.push_str("  \"findings\": [");
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("\n    {\n");
        s.push_str(&format!("      \"rule\": \"{}\",\n", esc(f.rule)));
        s.push_str(&format!("      \"lane\": \"{}\",\n", f.lane.slug()));
        s.push_str(&format!("      \"title\": \"{}\",\n", esc(&f.title)));
        s.push_str(&format!("      \"file\": \"{}\",\n", esc(&f.file)));
        s.push_str(&format!("      \"line\": {},\n", f.line));
        s.push_str(&format!("      \"quote\": \"{}\",\n", esc(&f.quote)));
        s.push_str(&format!("      \"impact\": \"{}\",\n", esc(&f.impact)));
        s.push_str(&format!("      \"fix\": \"{}\"\n", esc(&f.fix)));
        s.push_str("    }");
    }
    if findings.is_empty() {
        s.push(']');
    } else {
        s.push_str("\n  ]");
    }
    s.push_str("\n}\n");
    s
}

/// Escape a string for a JSON double-quoted value, per RFC 8259.
fn esc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escapes_control_and_quotes() {
        assert_eq!(esc("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }

    #[test]
    fn empty_findings_make_valid_json_array() {
        let out = render_json(&[], 10);
        assert!(out.contains("\"findings\": []"));
    }
}
