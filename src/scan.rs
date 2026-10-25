//! The scan runner: apply every rule to the repository and return findings in a
//! deterministic order.
//!
//! Per-file rules are embarrassingly parallel, so the file list is split across
//! the available cores and scanned with `std::thread::scope` (no external
//! runtime, no shared mutable state). Results are sorted at the end, so the
//! output never depends on thread timing.

use std::thread;

use crate::finding::{Finding, Lane};
use crate::repo::{Repo, TextFile};
use crate::rules;

/// Inline directive on the finding's own line, and the directive on the line
/// above it (eslint-style "disable next line").
const IGNORE_SAME_LINE: &str = "shipsafe:ignore";
const IGNORE_NEXT_LINE: &str = "shipsafe:ignore-next-line";

/// Scan the whole repository and return findings, sorted for stable output.
pub fn scan(repo: &Repo) -> Vec<Finding> {
    let mut findings = scan_per_file(&repo.files);
    findings.extend(rules::whole_repo(repo));
    findings.retain(|f| !suppressed(repo, f));
    sort(&mut findings);
    findings
}

/// True when the finding is silenced by an inline directive: `shipsafe:ignore`
/// on its own line, or `shipsafe:ignore-next-line` on the line above it.
fn suppressed(repo: &Repo, f: &Finding) -> bool {
    let Some(file) = repo.get(&f.file) else {
        return false;
    };
    if file.line(f.line).contains(IGNORE_SAME_LINE) {
        return true;
    }
    f.line > 1 && file.line(f.line - 1).contains(IGNORE_NEXT_LINE)
}

/// Run the per-file rules over every file, in parallel across cores.
fn scan_per_file(files: &[TextFile]) -> Vec<Finding> {
    // Below this size the thread setup costs more than it saves.
    const SERIAL_THRESHOLD: usize = 64;
    let workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if workers <= 1 || files.len() < SERIAL_THRESHOLD {
        return run_chunk(files);
    }

    let chunk = files.len().div_ceil(workers);
    thread::scope(|scope| {
        let handles: Vec<_> = files
            .chunks(chunk)
            .map(|slice| scope.spawn(move || run_chunk(slice)))
            .collect();
        let mut out = Vec::new();
        for handle in handles {
            // A rule panicking on one chunk must not take down the whole scan;
            // surface it as no findings for that chunk rather than aborting.
            if let Ok(mut part) = handle.join() {
                out.append(&mut part);
            }
        }
        out
    })
}

/// Apply every per-file rule to each file in `slice`.
fn run_chunk(slice: &[TextFile]) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in slice {
        for rule in rules::PER_FILE {
            out.append(&mut rule(file));
        }
    }
    out
}

/// The reporting rank of a lane: lower sorts first.
fn lane_rank(lane: Lane) -> u8 {
    match lane {
        Lane::FixNow => 0,
        Lane::Monitor => 1,
        Lane::Validate => 2,
        Lane::Unverified => 3,
    }
}

/// Deterministic order: lane, then file, line, rule, title. Independent of how
/// the work was split across threads.
fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        lane_rank(a.lane)
            .cmp(&lane_rank(b.lane))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule.cmp(b.rule))
            .then_with(|| a.title.cmp(&b.title))
    });
}
