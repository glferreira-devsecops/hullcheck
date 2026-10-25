//! shipsafe: a read-only, zero-network, zero-dependency security review for the
//! SaaS you built with an AI coding agent.
//!
//! The library is the whole tool; the binary is a thin CLI over [`scan::scan`].
//! Every finding carries the exact file, 1-based line, and quoted source line
//! behind it, and nothing is ever called a confirmed vulnerability without a
//! human in the loop.

pub mod finding;
pub mod ignore;
pub mod repo;
pub mod report;
pub mod rules;
pub mod scan;
pub mod walk;

use std::path::Path;

/// Load a repository and scan it. Returns the findings (sorted) and the number
/// of text files scanned.
pub fn review(root: &Path) -> (Vec<finding::Finding>, usize) {
    let repo = repo::Repo::load(root);
    let scanned = repo.files.len();
    let findings = scan::scan(&repo);
    (findings, scanned)
}
