//! The in-memory view of the repository that rules scan.
//!
//! Each file is read once, kept as its original text, and split into lines
//! once. Rules get both: whole-file substring tests hit `text` with no
//! re-allocation, and line-level evidence reads `lines` by 1-based index.

use std::fs;
use std::path::Path;

use crate::ignore::Ignore;
use crate::walk::{read_text, walk};

/// One text file: its original content and its lines.
pub struct TextFile {
    /// Repo-relative path, forward slashes.
    pub rel: String,
    /// Original file content (with `\r` stripped per line on the line view).
    pub text: String,
    /// Lines without trailing `\r`; index `n-1` is the 1-based line `n`.
    pub lines: Vec<String>,
}

impl TextFile {
    /// The 1-based line, or an empty string when out of range, so a rule can
    /// quote evidence without ever panicking on a bad index.
    pub fn line(&self, n: usize) -> &str {
        if n == 0 || n > self.lines.len() {
            ""
        } else {
            &self.lines[n - 1]
        }
    }

    /// The lowercase file extension, without the dot.
    pub fn ext(&self) -> &str {
        match self.rel.rsplit_once('.') {
            Some((_, e)) => e,
            None => "",
        }
    }

    /// The final path segment.
    pub fn name(&self) -> &str {
        match self.rel.rsplit_once('/') {
            Some((_, n)) => n,
            None => &self.rel,
        }
    }
}

/// Every scannable text file in the repository.
pub struct Repo {
    pub files: Vec<TextFile>,
}

impl Repo {
    /// Load the repository rooted at `root`, read-only. Non-text and oversized
    /// files are skipped by the walker, not loaded here.
    pub fn load(root: &Path) -> Repo {
        let ignore = match fs::read_to_string(root.join(".shipsafeignore")) {
            Ok(text) => Ignore::parse(&text),
            Err(_) => Ignore::empty(),
        };
        let mut files = Vec::new();
        for entry in walk(root) {
            if ignore.is_ignored(&entry.rel) {
                continue;
            }
            if let Some(text) = read_text(&entry.path) {
                let lines = text
                    .split('\n')
                    .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
                    .collect();
                files.push(TextFile {
                    rel: entry.rel,
                    text,
                    lines,
                });
            }
        }
        Repo { files }
    }

    /// True when a file at exactly this relative path exists.
    pub fn has(&self, rel: &str) -> bool {
        self.files.iter().any(|f| f.rel == rel)
    }

    /// The file at exactly this relative path, if present.
    pub fn get(&self, rel: &str) -> Option<&TextFile> {
        self.files.iter().find(|f| f.rel == rel)
    }
}
