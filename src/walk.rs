//! Read-only repository walker.
//!
//! It never writes, never follows symlinks, and never leaves the root. A size
//! cap keeps a committed bundle or lockfile from dominating the run.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories we never descend into: dependencies, build output, VCS, caches.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "dist",
    "build",
    "out",
    "coverage",
    ".turbo",
    ".cache",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".terraform",
    "target",
];

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A file worth scanning: its path on disk and its repo-relative path.
pub struct Entry {
    pub path: PathBuf,
    pub rel: String,
}

/// Walk `root` and return the files worth scanning, sorted by relative path so
/// output is deterministic across runs and platforms.
pub fn walk(root: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue, // unreadable dir: skip, do not abort the scan
        };
        for entry in entries.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue; // never follow links out of the tree
            }
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if ft.is_dir() {
                if SKIP_DIRS.contains(&name.as_ref()) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(Entry {
                        rel: rel.to_string_lossy().replace('\\', "/"),
                        path,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    out
}

/// Read a file as UTF-8, returning `None` when it is too large, binary, or
/// unreadable so a rule can skip it instead of failing the run.
pub fn read_text(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    // Reject files with NUL bytes: those are binary, not source we can quote.
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}
