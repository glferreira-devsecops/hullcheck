//! Path ignores, read from a `.hullcheckignore` file at the repository root, plus
//! the inline `hullcheck:ignore` directive handled by the scan runner.
//!
//! Every real scanner needs a way to silence vendored, generated, or
//! intentionally-insecure files (test fixtures, examples). The syntax is a small
//! gitignore-style subset: one pattern per line, `#` comments, `*` matching
//! within a path segment, `**` matching across segments, `?` matching one
//! non-slash character, and a trailing `/` marking a directory prefix.

/// A compiled set of ignore patterns.
pub struct Ignore {
    patterns: Vec<Pattern>,
}

struct Pattern {
    /// Segments split on `/`. A trailing-slash directory pattern keeps its
    /// segments and is matched as a prefix.
    segments: Vec<String>,
    dir_only: bool,
}

impl Ignore {
    /// Parse the contents of a `.hullcheckignore` file. An empty or missing file
    /// yields a set that ignores nothing.
    pub fn parse(text: &str) -> Ignore {
        let mut patterns = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let dir_only = line.ends_with('/');
            let trimmed = line.trim_end_matches('/').trim_start_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            patterns.push(Pattern {
                segments: trimmed.split('/').map(|s| s.to_string()).collect(),
                dir_only,
            });
        }
        Ignore { patterns }
    }

    /// An ignore set that matches nothing.
    pub fn empty() -> Ignore {
        Ignore {
            patterns: Vec::new(),
        }
    }

    /// True when `rel` (a forward-slash repo-relative path) should be skipped.
    pub fn is_ignored(&self, rel: &str) -> bool {
        let parts: Vec<&str> = rel.split('/').collect();
        self.patterns.iter().any(|p| p.matches(&parts))
    }
}

impl Pattern {
    fn matches(&self, path: &[&str]) -> bool {
        let pat: Vec<&str> = self.segments.iter().map(|s| s.as_str()).collect();
        if self.dir_only {
            // Directory pattern: match any file whose leading segments are the
            // pattern (i.e. the pattern is a prefix of the path).
            if path.len() <= pat.len() {
                return false;
            }
            match_segments(&pat, &path[..pat.len()])
        } else {
            match_segments(&pat, path)
        }
    }
}

/// Match pattern segments against path segments, with `**` spanning zero or more
/// path segments and `*`/`?` matching within one segment.
fn match_segments(pat: &[&str], path: &[&str]) -> bool {
    match pat.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => {
            // `**` consumes zero or more path segments.
            (0..=path.len()).any(|skip| match_segments(rest, &path[skip..]))
        }
        Some((seg, rest)) => match path.split_first() {
            Some((head, tail)) if glob_segment(seg.as_bytes(), head.as_bytes()) => {
                match_segments(rest, tail)
            }
            _ => false,
        },
    }
}

/// Match a single path segment against a glob segment with `*` (any run, no
/// slash) and `?` (one char).
fn glob_segment(pat: &[u8], text: &[u8]) -> bool {
    match pat.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| glob_segment(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && glob_segment(rest, &text[1..]),
        Some((c, rest)) => match text.split_first() {
            Some((t, ttail)) if t == c => glob_segment(rest, ttail),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_prefix_ignores_subtree() {
        let ig = Ignore::parse("tests/fixtures/\n");
        assert!(ig.is_ignored("tests/fixtures/vuln/app/page.tsx"));
        assert!(!ig.is_ignored("tests/scan.rs"));
        assert!(!ig.is_ignored("tests/fixtures")); // the dir entry itself, not a file under it
    }

    #[test]
    fn star_matches_within_segment_only() {
        let ig = Ignore::parse("*.min.js\n");
        assert!(ig.is_ignored("app.min.js"));
        assert!(!ig.is_ignored("app.js"));
    }

    #[test]
    fn double_star_spans_segments() {
        let ig = Ignore::parse("vendor/**\n");
        assert!(ig.is_ignored("vendor/a/b/c.js"));
        assert!(ig.is_ignored("vendor/x.js"));
        assert!(!ig.is_ignored("src/vendor/x.js"));
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let ig = Ignore::parse("# a comment\n\n   \n");
        assert!(!ig.is_ignored("anything"));
    }
}
