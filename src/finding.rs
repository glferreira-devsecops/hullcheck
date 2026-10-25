//! The finding model and the four RET lanes.
//!
//! Nothing reaches `FixNow` unless a concrete source line was quoted from a
//! file. Anything the scanner suspects but cannot confirm goes to `Unverified`,
//! never to `FixNow`. That rule is the whole point: evidence by file and line,
//! no false certainty.

use std::fmt;

/// Where a signal lands. The order is the reporting order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Evidenced, low-risk issue that can be corrected safely.
    FixNow,
    /// Signal that may return or depends on configuration outside the repo.
    Monitor,
    /// Risk touching login, customer data, billing, uploads, admin or AI tools,
    /// where a human must confirm before calling it a vulnerability.
    Validate,
    /// Suspected but not confirmable from the files present. Stays out of
    /// FixNow until someone shows the evidence.
    Unverified,
}

impl Lane {
    pub fn slug(self) -> &'static str {
        match self {
            Lane::FixNow => "fix-now",
            Lane::Monitor => "monitor",
            Lane::Validate => "validate",
            Lane::Unverified => "unverified",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Lane::FixNow => "Fix Now",
            Lane::Monitor => "Monitor",
            Lane::Validate => "Validate Manually",
            Lane::Unverified => "Unverified",
        }
    }

    pub const ALL: [Lane; 4] = [
        Lane::FixNow,
        Lane::Monitor,
        Lane::Validate,
        Lane::Unverified,
    ];
}

/// One evidenced signal. Every field is mandatory: a finding without a file, a
/// line and the quoted line is not evidence, so it cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable rule id, e.g. "supabase-rls".
    pub rule: &'static str,
    pub lane: Lane,
    /// Short human title.
    pub title: String,
    /// Repo-relative path, forward slashes.
    pub file: String,
    /// 1-based line number.
    pub line: usize,
    /// The exact source line behind the signal, trimmed.
    pub quote: String,
    /// Why it matters, in plain language.
    pub impact: String,
    /// The concrete next action.
    pub fix: String,
}

impl Finding {
    /// Build a finding, normalizing the quoted line. `line` must be 1-based.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule: &'static str,
        lane: Lane,
        title: impl Into<String>,
        file: impl Into<String>,
        line: usize,
        quote: impl Into<String>,
        impact: impl Into<String>,
        fix: impl Into<String>,
    ) -> Finding {
        debug_assert!(line >= 1, "line numbers are 1-based");
        let mut quote: String = quote.into().trim().to_string();
        if quote.chars().count() > 240 {
            quote = quote.chars().take(240).collect();
        }
        Finding {
            rule,
            lane,
            title: title.into(),
            file: file.into(),
            line,
            quote,
            impact: impact.into(),
            fix: fix.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}  {}", self.file, self.line, self.title)
    }
}
