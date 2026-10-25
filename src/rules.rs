//! The scan rules. Each is read-only and every finding it produces carries the
//! exact file, 1-based line, and quoted source line behind the signal.
//!
//! Rules are deliberately conservative: a rule stays silent rather than guess.
//! When a rule suspects a problem it cannot confirm from the files present, it
//! files the signal under `Lane::Unverified`, never under `Lane::FixNow`.
//!
//! Most rules look at one file at a time ([`PER_FILE`]) and so run in parallel
//! across files. The agent instruction doctor needs to see the whole file set
//! at once ([`whole_repo`]).

use crate::finding::{Finding, Lane};
use crate::repo::{Repo, TextFile};

/// A rule that decides from a single file. These run in parallel across files.
pub type PerFileRule = fn(&TextFile) -> Vec<Finding>;

/// Every per-file rule, in a stable order.
pub const PER_FILE: &[PerFileRule] = &[
    supabase_rls,
    credential_columns,
    client_secret,
    stripe_webhook,
    sourcemaps,
    mcp_and_hooks,
    github_actions_pin,
    github_pr_target,
];

/// Rules that need the whole repository at once (cross-file reasoning).
pub fn whole_repo(repo: &Repo) -> Vec<Finding> {
    agent_doctor(repo)
}

// ---- helpers ---------------------------------------------------------------

/// Case-insensitive substring test, ASCII-folded. The source keywords we match
/// on (create table, service_role, uses:) are all ASCII.
fn has(haystack: &str, needle: &str) -> bool {
    find_ci(haystack, needle).is_some()
}

/// Byte index of the first case-insensitive match of `needle` in `haystack`.
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let n = needle.as_bytes();
    if n.is_empty() {
        return Some(0);
    }
    let h = haystack.as_bytes();
    if n.len() > h.len() {
        return None;
    }
    'outer: for i in 0..=(h.len() - n.len()) {
        for j in 0..n.len() {
            if !h[i + j].eq_ignore_ascii_case(&n[j]) {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

/// True when `s` is exactly 40 hex chars: a git commit SHA.
fn is_commit_sha(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when the path looks like code that ships to the browser.
fn is_client_path(rel: &str) -> bool {
    rel.starts_with("public/")
        || rel.contains("/public/")
        || rel.ends_with(".tsx")
        || rel.ends_with(".jsx")
        || rel.ends_with(".vue")
        || rel.ends_with(".svelte")
        || rel.starts_with("app/")
        || rel.starts_with("src/")
        || rel.starts_with("components/")
        || rel.starts_with("pages/")
}

/// True when the extension is a source-code file, not prose or config.
fn is_code(ext: &str) -> bool {
    matches!(
        ext,
        "ts" | "tsx"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "py"
            | "rb"
            | "go"
            | "php"
            | "java"
            | "cs"
            | "rs"
    )
}

/// First 1-based line and its text containing `needle` (case-insensitive).
fn first_line<'a>(f: &'a TextFile, needle: &str) -> Option<(usize, &'a str)> {
    f.lines
        .iter()
        .enumerate()
        .find(|(_, l)| has(l, needle))
        .map(|(i, l)| (i + 1, l.as_str()))
}

// ---- rule: supabase row level security -------------------------------------

/// A table created in a migration with no `enable row level security` in the
/// same file is readable by anyone with the anon key. Also flags a policy whose
/// qualifier is `using (true)`, which matches every row.
fn supabase_rls(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "supabase-rls";
    let is_sql = f.ext() == "sql" || f.rel.contains("/migrations/") || f.rel.contains("migration");
    if !is_sql {
        return Vec::new();
    }
    let mut out = Vec::new();
    let rls_enabled = has(&f.text, "enable row level security");
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        if !rls_enabled {
            if let Some(table) = create_table_name(line) {
                out.push(Finding::new(
                    RULE,
                    Lane::Validate,
                    format!("Table `{table}` created with no row level security in this migration"),
                    &f.rel,
                    n,
                    line,
                    "Without RLS, any client holding the public anon key can read or change every row in this table.",
                    format!("Confirm RLS belongs here, then `alter table {table} enable row level security;` and add a policy scoped to the owner."),
                ));
            }
        }
        if has(line, "using (true)") || has(line, "using ( true )") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Row level security policy matches every row (USING (true))",
                &f.rel,
                n,
                line,
                "A `using (true)` policy lets every request read the rows it guards, so RLS is on but enforces nothing.",
                "Replace `true` with a predicate that ties the row to the caller, e.g. `auth.uid() = user_id`.",
            ));
        }
    }
    out
}

/// Extract the table name from `create table [if not exists] [schema.]name`.
fn create_table_name(line: &str) -> Option<String> {
    let idx = find_ci(line, "create table")?;
    let mut rest = line[idx + "create table".len()..].trim_start();
    if let Some(stripped) = strip_prefix_ci(rest, "if not exists") {
        rest = stripped.trim_start();
    }
    let token: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '(')
        .collect();
    let cleaned = token.trim_matches(|c| c == '"' || c == '`' || c == '[' || c == ']' || c == ';');
    let name = cleaned.rsplit('.').next().unwrap_or(cleaned);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Strip a case-insensitive prefix, returning the remainder when it matched.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

// ---- rule: credential columns in app tables --------------------------------

/// A column literally named `password` in a migration usually means the app
/// stores credentials itself, beside a managed auth provider. That was the
/// second mistake behind the 2026 Supabase exposures: plaintext passwords in
/// application tables (UpGuard, Sep 2026).
fn credential_columns(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "credential-columns";
    let is_sql = f.ext() == "sql" || f.rel.contains("/migrations/") || f.rel.contains("migration");
    if !is_sql {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // A column definition whose name is exactly `password` (not
        // `password_hash`/`password_digest`), followed by a type.
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("password") {
            let next = rest.chars().next();
            let is_bare = matches!(next, Some(c) if c.is_whitespace());
            let typed = has(rest, "text")
                || has(rest, "varchar")
                || has(rest, "char")
                || has(rest, "citext");
            if is_bare && typed {
                out.push(Finding::new(
                    RULE,
                    Lane::Validate,
                    "Column named `password` in a migration",
                    &f.rel,
                    i + 1,
                    line,
                    "A `password` column often means the app stores credentials itself; in the 2026 Supabase exposures these were plaintext.",
                    "Confirm it is a salted hash, or move authentication to a managed provider and drop the column.",
                ));
            }
        }
    }
    out
}

// ---- rule: secrets in client code ------------------------------------------

/// High-signal secret literals that must never reach the browser bundle.
fn client_secret(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "client-secret";
    let client = is_client_path(&f.rel);
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;

        // A public env var whose name screams secret: shipped to every visitor.
        for prefix in [
            "NEXT_PUBLIC_",
            "EXPO_PUBLIC_",
            "REACT_APP_",
            "VITE_",
            "PUBLIC_",
        ] {
            if let Some(pos) = line.find(prefix) {
                // Require an identifier boundary before the prefix so `PUBLIC_`
                // does not also match inside `NEXT_PUBLIC_` and double-report.
                let boundary = pos == 0 || {
                    let b = line.as_bytes()[pos - 1];
                    !b.is_ascii_alphanumeric() && b != b'_'
                };
                if !boundary {
                    continue;
                }
                let after = &line[pos + prefix.len()..];
                let var: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let v = var.to_ascii_uppercase();
                if v.contains("SERVICE_ROLE")
                    || v.contains("SECRET")
                    || v.contains("PRIVATE")
                    || v.contains("PASSWORD")
                {
                    out.push(Finding::new(
                        RULE,
                        Lane::FixNow,
                        format!("Secret exposed through public env var `{prefix}{var}`"),
                        &f.rel,
                        n,
                        line,
                        "Any variable with a public prefix is inlined into the client bundle and visible to every visitor.",
                        "Drop the public prefix and read this value only on the server; rotate it, since it was already shipped.",
                    ));
                }
            }
        }

        // Live or test Stripe secret key literal.
        // shipsafe:ignore-next-line detector pattern
        if line.contains("sk_live_") || line.contains("sk_test_") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Stripe secret key hardcoded in source",
                &f.rel,
                n,
                line,
                "A Stripe secret key in the repo can create charges and refunds; a test key still leaks account structure.",
                "Remove it, move it to a server-only env var, and roll the key in the Stripe dashboard.",
            ));
        }

        // A privileged Supabase client built in browser code: the real smell is
        // the privileged key passed into the client builder on one line, not a
        // bare mention in a comment or type.
        // shipsafe:ignore-next-line detector pattern
        if client && has(line, "service_role") && has(line, "createClient") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Supabase client built with service_role in client code",
                &f.rel,
                n,
                line,
                "The service_role key bypasses RLS; in client code it hands every visitor full database access.",
                "Use the anon key in the browser and keep service_role on the server only.",
            ));
        }

        // AWS access key id literal.
        if let Some(k) = aws_key(line) {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "AWS access key id hardcoded in source",
                &f.rel,
                n,
                k,
                "A committed AWS key can be used until it is revoked, even from private history.",
                "Remove it, rotate the key in IAM, and load credentials from the environment or a role.",
            ));
        }

        // Private key material.
        // shipsafe:ignore-next-line detector pattern
        if line.contains("-----BEGIN") && has(line, "PRIVATE KEY") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Private key committed to the repository",
                &f.rel,
                n,
                line,
                "A committed private key stays usable from git history until the key is rotated.",
                "Remove it, rotate the key pair, and keep private keys out of the repo entirely.",
            ));
        }
    }
    out
}

/// Return the AWS key literal when the line contains an `AKIA`/`ASIA` id of the
/// right length.
fn aws_key(line: &str) -> Option<String> {
    for marker in ["AKIA", "ASIA"] {
        if let Some(pos) = line.find(marker) {
            let token: String = line[pos..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .collect();
            if token.len() == 20 {
                return Some(token);
            }
        }
    }
    None
}

// ---- rule: stripe webhook signature ----------------------------------------

/// A Stripe webhook handler that never verifies the signature lets anyone POST
/// a fake `checkout.session.completed` and unlock paid access.
fn stripe_webhook(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "stripe-webhook";
    // Only handler code, not prose or docs that merely discuss webhooks.
    if !is_code(f.ext()) {
        return Vec::new();
    }
    let is_stripe = has(&f.text, "stripe");
    let is_webhook = has(&f.rel, "webhook") || has(&f.text, "webhook");
    if !(is_stripe && is_webhook) {
        return Vec::new();
    }
    let verifies = has(&f.text, "constructEvent")
        || has(&f.text, "construct_event")
        || has(&f.text, "verifyHeader")
        || has(&f.text, "stripe-signature");
    if verifies {
        return Vec::new();
    }
    let (n, line) = first_line(f, "webhook").unwrap_or((1, f.line(1)));
    vec![Finding::new(
        RULE,
        Lane::Validate,
        "Stripe webhook handler with no signature verification found",
        &f.rel,
        n,
        line,
        "Without verifying the `stripe-signature` header, anyone who finds the URL can forge a paid event.",
        "Verify the event with `stripe.webhooks.constructEvent(body, sig, secret)` before acting on it, and reject on failure.",
    )]
}

// ---- rule: production source maps ------------------------------------------

/// Source maps shipped to production hand your original source to anyone who
/// opens dev tools.
fn sourcemaps(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "public-sourcemaps";
    let is_config = f.name().starts_with("next.config")
        || f.name().starts_with("vite.config")
        || f.name().starts_with("nuxt.config");
    if !is_config {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        let hit = (has(line, "productionBrowserSourceMaps") && has(line, "true"))
            || (has(line, "sourcemap") && has(line, "true") && !has(line, "false"));
        if hit {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "Production source maps appear to be enabled",
                &f.rel,
                n,
                line,
                "Public source maps expose your original source, including comments and internal names, to anyone.",
                "Confirm this build ships to production; if so, disable browser source maps for the production build.",
            ));
        }
    }
    out
}

// ---- rule: mcp servers and agent hooks -------------------------------------

/// MCP server configs and editor hooks run local commands the agent can trigger.
/// Worth a human look, because a malicious entry runs with your permissions.
fn mcp_and_hooks(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "mcp-hooks";
    let watched = f.name() == ".mcp.json"
        || f.rel.ends_with(".cursor/mcp.json")
        || f.rel.ends_with(".cursor/hooks.json")
        || f.rel.ends_with(".vscode/mcp.json")
        || f.rel.ends_with(".claude/settings.json");
    if !watched {
        return Vec::new();
    }
    match first_line(f, "\"command\"") {
        Some((n, line)) => vec![Finding::new(
            RULE,
            Lane::Validate,
            "MCP server or agent hook runs a local command",
            &f.rel,
            n,
            line,
            "An MCP server or hook runs with your permissions; a command you did not vet can read secrets or change files.",
            "Read each command, confirm you trust the source, and remove any entry you did not add yourself.",
        )],
        None => Vec::new(),
    }
}

// ---- rule: github actions pinned by sha ------------------------------------

/// A third-party action pinned to a tag or branch can be moved under you; only a
/// commit SHA is immutable.
fn github_actions_pin(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "gha-pin";
    let in_workflows =
        f.rel.starts_with(".github/workflows/") && (f.ext() == "yml" || f.ext() == "yaml");
    if !in_workflows {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        let Some(pos) = find_ci(line, "uses:") else {
            continue;
        };
        let value = line[pos + "uses:".len()..]
            .trim()
            .trim_matches(|c| c == '"' || c == '\'');
        if value.starts_with("./") || value.starts_with("docker://") {
            continue; // local or docker action: not tag-pinned
        }
        let Some((_, reference)) = value.split_once('@') else {
            continue;
        };
        let reference = reference.split_whitespace().next().unwrap_or(reference);
        if !is_commit_sha(reference) {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "GitHub Action pinned to a tag or branch, not a commit SHA",
                &f.rel,
                n,
                line,
                "A tag or branch can be repointed at new code without a PR, so the action you review is not always the action that runs.",
                "Pin third-party actions to a full 40-char commit SHA and let Dependabot bump it.",
            ));
        }
    }
    out
}

// ---- rule: github pull_request_target --------------------------------------

/// A workflow triggered by `pull_request_target` runs with the base repo's
/// secrets while checking out code from the (untrusted) fork. Combined with a
/// checkout of the PR head, it is the common root cause of the 2026 GitHub
/// Actions supply-chain incidents.
fn github_pr_target(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "gha-pr-target";
    let in_workflows =
        f.rel.starts_with(".github/workflows/") && (f.ext() == "yml" || f.ext() == "yaml");
    if !in_workflows {
        return Vec::new();
    }
    for (i, line) in f.lines.iter().enumerate() {
        if has(line, "pull_request_target") {
            return vec![Finding::new(
                RULE,
                Lane::Validate,
                "Workflow uses the `pull_request_target` trigger",
                &f.rel,
                i + 1,
                line,
                "pull_request_target runs with your repository secrets; if it also checks out the PR head, a fork can exfiltrate them.",
                "Confirm this workflow does not check out or run untrusted PR code, or move it to the `pull_request` trigger.",
            )];
        }
    }
    Vec::new()
}

// ---- rule: agent instruction doctor ----------------------------------------

/// Which instruction file does each agent actually load? A `CLAUDE.md` silently
/// shadows `AGENTS.md`, an `.antigravity.md` is read by nothing, a `.md` under
/// `.cursor/rules` is ignored, and a stray `.cursorrules` can win over
/// `AGENTS.md` in first-match loaders like Zed. These waste the rules you wrote.
fn agent_doctor(repo: &Repo) -> Vec<Finding> {
    const RULE: &str = "agent-doctor";
    let mut out = Vec::new();

    if let (true, Some(claude)) = (repo.has("AGENTS.md"), repo.get("CLAUDE.md")) {
        let references_agents = claude.lines.iter().any(|l| has(l, "AGENTS.md"));
        if !references_agents {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "Claude Code reads CLAUDE.md and ignores AGENTS.md here",
                "CLAUDE.md",
                1,
                claude.line(1),
                "When a CLAUDE.md exists, Claude Code loads it and does not also load AGENTS.md, so the AGENTS.md rules never reach that agent.",
                "Add `@AGENTS.md` to the first line of CLAUDE.md so both are loaded.",
            ));
        }
    }

    if let Some(f) = repo.get(".antigravity.md") {
        out.push(Finding::new(
            RULE,
            Lane::Validate,
            "`.antigravity.md` is read by no agent",
            ".antigravity.md",
            1,
            f.line(1),
            "Antigravity reads AGENTS.md, GEMINI.md and .agents/rules/*.md; there is no .antigravity.md convention, so this file does nothing.",
            "Move these rules into AGENTS.md or an .agents/rules/*.md file with a trigger.",
        ));
    }

    for f in &repo.files {
        if f.rel.starts_with(".cursor/rules/") && f.ext() == "md" {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "Cursor ignores `.md` rules in .cursor/rules (needs .mdc)",
                &f.rel,
                1,
                f.line(1),
                "Cursor loads rule files with the .mdc extension; a plain .md in .cursor/rules is skipped.",
                "Rename this file to .mdc and add the Cursor rule frontmatter.",
            ));
        }
    }

    for stray in [".cursorrules", ".windsurfrules"] {
        if let (true, Some(f)) = (repo.has("AGENTS.md"), repo.get(stray)) {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                format!("Stray `{stray}` can win over AGENTS.md in first-match loaders"),
                stray,
                1,
                f.line(1),
                "Editors like Zed load the first instruction file they find, and a leftover rules file can be picked before AGENTS.md.",
                "Delete the leftover file once its content lives in AGENTS.md.",
            ));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_sha_detection() {
        assert!(is_commit_sha("8bab26f4f0000000000000000000000000000abc"));
        assert!(!is_commit_sha("v4"));
        assert!(!is_commit_sha("main"));
    }

    #[test]
    fn table_name_parsing() {
        assert_eq!(
            create_table_name("create table public.profiles (").as_deref(),
            Some("profiles")
        );
        assert_eq!(
            create_table_name("CREATE TABLE IF NOT EXISTS orders(").as_deref(),
            Some("orders")
        );
        assert_eq!(
            create_table_name("  create table \"users\"").as_deref(),
            Some("users")
        );
        assert_eq!(create_table_name("select 1"), None);
    }

    #[test]
    fn aws_key_shape() {
        // Build the 20-char key id at runtime so the literal is not committed.
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        assert_eq!(
            aws_key(&format!("const k = '{key}'")).as_deref(),
            Some(key.as_str())
        );
        assert_eq!(aws_key("no key here"), None);
    }

    #[test]
    fn find_ci_matches_case_insensitively() {
        assert_eq!(find_ci("Hello World", "world"), Some(6));
        assert_eq!(find_ci("abc", "xyz"), None);
        assert_eq!(find_ci("", "x"), None);
    }
}
