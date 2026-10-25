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
    gha_injection,
    firebase_rules,
    committed_env,
    cors_wildcard,
    tls_verification_off,
    jwt_alg_none,
    dangerous_html,
    prisma_raw_unsafe,
    debug_production,
    pii_sensitive_data,
    tracking_consent,
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

/// True when the file is a `.env`-family file (but not an example/template). Env
/// files are handled only by `committed_env`, which redacts values, so no other
/// rule ever prints a line from one.
fn is_env_file(name: &str) -> bool {
    name == ".env"
        || (name.starts_with(".env.")
            && !name.ends_with(".example")
            && !name.ends_with(".sample")
            && !name.ends_with(".template")
            && !name.ends_with(".dist"))
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
    // Env files are handled by committed_env with redaction; never scan their
    // raw lines here, or a real secret value would be printed in a finding.
    if is_env_file(f.name()) {
        return Vec::new();
    }
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
        // hullcheck:ignore-next-line detector pattern
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
        // hullcheck:ignore-next-line detector pattern
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
        // hullcheck:ignore-next-line detector pattern
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

        // Well-known provider token prefixes (patterns informed by Gitleaks).
        for (marker, label) in TOKEN_MARKERS {
            if line.contains(marker) {
                out.push(Finding::new(
                    RULE,
                    Lane::FixNow,
                    format!("{label} hardcoded in source"),
                    &f.rel,
                    n,
                    line,
                    "A committed provider token works until it is revoked, including from git history.",
                    "Remove it, move it to a server-only secret, and rotate the token with the provider.",
                ));
                break; // one token finding per line is enough
            }
        }
    }
    out
}

/// Well-known secret token prefixes and what they are. The patterns are informed
/// by the Gitleaks ruleset; each line carries the ignore directive because the
/// literal below is a detector pattern, not a real secret.
const TOKEN_MARKERS: &[(&str, &str)] = &[
    ("ghp_", "GitHub personal access token"), // hullcheck:ignore
    ("github_pat_", "GitHub fine-grained token"), // hullcheck:ignore
    ("gho_", "GitHub OAuth token"),           // hullcheck:ignore
    ("glpat-", "GitLab personal access token"), // hullcheck:ignore
    ("xoxb-", "Slack bot token"),             // hullcheck:ignore
    ("xoxp-", "Slack user token"),            // hullcheck:ignore
    ("sk-ant-", "Anthropic API key"),         // hullcheck:ignore
    ("sk-proj-", "OpenAI project key"),       // hullcheck:ignore
    ("AIza", "Google API key"),               // hullcheck:ignore
    ("rk_live_", "Stripe restricted key"),    // hullcheck:ignore
    ("dop_v1_", "DigitalOcean token"),        // hullcheck:ignore
];

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

// ---- rule: firebase security rules -----------------------------------------

/// A Firebase rule that grants access with `if true` (Firestore/Storage) or
/// `".read"/".write": true` (Realtime Database) is the Firebase equivalent of the
/// open-Supabase mistake: anyone can read or write the data.
fn firebase_rules(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "firebase-rules";
    let name = f.name();
    let is_fb = name == "firestore.rules"
        || name == "storage.rules"
        || name == "database.rules.json"
        || f.ext() == "rules";
    if !is_fb {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        if has(line, "allow") && has(line, "if true") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Firebase rule grants access to everyone (if true)",
                &f.rel,
                n,
                line,
                "An `if true` rule lets any client read or write the data it guards, with no authentication.",
                "Scope the rule to the signed-in user, e.g. `allow read, write: if request.auth != null && request.auth.uid == resource.data.owner;`.",
            ));
        } else if (has(line, "\".read\"") || has(line, "\".write\"")) && has(line, "true") {
            out.push(Finding::new(
                RULE,
                Lane::FixNow,
                "Realtime Database rule is open (true)",
                &f.rel,
                n,
                line,
                "A `.read`/`.write` of `true` opens the database node to anyone.",
                "Replace `true` with an `auth`-based condition, e.g. `\"auth.uid === $uid\"`.",
            ));
        }
    }
    out
}

// ---- rule: committed .env file ---------------------------------------------

/// A committed `.env` usually means real secrets live in git history. Values are
/// never printed: the evidence is the variable name with the value redacted.
fn committed_env(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "committed-env";
    let name = f.name();
    if !is_env_file(name) {
        return Vec::new();
    }
    let (n, quote) = f
        .lines
        .iter()
        .enumerate()
        .find(|(_, l)| !l.trim_start().starts_with('#') && l.contains('='))
        .map(|(i, l)| (i + 1, redact_env(l)))
        .unwrap_or((1, "(environment file present)".to_string()));
    vec![Finding::new(
        RULE,
        Lane::Validate,
        format!("Environment file `{name}` is committed to the repository"),
        &f.rel,
        n,
        quote,
        "A committed .env usually means real secrets are readable by anyone with the repo, including from git history.",
        "Remove it from the repo, add it to .gitignore, rotate anything it held, and commit a .env.example with blank values instead.",
    )]
}

/// Keep only the variable name, replacing the value with an ellipsis, so a real
/// secret is never printed in a finding.
fn redact_env(line: &str) -> String {
    match line.split_once('=') {
        Some((k, _)) => format!("{}=…", k.trim()),
        None => "…".to_string(),
    }
}

// ---- rule: permissive CORS -------------------------------------------------

/// CORS set to any origin lets any website call the endpoint from a browser; with
/// credentials it can read authenticated responses.
fn cors_wildcard(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "cors-wildcard";
    if !is_code(f.ext()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        // hullcheck:ignore-next-line detector pattern
        if has(line, "access-control-allow-origin") && line.contains('*') {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "CORS allows any origin (wildcard header)",
                &f.rel,
                n,
                line,
                "Any site can call this endpoint from a browser; combined with credentials it can read authenticated responses.",
                "Return an explicit allowlist of origins instead of `*`, especially when the endpoint uses cookies or auth.",
            ));
        // hullcheck:ignore-next-line detector pattern
        } else if has(line, "origin: true") || has(line, "origin:true") {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "CORS reflects any request origin",
                &f.rel,
                n,
                line,
                "Reflecting any request origin is the same as allowing all origins, and it passes the credentialed-request check.",
                "Pass an explicit list of allowed origins instead of `true`.",
            ));
        }
    }
    out
}

// ---- rule: github actions script injection ---------------------------------

/// Interpolating attacker-controllable context (a PR title, a branch name) into a
/// workflow runs their text as part of your job. Pattern informed by zizmor's
/// template-injection check.
fn gha_injection(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "gha-injection";
    let in_workflows =
        f.rel.starts_with(".github/workflows/") && (f.ext() == "yml" || f.ext() == "yaml");
    if !in_workflows {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let n = i + 1;
        let interpolates =
            has(line, "${{") && (has(line, "github.event.") || has(line, "github.head_ref"));
        let attacker_field = has(line, ".title")
            || has(line, ".body")
            || has(line, "head_ref")
            || has(line, ".name")
            || has(line, ".email")
            || has(line, ".ref")
            || has(line, ".label");
        if interpolates && attacker_field {
            out.push(Finding::new(
                RULE,
                Lane::Validate,
                "Workflow interpolates attacker-controllable context",
                &f.rel,
                n,
                line,
                "A PR title, branch name or similar is attacker-controlled; interpolated into a `run:` block it executes as your job.",
                "Pass the value through an `env:` variable and reference it as `\"$VAR\"`, instead of inlining the `${{ ... }}` expression.",
            ));
        }
    }
    out
}

// ---- rules scoped to web/python source (never match this Rust file) --------

/// JavaScript/TypeScript front- and back-end source. Scoping the web rules here
/// keeps them off this crate's own `.rs` detector lines, so no ignore directive
/// is needed.
fn is_web_code(ext: &str) -> bool {
    matches!(
        ext,
        "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" | "vue" | "svelte"
    )
}

/// Disabling TLS certificate verification lets any server, including an
/// attacker's, impersonate the real one. Pattern from Semgrep's insecure-transport.
fn tls_verification_off(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "tls-verification-off";
    if !is_web_code(f.ext()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let off = (has(line, "rejectunauthorized") && has(line, "false"))
            || (has(line, "node_tls_reject_unauthorized")
                && (has(line, "\"0\"") || has(line, "'0'") || has(line, "=0") || has(line, "= 0")));
        if off {
            out.push(Finding::new(
                RULE,
                Lane::Validate,
                "TLS certificate verification disabled",
                &f.rel,
                i + 1,
                line,
                "With verification off, any server (including an attacker's) can impersonate the real one and read the traffic.",
                "Remove this, fix the real certificate or CA issue, and scope any exception to one https.Agent with NODE_EXTRA_CA_CERTS.",
            ));
        }
    }
    out
}

/// A JWT configured to accept the `none` algorithm means tokens are trusted with
/// no signature, so anyone can forge them. Pattern from the SAST jwt-none rules.
fn jwt_alg_none(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "jwt-alg-none";
    if !(is_web_code(f.ext()) || f.ext() == "py") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let names_alg = has(line, "alg");
        let picks_none = has(line, "\"none\"") || has(line, "'none'");
        if names_alg && picks_none {
            out.push(Finding::new(
                RULE,
                Lane::Validate,
                "JWT allows the none algorithm",
                &f.rel,
                i + 1,
                line,
                "The none algorithm accepts tokens with no signature, so anyone can forge a valid-looking token.",
                "Pin an explicit algorithm (HS256/RS256) in sign and verify, and never list none among the allowed ones.",
            ));
        }
    }
    out
}

/// `dangerouslySetInnerHTML` bypasses React's escaping; user- or model-derived
/// HTML here is an XSS vector, the most common AI-generated web bug.
fn dangerous_html(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "dangerous-html";
    if !is_web_code(f.ext()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        if has(line, "dangerouslySetInnerHTML") {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "React dangerouslySetInnerHTML in use",
                &f.rel,
                i + 1,
                line,
                "This bypasses React's escaping; if the HTML is user- or model-derived it executes as script in the browser.",
                "Render as text where possible, or sanitize with DOMPurify before setting, and add a Content-Security-Policy.",
            ));
        }
    }
    out
}

/// Prisma's `$queryRawUnsafe`/`$executeRawUnsafe` run the string as SQL; any
/// interpolated input is an injection path (the tagged `$queryRaw` form is safe).
fn prisma_raw_unsafe(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "prisma-raw-unsafe";
    if !is_web_code(f.ext()) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        if has(line, "queryRawUnsafe") || has(line, "executeRawUnsafe") {
            out.push(Finding::new(
                RULE,
                Lane::Validate,
                "Prisma raw-unsafe query in use",
                &f.rel,
                i + 1,
                line,
                "$queryRawUnsafe / $executeRawUnsafe run the string as SQL, so interpolated user input becomes SQL injection.",
                "Use the tagged `$queryRaw`...${value}...`` form for values, and allowlist any dynamic identifiers.",
            ));
        }
    }
    out
}

/// Flask/Django debug mode in production leaks stack traces and settings, and
/// Flask's debugger exposes a remote code-execution console.
fn debug_production(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "debug-enabled";
    if f.ext() != "py" {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let normalized = line.replace(' ', "").to_ascii_lowercase();
        if normalized.contains("debug=true") {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "Debug mode enabled",
                &f.rel,
                i + 1,
                line,
                "Debug mode leaks stack traces and settings, and Flask's debugger exposes a remote code-execution console.",
                "Load the flag from an env var that defaults to False, and keep debug off in production.",
            ));
        }
    }
    out
}

// ---- rule: sensitive personal data (LGPD / GDPR) ---------------------------

/// Column names for sensitive or special-category personal data.
const SENSITIVE_PII: &[&str] = &[
    "cpf",
    "cnpj",
    "rg",
    "ssn",
    "passport",
    "national_id",
    "tax_id",
    "birthdate",
    "date_of_birth",
    "dob",
    "biometric",
    "biometrics",
    "health",
    "religion",
    "race",
    "ethnicity",
    "sexual_orientation",
];

/// A migration column holding sensitive or special-category personal data raises
/// the compliance bar: under Brazil's LGPD (Art. 11) and the GDPR (Art. 9) it
/// needs a lawful basis, encryption, tight access and a retention limit.
fn pii_sensitive_data(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "pii-sensitive-data";
    let is_sql = f.ext() == "sql" || f.rel.contains("/migrations/") || f.rel.contains("migration");
    if !is_sql {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let lowered = line.trim_start().to_ascii_lowercase();
        let column = lowered.trim_start_matches(['"', '`', '[']);
        let name: String = column
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !SENSITIVE_PII.contains(&name.as_str()) {
            continue;
        }
        // Require a column type after the name so a word in prose does not match.
        let rest = &column[name.len()..];
        let typed = has(rest, "text")
            || has(rest, "varchar")
            || has(rest, "char")
            || has(rest, "date")
            || has(rest, "timestamp")
            || has(rest, "jsonb")
            || has(rest, "bytea")
            || has(rest, "int")
            || has(rest, "numeric")
            || has(rest, "bool");
        if typed {
            out.push(Finding::new(
                RULE,
                Lane::Validate,
                format!("Sensitive personal data column `{name}`"),
                &f.rel,
                i + 1,
                line,
                "Sensitive or special-category personal data (LGPD Art. 11 / GDPR Art. 9) needs a lawful basis, encryption at rest, tight access and a retention limit.",
                "Confirm the lawful basis, encrypt it at rest, restrict access, keep it only as long as needed, and record it in your data map; avoid storing it if you can.",
            ));
        }
    }
    out
}

// ---- rule: tracking without consent (LGPD / GDPR) --------------------------

/// Non-essential analytics or marketing tracking usually needs the user's
/// consent before it loads, under the LGPD and the GDPR.
fn tracking_consent(f: &TextFile) -> Vec<Finding> {
    const RULE: &str = "tracking-consent";
    if !(is_web_code(f.ext()) || f.ext() == "html") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (i, line) in f.lines.iter().enumerate() {
        let hit = has(line, "googletagmanager.com")
            || has(line, "google-analytics.com")
            || has(line, "connect.facebook.net")
            || has(line, "static.hotjar.com")
            || has(line, "clarity.ms")
            || has(line, "cdn.segment.com")
            || line.contains("fbq(")
            || line.contains("gtag(");
        if hit {
            out.push(Finding::new(
                RULE,
                Lane::Monitor,
                "Third-party tracking loaded without a visible consent gate",
                &f.rel,
                i + 1,
                line,
                "Non-essential analytics or marketing tracking usually needs the user's consent before it loads (LGPD and GDPR).",
                "Load the tracker only after consent through a consent manager, and record the lawful basis in your privacy policy.",
            ));
        }
    }
    out
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
