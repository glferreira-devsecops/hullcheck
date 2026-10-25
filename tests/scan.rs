//! Integration tests: run the whole review over the committed fixtures and
//! assert on the findings, by rule and by the exact quoted evidence.

use std::path::Path;

use hullcheck::finding::{Finding, Lane};
use hullcheck::review;

fn review_fixture(name: &str) -> Vec<Finding> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let (findings, scanned) = review(&root);
    assert!(scanned > 0, "fixture {name} should have scannable files");
    findings
}

fn has_rule(findings: &[Finding], rule: &str) -> bool {
    findings.iter().any(|f| f.rule == rule)
}

fn rule_at<'a>(findings: &'a [Finding], rule: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.rule == rule).collect()
}

#[test]
fn vuln_fixture_flags_every_rule() {
    let f = review_fixture("vuln");
    for rule in [
        "supabase-rls",
        "credential-columns",
        "client-secret",
        "stripe-webhook",
        "public-sourcemaps",
        "mcp-hooks",
        "gha-pin",
        "gha-pr-target",
        "gha-injection",
        "firebase-rules",
        "committed-env",
        "cors-wildcard",
        "tls-verification-off",
        "jwt-alg-none",
        "dangerous-html",
        "prisma-raw-unsafe",
        "debug-enabled",
        "pii-sensitive-data",
        "tracking-consent",
        "agent-doctor",
    ] {
        assert!(has_rule(&f, rule), "expected a {rule} finding, got: {f:?}");
    }
}

#[test]
fn clean_fixture_is_silent() {
    let f = review_fixture("clean");
    assert!(
        f.is_empty(),
        "clean fixture should produce no findings, got: {f:?}"
    );
}

#[test]
fn rls_policy_using_true_is_fix_now_with_quote() {
    let f = review_fixture("vuln");
    let policy = rule_at(&f, "supabase-rls")
        .into_iter()
        .find(|x| x.quote.contains("using (true)"))
        .expect("the using(true) policy should be flagged");
    assert_eq!(policy.lane, Lane::FixNow);
    assert!(policy.file.ends_with("001_init.sql"));
}

#[test]
fn public_service_role_env_is_fix_now() {
    let f = review_fixture("vuln");
    let secret = rule_at(&f, "client-secret")
        .into_iter()
        .find(|x| x.quote.contains("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"))
        .expect("the public service_role env var should be flagged");
    assert_eq!(secret.lane, Lane::FixNow);
}

#[test]
fn aws_example_key_is_quoted_exactly() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "client-secret")
        .into_iter()
        .find(|x| x.quote == "AKIAIOSFODNN7EXAMPLE")
        .expect("the AWS key id should be quoted as the evidence");
    assert_eq!(hit.lane, Lane::FixNow);
}

#[test]
fn stripe_webhook_without_signature_is_validate() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "stripe-webhook")
        .into_iter()
        .next()
        .expect("stripe webhook finding");
    assert_eq!(hit.lane, Lane::Validate);
    assert!(hit.file.ends_with("route.ts"));
}

#[test]
fn gha_tag_pin_is_monitor_and_skips_local_action() {
    let f = review_fixture("vuln");
    let hits = rule_at(&f, "gha-pin");
    assert_eq!(
        hits.len(),
        1,
        "only the tag-pinned action, not the local one"
    );
    assert!(hits[0].quote.contains("actions/checkout@v4"));
    assert_eq!(hits[0].lane, Lane::Monitor);
}

#[test]
fn agent_doctor_flags_shadow_antigravity_and_cursor_md() {
    let f = review_fixture("vuln");
    let hits = rule_at(&f, "agent-doctor");
    assert!(
        hits.iter().any(|x| x.file == "CLAUDE.md"),
        "CLAUDE.md shadowing AGENTS.md"
    );
    assert!(
        hits.iter().any(|x| x.file == ".antigravity.md"),
        ".antigravity.md read by nothing"
    );
    assert!(
        hits.iter().any(|x| x.file.starts_with(".cursor/rules/")),
        ".md in .cursor/rules ignored"
    );
}

#[test]
fn password_column_is_validate_and_not_password_hash() {
    let f = review_fixture("vuln");
    let hits = rule_at(&f, "credential-columns");
    assert_eq!(
        hits.len(),
        1,
        "only the bare `password` column, not email or id"
    );
    assert!(hits[0].quote.contains("password text"));
    assert_eq!(hits[0].lane, Lane::Validate);
}

#[test]
fn pull_request_target_is_validate() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "gha-pr-target")
        .into_iter()
        .next()
        .expect("pr-target finding");
    assert_eq!(hit.lane, Lane::Validate);
    assert!(hit.file.ends_with("pr.yml"));
}

#[test]
fn ignore_directive_and_hullcheckignore_silence_findings() {
    // secret.ts has an inline `hullcheck:ignore`; vendor/ is path-ignored via
    // the fixture's own .hullcheckignore. Both triggers must be suppressed.
    let f = review_fixture("ignore-demo");
    assert!(
        f.is_empty(),
        "both ignore mechanisms should silence the findings, got: {f:?}"
    );
}

#[test]
fn committed_env_never_prints_the_value() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "committed-env")
        .into_iter()
        .next()
        .expect("committed-env finding");
    assert_eq!(hit.lane, Lane::Validate);
    assert!(
        hit.quote.contains("=…"),
        "value must be redacted, got: {}",
        hit.quote
    );
    assert!(
        !hit.quote.contains("secretpw"),
        "a real secret value leaked into the finding"
    );
    // No other rule should have printed a raw line from the .env either.
    assert!(
        !f.iter()
            .any(|x| x.file.ends_with(".env") && x.quote.contains("secretpw")),
        "no rule may print a raw .env value"
    );
}

#[test]
fn firebase_if_true_is_fix_now() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "firebase-rules")
        .into_iter()
        .next()
        .expect("firebase finding");
    assert_eq!(hit.lane, Lane::FixNow);
    assert!(hit.quote.contains("if true"));
}

#[test]
fn provider_token_prefix_is_fix_now() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "client-secret")
        .into_iter()
        .find(|x| x.title.contains("GitHub personal access token"))
        .expect("the ghp_ token should be flagged");
    assert_eq!(hit.lane, Lane::FixNow);
}

#[test]
fn gha_injection_is_validate() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "gha-injection")
        .into_iter()
        .next()
        .expect("gha-injection finding");
    assert_eq!(hit.lane, Lane::Validate);
    assert!(hit.quote.contains("github.event.pull_request.title"));
}

#[test]
fn tls_off_is_validate_and_debug_is_python_only() {
    let f = review_fixture("vuln");
    let tls = rule_at(&f, "tls-verification-off")
        .into_iter()
        .next()
        .expect("tls finding");
    assert_eq!(tls.lane, Lane::Validate);
    assert!(tls.quote.contains("rejectUnauthorized"));
    let dbg = rule_at(&f, "debug-enabled")
        .into_iter()
        .next()
        .expect("debug finding");
    assert!(dbg.file.ends_with(".py"), "debug rule is python-only");
}

#[test]
fn dangerous_html_is_monitor() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "dangerous-html")
        .into_iter()
        .next()
        .expect("dangerous-html finding");
    assert_eq!(hit.lane, Lane::Monitor);
}

#[test]
fn pii_sensitive_data_is_validate_and_names_the_column() {
    let f = review_fixture("vuln");
    let hits = rule_at(&f, "pii-sensitive-data");
    assert!(hits.iter().all(|x| x.lane == Lane::Validate));
    assert!(
        hits.iter().any(|x| x.quote.contains("cpf")),
        "cpf column flagged"
    );
    assert!(
        hits.iter().any(|x| x.quote.contains("date_of_birth")),
        "date_of_birth column flagged"
    );
    // a plain `email`/`user_id` column must not be flagged as sensitive
    assert!(!hits
        .iter()
        .any(|x| x.title.contains("`email`") || x.title.contains("`user_id`")));
}

#[test]
fn tracking_without_consent_is_monitor() {
    let f = review_fixture("vuln");
    let hit = rule_at(&f, "tracking-consent")
        .into_iter()
        .next()
        .expect("tracking finding");
    assert_eq!(hit.lane, Lane::Monitor);
}

#[test]
fn output_order_is_deterministic() {
    let a = review_fixture("vuln");
    let b = review_fixture("vuln");
    assert_eq!(
        a, b,
        "two runs over the same tree must produce identical, ordered findings"
    );
}
