//! Integration tests: run the whole review over the committed fixtures and
//! assert on the findings, by rule and by the exact quoted evidence.

use std::path::Path;

use shipsafe::finding::{Finding, Lane};
use shipsafe::review;

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
fn ignore_directive_and_shipsafeignore_silence_findings() {
    // secret.ts has an inline `shipsafe:ignore`; vendor/ is path-ignored via
    // the fixture's own .shipsafeignore. Both triggers must be suppressed.
    let f = review_fixture("ignore-demo");
    assert!(
        f.is_empty(),
        "both ignore mechanisms should silence the findings, got: {f:?}"
    );
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
