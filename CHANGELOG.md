# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added

- First release: a read-only, zero-dependency, zero-network repository scanner.
- Eighteen rules, grouped by area:
  - data access: `supabase-rls`, `firebase-rules`, `credential-columns`, `prisma-raw-unsafe`
  - secrets: `client-secret` (incl. GitHub/GitLab/Slack/OpenAI/Anthropic/Google/DigitalOcean tokens), `committed-env`
  - money: `stripe-webhook`
  - transport & auth: `tls-verification-off`, `jwt-alg-none`, `cors-wildcard`
  - frontend: `dangerous-html`, `public-sourcemaps`
  - server config: `debug-enabled`
  - CI & supply chain: `gha-pin`, `gha-pr-target`, `gha-injection`
  - agents & tooling: `mcp-hooks`, `agent-doctor`
- Four reporting lanes: Fix Now, Monitor, Validate Manually, Unverified. Every
  finding carries `file:line` and the quoted source line; `.env` values are redacted.
- `--json` output, `--exit-zero`, and an exit code of `1` on any Fix Now finding.
- `.hullcheckignore` (gitignore-style) and inline `hullcheck:ignore` /
  `hullcheck:ignore-next-line` directives.
- Parallel scan across cores, with deterministic output.
- Shell completions (bash, zsh, fish) and a man page.
- Two portable review skills and a Claude plugin marketplace manifest.
- Prebuilt-binary release pipeline and a self-verifying installer.
- Detection patterns informed by the Gitleaks, Semgrep and zizmor rulesets,
  reimplemented natively to stay dependency-free.

[Unreleased]: https://github.com/glferreira-devsecops/hullcheck/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/glferreira-devsecops/hullcheck/releases/tag/v0.1.0
