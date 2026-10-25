# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-25

### Added

- First release: a read-only, zero-dependency, zero-network repository scanner.
- Nine rules: `supabase-rls`, `credential-columns`, `client-secret`,
  `stripe-webhook`, `public-sourcemaps`, `mcp-hooks`, `gha-pin`, `gha-pr-target`,
  and the agent instruction `agent-doctor`.
- Four reporting lanes: Fix Now, Monitor, Validate Manually, Unverified. Every
  finding carries `file:line` and the quoted source line.
- `--json` output, `--exit-zero`, and an exit code of `1` on any Fix Now finding.
- `.shipsafeignore` (gitignore-style) and inline `shipsafe:ignore` /
  `shipsafe:ignore-next-line` directives.
- Parallel scan across cores, with deterministic output.
- Two portable review skills and a Claude plugin marketplace manifest.
- Prebuilt-binary release pipeline and a self-verifying installer.

[Unreleased]: https://github.com/glferreira-devsecops/shipsafe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/glferreira-devsecops/shipsafe/releases/tag/v0.1.0
