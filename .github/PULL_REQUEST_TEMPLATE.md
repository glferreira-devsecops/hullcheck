## What this changes

<!-- One or two lines on the effect, not the diff. -->

## Why

<!-- The reason, and anything a reviewer needs to judge the risk. -->

## Checklist

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all` pass
- [ ] No new dependencies (the tool is std-only)
- [ ] New or changed rule has a fixture and a test asserting the quoted evidence
- [ ] Rule lanes are conservative (Fix Now only with a confirmed line)
