# Contributing

Thanks for helping. hullcheck stays small on purpose: read-only, zero network,
zero dependencies. Those three are hard constraints, not preferences.

## Add a rule

A rule is one function in [`src/rules.rs`](src/rules.rs) that takes a `&TextFile`
and returns `Vec<Finding>`, each finding built with a quoted source line.

1. Write the function and register it in the `PER_FILE` list (or `whole_repo`
   when it needs the whole file set, like `agent-doctor`).
2. Add a fixture under `tests/fixtures/` that triggers it.
3. Add a test in [`tests/scan.rs`](tests/scan.rs) asserting the rule, the lane,
   and the quoted evidence.

Keep rules conservative. When a signal cannot be confirmed from the files
present, use the `Unverified` lane; when it needs a human (money, access,
customer data), use `Validate`. Nothing lands in `Fix Now` without a quoted line.

## Before you open a PR

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all
```

All three must pass. New dependencies are not accepted: the tool is std-only by
design. Keep the diff small and the finding text plain, in the voice of the
existing rules.

## Reporting bugs and false positives

Open an issue with the smallest file that reproduces it and the output you got.
A false positive is a bug worth reporting; precision is the point of the project.
