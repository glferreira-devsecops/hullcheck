# Security

shipsafe is read-only. It reads files under the path you give it, makes no
network calls, writes nothing, runs no code from the scanned repo, and collects
no telemetry. The whole tool is std-only Rust with zero dependencies, so there
is no package tree to audit beyond this repository.

## Reporting a vulnerability

Email security@rettecnologia.org with the details and a way to reproduce. Please
do not open a public issue for a security report. We aim to acknowledge within
three business days.

## Scope

Use shipsafe only on code you own or are authorized to review. It does not test
third-party systems, write exploits, or prove an application is secure. Findings
in the "Validate Manually" lane need a human before they are called a
vulnerability.
