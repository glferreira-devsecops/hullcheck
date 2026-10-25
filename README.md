<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="shipsafe" width="300">
  </picture>
</p>

<p align="center">
  <strong>Read-only security review for the SaaS you built with an AI agent.</strong><br>
  Zero dependencies. Zero network. Every finding quotes the exact file and line. No false certainty.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/dependencies-0-22D3EE?style=flat-square" alt="zero dependencies">
  <img src="https://img.shields.io/badge/network-none-22D3EE?style=flat-square" alt="no network">
  <img src="https://img.shields.io/badge/license-MIT-0B1B2B?style=flat-square" alt="MIT">
  <a href="https://github.com/glferreira-devsecops/shipsafe/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/glferreira-devsecops/shipsafe/ci.yml?style=flat-square&label=CI" alt="CI"></a>
</p>

<p align="center">
  <img src="assets/demo.svg" alt="shipsafe scan output" width="720">
</p>

---

Vibe-coded a SaaS and not sure what shipped with it? `shipsafe` reads your repo and
points at the handful of mistakes that actually leak data or money: a Supabase table
with no row level security, a `service_role` key in the browser bundle, a Stripe webhook
that never checks its signature, an action pinned to a movable tag. It quotes the exact
line behind each one, and it refuses to call anything a vulnerability it cannot show you.

It reads files. It makes no network calls, writes nothing, runs no code from your repo,
and never tells you your app is secure.

- [Install](#install)
- [Usage](#usage)
- [What it looks like](#what-it-looks-like)
- [What it checks](#what-it-checks)
- [Ignoring files and lines](#ignoring-files-and-lines)
- [Use it in CI](#use-it-in-ci)
- [JSON output](#json-output)
- [Why it is different](#why-it-is-different)
- [Skills and the full kit](#skills-and-the-full-kit)
- [Contributing](#contributing)
- [FAQ](#faq)

## Install

```sh
# a prebuilt binary (macOS / Linux) — verifies its own checksum
curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/shipsafe/main/install.sh | sh

# or from source, with Rust
cargo install --git https://github.com/glferreira-devsecops/shipsafe

# or build it yourself
git clone https://github.com/glferreira-devsecops/shipsafe && cd shipsafe
cargo build --release   # binary at target/release/shipsafe
```

The installer drops the binary in `~/.local/bin` by default (override with `INSTALL_DIR`).
Prebuilt binaries ship for `x86_64-linux`, `aarch64-apple-darwin` and `x86_64-apple-darwin`;
any other platform builds from source.

## Usage

```sh
shipsafe [PATH] [OPTIONS]
```

| | |
| --- | --- |
| `PATH` | repository to scan (default: current directory) |
| `--json` | emit JSON instead of the human report |
| `--exit-zero` | always exit 0, even with Fix Now findings |
| `-h`, `--help` | print help |
| `-V`, `--version` | print version |

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | no Fix Now findings (or `--exit-zero`) |
| `1` | at least one Fix Now finding |
| `2` | bad usage (unknown flag, path is not a directory) |

## What it looks like

```text
shipsafe 0.1.0  ·  412 files scanned  ·  .
read-only, no network. evidence is quoted by file and line.

Fix Now 2   Monitor 1   Validate Manually 2   Unverified 0

## Fix Now

app/page.tsx:2  Secret exposed through public env var `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`
    const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
    why: Any variable with a public prefix is inlined into the client bundle and visible to every visitor.
    fix: Drop the public prefix and read this value only on the server; rotate it, since it was already shipped.

supabase/migrations/001_init.sql:7  Row level security policy matches every row (USING (true))
    create policy "read" on public.profiles for select using (true);
    why: A `using (true)` policy lets every request read the rows it guards, so RLS is on but enforces nothing.
    fix: Replace `true` with a predicate that ties the row to the caller, e.g. `auth.uid() = user_id`.

## Validate Manually

app/api/webhook/route.ts:4  Stripe webhook handler with no signature verification found
    const event = await req.json();
    why: Without verifying the stripe-signature header, anyone who finds the URL can forge a paid event.
    fix: Verify the event with stripe.webhooks.constructEvent(body, sig, secret) before acting on it.
```

Each finding ends with a ready prompt you can hand to your coding agent:

```
For each shipsafe finding, open the quoted file:line, confirm the issue is real,
then propose the smallest safe fix and a test that fails before it. Do not change
anything you cannot confirm from the file.
```

## What it checks

| Rule | Looks for | Lane |
| --- | --- | --- |
| `supabase-rls` | table created with no row level security; a policy with `using (true)` | Validate / Fix Now |
| `credential-columns` | a `password` column in a migration (the 2026 Supabase plaintext mistake) | Validate |
| `client-secret` | `service_role`, a Stripe secret key, an AWS key, a private key, or a secret behind a public env prefix | Fix Now |
| `stripe-webhook` | a Stripe webhook handler that never verifies the signature | Validate |
| `public-sourcemaps` | production browser source maps turned on | Monitor |
| `mcp-hooks` | an MCP server or editor hook that runs a local command | Validate |
| `gha-pin` | a GitHub Action pinned to a tag or branch, not a commit SHA | Monitor |
| `gha-pr-target` | a workflow using the `pull_request_target` trigger | Validate |
| `agent-doctor` | `CLAUDE.md` shadowing `AGENTS.md`, a `.md` in `.cursor/rules`, an ignored `.antigravity.md`, a stray `.cursorrules` | Monitor / Validate |

Lanes: **Fix Now** is safe to correct today. **Monitor** depends on config outside the repo.
**Validate Manually** touches login, data, billing, uploads, admin or AI tools, so a human
confirms before anyone calls it a vulnerability. **Unverified** is a signal whose line could
not be confirmed; it never enters Fix Now.

These are a sharp set of common, high-cost mistakes, not a full audit.

## Ignoring files and lines

shipsafe skips `node_modules`, `.git`, build output and caches on its own. For the rest, it
reads a `.shipsafeignore` at the repository root, one gitignore-style pattern per line:

```gitignore
# vendored or generated code
vendor/
public/build/**
*.min.js

# a file you reviewed and accept
supabase/migrations/legacy.sql
```

Patterns support `*` (within a path segment), `**` (across segments), `?`, and a trailing `/`
for a directory. To silence a single line, annotate the source instead:

```ts
const legacyKey = process.env.OLD_KEY; // shipsafe:ignore

// shipsafe:ignore-next-line
const other = buildClient(url, key);
```

## Use it in CI

shipsafe exits `1` on a Fix Now finding, so it gates a job with no extra config:

```yaml
# .github/workflows/shipsafe.yml
name: shipsafe
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
      - run: cargo install --git https://github.com/glferreira-devsecops/shipsafe
      - run: shipsafe .
```

Use `shipsafe --json .` to post findings to another tool, or `shipsafe --exit-zero .` to
report without ever failing the build.

## JSON output

`--json` prints a stable document: a summary count per lane and one object per finding.

```json
{
  "tool": "shipsafe",
  "version": "0.1.0",
  "scannedFiles": 412,
  "summary": { "fixNow": 2, "monitor": 1, "validate": 2, "unverified": 0 },
  "findings": [
    {
      "rule": "client-secret",
      "lane": "fix-now",
      "title": "Secret exposed through public env var `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY`",
      "file": "app/page.tsx",
      "line": 2,
      "quote": "const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;",
      "impact": "Any variable with a public prefix is inlined into the client bundle...",
      "fix": "Drop the public prefix and read this value only on the server; rotate it..."
    }
  ]
}
```

## Why it is different

The scanners in this space are known for two things: a wall of findings, and findings that
are wrong. `shipsafe` is built against both.

- **Evidence or it does not exist.** Every finding carries `file:line` and the quoted source
  line. A signal that cannot be confirmed from the files present lands in a separate
  **Unverified** lane, never in Fix Now.
- **Lanes, not a severity lottery.** You always know whether something is safe to fix now or
  needs a human first.
- **Zero dependencies, zero network.** The whole tool is std-only Rust (~1.5k lines). No
  package tree can ship a surprise, nothing phones home, and you can audit all of it in one
  sitting. It scans files in parallel and finishes in well under a second on a typical repo.
- **It reads the agent, not just the app.** The *agent instruction doctor* tells you which
  instruction file each coding agent actually loads, so the rules you wrote are not silently
  ignored.

It is the fast first pass, not a replacement for deeper tools. For full SAST, dependency CVEs
and secret history, run [Semgrep](https://semgrep.dev),
[osv-scanner](https://github.com/google/osv-scanner) and
[gitleaks](https://github.com/gitleaks/gitleaks) alongside it.

## Skills and the full kit

The repo ships two portable **skills** (`skills/`): tenant isolation and billing webhooks.
Copy them to `.claude/skills/`, `.github/skills/` or `.agents/skills/`, or add the repo with
`npx skills add glferreira-devsecops/shipsafe`.

The [RET Promptbook](https://www.rettecnologia.org/promptbook) takes this further: 13 review
skills (auth, uploads, AI and MCP, secrets and supply chain, diff review, threat model, abuse
and rate limits, LGPD, skill vetting and more), an evidence verifier for Claude Code and
Codex, agent-file paths checked against each tool's official docs, and the full triage flow
from signal to decision.

## Contributing

A rule is one function in [`src/rules.rs`](src/rules.rs) that takes a file and returns
findings, each with a quoted line. Add it to the `PER_FILE` list, add a fixture under
`tests/fixtures/`, and a test in [`tests/scan.rs`](tests/scan.rs). `cargo test`, `cargo fmt`
and `cargo clippy -- -D warnings` must pass. Keep rules conservative: when in doubt, use the
Validate or Unverified lane rather than Fix Now.

## FAQ

**Does it send my code anywhere?** No. It reads files on disk and makes no network calls.

**Does it change my repo?** No. It is read-only and writes nothing.

**Does a clean run mean my app is secure?** No. shipsafe covers a set of common, high-cost
mistakes. A clean run means those specific checks found nothing, not that there is nothing to
find.

## License

MIT. Use it only on code you own or are authorized to review.

---

<details>
<summary><strong>Português</strong></summary>

`shipsafe` lê o repositório do SaaS que você construiu com um agente de código e aponta os
poucos erros que de fato vazam dado ou dinheiro: tabela do Supabase sem row level security,
`service_role` no bundle do navegador, webhook do Stripe sem conferir a assinatura, action
presa a uma tag móvel. Cita a linha exata atrás de cada um e não chama de vulnerabilidade
nada que não possa te mostrar.

Só lê arquivos. Não faz chamada de rede, não escreve nada, não roda código do seu repo e
nunca diz que seu app está seguro.

**Rodar:** `cargo install --git https://github.com/glferreira-devsecops/shipsafe`, depois
`shipsafe` dentro do projeto. Sai com código `1` quando há achado em *Fix Now*, então serve
de gate no CI; `--json` para outra ferramenta e `--exit-zero` para não derrubar o build.

**Faixas:** *Fix Now* (seguro corrigir agora), *Monitor* (depende de config fora do repo),
*Validate Manually* (toca login, dado, cobrança, upload, admin ou IA, então um humano
confirma) e *Unverified* (o que não deu para confirmar fica fora de Fix Now).

**Ignorar:** um `.shipsafeignore` na raiz (padrões estilo gitignore) ou um comentário
`// shipsafe:ignore` na linha (ou `// shipsafe:ignore-next-line` na linha de cima).

Zero dependências, zero rede, tudo em Rust std. Dá para auditar o tool inteiro de uma vez. O
kit completo (13 skills, verificador de evidência, fluxo de triagem) está no
[RET Promptbook](https://www.rettecnologia.org/promptbook).

</details>
