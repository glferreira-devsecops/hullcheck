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

---

Vibe-coded a SaaS and not sure what shipped with it? `shipsafe` reads your repo and
points at the handful of mistakes that actually leak data or money: a Supabase table
with no row level security, a `service_role` key in the browser bundle, a Stripe webhook
that never checks its signature, an action pinned to a movable tag. It quotes the exact
line behind each one, and it refuses to call anything a vulnerability it cannot show you.

It reads files. It makes no network calls, writes nothing, runs no code from your repo,
and never tells you your app is secure.

## Run it

```sh
# from source (needs Rust)
cargo install --git https://github.com/glferreira-devsecops/shipsafe

# or grab a prebuilt binary (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/glferreira-devsecops/shipsafe/main/install.sh | sh

# then, in your project
shipsafe
```

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

Exit code is `1` when there is a Fix Now finding, so it gates a CI job. `--json` emits the
same findings for a bot; `--exit-zero` never fails the build.

## Why it is different

The scanners in this space are famous for two things: a wall of findings, and findings
that are wrong. `shipsafe` is built against both.

- **Evidence or it does not exist.** Every finding carries `file:line` and the quoted
  source line. A signal that cannot be confirmed from the files present lands in a separate
  **Unverified** lane, never in Fix Now.
- **Lanes, not a severity lottery.** *Fix Now* is safe to correct today. *Monitor* depends
  on config outside the repo. *Validate Manually* touches login, data, billing, uploads,
  admin or AI tools, so a human confirms before anyone calls it a vulnerability.
- **Zero dependencies, zero network.** The whole tool is std-only Rust. No package tree can
  ship a surprise, nothing phones home, and you can audit all of it in one sitting.
- **It reads the agent, not just the app.** The *agent instruction doctor* tells you which
  instruction file each coding agent actually loads, so the rules you wrote are not silently
  ignored.

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

These are a sharp set of common, high-cost mistakes, not a full audit.

## Hand the findings to your agent

```
For each shipsafe finding, open the quoted file:line, confirm the issue is real,
then propose the smallest safe fix and a test that fails before it. Do not change
anything you cannot confirm from the file.
```

The repo also ships two portable **skills** (`skills/`): tenant isolation and billing
webhooks. Copy them to `.claude/skills/`, `.github/skills/` or `.agents/skills/`, or add
the whole repo with `npx skills add glferreira-devsecops/shipsafe`.

## Not a silver bullet

`shipsafe` is the fast first pass: a few minutes, no setup, no account. It does not replace
deeper tools. For full SAST, dependency CVEs and secret history, run
[Semgrep](https://semgrep.dev), [osv-scanner](https://github.com/google/osv-scanner) and
[gitleaks](https://github.com/gitleaks/gitleaks) alongside it. And when a finding touches
money, access or customer data, a human validates before it is called a vulnerability.

## The full review kit

The [RET Promptbook](https://www.rettecnologia.org/promptbook) takes this further: 13 review
skills (auth, uploads, AI and MCP, secrets and supply chain, diff review, threat model,
abuse and rate limits, LGPD, skill vetting and more), an evidence verifier for Claude Code
and Codex, agent-file paths checked against each tool's official docs, and the full triage
flow from signal to decision.

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
`shipsafe` dentro do projeto. Saída em faixas: *Fix Now*, *Monitor*, *Validate Manually* e
*Unverified* (o que não deu pra confirmar fica fora de Fix Now).

Zero dependências, zero rede, tudo em Rust std. Dá pra auditar o tool inteiro de uma vez.

O kit completo (13 skills, verificador de evidência, fluxo de triagem) está no
[RET Promptbook](https://www.rettecnologia.org/promptbook).

</details>
