---
name: ret-tenant-isolation-review
description: Use when the user asks whether one customer, workspace or organization can see or change another one's data, or asks to review IDOR, authorization by owner, RLS or multi-tenant queries in their own SaaS.
---

# RET Tenant Isolation Review

Find places where customer A could read or change customer B's data.

## Steps

1. List every route, server action, API handler, background job and export that loads data by an id.
2. For each one, find where the owner, tenant, organization or workspace is checked on the server. A check only in the UI does not count.
3. If the project uses Supabase or Postgres RLS, list sensitive tables and confirm RLS is on and the policy is not `USING (true)`.
4. Check storage paths and signed URLs for the tenant id.
5. Propose the failing test first: two test accounts, account A requests account B's resource and must get 403 or 404.

## Boundaries

- Review only this repository and its documented runtime assumptions.
- Stay read-only until the human approves a fix.
- Do not read or print secrets, `.env` files, tokens, cookies, private keys, customer data, card data or raw webhook payloads.
- Do not test third-party systems and do not write exploit payloads.
- Do not say the SaaS is secure.

## Evidence rule

Quote the exact line behind each signal, with file path and line number, and re-open the file to confirm it before answering. Anything you cannot confirm goes under Unverified.

## Output

1. Executive Snapshot
2. Fix Now
3. Monitor
4. Validate Manually
5. Missing Tests
6. Recommended Next Step
7. Unverified
