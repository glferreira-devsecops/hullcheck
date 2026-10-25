---
name: ret-billing-webhook-review
description: Use when the user asks to review Stripe checkout, webhooks, subscriptions, entitlements, paid access, digital delivery or refunds in their own SaaS.
---

# RET Billing And Webhook Review

Find places where paid access can be released without a confirmed payment, or where a webhook can be faked, replayed or processed twice.

## Steps

1. Find where checkout sessions are created and confirm the price comes from a server-side allowlist, never from the browser.
2. Find the webhook handler and confirm it verifies the signature over the raw body before parsing.
3. Confirm access is granted by the signed webhook, not by the success URL.
4. Check idempotency by event id, out-of-order events, delayed payment methods, cancellation, refund and dispute.
5. Check the event destination type (thin or snapshot events) and the API version pinned on the endpoint.
6. Confirm logs do not keep payment data or raw payloads.

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
