# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users
Two audiences, served by one interface:
- **Builders** — solo and "vibe" coders who shipped an API quickly and want to know, in plain language, whether it leaks data or lets the wrong people in before or after launch.
- **Product teams** — engineers at small companies who own their APIs and want a repeatable, documented check before releases, with enough technical detail (evidence, request/response) to fix and verify.

Default to plain language; keep expert detail (evidence, headers, confidence, check IDs) one step away rather than hidden.

## Product Purpose
breakAPI checks APIs the user owns or is authorized to test for common weaknesses — broken access control, authentication gaps, cross-account data exposure (changing an ID to see another user's data), unsafe input handling, misconfiguration, and missing rate limits — and explains each finding with evidence, impact, and a fix. Success: a user finds a real gap, fixes it, and confirms the fix with a retest.

## Positioning
Consent is the product's first step, not a disclaimer: no request is sent until an authorization is recorded (who, basis, scope, allowed tests, expiry), the target host is in scope and, for non-local hosts, control is verified. Every request is bounded by owner-set safety controls and traceable via an `X-BreakAPI-Scan` header. Reports carry the authorization record.

## Operating Context
Workflow: create project → record authorization → set base URL and import endpoints (OpenAPI JSON, Postman, manual list) → add test accounts with owned resource IDs → set safety controls → run scan (live progress, pause/stop) → read report → fix → retest and compare. Users run it against local dev servers, staging, or their own production with test accounts.

## Capabilities and Constraints
- Node app with no dependencies and no build step. Multi-user: email/password accounts with `admin` and `user` roles, project membership, email verification and authorizer confirmation by email. Runs locally (`npm start`) or hosted (behind an HTTPS proxy, see the README); intended to grow into a hosted SaaS. Single-process JSON data store.
- Strict CSP (`default-src 'self'`): no inline styles/scripts, no third-party assets at runtime.
- Non-destructive by default; DELETE is never sent; write methods require separate authorization.
- Cannot prove an API is secure; findings may include false positives.

## Brand Commitments
- Name: **breakAPI** (lowercase "break", uppercase "API").
- Tagline: **"How secure is your API?"**
- Closing line: "breakAPI helps teams find and fix API security gaps in systems they are authorized to test."

## Evidence on Hand
No customers, testimonials, benchmarks, or pricing exist — do not fabricate any. A deliberately vulnerable demo API (`demo/`) and an end-to-end test suite (`test/`) exist for demonstrations.

## Product Principles
1. Permission before probing — the authorization flow is never skippable or buried.
2. Explain, then prove — every finding states what, why it matters, and how to fix, with evidence behind it.
3. The owner stays in control — limits, pause, stop, and revoke are always visible and immediate.
4. Honest about limits — never imply an API is "secure"; absence of findings is not proof.
5. Fix-and-verify loop — retesting and comparison are first-class, not an afterthought.
