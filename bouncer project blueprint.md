## Project: `bouncer` — a policy enforcement point for agent spending

You are building an open-source Python library + local sidecar called **bouncer**.

**One sentence:** bouncer sits between an AI agent and any payment rail, blocks
transactions that violate a declarative policy, and writes a tamper-evident,
signed audit log of every decision.

### Why this shape

The agent-payment standards war (ACP, MPP, UCP, AP2, x402, Visa TAP) is
unsettled and will be won by whoever has distribution. bouncer is deliberately
_invariant_ to which standard wins — it is an adapter + policy layer, not a
fifth standard. It never custodies funds, so it carries no money transmitter
exposure.

### Architectural constraint

Keep a clean seam between where policy _comes from_ and where policy is
_enforced_:

- The engine loads policy through a `PolicySource` interface. v1 ships exactly
  one implementation, `LocalFileSource`. A different source must be droppable
  in later without touching the engine.
- Audit log JSON export is a first-class library function, not a script.
- Nothing in this repo may assume a server exists. It stays local, free, and
  dependency-light.

---

## Hard scope fence — DO NOT BUILD

Reject these even if they seem natural. If you think one is required, stop and
ask first.

| Not building                           | Why                                                         |
| -------------------------------------- | ----------------------------------------------------------- |
| Any blockchain, chain client, or token | Hash-chained SQLite gives tamper-evidence. Delete the part. |
| Fund custody, wallets, balances        | The moment we hold money we need licensing. Never.          |
| A new wire protocol or spec            | We adapt to existing ones. We do not create a fifth.        |
| Agent-to-agent negotiation logic       | Out of scope. bouncer authorizes; it does not haggle.       |
| A web dashboard / React UI             | CLI + REST only for v1.                                     |
| Multi-tenant SaaS, auth, billing       | Single-operator local process.                              |
| An authentication system for CLI roles | See Threat Model. v1 assumes one trusted operator.          |
| LLM calls anywhere in the path         | Policy decisions must be deterministic, fast, and testable. |

---

## Architecture

```
agent ──> bouncer proxy ──> [policy engine] ──> payment rail
                                  │
                                  ├──> signed mandate (Ed25519, scoped, TTL)
                                  ├──> hash-chained audit log (SQLite)
                                  └──> approval queue (if over threshold,
                                       tagged by role)
```

**Stack:** Python 3.11+, FastAPI, SQLite (SQLAlchemy), `cryptography` for
Ed25519, `pydantic` for policy schema, `pytest`. No other runtime deps without
asking.

---

## Threat model

Build to this, and reproduce it verbatim in the README. Do not let the docs
claim more than this section claims.

**bouncer guarantees:**

- An agent whose traffic reaches bouncer cannot obtain a valid mandate for a
  transaction the policy denies.
- Every decision is logged. Tampering with the log after the fact is detectable
  via the hash chain and operator signature.
- Mandates are scoped to one merchant and amount, expire, and cannot be
  replayed.

**bouncer does NOT guarantee:**

- **It is not a sandbox.** An agent with unrestricted network egress can ignore
  the proxy entirely. Actual containment requires egress control at the
  network or container layer — firewall rules that make bouncer the only route
  out. bouncer is the policy decision point; the network is the enforcement
  point. Say this plainly in the README.
- **CLI roles are not authenticated.** `--role finance` is an assertion by
  whoever has shell access, not a login. v1 assumes a single trusted operator
  on a trusted machine. Anyone who can run the CLI can approve anything.
- The operator signing key proves the log was not altered _after_ writing. It
  proves nothing about a compromised operator at write time.
- Nothing here has been security audited.

---

## Milestones

Build in this order. Each milestone must have passing tests and a working CLI
demo before you move on. Commit at each milestone.

### M1 — Policy engine (pure, no I/O)

- Pydantic model for a YAML policy file supporting: per-transaction cap,
  rolling-window ceiling (e.g. $2k/30d), merchant allowlist + denylist,
  category rules, allowed time windows, and per-agent identity scoping.
- The `approval_required_above` threshold must specify an `approver_role`
  (e.g. `manager`, `finance`, `cfo`).
- `evaluate(request, policy, spend_history) -> Decision`, where `Decision` is
  one of `ALLOW | DENY | REQUIRE_APPROVAL` — always carrying a machine-readable
  reason code, the specific rule that fired, and the required role if
  applicable.
- Deterministic. No network. No clock reads except an injected `now`.
- Tests: at minimum 20 cases including boundary conditions (exactly at cap,
  window rollover, denylist beating allowlist, empty policy = deny-by-default).
- **Deny-by-default is non-negotiable.** An empty or malformed policy denies.

### M2 — Tamper-evident audit log

- SQLite table where each row stores the decision, the full request, timestamp,
  policy hash, and `prev_hash`.
- Each row hashed (SHA-256 over canonical JSON) and chained to the previous.
- Each row signed with an Ed25519 operator key.
- **Data portability:** line-by-line JSON export as a first-class library
  function, for SIEM ingestion.
- `bouncer verify` CLI command walks the whole chain and reports the first
  broken link, if any.
- Test: write 100 entries, mutate one row directly in SQLite, prove `verify`
  catches it and names the row.

### M3 — Signed mandates

- On `ALLOW`, emit a scoped, short-TTL mandate: JSON payload (agent id, max
  amount, merchant, expiry, nonce), signed Ed25519, base64url encoded.
- `verify_mandate()` helper that any downstream service can call.
- Replay protection via a nonce store.
- Test: expired mandate rejected, altered amount rejected, replayed nonce
  rejected.

### M4 — The proxy

- FastAPI service. `POST /authorize` takes a payment intent, returns the
  decision + mandate.
- HTTP forward-proxy mode: intercept outbound calls, parse the intent, enforce,
  then forward or block.
- Adapters (thin, isolated in `bouncer/adapters/`, each ~50 lines):
  - `x402` — parse an HTTP 402 challenge into a normalized intent
  - `stripe` — parse a Stripe PaymentIntent create call (test mode only)
  - `generic` — explicit JSON intent
- Normalized internal `PaymentIntent` model that all adapters map into. Adding
  a new rail must mean writing one adapter file and nothing else.
- An intent that no adapter can parse is denied, logged, and surfaced. Never
  passed through unexamined.

### M5 — Human-in-the-loop (RBAC enabled)

- `REQUIRE_APPROVAL` decisions land in a pending queue, strictly tagged with
  the required `approver_role` defined in M1.
- `bouncer pending` lists them. Filter flag: `bouncer pending --role finance`.
- `bouncer approve <id> --role <role>` and `bouncer deny <id> --role <role>`
  resolve them. Both validate that the provided role matches the required role.
  Approve and deny are symmetric — no asymmetric authority.
- The role check is a workflow guardrail, not a security control (see Threat
  Model). Do not build authentication for it.
- Blocking mode: `/authorize` long-polls up to a configurable timeout, then
  denies. Timeout defaults to deny, never to allow.
- Optional webhook fired on new pending item — for later Slack / Teams
  integration.

### M6 — Demo + docs

- `examples/demo.py`: a scripted agent tries six purchases against a sample
  policy — one allowed, one over the per-txn cap, one to a denied merchant, one
  that trips the rolling window, one needing role-based approval, and one with
  a replayed mandate. Output must be legible enough to screen-record in 60
  seconds.
- `README.md`: what it is, the Threat Model section reproduced verbatim, a
  5-line quickstart, and an explicit "what this is not" section (not custody,
  not a standard, not a sandbox, not audited).
- MIT license.

---

## Engineering standards

- Type hints everywhere; `mypy --strict` clean.
- Every security-relevant function gets a docstring stating its threat model.
- No `TODO` comments in committed code — either build it or put it in
  `ROADMAP.md`.
- Tests run in under 10 seconds total.
- If a requirement above seems wrong or overbuilt, say so before implementing
  it. Preference is always: delete the requirement, then simplify, then build.

---

## Definition of done for v1

A developer clones the repo, writes a 15-line YAML policy with distinct role
approvals, and points their agent's `HTTP_PROXY` at bouncer. Every spend
attempt is then allowed under policy, denied, or held for the right approver —
with a signed, verifiable log proving which. Paired with egress control at the
network layer, the agent has no route to spend outside the policy.
