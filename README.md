# bouncer

**A policy enforcement point for agent spending.**

bouncer sits between an AI agent and any payment rail, blocks transactions that
violate a declarative policy, and writes a tamper-evident, signed audit log of
every decision.

It never custodies funds.

```
agent ──> bouncer proxy ──> [policy engine] ──> payment rail
                                  │
                                  ├──> signed mandate (Ed25519, scoped, TTL)
                                  ├──> hash-chained audit log (SQLite)
                                  └──> approval queue (if over threshold,
                                       tagged by role)
```

---

## Quickstart

```bash
pip install -e .                                    # 1. install
bouncer init                                        # 2. key + starter policy in ~/.bouncer
$EDITOR ~/.bouncer/policy.yaml                      # 3. write your rules
bouncer serve &                                     # 4. run the decision point
export HTTP_PROXY=http://127.0.0.1:8081             # 5. point your agent at it
```

Then watch it work:

```bash
python examples/demo.py
```

Six purchases against a sample policy: one allowed, one over the per-transaction
cap, one to a denied merchant, one that trips the rolling window, one held for a
human approver, and one replayed mandate. It finishes by verifying the audit
chain, then tampering with a row to show the evidence fire.

---

## Threat model

Build to this. This section is the contract; nothing else in these docs claims
more than it does.

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

### Three limits the implementation adds

Building v1 surfaced three more boundaries. They narrow the claims above; they
never widen them.

**Tail truncation is not detectable from the log alone.** The hash chain catches
edits, insertions, and deletions from the middle. An attacker who deletes the
most recent N rows leaves a chain that is internally perfect. `bouncer verify`
prints the head hash — record it somewhere bouncer cannot reach, and pass it
back to close the gap:

```bash
bouncer verify --expect-head 6b38557b4efae22e...
```

**CONNECT tunnels cannot be policed, so they are denied by default.** Inside a
TLS tunnel bouncer sees a hostname and nothing else — no amount, no category, no
intent. Caps, rolling windows and approval thresholds cannot apply. Running the
proxy with `--allow-connect` permits tunnels to *explicitly allowlisted* hosts
only, and the traffic inside them is **unenforced**. Full enforcement of HTTPS
payment traffic needs TLS termination, which v1 does not do (see
[ROADMAP.md](ROADMAP.md)).

**The API authenticates nobody.** The `agent_id` in a request is an assertion by
the caller. An agent that can reach `/authorize` can claim to be any agent in
the policy. Bind to loopback and treat network reachability as the boundary.

**x402 over the proxy is not fully enforceable.** The adapter reads a 402
challenge, which is a *response*. An agent's follow-up payment carries an
`X-PAYMENT` header whose payload names an amount in atomic units but no asset
decimals, so its true value cannot be determined without an off-chain lookup the
engine is not allowed to make. bouncer denies what it cannot price. Send x402
intents to `/authorize` explicitly, where the challenge supplies the scale.

---

## What this is not

- **Not custody.** bouncer never holds, moves, or touches funds. It emits a
  signed authorization; something else settles the payment. This is deliberate:
  the moment it holds money it needs a money transmitter licence.
- **Not a standard.** The agent-payment standards war (ACP, MPP, UCP, AP2, x402,
  Visa TAP) is unsettled. bouncer is invariant to which one wins — it is an
  adapter plus a policy layer, not a fifth protocol.
- **Not a sandbox.** See the threat model. Without egress control, an agent can
  route around it.
- **Not audited.** No security review has been performed. The Stripe adapter
  refuses live-mode keys for exactly this reason.
- **Not multi-tenant.** One operator, one machine, one local process. No auth,
  no billing, no dashboard.

---

## Writing a policy

Everything is deny-by-default. An agent that is not named cannot spend at all.

```yaml
version: 1
currency: USD

agents:
  research-bot:
    per_transaction_cap: 50.00

    rolling_windows:
      - amount: 100.00
        window: 30d

    merchants:
      allow: ["api.weather.example", "*.trusted-vendor.example"]
      deny: ["*.casino.example"]

    categories:
      deny: ["gambling"]

    time_windows:
      - days: [mon, tue, wed, thu, fri]
        start: "09:00"
        end: "18:00"
        timezone: "America/New_York"

    approval_required_above:
      amount: 20.00
      approver_role: finance
```

The choices behind the schema, all of which fail closed:

| Rule | Behavior |
| --- | --- |
| Unknown agent | Denied. `"*"` is a valid catch-all key, but you must write it. |
| Misspelled rule name | Load error. It never reads as a missing restriction. |
| `per_transaction_cap` | Mandatory. There is no unlimited rule set. |
| Denylist vs allowlist | Denylist always wins. |
| Missing allowlist | Not a constraint; any merchant not denied passes. |
| Empty allowlist (`[]`) | Nothing passes. A usable way to freeze an agent. |
| Uncategorized request | Denied whenever `categories.allow` is set. |
| Currency mismatch | Denied. bouncer never converts — that needs a live rate. |
| Amounts in YAML | Parsed as decimals, never binary floats. `100.10` is exact. |
| Approval threshold ≥ cap | Load error. It could never fire, so it is a typo. |
| Empty or malformed policy | Denies everything. |

Prohibitions are evaluated **before** the approval threshold, so a forbidden
transaction is never offered to a human. Approvers exercise judgment inside
policy, not over it.

---

## Using it

### As a proxy

```bash
bouncer proxy --port 8081
export HTTP_PROXY=http://127.0.0.1:8081
```

Plaintext HTTP is parsed, judged, and either forwarded or blocked with a 403.
An authorized request is forwarded with an `X-Bouncer-Mandate` header the
upstream service can verify. Traffic no adapter can parse is denied and logged —
never forwarded unexamined.

### As an API

```bash
curl -X POST localhost:8080/authorize \
  -H 'content-type: application/json' \
  -d '{"agent_id":"research-bot","merchant":"api.weather.example","amount":"12.00","currency":"USD"}'
```

`200` allowed (with a mandate), `403` denied, `202` awaiting a human. Add
`?wait=true` to long-poll for an approval; **the wait times out into a deny.**

### As a library

```python
from datetime import datetime, timezone
from bouncer import LocalFileSource, PaymentIntent, evaluate

decision = evaluate(
    PaymentIntent(agent_id="research-bot", merchant="api.weather.example",
                  amount="12.00", currency="USD"),
    LocalFileSource("policy.yaml").load(),
    spend_history,
    now=datetime.now(timezone.utc),
)
```

`evaluate` is pure: no network, no disk, no clock reads, no model calls. The
same inputs always produce the same decision.

---

## The audit log

Every decision is one hash-chained, Ed25519-signed SQLite row.

```bash
bouncer verify                  # walk the chain, name the first broken row
bouncer export -o audit.jsonl   # line-delimited JSON for SIEM ingestion
```

Export is a first-class library function, not a script:

```python
from bouncer.audit import AuditLog, export_jsonl, verify_exported
export_jsonl(log, "audit.jsonl")
```

An exported file re-verifies standalone from the operator's **public** key, so
an auditor can check a log you hand them without database access or your
signing key.

Spent mandate nonces accumulate in the same database. `bouncer purge` drops the
ones whose mandates have expired — safe by construction, since an expired
mandate is already rejected on the expiry check. It never touches the
append-only audit log. Run it from cron if you are issuing a lot of mandates.

---

## Approvals

```bash
bouncer pending --role finance
bouncer approve <id> --role finance
bouncer deny    <id> --role finance
```

Approve and deny run the identical role check — there is no asymmetric
authority where vetoing is easier than approving. Resolution is once-only.
Set `BOUNCER_WEBHOOK_URL` to get a POST when something lands in the queue; a
webhook failure never changes an outcome.

**The role check is a workflow guardrail, not a security control.** See the
threat model.

---

## Adding a payment rail

Write one file in `bouncer/adapters/` that turns the rail's traffic into a
`PaymentIntent`, and add it to `DEFAULT_ADAPTERS`. Nothing else changes.

Shipped: `x402` (HTTP 402 challenges), `stripe` (PaymentIntent creates, **test
mode only**), `generic` (explicit JSON).

Adapters never decide anything — they extract fields and hand them to the
engine. An adapter that cannot confidently parse a request raises, and that
becomes a logged deny. Refusing beats guessing: the x402 adapter will not
assume an unknown asset's decimal scale, because guessing wrong is a
factor-of-a-million error.

---

## Development

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"
.venv/bin/python -m pytest          # 223 tests, ~4s
.venv/bin/python -m mypy            # strict, clean
```

On Windows the interpreter is `.venv\Scripts\python.exe`, and one test skips:
key file permissions are POSIX mode bits, which Windows does not honour. The
key is left under the inherited directory ACL there — see the note in
`bouncer/keys.py`.

Standards: type hints everywhere, `mypy --strict` clean, no `TODO` in committed
code (it goes in [ROADMAP.md](ROADMAP.md)), tests under 10 seconds, and a
docstring stating the threat model on every security-relevant function.

## License

MIT — see [LICENSE](LICENSE).
