# Capability Broker

A teaching-grade **authority-and-enforcement layer** for LLM agents. Every tool call
goes through the broker. The broker assumes the agent is already compromised: it
mints a scoped, short-lived, single-use credential for the specific call, enforces
deny-by-default policy, logs a hash-chained audit trail, and can revoke authority
mid-run.

This is a reference implementation of patterns that companies like Zenity, Act,
Hush, and Arcade are commercializing. It is **not** a hardened production gateway.

## Why this exists

Agents take actions in real systems. The moment an agent reads untrusted content
(a web page, an email, a document, a tool result), that content can carry
instructions that hijack the agent. That is prompt injection, and there is no
reliable way to stop the model from being fooled.

So the defense cannot live in the model. It has to live **around** it: least
privilege, scoped credentials, a policy the agent cannot talk its way past, and
an audit trail for when something slips through.

Independent testing puts container-escape and unauthorized-action rates for
frontier agents in the double digits. Prompt injection remains an unsolved
model-level problem. The industry response is a runtime authority layer. This
project is that layer, small enough to read and attack.

**What this project actually claims:** not that it stops injection. It assumes
injection succeeds at the model level and stops the *consequences* via least
privilege, provenance-aware policy, and egress control. The red-team suite is
the deliverable.

## Attack → defending layer

| Attack | Outcome | Defending layer | Ablation (control off) |
|---|---|---|---|
| Direct escalation | BLOCKED | `least_privilege` | attack succeeds |
| Resource scope break | BLOCKED | `resource_scope` | attack succeeds |
| Injected exfiltration | BLOCKED | `egress` | attack succeeds |
| Confused deputy | BLOCKED | `resource_scope` | attack succeeds |
| Credential replay | BLOCKED | `single_use` | attack succeeds |
| Caveat stripping | BLOCKED | `signature` | attack succeeds |
| Elevation bypass | BLOCKED | `elevation` | attack succeeds |
| Aggregate scope creep | BLOCKED | `rate_count` | attack succeeds |
| Provenance laundering | BLOCKED | `provenance` | attack succeeds |
| Revocation race | BLOCKED | `revocation` | attack succeeds |

Headline (from `go run ./cmd/attacker`):

- **Block rate on attacks:** 10/10 (100%)
- **False-positive rate on benign traffic:** 0/8 (0%)

A perfect score with a tiny benign set is not a victory lap. The benign cases
include a borderline “email a fetched link to support@ourco.com” path that we
**allow** on purpose. A real system tunes this tradeoff; a broker that blocks
everything scores 100% on attacks and fails the point.

## Threat model

### Trust boundaries

| Zone | What | Why |
|---|---|---|
| **Untrusted** | The LLM/agent and anything it outputs | Assume it may be fully manipulated |
| **Untrusted** | All content the agent ingests (web, email, docs, tool results) | This is the injection vector |
| **Trusted** | The broker, its policy store, and the credential minting authority | If the broker is owned, the model collapses |
| **Semi-trusted** | Downstream tools/APIs | They enforce their own auth but must never receive more authority than the task needs |

### Adversary goals we defend against

1. **Privilege escalation** — call a tool or scope that was not granted
2. **Injection-driven action** — untrusted content tells the agent to exfiltrate, email, or delete
3. **Credential theft/replay** — a leaked credential is reused
4. **Confused deputy** — the agent uses legitimate authority for the attacker’s ends
5. **Data exfiltration** — sensitive data to an unapproved destination
6. **Scope creep over a session** — many plausible calls that aggregate into an attack

## How it works

```
operator ──grants──► broker ──minted credential──► mock tool
                       ▲                │
                       │                ▼
                    naive agent    hash-chained audit
                    (untrusted)
```

1. The operator creates a **task** with typed grants (tool + operation + resource pattern + caveats).
2. The agent asks to call a tool. The broker evaluates **deny-by-default** policy.
3. On allow, it mints an Ed25519-signed, macaroon-style credential valid for **that call**, **once**, for a few seconds.
4. The tool executor verifies the credential independently. No standing token.
5. Every decision, mint, execution, elevation, and revocation is appended to a SHA-256 **hash chain**.

### Capabilities, not roles

Roles are too coarse for per-action agent authority (“the support agent can use email”).
A grant is narrow: `email.send` on `email://*` with destination allowlist `*@ourco.com`,
bound to one task, attenuable only downward. The agent can request a *narrower*
credential than its grant, never a broader one. That is the core capability-security
property, and it is tested.

### Why macaroon-style tokens (with Ed25519)

Classic macaroons model attenuation and delegation with caveats, so a credential
proves its own limits without a callback to the issuer. JWTs need a revocation
list to shrink authority after issue; caveats are self-describing.

We sign a **chained caveat hash** with Ed25519 (stdlib). Stripping or widening a
caveat changes the chain head and the signature fails. This is not libmacaroon;
it is the same attenuation idea with the signature algorithm the spec asked for.

**Local signing key ≠ KMS.** The broker generates or loads an Ed25519 key from
disk. The minting pattern is identical to wrapping this with a KMS; the key
management is simplified for a solo project. Say that in an interview.

### Policy as code

Policies live as auditable Rego in `internal/policy/rego/`. The runtime is a
typed Go DSL that evaluates the same rules (`internal/policy/engine.go`) so CI
has no OPA versioning surprises and no extra binary. Policy is data, versioned
and diffable — not `if` statements buried in the HTTP handler.

Rules, each with a test:

- **least privilege** — no matching grant → deny
- **resource scoping** — `db://customers/123/*` does not authorize `db://customers/124`
- **rate/count** — session caveats, not just per-call
- **high-risk → elevation** — `payments.charge`, `db.delete`, external `email.send`
- **provenance** — web/doc-derived args targeting a sensitive resource are denied
- **egress** — send/write to a destination not on the allowlist is denied

### Injection defense-in-depth

Injection may fool the model. To cause harm the model must then make a tool
call, and every tool call must pass provenance-aware, deny-by-default policy
with egress control.

| Layer | What it does | Honest limit |
|---|---|---|
| Provenance tagging | Every input is `user` / `tool` / `web` / `doc`; labels propagate through intermediate tools | Useless if it does not propagate (scenario 9 exists to catch that) |
| Spotlighting | Untrusted content is delimited with unique tags | Reduces, does not eliminate, instruction-following |
| Rules guard | Classifier on tool args; optional Ollama, never required | CI runs rules-only |
| Data-flow / egress | Sensitive payload to a non-allowlisted destination is blocked | This is the exfil defense |

The demo agent is **deliberately injectable**. It parses `INSTRUCTION:` lines
out of a fetched page and tries to obey them. Spotlighting does not save it.
Policy does.

### Elevation and revocation

High-risk ops do not get standing authority. `RequireElevation` queues a
human approval (tests simulate the human). Approval is scoped to that one
call and cannot be reused.

Any grant can be revoked at any time; the next call is denied. Combined with
a 5-second credential TTL, that is the damage window on a revoked-but-not-yet-
expired grant.

### Audit

Every allow/deny/elevate, every mint, every execution, every revocation is
hash-chained. `verify` walks the chain and names the broken link. That is
what answers “why did the agent do that” six weeks later, even if someone
tries to doctor the log.

### How this composes with a sandbox

The broker governs **authority** (what the agent is allowed to intend). A
sibling sandbox project would govern **execution** (what the process can
touch at the OS/network layer). An allowed `http.fetch` still runs inside
whatever filesystem/network jail you wrap the tool in. They stack: sandbox
without a broker is a jail with a confused deputy; a broker without a
sandbox is an authority layer whose tools are themselves fully privileged
processes.

## Repository

```
cmd/broker          HTTP gateway (proto contract in proto/broker.proto)
cmd/demo-agent      Naive, injectable agent
cmd/attacker        Red-team runner; CI fails if block rate drops
internal/capability Grants, caveats, mint, verify (single-use, attenuation)
internal/policy     Deny-by-default engine + Rego-as-source
internal/injection  Provenance, spotlight, guard, data-flow
internal/elevation  JIT approval queue
internal/revocation Mid-run revoke
internal/audit      Hash-chained log
internal/tools      Mock email, db, files, http, payments
redteam/            Declarative attacks + benign traffic
```

Transport: the proto file is the service contract (`CreateTask`, `CallTool`,
`Elevate`, `Revoke`, …). The process you run is an HTTP/JSON gateway that
implements those RPCs so demos and CI stay interceptable without `protoc`.
Broker↔tool “gRPC” in the architecture sense is the same intercept point:
nothing reaches a tool except through `CallTool` after mint+verify.

## Quick start

```bash
go test ./...
go run ./cmd/attacker          # prints the attack table + rates
go run ./cmd/broker            # :8080
# other terminal
./scripts/demo_attack.sh
go run ./cmd/demo-agent
```

Docker:

```bash
docker compose up --build broker
docker compose --profile demo run --rm demo-agent
docker compose --profile attack run --rm attacker
```

## Measurements

Collected by `go test ./...` and `go run ./cmd/attacker` (rules-only guard;
no model).

| Metric | Value |
|---|---|
| Attack block rate | 10/10 (CI fails if this drops) |
| Benign allow rate | 8/8 |
| False-positive rate | 0/8 (benign set is teaching-grade; say so) |
| Ablation proofs | 10/10 attacks succeed with the defending control off |
| Credential TTL / damage window | 5s |
| Audit tamper | detected; broken link named by seq |
| Policy-eval latency | ~170 ns/op allow, ~41 ns/op deny (`go test ./internal/policy -bench .`) |
| Full `CallTool` (mint+verify+exec+audit) | milliseconds; dominated by I/O, not policy |
| Tests | 72 passing (`go test ./...`) |
| Guard model | optional, unused in CI |

Coverage of non-crypto-primitive code, measured by `go test ./internal/... ./redteam/... -cover` (stdlib Ed25519/SHA-256 are not the point):

| Package | Coverage |
|---|---|
| audit | 89% |
| elevation | 95% |
| injection | 88% |
| store | 80% |
| redteam | 80% |
| capability | 75% |
| policy | 76% |
| tools | 74% |
| broker | 72% |
| revocation | 71% |
| server | 68% |

The core security packages (audit, capability, policy, injection, elevation) sit in the mid-70s to 90s. HTTP glue and the mock tools are lower; CI still fails the build if a must-block scenario regresses. That gate is the one that matters.

## Tests

- **Unit:** caveat attenuation, credential verify (bad sig / expired / replay),
  each policy rule, provenance propagation, hash-chain tamper, data-flow
- **Integration:** allowed task through HTTP + complete audit chain; elevation
  approve and deny paths; revocation on the next call
- **Red-team:** all ten attacks + eight benign scenarios; ablation A/B; CI
  gate on block rate
