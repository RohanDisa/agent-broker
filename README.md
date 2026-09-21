# Capability Broker

An authority-and-enforcement layer for LLM agents. Every tool call goes through the broker. The broker assumes the agent is already compromised: it mints a scoped, short-lived, single-use credential for the specific call, enforces deny-by-default policy, logs a hash-chained audit trail, and can revoke authority mid-run.

It implements the runtime authority patterns that vendors like Zenity, Act, Hush, and Arcade are building products around, small enough to read end to end and attack directly.

## Why this exists

Agents take actions in real systems. The moment an agent reads untrusted content, a web page, an email, a document, a tool result, that content can carry instructions that hijack the agent. That is prompt injection, and there is no reliable way to stop the model from being fooled.

So the defense does not live in the model. It lives around it: least privilege, scoped credentials, a policy the agent cannot talk its way past, and an audit trail for when something slips through. Independent testing puts container-escape and unauthorized-action rates for frontier agents in the double digits, and prompt injection remains an unsolved model-level problem. The industry response is a runtime authority layer. This project is that layer.

The claim is precise: it does not stop injection. It assumes injection succeeds at the model level and stops the **consequences** through least privilege, provenance-aware policy, and egress control. The red-team suite is the deliverable that proves it.

## Results

Block rate and false-positive rate from `go run ./cmd/attacker` (rules-only guard, no model):

```
Block rate on attacks:            10/10 (100%)
False-positive rate on benign:    0/8   (0%)
```

Every attack is blocked by one named control, and every control is proven load-bearing by an ablation: turn that single control off, re-run, and the attack succeeds.

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

The benign set includes a deliberately allowed borderline path, emailing a fetched link to `support@ourco.com`, to confirm the broker is tuned rather than blunt. A broker that blocks everything scores 100% on attacks and is useless; the benign allow rate is what keeps that honest.

---

## Threat model

### Trust boundaries

| Zone | What | Why |
|---|---|---|
| Untrusted | The LLM/agent and anything it outputs | Assume it may be fully manipulated |
| Untrusted | All content the agent ingests (web, email, docs, tool results) | This is the injection vector |
| Trusted | The broker, its policy store, and the credential minting authority | If the broker is owned, the model collapses |
| Semi-trusted | Downstream tools/APIs | They enforce their own auth but must never receive more authority than the task needs |

### Adversary goals we defend against

- **Privilege escalation** — call a tool or scope that was not granted
- **Injection-driven action** — untrusted content tells the agent to exfiltrate, email, or delete
- **Credential theft/replay** — a leaked credential is reused
- **Confused deputy** — the agent uses legitimate authority for the attacker's ends
- **Data exfiltration** — sensitive data to an unapproved destination
- **Scope creep over a session** — many plausible calls that aggregate into an attack

---

## How it works

```
operator ──grants──► broker ──minted credential──► mock tool
                       ▲                │
                       │                ▼
                    naive agent    hash-chained audit
                    (untrusted)
```

1. The operator creates a task with typed grants (tool + operation + resource pattern + caveats).
2. The agent asks to call a tool. The broker evaluates deny-by-default policy.
3. On allow, it mints an Ed25519-signed, macaroon-style credential valid for that one call, once, for a few seconds.
4. The tool executor verifies the credential independently. No standing token.
5. Every decision, mint, execution, elevation, and revocation is appended to a SHA-256 hash chain.

Nothing reaches a tool except through `CallTool` after mint and verify.

