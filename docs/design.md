# Warden design

Warden is a zero-trust access broker. Every call from a human, a backend
service or an AI agent to an internal tool goes through one gateway. The gateway
verifies identity, asks a policy engine for a decision, runs guardrails, and
writes a structured decision log. That log feeds the analytics that measure how
well the controls work and propose tighter policy.

## 1. The simulated company

"Acme" is small on purpose, so every policy can be reasoned about by hand.

| Kind | Members |
|---|---|
| Tools (5) | `tickets`, `hr`, `docs`, `finance`, `comms` (email and outbound HTTP) |
| Humans (10) | alice, bob (engineers); carol, dave (HR); erin, frank (finance); grace (eng manager), heidi (HR manager), ivan (finance manager), judy (executive) |
| Services (2) | `billing-svc`, `ticket-sync-svc` |
| Agents (3) | `support-agent`, `hr-assistant`, `research-agent` |

Actions are named `tool:verb`, for example `tickets:read`, `hr:read_record`,
`finance:create_payment`, `comms:send_email`. Every resource carries a
sensitivity label: 0 public, 1 internal, 2 confidential, 3 restricted.

## 2. Architecture

```
 Users (OIDC + passkeys) ─┐
 Services (client creds,  ├─► Warden Gateway (FastAPI)
  mTLS-bound JWT)         │     1. authenticate: signature, audience, expiry, revocation
 Agents (RFC 8693) ───────┘     2. resolve principal(s) and risk score
                                3. Cedar decision (agent AND delegating user)
                                4. guardrails: approval, exfil/taint, injection scan
                                5. call tool (MCP server), scan output, update taint
                                6. write decision log
                                         │
                                         ▼
                              DuckDB: decisions, tokens, approvals
                                         │
                       analytics: SQL, replay, recommendations, attack paths
```

The gateway is the only network path to the tools. The tools are an in-process
MCP server (`warden/mcp_server.py`) so they could be moved behind a network
boundary without changing the gateway.

## 3. Trust boundaries

1. **Client to gateway.** Untrusted. Everything arrives as a bearer token plus
   request body. Nothing in the body is believed for authorization.
2. **Gateway to policy engine.** Same process, trusted. Policies are code
   reviewed in git and tested in CI.
3. **Gateway to tools.** Tools are trusted to do what they are told but **their
   output is untrusted data**. A ticket body is attacker-controlled text.
4. **Tool output to agent.** The key AI boundary. Output is scanned and labelled
   before it re-enters a model context.
5. **Keycloak to gateway.** The gateway trusts Keycloak's signing keys (JWKS)
   for human and service identity, and trusts only its own STS keys for agent
   tokens.

## 4. Assets

- HR records (salary, SSN): restricted.
- Finance reports and the ability to create payments.
- Internal docs and roadmap: confidential.
- Tickets: internal, but they are the main carrier of injected text.
- Signing keys and the revocation list.
- The decision log itself (integrity matters for detection and forensics).

## 5. Identity model

| Actor | How they authenticate | What the gateway sees |
|---|---|---|
| Human | OIDC login at Keycloak, passkey (WebAuthn) for step-up | `typ=user`, `acr` shows whether a passkey was used |
| Service | OAuth client credentials; optional mTLS certificate binding (RFC 8705 `cnf`) | `typ=service`, scopes |
| Agent | Own client credential is only an **actor token**. Useless alone. Warden's STS exchanges `subject_token` (the user) plus `actor_token` (the agent) for a short-lived delegated token (RFC 8693) | `typ=agent`, `sub` = user, `act.sub` = agent, narrowed `scope`, 5 minute lifetime |

### The delegation rule

An agent has no standing access. Its effective permission for any request is

```
effective = agent scopes in the token  ∩  what the delegating user may do
```

The gateway enforces it by running two Cedar evaluations and requiring both to
allow: one for the agent principal (scope check, agent-specific forbids) and one
for the user principal (RBAC, ABAC, ReBAC) on the same action and resource. The
decision log stores both outcomes, so a denial says which side refused.

Scopes are narrowed at exchange time (requested ∩ agent maximum) and again at
request time (user's current permissions). Revoking the user, the agent or a
single token takes effect on the next request.

## 6. Authorization model

One Cedar policy set covers three models.

- **RBAC.** `User` entities have `Role` parents. Roles map to action sets.
- **ABAC.** Context carries `risk_score`, `device_trusted`, `stepped_up`,
  `business_hours`. Resources carry `sensitivity`. Forbids express the rules:
  no restricted data from untrusted devices, payments and HR writes need a
  passkey step-up, no access at risk 80 or above.
- **ReBAC.** An HR record has `subject` and `subject_manager`. A manager may read
  the records of direct reports, and anyone may read their own.

Cedar's forbid-overrides-permit semantics give us default deny and make the ABAC
rules impossible to bypass with a broad permit.

## 7. Guardrails and adaptive access

Each guardrail is a switch on a **policy version**, which is what the A/B tests
compare (`policies/versions.json`).

| Guardrail | What it does |
|---|---|
| Injection scan | Scans tool output returned to an agent. Detectors: heuristic rules, a trained n-gram classifier, optional LLM judge. A hit quarantines the output and raises session risk. |
| Taint tracking | Output from confidential or restricted data taints the session with value fingerprints. Outbound tools check the payload against the taint set and the destination domain. |
| Approval | High-risk actions (payments, deletes, external email) stop at `pending_approval` until a different, authorized human approves. |
| Risk score | New device, unusual tool sequence, request burst, injection suspicion, recent denials. Maps to allow, step-up required, or deny. |

## 8. Decision log

One row per request: timestamp, request id, session, principal kind, user, agent,
action, resource, sensitivity, decision, deciding policy ids, per-principal
outcomes, risk score, guardrail verdicts, reason string, policy version, latency.
It is the single source for dashboards, detections, replay and recommendations.

## 9. Out of scope

Real device attestation (device posture is a token claim), network-level
segmentation, key management beyond a local key file, multi-tenant isolation.
Each is listed under residual risk in the threat model.

## 10. Free-tier constraints

Everything runs locally or on free GitHub Actions: Keycloak and Postgres in
Docker Compose, Cedar through `cedarpy`, DuckDB for storage, no paid API needed.
The LLM detector is optional and off by default.

## 11. As built (changes from the plan)

- **Identity.** Keycloak authenticates humans and service accounts; its JWKS is trusted by the gateway (`warden/identity.py`, tested live in `tests/test_keycloak_integration.py`). Keycloak's standard token exchange has no actor claim, so agent delegation (RFC 8693 with `act`) is done by Warden's own STS. A built-in dev IdP with the same claim layout backs the unit tests. Passkey step-up is modelled with the `acr` claim; no passkey ceremony was run.
- **Policy versions.** `v0` authorization only; `v1` heuristic detector; `v2` classifier; `v3` local Ollama judge; `v4` v2 plus digit-normalised taint matching, approval for external sends within 10 minutes of a sensitive read (any principal), and approval after 20 restricted reads in 15 minutes. `g-*` versions switch one guardrail on alone for ablation.
- **Evaluation.** Three corpora: the first (107 attacks, 159 benign), a held-out hard set, and a second held-out set whose baseline was recorded before v4 existed. A real local model can act as the victim agent. See `eval/report.md` and `eval/report_hard.md`.
- **Known holes.** Waiting out the 10 minute taint window defeats the tainted-send approval. Value-matching misses transformed values; only the approval covers those. Detection of injected text is unreliable on its own (see the reports).
