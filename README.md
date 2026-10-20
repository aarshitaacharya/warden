# Warden

[![ci](https://github.com/aarshitaacharya/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/aarshitaacharya/warden/actions/workflows/ci.yml)

A zero-trust access broker for humans, backend services and AI agents. Every request to an internal tool goes through one gateway that verifies identity, asks a Cedar policy engine for a decision, runs agent guardrails, and writes a structured, hash-chained decision log. The same logs are then used to measure how well the controls work and to propose tighter, replay-validated policy.

Everything runs locally on free tooling: Python, Cedar (`cedarpy`), DuckDB, NetworkX, and Keycloak in Docker. No paid API is needed.

## Architecture

```
 Users (OIDC + passkeys) ─┐
 Services (client creds,  ├─► Warden gateway (FastAPI / MCP front end)
  cert-bound JWT)         │     1 authenticate: signature, issuer, audience, expiry, revocation
 Agents (RFC 8693) ───────┘     2 risk score (device, burst, denials, sequence, injection)
                                3 Cedar: RBAC + ABAC + ReBAC, agent scope ∩ delegating user
                                4 guardrails: exfil/taint, human approval
                                5 run tool, scan output for injection, update taint
                                6 decision log (DuckDB, hash chain)
                                          │
                  ┌───────────────────────┼────────────────────────┐
                  ▼                       ▼                        ▼
         eval/ red team + A/B     analytics/ least privilege   detections/ + incident
```

The key design piece is agent delegation. An agent holds no standing access. Its own credential is only valid as the `actor_token` in an RFC 8693 exchange with a user's `subject_token`, producing a five minute token whose `sub` is the user and `act.sub` is the agent. At request time the gateway requires **both** the agent (scope) and the user (roles, relationships, context) to be allowed. The log records each side.

## Quickstart

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python -m pytest -q                 # policy, identity, guardrail, analytics, incident tests
python scripts/demo.py              # same attack vs authz-only and full Warden
uvicorn warden.gateway:app          # API + http://localhost:8000/dashboard
python -m eval.run                  # regenerate eval/report.md (about 3 minutes)
python -m analytics.run             # regenerate analytics/report.md and the policy diffs
python -m incident.simulate         # compromised-agent incident, writes incident/timeline.json
docker compose up                   # Keycloak (+ Postgres) and the gateway
```

`docker compose up` loads the `acme` realm from `infra/keycloak/acme-realm.json` (regenerate with `python scripts/gen_realm.py`). The gateway trusts Keycloak's JWKS when `WARDEN_KEYCLOAK_JWKS` and `WARDEN_KEYCLOAK_ISSUER` are set. Without them it runs a built-in dev identity provider with the same claim layout, which is what the tests use.

## Headline results

From `eval/report.md`: 107 attack scenarios and 159 benign tasks, synthetic, with a scripted victim agent.

| | Authorization only | Warden v1 (heuristic) | Warden v2 (classifier) |
|---|---|---|---|
| Attacks that executed | 55/107 (51%) | 0/107 | 0/107 |
| Benign tasks broken | 0/159 | 13/159 (8.2%) | 8/159 (5.0%) |

Each guardrail added alone to authorization, scored on the attacks it targets that authorization lets through:

| Guardrail | Precision | Recall |
|---|---|---|
| Heuristic injection detector | 56.7% | 70.8% |
| Classifier injection detector | 74.2% | 95.8% |
| Taint / exfiltration control | 100% | 80.0% |
| Human approval | 100% | 100% |
| Risk scoring (behavioural attacks) | 100% | 100% |

A/B v1 vs v2 (paired bootstrap): injection detection +17.5 points, 95% CI [+7.5, +30.0]. The drop in benign false blocks (-3.1 points, CI [-8.2, +1.9]) is not distinguishable from zero on this corpus.

Read the caveats in the report. The corpus was written by the defender, so a score of zero attacks executed shows the layers cover this corpus, not that they cover everything. The per-guardrail numbers are the honest ones.

From `analytics/report.md` (simulated month of traffic): agents and users used 12 to 50 percent of the permissions they were granted; the generated least-privilege proposal, learned on 20 days, would have broken 8 of 441 requests in the last 10 days (all one legitimate change in behaviour, caught by replay); 20 agent/user pairs could read sensitive data and send it outside, 0 after the proposal. See `analytics/cloudtrail_report.md` for the same analysis on the public flaws.cloud CloudTrail dataset.

Simulated incident (`docs/incident-postmortem.md`): a stolen agent token read six HR records, five exfiltration attempts were all blocked (two by taint, two by accumulated risk, one by scope), detection at 90 seconds, containment 120 seconds later, zero external messages delivered.

## Repository map

| Path | What |
|---|---|
| `docs/design.md`, `docs/threat-model.md` | Design, STRIDE and agent threats, post-build re-assessment |
| `warden/identity.py` | Dev IdP, RFC 8693 STS, verifier, revocation, certificate binding |
| `policies/cedar/` | RBAC, ABAC, ReBAC and workload policies; `policies/versions.json` toggles guardrails per version |
| `warden/engine.py`, `warden/gateway.py`, `warden/mcp_server.py` | Enforcement point, HTTP API, MCP front end |
| `warden/guardrails/` | Injection detectors, taint, risk, approvals |
| `warden/detections.py` | SQL detection rules over the decision log |
| `eval/` | Attack and benign corpora, harness, statistics, CI gate, report |
| `analytics/` | Simulator, SQL, recommendations, replay, attack-path graph, CloudTrail |
| `incident/` | Incident simulation |
| `.github/workflows/ci.yml` | Tests, corpus freshness check, red-team gate |

## Known limits

- Device posture and passkey step-up are claims in the token, not real attestation. Keycloak's realm export is provided and the gateway can validate its JWKS, but this repo's tests run against the built-in dev IdP; the Keycloak path has not been exercised end to end.
- The LLM injection detector (`warden/guardrails/injection.py`, `LLMDetector`) is implemented but not evaluated, to keep the project free to run.
- The MCP front end calls the engine in process; the tool handlers are not a separate network service.
- Keys live in process memory.

## License

MIT
