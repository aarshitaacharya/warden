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

### The first corpus was too easy, so there is a second

Zero attacks executing on the first corpus came from overlapping layers and from me writing both the attacks and the detectors. `eval/report_hard.md` runs a held-out set built to evade them (40 attacks, 34 benign tasks):

| | Authorization only | v1 heuristic | v2 classifier | v3 local LLM judge |
|---|---|---|---|---|
| Hard attacks executed | 37/40 | 7/40 (17.5%) | 7/40 (17.5%) | 7/40 (17.5%) |
| Hard benign tasks broken | 0/34 | 10/34 | 8/34 | 0/34 |

The 7 that get through are not injections: insider exfiltration that reformats the value (number formatting, spelled-out digits, paraphrase, chunking, translation) and two low-and-slow scraping runs.

### Hardening v4, measured on a second held-out set

I wrote a second set (`eval/corpus_hard2.py`, 21 attacks, 27 benign) and recorded its baseline **before** implementing the fix, then ran the fix against it once. v4 adds digit-normalised taint matching, an approval for any external send within 10 minutes of a sensitive read (humans included), and an approval after 20 restricted reads in 15 minutes.

| Second held-out set | v2 | v4 |
|---|---|---|
| Attacks executed | 14/21 (66.7%) | 0/21 (0%), 95% CI [0, 15.5] |
| Benign tasks broken | 3/27 | 6/27 (22.2%) |

Where the gain comes from: normalisation alone stops 10 of 21; the content-independent tainted-send approval stops 16; bulk-read approval is the only thing that stops the slow scraping. The price is friction: 3 benign "read a record, then email an outsider something unrelated" tasks now wait for approval, and the classifier's false blocks on security prose are unchanged. A hole remains: an attacker who waits more than 10 minutes between reading and sending is not caught (checked ad hoc, not in the corpus). On this size of corpus the confidence interval on 0/21 still allows up to about 15%.

Detectors alone, all three corpora combined (scan level): heuristic recall 46.5% / FPR 14.6%; classifier recall 90.1% / FPR 13.8%; local `qwen2.5:7b` judge via Ollama recall 42.3% / FPR 0%. The classifier's high recall is the least trustworthy number here, because I wrote its training data and the attacks. The LLM judge never false-blocks but misses split, dilution and customer-voice payloads entirely.

With a real model as the victim (qwen2.5:7b deciding whether to obey), 31.5% of 73 injection scenarios executed with authorization alone and 0% with any Warden stack. Part of that is the detector and part is taint tracking, so removing approvals and taint (ablation rows in the report) is what exposes the detector's own gaps.

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

- Device posture is a user attribute mapped into the token, and passkey step-up is the `acr` claim; neither is real attestation, and no passkey ceremony was run. Authentication, JWKS validation, service accounts and the agent exchange are tested against a live Keycloak (`tests/test_keycloak_integration.py`, skipped when it is not running; `scripts/e2e_keycloak.sh` for the HTTP path).
- The LLM judge runs locally through Ollama (`WARDEN_OLLAMA_MODEL`, default `qwen2.5:7b`); results are cached in `eval/results/` so reports reproduce without it. A paid-API judge (`LLMDetector`) exists but is not evaluated.
- The MCP front end calls the engine in process; the tool handlers are not a separate network service.
- Keys live in process memory.

## License

MIT
