# Warden threat model

Status: Phase 0 draft. Each row names the control that mitigates it and the phase
that builds it. Section 5 is re-assessed after the build in Phase 6.

Scope: the gateway, STS, policy engine, tools, decision log and the agent
interaction path. Actors: authenticated employees, services, agents, an external
attacker with no credentials, and an attacker who can write text into tickets or
docs (the realistic indirect-injection position).

## 1. STRIDE

| # | Threat | Category | Control | Phase |
|---|---|---|---|---|
| S1 | Stolen user bearer token replayed | Spoofing | Short lifetimes, revocation by `jti`/user, device claim feeds risk score, passkey step-up for sensitive actions | 1, 3 |
| S2 | Agent client credential used directly against tools | Spoofing | Client credential is only valid as `actor_token`; gateway rejects `typ=agent_client` | 1 |
| S3 | Forged token from an untrusted issuer or `alg=none` | Spoofing | Issuer allow-list, pinned algorithms, audience check | 1 |
| S4 | Service token reused from another host | Spoofing | Certificate binding (`cnf.x5t#S256`) checked against the proxy-provided thumbprint | 1 |
| T1 | Tool arguments altered to reach another record | Tampering | Authorization is on the resource named in the request and rechecked by tool, never on client claims | 2 |
| T2 | Policy files modified | Tampering | Policies in git, CI policy tests, version id logged on every decision | 2, 6 |
| T3 | Decision log edited to hide activity | Tampering | Append-only writes from gateway, hash chain on rows (see residual risk) | 2, 6 |
| R1 | User denies approving a payment | Repudiation | Approval records store approver identity, acr and time; approver cannot be the requester | 3 |
| R2 | Cannot tell agent action from user action | Repudiation | Every row stores user, agent and token `jti` | 2 |
| I1 | Over-broad query leaks HR data | Info disclosure | RBAC + ReBAC + sensitivity ABAC, field-level data minimization in the tool | 2 |
| I2 | Error messages leak policy internals | Info disclosure | Clients get a short reason code; details only in the log | 2 |
| D1 | Request flood or runaway agent loop | Denial of service | Burst signal raises risk to deny, per-session rate limit | 3 |
| E1 | Role confusion lets a user reach finance | Elevation | Default deny, role→action table tested exhaustively | 2 |
| E2 | Agent exceeds the user it acts for | Elevation | Dual evaluation: agent scope ∩ user permission | 2 |
| E3 | Self-approval of high-risk action | Elevation | Approver must differ from requester and hold approver role | 3 |

## 2. Agent-specific threats

### A1. Indirect prompt injection
Attacker writes instructions into a ticket, doc or HR note. A legitimate agent
reads it and treats it as a command.
- Controls: output scanning (heuristic and classifier), quarantine of flagged
  output, session risk bump after a hit, and the authorization layer that limits
  the damage even when detection fails.
- Measured by: recall and precision of the injection guardrail on the red-team
  corpus, false blocks on benign docs that merely discuss security.
- Known gap: novel phrasings, other languages, and payloads split across several
  tool outputs will evade the heuristic. The classifier narrows but does not
  close this.

### A2. Confused deputy
A low-privilege user induces a powerful agent to perform an action the user could
not do. Example: an engineer asks `hr-assistant` for a colleague's salary.
- Control: dual evaluation. The agent never authorizes on its own authority.
- Measured by: confused-deputy scenarios in the corpus must be denied with the
  user side as the deciding policy.

### A3. Over-privilege
Agents are granted more scopes than they use because it is convenient.
- Controls: scope narrowing at exchange, deny-by-default for destructive actions
  on agents, analytics comparing granted to used scopes with generated reductions.

### A4. Data exfiltration
Sensitive data read by an agent is sent out through email or HTTP, either by an
injected instruction or by a compromised agent.
- Controls: taint tracking, destination domain policy, approval for external
  email, risk escalation after a taint plus outbound pattern.
- Measured by: exfiltration chains in the corpus, including encoded and chunked
  variants.
- Known gap: values transformed beyond fingerprint matching (summaries,
  paraphrases, steganography) are only caught by the domain and approval controls.

### A5. Tool-sequence abuse
Each call is individually allowed but the sequence is harmful (read HR, then
http_post). Controls: taint (A4) and a sequence signal in the risk score.

### A6. Token theft from agent runtime
Agent token leaked through logs or a tool output. Controls: 5 minute lifetime,
narrow scope, revocation, no refresh token issued.

## 3. Trust assumptions

- Keycloak and the STS signing keys are not compromised.
- The gateway process and policy files are intact.
- Device posture claims come from a trusted attestation source (simulated here).

## 4. Assets ranked

1. HR restricted data and payment initiation.
2. Signing keys.
3. Decision log integrity.
4. Confidential docs.

## 5. Re-assessment (after the build)

Measured against the 107-scenario red-team corpus and the simulated incident. See `eval/report.md`
and `docs/incident-postmortem.md`. Scenario results are on a synthetic, defender-authored corpus,
so "mitigated" means "stopped in our tests", not "proven".

| # | Threat | Result | What changed from the plan |
|---|---|---|---|
| S1 | Stolen user token | Partly mitigated | Revocation and short life work. Tokens are not sender-constrained, so reuse from a new device is only a risk signal. |
| S2 | Agent credential used directly | Mitigated | 1 scenario, rejected as `agent_credential_not_accepted`. |
| S3 | Forged token, `alg=none`, untrusted issuer | Mitigated | 4 scenarios plus unit tests. |
| S4 | Service token replay | Mitigated | Certificate binding implemented; tested at unit level only (no real mTLS terminator). |
| T2 | Policy tampering | Partly mitigated | Policies tested in CI; no signed policy bundles. |
| T3 | Log tampering | Mitigated for detection | Hash chain detects edits and is verified in tests. It does not prevent deletion of a whole tail. Anchoring the head hash externally is open. |
| R1 | Repudiated approval | Mitigated | Approver identity and acr stored; requester cannot approve; approval bound to the arguments and single use. |
| D1 | Request floods | Partly mitigated | Burst signal feeds risk. No hard rate limit. |
| E1 | Role confusion | Mitigated | Authorization alone stopped all 30 confused-deputy and privilege scenarios. |
| E2 | Agent exceeds its user | Mitigated | Intersection invariant checked in tests and on the attack-path graph. |
| E3 | Self-approval | Mitigated | All 8 approval-bypass scenarios stopped (self-approval, non-manager, replay, mutated arguments, no passkey). |
| A1 | Indirect prompt injection | **Partly mitigated** | Heuristic detector caught 57.5% of poisoned outputs, classifier 75%, and both false-block benign security text (8.2% and 5.0% of benign tasks). Detection alone is not trustworthy. |
| A2 | Confused deputy | Mitigated | 12 scenarios, all denied on the user side. |
| A3 | Over-privilege | Detected, not prevented | Analytics found unused agent scopes and generated reductions. Applying them is a manual step. |
| A4 | Exfiltration | **Partly mitigated** | Taint blocked 12 of 15 exfil attacks that authorization alone allowed. Reversed, split and paraphrased values evade it. Approval for agent-originated external sends and risk scoring covered those in the corpus. |
| A5 | Tool-sequence abuse | Partly mitigated | Only the read-then-outbound sequence is modelled. |
| A6 | Agent token theft | Partly mitigated | 5 minute life and revocation; see S1. |

### New risks found during the build

- **Defence overlap hides weak layers.** End-to-end attack success was 0 for both v1 and v2, but the isolated tests show the injection detector alone misses 7 (heuristic) or 1 (classifier) of 24 attacks that authorization lets through. A single layer failing is invisible in the headline number.
- **Quarantine is a denial of service on content.** Every false positive withholds a legitimate document from an agent.
- **Hash-chain tail truncation** (above).
- **Simulated victim agent.** Real LLMs may ignore injections the scripted agent obeys, or comply with ones it never sees.
- **Replay fidelity.** Policy replay approximates context (device, risk) that the log does not store in full.

### Residual risks accepted

Novel injection phrasing and non-text payloads, paraphrased exfiltration, device attestation fidelity, key management (keys live in process memory in this build), multi-tenant isolation.
