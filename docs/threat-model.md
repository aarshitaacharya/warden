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

## 5. Re-assessment (to be completed in Phase 6)

Filled in after the build: what changed against the plan, what the measurements
showed, and which risks remain open.
