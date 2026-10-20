# Postmortem: compromised hr-assistant attempts HR data exfiltration

Type: simulated incident (`python -m incident.simulate`, raw timeline in `incident/timeline.json`).
Severity if it had succeeded: high (SSNs and salaries for six employees).
Outcome: **no data left the company**. Six HR records were read by the attacker. The agent was revoked and its scopes reduced.

Timings are on the simulation clock. Detection and response delays are stated assumptions, not measurements of a real team.

## Summary

A delegated token for `hr-assistant` (acting for carol, an HR user) was stolen and used from a device carol had never used. The attacker read six HR records, then tried five ways to send the data to an external address and probed four actions outside the agent's scope. Taint tracking blocked the two exfiltration attempts that contained recorded values verbatim. Accumulated risk blocked the two that evaded fingerprint matching. A fifth was stopped by the agent's scope. Detection rules fired 90 seconds after the attack began; a manager revoked the agent 120 seconds after that.

## Timeline

| T+ (s) | Event |
|---|---|
| 60 | Baseline: hr-assistant reads two HR records for carol |
| 3600 | Attack starts: stolen token used from unknown device `vps-185` |
| 3600-3625 | Attacker reads six HR records (allowed: within the agent's scope and carol's rights) |
| 3640 | Email with a record in the body: **denied**, `guardrail:exfil_blocked` (taint) |
| 3644 | HTTP post to a collector: **denied**, agent has no `comms:http_post` scope |
| 3648 | SSN in the subject line: **denied**, `guardrail:exfil_blocked` |
| 3652 | SSN split in half: **denied**, `abac-risk-deny` (risk score reached 80) |
| 3656 | SSN reversed: **denied**, `abac-risk-deny` |
| 3670-3679 | Probes for payment, delete and update: all denied (default deny, `agent-no-destructive`) |
| 3690 | Detections DET-001 (high), DET-003, DET-004 (medium) raised |
| 3795 | `hr-assistant` revoked by a manager with passkey step-up |
| 3800 | Stolen token returns `401 agent_revoked` |
| 3800 | `comms:*` removed from hr-assistant's maximum scopes |
| 4400 | Fresh delegated token: reads work, external-capable email is no longer in scope |

## What worked

- **Intersection rule.** The stolen token could only do what both the agent and carol could do. The attacker got HR reads and nothing else.
- **Taint tracking** caught both verbatim exfiltration attempts, and recognised a single field value even when buried in a different message.
- **Risk scoring caught what taint missed.** Splitting and reversing a value defeat fingerprint matching. By then the session had a new device (+25), a sensitive read followed by outbound (+35) and repeated denials, and the score hit the deny threshold. This was not planned as a design goal; it came out of the simulation.
- **Hash-chained decision log** stayed intact (`verify_chain` true), so the timeline above can be trusted.

## What did not work

1. **The attacker read six records before anything fired.** Reading is allowed and the new-device signal alone (25) is below the step-up threshold. Nothing alerted until the exfiltration attempts began.
2. **Detection is batch.** The assumed 30 second rule cadence means 90 seconds from first malicious call to alert. An exfiltration that evaded taint and approvals would have had that long.
3. **Revocation is blunt.** Revoking `hr-assistant` also invalidated carol's legitimate session, because revocation is by agent, not by token family. Acceptable during an incident, painful otherwise.
4. **Delegated tokens were stealable at all.** A bearer token valid for five minutes was reused from another device. The device claim fed risk but was not bound to the token.
5. **hr-assistant held `comms:send_email` it did not need for this work.** Phase 5's analytics had already flagged the scope as unused in simulated traffic.

## Contributing factors

- Over-provisioned agent scope (item 5).
- No sender-constrained tokens (item 4).
- Risk thresholds treat a new device as a weak signal even when it appears together with a restricted-data read.

## Actions

| Action | Owner | Status |
|---|---|---|
| Revoke agent, verify stolen token rejected | on-call | done in simulation |
| Remove `comms:*` from hr-assistant | security | done in simulation |
| Alert on new device + restricted read (not only on outbound) | detection | open |
| Revoke by token family instead of whole agent | engineering | open |
| Bind delegated tokens to the caller's device (DPoP or mTLS `cnf`) | engineering | open |
| Run detections as a streaming check on write | engineering | open |

## Lessons

1. Defence in depth was real: three independent controls (taint, risk, scope) each stopped part of the attack, and no single one stopped all of it.
2. A control that is easy to evade on its own (fingerprint matching) is still worth having when others cover its gaps, but the postmortem should say which ones, and this one does.
3. Containment speed is dominated by human response time. Everything before that point was automatic.
