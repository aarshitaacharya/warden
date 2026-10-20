# Access analytics report

Source: 1408 decisions from `analytics.sim` (30 simulated days). Proposal learned from the first 70% (20 days) and replayed on the remaining days.

## Granted vs used

| identity | kind | granted | used | pct_used |
|---|---|---|---|---|
| grace | user | 8 | 1 | 12.5 |
| heidi | user | 7 | 1 | 14.3 |
| ivan | user | 7 | 1 | 14.3 |
| dave | user | 6 | 1 | 16.7 |
| erin | user | 5 | 1 | 20.0 |
| frank | user | 5 | 1 | 20.0 |
| judy | user | 5 | 1 | 20.0 |
| agent:hr-assistant | agent | 4 | 1 | 25.0 |
| agent:research-agent | agent | 4 | 1 | 25.0 |
| bob | user | 7 | 2 | 28.6 |
| carol | user | 6 | 2 | 33.3 |
| agent:support-agent | agent | 5 | 2 | 40.0 |
| alice | user | 7 | 3 | 42.9 |
| billing-svc | service | 2 | 1 | 50.0 |
| ticket-sync-svc | service | 2 | 1 | 50.0 |

## Dormant identities (idle 14 days or more)

| identity | total_requests | days_idle |
|---|---|---|
| agent:research-agent | 8 | 22.0 |

## Role actions nobody used

Actions granted through roles that no holder exercised in the whole window.

| action | holders | users_who_used |
|---|---|---|
| comms:http_post | 3 | 0 |
| comms:send_email | 10 | 0 |
| docs:write | 3 | 0 |
| finance:create_payment | 3 | 0 |
| hr:update_record | 3 | 0 |
| tickets:create | 10 | 0 |
| tickets:delete | 4 | 0 |

## Anomalies

Daily volume more than 3 standard deviations above the identity's own baseline, or 10 or more denials in a day.

| identity | day | n | denies | z |
|---|---|---|---|---|
| bob | 2026-02-28 | 46 | 40 | 5.1 |

### Identities seen on a second, low-volume device

| identity | device_id | requests |
|---|---|---|
| bob | unknown-device-3 | 40 |

## Least-privilege proposal

```diff
--- a/policies/cedar/rbac.cedar
+++ b/policies/cedar/rbac.cedar
@@ -2,25 +2,25 @@
 
 @id("rbac-employee")
 permit(principal in Role::"employee",
-       action in [Action::"tickets:create", Action::"docs:read", Action::"comms:send_email"],
+       action in [Action::"docs:read"],
        resource);
 
 @id("rbac-engineer")
 permit(principal in Role::"engineer",
-       action in [Action::"tickets:read", Action::"tickets:update", Action::"docs:write", Action::"comms:http_post"],
+       action in [Action::"tickets:read", Action::"tickets:update"],
        resource);
 
 @id("rbac-hr")
 permit(principal in Role::"hr",
-       action in [Action::"hr:read_record", Action::"hr:update_record", Action::"tickets:read"],
+       action in [Action::"hr:read_record"],
        resource);
 
 @id("rbac-finance")
 permit(principal in Role::"finance",
-       action in [Action::"finance:read_report", Action::"finance:create_payment"],
+       action in [Action::"finance:read_report"],
        resource);
 
 @id("rbac-manager")
 permit(principal in Role::"manager",
-       action in [Action::"tickets:read", Action::"tickets:delete"],
+       action in [Action::"tickets:read"],
        resource);
--- a/agent-scopes.json
+++ b/agent-scopes.json
@@ -1,21 +1,12 @@
 {
   "support-agent": [
     "docs:read",
-    "hr:read_record",
-    "tickets:create",
-    "tickets:read",
-    "tickets:update"
+    "tickets:read"
   ],
   "hr-assistant": [
-    "comms:send_email",
-    "docs:read",
-    "hr:read_record",
-    "tickets:create"
+    "hr:read_record"
   ],
   "research-agent": [
-    "comms:http_post",
-    "comms:send_email",
-    "docs:read",
-    "tickets:read"
+    "docs:read"
   ]
 }
--- a/service-scopes.json
+++ b/service-scopes.json
@@ -1,10 +1,8 @@
 {
   "billing-svc": [
-    "finance:create_payment",
     "finance:read_report"
   ],
   "ticket-sync-svc": [
-    "tickets:read",
-    "tickets:update"
+    "tickets:read"
   ]
 }
```

## Validation by replay

Baseline fidelity: replaying 441 held-out requests against the **current** policy reproduces history with 0 mismatches (this checks the replay itself).

Proposed policy: **8 of 441** held-out requests would have broken.

| identity | action | requests |
|---|---|---|
| carol | tickets:read | 8 |

These are legitimate behaviours that began after the learning window. Reviewing this list before rollout is the point: ship with the missing grants added back, or accept the break.

## Attack paths

- Identities with a path to restricted data (sensitivity 3): **61** now, **45** after the proposal.
- Intersection invariant (an agent never reaches data its user cannot): **holds**.
- Agent instances that can read sensitive data and send it outside: **20** now, **0** after the proposal.

| agent | acting for | can reach |
|---|---|---|
| hr-assistant | alice | board_deck, roadmap |
| research-agent | alice | board_deck, roadmap |
| hr-assistant | bob | board_deck, roadmap |
| research-agent | bob | board_deck, roadmap |
| hr-assistant | carol | board_deck, hr_records, roadmap |
| research-agent | carol | board_deck, roadmap |
| hr-assistant | dave | board_deck, hr_records, roadmap |
| research-agent | dave | board_deck, roadmap |
| hr-assistant | erin | board_deck, roadmap |
| research-agent | erin | board_deck, roadmap |
| hr-assistant | frank | board_deck, roadmap |
| research-agent | frank | board_deck, roadmap |

_(first 12 shown)_
