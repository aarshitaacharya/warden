"""Detection rules over the decision log. Each rule is a SQL query returning offending rows."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Rule:
    id: str
    severity: str
    description: str
    sql: str            # must select: identity, evidence
    contain: str        # recommended containment


IDENT = "CASE WHEN agent_id IS NOT NULL THEN 'agent:' || agent_id ELSE principal_user END"

RULES = [
    Rule("DET-001", "high", "Exfiltration attempt blocked by taint tracking",
         f"SELECT {IDENT} AS identity, count(*) || ' blocked outbound sends' AS evidence FROM decisions "
         "WHERE reason LIKE 'guardrail:exfil_blocked%' GROUP BY 1",
         "revoke the agent, review the session"),
    Rule("DET-002", "high", "Prompt injection followed by a denied or blocked action in the same identity window",
         f"SELECT {IDENT} AS identity, 'injection quarantined then ' || count(*) || ' blocked calls' AS evidence "
         "FROM decisions d WHERE d.decision = 'deny' AND d.agent_id IS NOT NULL AND EXISTS ("
         "  SELECT 1 FROM decisions i WHERE i.agent_id = d.agent_id AND i.principal_user = d.principal_user "
         "  AND i.reason LIKE 'output_quarantined%' AND i.ts <= d.ts AND d.ts - i.ts < 600) GROUP BY 1",
         "revoke the agent token, tighten scopes"),
    Rule("DET-003", "medium", "Agent denied 5 or more times in 5 minutes (probing its own permissions)",
         f"SELECT {IDENT} AS identity, count(*) || ' denials in 5 min' AS evidence FROM decisions "
         "WHERE decision = 'deny' AND agent_id IS NOT NULL GROUP BY 1, cast(ts / 300 AS BIGINT) HAVING count(*) >= 5",
         "investigate; consider revoking"),
    Rule("DET-004", "medium", "Sensitive read followed by an outbound call within 10 minutes",
         "SELECT CASE WHEN o.agent_id IS NOT NULL THEN 'agent:' || o.agent_id ELSE o.principal_user END AS identity, 'read restricted data then ' || o.action || ' (' || count(*) || ' pairs)' AS evidence FROM decisions r JOIN decisions o "
         "ON r.principal_user = o.principal_user AND coalesce(r.agent_id, '') = coalesce(o.agent_id, '') "
         "WHERE r.decision = 'allow' AND r.sensitivity >= 3 AND o.action LIKE 'comms:%' "
         "AND o.ts > r.ts AND o.ts - r.ts < 600 GROUP BY o.agent_id, o.principal_user, o.action",
         "review the payload"),
    Rule("DET-005", "medium", "User touching many distinct HR records in a day",
         "SELECT principal_user AS identity, count(DISTINCT resource) || ' HR records' AS evidence FROM decisions "
         "WHERE action = 'hr:read_record' AND decision = 'allow' AND agent_id IS NULL "
         "GROUP BY principal_user, cast(ts / 86400 AS BIGINT) HAVING count(DISTINCT resource) >= 8",
         "confirm business need; step-up"),
    Rule("DET-006", "low", "Approval requested for a high-risk action",
         f"SELECT {IDENT} AS identity, action || ' pending approval' AS evidence FROM decisions WHERE decision = 'pending_approval'",
         "approver reviews"),
    Rule("DET-007", "high", "Authentication failures that look like token replay or forgery",
         "SELECT 'unauthenticated' AS identity, reason AS evidence FROM decisions WHERE status = 401 AND reason NOT LIKE '%token_expired%' "
         "AND reason NOT LIKE 'risk:%' GROUP BY reason",
         "check issuer keys; rotate if forged tokens were accepted"),
]


def evaluate(log) -> list[dict]:
    """Run every rule against the DuckDB decision log. Returns alerts."""
    alerts = []
    for r in RULES:
        try:
            rows = log.con.execute(r.sql).fetchall()
        except Exception as e:      # a broken rule must not stop the others
            alerts.append({"rule": r.id, "severity": "error", "identity": "-", "evidence": str(e), "contain": ""})
            continue
        for ident, ev in rows:
            alerts.append({"rule": r.id, "severity": r.severity, "identity": ident, "evidence": ev,
                           "description": r.description, "contain": r.contain})
    return alerts
