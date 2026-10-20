"""Generate a realistic month of Acme traffic through Warden to analyse.

Writes a DuckDB file with the `decisions` table, plus a `grants` table describing
what each identity was *granted* (for granted-vs-used analysis).

    python -m analytics.sim data/warden.duckdb
"""
from __future__ import annotations

import random
import sys
import time

import duckdb

from warden import acme
from warden.engine import Warden
from eval.harness import NOON

DAY = 86400


def simulate(path: str, days: int = 30, seed: int = 5) -> Warden:
    rng = random.Random(seed)
    w = Warden(version="v1", db_path=path)
    start = NOON - days * DAY
    habits = {   # what people actually do day to day (a subset of what RBAC lets them do)
        "alice": [("tickets:read", {"id": "T-100"}), ("tickets:update", {"id": "T-101", "body": "wip"}), ("docs:read", {"id": "eng-runbook"})],
        "bob": [("tickets:read", {"id": "T-102"}), ("docs:read", {"id": "eng-runbook"})],
        "carol": [("hr:read_record", {"user": "alice"}), ("hr:read_record", {"user": "bob"})],
        "dave": [("hr:read_record", {"user": "carol"})],
        "erin": [("finance:read_report", {"id": "q3-revenue"})],
        "frank": [("finance:read_report", {"id": "q3-revenue"})],
        "grace": [("tickets:read", {"id": "T-100"}), ("hr:read_record", {"user": "alice"})],
        "heidi": [("hr:read_record", {"user": "carol"})],
        "ivan": [("finance:read_report", {"id": "payroll-summary"})],
        "judy": [("docs:read", {"id": "roadmap"})],
    }
    for d in range(days):
        day = start + d * DAY
        for u, acts in habits.items():
            if rng.random() < 0.15:      # weekends / out of office
                continue
            tok = w.idp.user_token(u, passkey=True)
            for k in range(rng.randint(2, 6)):
                a, args = rng.choice(acts)
                w.handle(tok, a, args, now=day + k * 600 + rng.randint(0, 300))
        # the support agent works tickets for alice every day; it never touches HR even though it can
        tok = _agent(w, "alice", "support-agent", "tickets:read tickets:create tickets:update docs:read hr:read_record")
        for k in range(rng.randint(3, 8)):
            if rng.random() < 0.7:
                w.handle(tok, "tickets:read", {"id": rng.choice(["T-100", "T-101", "T-102"])}, now=day + 3600 + k * 120)
            else:
                w.handle(tok, "docs:read", {"id": "eng-runbook"}, now=day + 3600 + k * 120)
        tok = _agent(w, "carol", "hr-assistant", "hr:read_record docs:read comms:send_email")
        for k in range(rng.randint(1, 3)):
            w.handle(tok, "hr:read_record", {"user": rng.choice(["alice", "bob", "dave"])}, now=day + 7200 + k * 200)
        if d >= days - 8:      # carol starts using tickets late: a rare-but-legitimate change in behaviour
            w.handle(w.idp.user_token("carol", passkey=True), "tickets:read", {"id": "T-102"}, now=day + 4000)
        # research-agent went dormant after day 8
        if d < 8:
            tok = _agent(w, "grace", "research-agent", "docs:read tickets:read")
            w.handle(tok, "docs:read", {"id": "handbook"}, now=day + 9000)
        for svc, secret in (("ticket-sync-svc", "sync-dev-secret"), ("billing-svc", "billing-dev-secret")):
            t = w.idp.service_token(svc, secret)
            w.handle(t, "tickets:read" if svc.startswith("ticket") else "finance:read_report",
                     {"id": "T-100"} if svc.startswith("ticket") else {"id": "q3-revenue"}, now=day + 5000)
    # two anomalies near the end: a burst of HR scraping at night by bob's account, and probing
    tok = w.idp.user_token("bob", device_id="unknown-device-3")
    for k in range(40):
        w.handle(tok, "hr:read_record", {"user": rng.choice(list(acme.USERS))}, now=NOON - 3 * DAY + 11 * 3600 + k)
    w.log.con.execute("CREATE TABLE IF NOT EXISTS grants (identity VARCHAR, kind VARCHAR, action VARCHAR, via VARCHAR)")
    rows = []
    for u in acme.USERS:
        for a in sorted(acme.effective_user_actions(u)):
            rows.append((u, "user", a, "role"))
    for s, m in acme.SERVICES.items():
        rows += [(s, "service", a, "scope") for a in m["scopes"]]
    for ag, m in acme.AGENTS.items():
        rows += [(ag, "agent", a, "scope") for a in m["scopes"]]
    w.log.con.executemany("INSERT INTO grants VALUES (?,?,?,?)", rows)
    return w


def _agent(w, user, agent, scope):
    sub = w.idp.user_token(user, passkey=True)
    act = w.idp.agent_client_token(agent, acme.AGENTS[agent]["secret"])
    return w.sts.exchange(subject_token=sub, actor_token=act, scope=scope)["access_token"]


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/warden.duckdb"
    w = simulate(out)
    n = w.log.con.execute("select count(*) from decisions").fetchone()[0]
    print(f"wrote {n} decisions to {out}")
