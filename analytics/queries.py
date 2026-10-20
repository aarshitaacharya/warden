"""SQL over Warden's decision log: usage, dormancy, anomalies."""
from __future__ import annotations

import duckdb

# One row per identity key. Users are `alice`; agents are `agent:support-agent`; services keep their name.
IDENT = """CASE WHEN agent_id IS NOT NULL THEN 'agent:' || agent_id
                WHEN principal_kind = 'service' THEN principal_user
                ELSE principal_user END"""

GRANTED_VS_USED = f"""
WITH used AS (
  SELECT {IDENT} AS identity, action, count(*) AS n, max(ts) AS last_ts
  FROM decisions WHERE decision = 'allow' AND status = 200 GROUP BY 1, 2
), g AS (
  SELECT CASE WHEN kind = 'agent' THEN 'agent:' || identity ELSE identity END AS identity, kind, action
  FROM grants
)
SELECT g.identity, g.kind, g.action, coalesce(used.n, 0) AS uses, used.last_ts
FROM g LEFT JOIN used USING (identity, action)
ORDER BY g.identity, g.action
"""

UTILISATION = f"""
WITH r AS ({GRANTED_VS_USED})
SELECT identity, kind, count(*) AS granted, count(*) FILTER (WHERE uses > 0) AS used,
       round(100.0 * count(*) FILTER (WHERE uses > 0) / count(*), 1) AS pct_used
FROM r GROUP BY 1, 2 ORDER BY pct_used, identity
"""

DORMANT = f"""
WITH last AS (SELECT {IDENT} AS identity, max(ts) AS last_ts, count(*) AS n FROM decisions GROUP BY 1),
     now_ AS (SELECT max(ts) AS t FROM decisions)
SELECT identity, n AS total_requests, round((now_.t - last_ts) / 86400, 1) AS days_idle
FROM last, now_ WHERE (now_.t - last_ts) / 86400 >= ? ORDER BY days_idle DESC
"""

# Roles whose members never exercise a given action within the window.
UNUSED_ROLE_ACTIONS = """
SELECT g.action, count(DISTINCT g.identity) AS holders,
       count(DISTINCT u.identity) AS users_who_used
FROM grants g
LEFT JOIN (SELECT principal_user AS identity, action FROM decisions
           WHERE decision = 'allow' AND status = 200 AND agent_id IS NULL) u
  ON u.identity = g.identity AND u.action = g.action
WHERE g.kind = 'user' GROUP BY g.action HAVING count(DISTINCT u.identity) = 0 ORDER BY g.action
"""

# Daily volume per identity vs its own baseline (z-score), and off-hours/new-device/denial signals.
ANOMALIES = f"""
WITH daily AS (
  SELECT {IDENT} AS identity, CAST(to_timestamp(ts) AS DATE) AS day, count(*) AS n,
         count(*) FILTER (WHERE decision = 'deny') AS denies,
         count(DISTINCT device_id) AS devices
  FROM decisions GROUP BY 1, 2
), stats AS (
  SELECT identity, avg(n) AS mu, stddev_pop(n) AS sd FROM daily GROUP BY 1
)
SELECT d.identity, d.day, d.n, d.denies, round((d.n - s.mu) / nullif(s.sd, 0), 1) AS z
FROM daily d JOIN stats s USING (identity)
WHERE (d.n - s.mu) / nullif(s.sd, 0) >= 3 OR d.denies >= 10
ORDER BY z DESC NULLS LAST
"""

NEW_DEVICES = f"""
WITH first_seen AS (
  SELECT {IDENT} AS identity, device_id, min(ts) AS first_ts, count(*) AS n
  FROM decisions WHERE device_id IS NOT NULL GROUP BY 1, 2
), counts AS (SELECT identity, count(*) AS k FROM first_seen GROUP BY 1)
SELECT f.identity, f.device_id, f.n AS requests FROM first_seen f JOIN counts c USING (identity)
WHERE c.k > 1 AND f.n < 100 ORDER BY f.n DESC
"""

def run(con: duckdb.DuckDBPyConnection, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]
