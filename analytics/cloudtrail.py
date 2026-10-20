"""Real-world scale: load the public flaws.cloud CloudTrail dataset into DuckDB and run
the same least-privilege and anomaly analysis on it.

    scripts/fetch_flaws.sh && python -m analytics.cloudtrail
"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "data/raw/flaws/extracted/flaws_cloudtrail_logs"
DB = ROOT / "data/cloudtrail.duckdb"


def load(con):
    """Load one file at a time to keep memory flat."""
    con.execute("SET preserve_insertion_order=false")
    con.execute("""CREATE OR REPLACE TABLE cloudtrail (ts TIMESTAMP, source VARCHAR, event VARCHAR, id_type VARCHAR,
                   principal VARCHAR, access_key VARCHAR, ip VARCHAR, ua VARCHAR, error VARCHAR, region VARCHAR)""")
    for f in sorted(SRC.glob("*.json.gz")):
        con.execute(f"""
            INSERT INTO cloudtrail
            SELECT CAST(json_extract_string(r, '$.eventTime') AS TIMESTAMP), json_extract_string(r, '$.eventSource'),
                   json_extract_string(r, '$.eventName'), json_extract_string(r, '$.userIdentity.type'),
                   coalesce(json_extract_string(r, '$.userIdentity.arn'), json_extract_string(r, '$.userIdentity.principalId'), 'unknown'),
                   json_extract_string(r, '$.userIdentity.accessKeyId'), json_extract_string(r, '$.sourceIPAddress'),
                   json_extract_string(r, '$.userAgent'), json_extract_string(r, '$.errorCode'), json_extract_string(r, '$.awsRegion')
            FROM (SELECT unnest(Records) AS r FROM read_json('{f}', maximum_object_size=268435456, columns={{Records: 'JSON[]'}}))
        """)


def tbl(rows, cols):
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def main():
    if not SRC.exists():
        raise SystemExit("run scripts/fetch_flaws.sh first")
    import sys
    if "--reload" in sys.argv:
        DB.unlink(missing_ok=True)
    con = duckdb.connect(str(DB))
    if not con.execute("select count(*) from information_schema.tables where table_name='cloudtrail'").fetchone()[0]:
        load(con)
    n, t0, t1, p = con.execute("select count(*), min(ts), max(ts), count(distinct principal) from cloudtrail").fetchone()
    L = ["# CloudTrail analysis (flaws.cloud public dataset)\n",
         f"{n:,} events, {t0} to {t1}, {p:,} distinct principals. Loaded by `python -m analytics.cloudtrail`.\n",
         "> Caveat: flaws.cloud is a security CTF, so most of this traffic is players enumerating the API with leaked keys. "
         "It is a good scale and anomaly test, but 'observed usage' here is attacker behaviour, not a healthy baseline. "
         "A least-privilege policy built from it would freeze that behaviour in.\n"]

    L += ["## Who calls the API\n", tbl(con.execute("""select id_type, count(*) n, count(distinct principal) principals
                 from cloudtrail group by 1 order by n desc""").fetchall(), ["identity type", "events", "principals"])]

    L += ["## Granted vs used: distinct actions per principal\n",
          "Observed usage is the only half we have here (CloudTrail does not show what a principal was *allowed* to do). "
          "Actions are `service:Event`; a least-privilege policy for a principal is exactly this set.\n",
          tbl(con.execute("""select principal, count(*) events, count(distinct source || ':' || event) distinct_actions,
                 count(distinct ip) ips from cloudtrail group by 1 order by events desc limit 10""").fetchall(),
              ["principal", "events", "distinct actions", "source IPs"])]

    L += ["## Probable reconnaissance: principals with high denial rates\n",
          tbl(con.execute("""select principal, count(*) events,
                 count(*) filter (where error ilike '%denied%' or error ilike '%unauthorized%') denied,
                 round(100.0 * count(*) filter (where error ilike '%denied%' or error ilike '%unauthorized%') / count(*), 1) pct
                 from cloudtrail group by 1 having count(*) >= 20 order by pct desc, events desc limit 10""").fetchall(),
              ["principal", "events", "denied", "% denied"])]

    L += ["## Daily volume spikes (z-score >= 3 against the principal's own days)\n",
          tbl(con.execute("""with d as (select principal, cast(ts as date) as day, count(*) n from cloudtrail group by 1, 2),
                 s as (select principal, avg(n) mu, stddev_pop(n) sd, count(*) as ndays from d group by 1)
                 select d.principal, d.day, d.n, round((d.n - s.mu) / s.sd, 1) z from d join s using (principal)
                 where s.ndays >= 3 and s.sd > 0 and (d.n - s.mu) / s.sd >= 3 order by z desc limit 10""").fetchall(),
              ["principal", "day", "events", "z"])]

    L += ["## Clients (user agent family)\n",
          tbl(con.execute("""select ua, count(*) n, count(distinct principal) principals from cloudtrail
                 group by 1 order by n asc limit 0""").fetchall(), ["ua", "events", "principals"]) if False else "",
          tbl(con.execute("""select regexp_extract(ua, '^[^ /]+', 0) client, count(*) n, count(distinct principal) principals
                 from cloudtrail group by 1 order by n desc limit 8""").fetchall(), ["client", "events", "principals"])]

    # Generate a least-privilege policy for the busiest IAM principal and report the reduction.
    top = con.execute("""select principal from cloudtrail where principal like 'arn:aws:%' group by 1
                         order by count(*) desc limit 1""").fetchone()
    if top:
        acts = sorted(r[0] for r in con.execute("""select distinct replace(source, '.amazonaws.com', '') || ':' || event
                         from cloudtrail where principal = ?""", [top[0]]).fetchall())
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": acts, "Resource": "*"}]}
        out = ROOT / "analytics/out/cloudtrail_least_privilege.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps({"principal": top[0], "policy": policy}, indent=2))
        L += [f"## Generated least-privilege policy\n",
              f"For `{top[0]}`: {len(acts)} distinct actions observed. Policy written to `{out.relative_to(ROOT)}`. "
              "Replay check: every event this principal made is covered by construction; the real validation is "
              "holding out a later time slice, as done for Warden's own logs in `analytics/report.md`.\n"]
        cut = con.execute("select min(ts) + 0.7 * (max(ts) - min(ts)) from cloudtrail where principal = ?", [top[0]]).fetchone()[0]
        learned = {r[0] for r in con.execute("""select distinct replace(source, '.amazonaws.com', '') || ':' || event
                         from cloudtrail where principal = ? and ts < ?""", [top[0], cut]).fetchall()}
        late = con.execute("""select replace(source, '.amazonaws.com', '') || ':' || event, count(*) from cloudtrail
                         where principal = ? and ts >= ? group by 1""", [top[0], cut]).fetchall()
        broken = [(a, c) for a, c in late if a not in learned]
        L += [f"Holdout replay (learn on first 70% of this principal's time span, replay the rest): "
              f"{sum(c for _, c in broken)} of {sum(c for _, c in late)} later events would have been denied "
              f"({len(broken)} distinct actions).\n"]
    (ROOT / "analytics/cloudtrail_report.md").write_text("\n".join(x for x in L if x))
    print(f"{n:,} events loaded")


if __name__ == "__main__":
    main()
