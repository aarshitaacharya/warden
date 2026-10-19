"""Structured, hash-chained decision log stored in DuckDB."""
from __future__ import annotations

import hashlib
import json
import threading

import duckdb

COLUMNS = [
    ("ts", "DOUBLE"), ("request_id", "VARCHAR"), ("session_id", "VARCHAR"), ("policy_version", "VARCHAR"),
    ("principal_kind", "VARCHAR"), ("principal_user", "VARCHAR"), ("agent_id", "VARCHAR"), ("token_jti", "VARCHAR"),
    ("action", "VARCHAR"), ("resource", "VARCHAR"), ("sensitivity", "INTEGER"),
    ("decision", "VARCHAR"), ("status", "INTEGER"), ("deciding_policies", "VARCHAR"),
    ("user_decision", "VARCHAR"), ("agent_decision", "VARCHAR"), ("risk_score", "DOUBLE"),
    ("risk_signals", "VARCHAR"), ("guardrails", "VARCHAR"), ("reason", "VARCHAR"),
    ("device_id", "VARCHAR"), ("latency_ms", "DOUBLE"),
    ("prev_hash", "VARCHAR"), ("row_hash", "VARCHAR"),
]
NAMES = [c for c, _ in COLUMNS]


class DecisionLog:
    def __init__(self, path: str = ":memory:"):
        self.con = duckdb.connect(path)
        self.lock = threading.Lock()
        self.con.execute("CREATE TABLE IF NOT EXISTS decisions (" + ", ".join(f"{c} {t}" for c, t in COLUMNS) + ")")
        row = self.con.execute("SELECT row_hash FROM decisions ORDER BY ts DESC, rowid DESC LIMIT 1").fetchone()
        self._last = row[0] if row else "genesis"

    def write(self, rec: dict) -> dict:
        rec = {k: rec.get(k) for k in NAMES if k not in ("prev_hash", "row_hash")}
        for k in ("deciding_policies", "risk_signals", "guardrails"):
            if not isinstance(rec.get(k), (str, type(None))):
                rec[k] = json.dumps(rec[k], sort_keys=True)
        with self.lock:
            rec["prev_hash"] = self._last
            body = json.dumps(rec, sort_keys=True, default=str)
            rec["row_hash"] = hashlib.sha256(body.encode()).hexdigest()
            self.con.execute(f"INSERT INTO decisions VALUES ({','.join('?' * len(NAMES))})", [rec[k] for k in NAMES])
            self._last = rec["row_hash"]
        return rec

    def rows(self, where: str = "", params: list | None = None) -> list[dict]:
        cur = self.con.execute("SELECT * FROM decisions " + (f"WHERE {where} " if where else "") + "ORDER BY ts, rowid", params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def verify_chain(self) -> bool:
        prev = "genesis"
        for r in self.rows():
            claimed = r.pop("row_hash")
            if r["prev_hash"] != prev:
                return False
            if hashlib.sha256(json.dumps(r, sort_keys=True, default=str).encode()).hexdigest() != claimed:
                return False
            prev = claimed
        return True
