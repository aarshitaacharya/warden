"""FastAPI front door."""
from __future__ import annotations

import os

from fastapi import FastAPI, Form, Header, HTTPException
from pydantic import BaseModel, Field

from . import identity
from .engine import Warden

app = FastAPI(title="Warden gateway", version="0.1.0")
warden = Warden(version=os.environ.get("WARDEN_POLICY_VERSION", "v1"),
                db_path=os.environ.get("WARDEN_DB", ":memory:"))

if os.environ.get("WARDEN_KEYCLOAK_JWKS"):
    import httpx
    jwks = httpx.get(os.environ["WARDEN_KEYCLOAK_JWKS"], timeout=10).json()
    warden.verifier.trust_jwks(os.environ["WARDEN_KEYCLOAK_ISSUER"], jwks)


class ToolCall(BaseModel):
    args: dict = Field(default_factory=dict)


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    return authorization.split(" ", 1)[1].strip()


@app.get("/healthz")
def healthz():
    return {"ok": True, "policy_version": warden.version}


@app.post("/v1/tools/{action}")
def call_tool(action: str, body: ToolCall, authorization: str | None = Header(None),
              x_warden_session: str | None = Header(None),
              x_client_cert_sha256: str | None = Header(None),
              x_approval_id: str | None = Header(None)):
    r = warden.handle(_bearer(authorization), action, body.args, session_id=x_warden_session,
                      cert_thumbprint=x_client_cert_sha256, approval_id=x_approval_id)
    payload = {"request_id": r.request_id, "decision": r.decision, "reason": r.reason}
    if r.data is not None:
        payload["data"] = r.data
    if r.approval_id:
        payload["approval_id"] = r.approval_id
    from fastapi.responses import JSONResponse
    return JSONResponse(payload, status_code=r.status)


@app.post("/sts/exchange")
def exchange(grant_type: str = Form(...), subject_token: str = Form(...), actor_token: str = Form(...),
             scope: str = Form("")):
    """RFC 8693 token exchange."""
    try:
        return warden.sts.exchange(subject_token=subject_token, actor_token=actor_token,
                                   scope=scope, grant_type=grant_type)
    except identity.AuthError as e:
        raise HTTPException(400, {"error": e.code, "error_description": e.detail})


@app.post("/admin/revoke")
def revoke(kind: str, value: str, authorization: str | None = Header(None)):
    """Contain an incident: revoke a token (jti), a user, or an agent."""
    caller = warden.verifier.decode(_bearer(authorization))
    if caller.kind != "user" or "manager" not in caller.roles or not caller.stepped_up:
        raise HTTPException(403, "revocation requires a manager with passkey step-up")
    rl = warden.verifier.revocations
    {"token": rl.revoke_token, "user": rl.revoke_user, "agent": rl.revoke_agent}[kind](value)
    return {"revoked": {kind: value}}


@app.post("/v1/approvals/{approval_id}/{verdict}")
def decide(approval_id: str, verdict: str, authorization: str | None = Header(None)):
    if verdict not in ("approve", "reject"):
        raise HTTPException(404)
    try:
        out = warden.decide_approval(approval_id, _bearer(authorization), verdict == "approve")
    except identity.AuthError as e:
        raise HTTPException(401, e.code)
    if not out["ok"]:
        raise HTTPException(403, out["error"])
    return out


# ---- demo dashboard ---------------------------------------------------------
@app.get("/dashboard/data")
def dashboard_data():
    import json
    from pathlib import Path
    rows = warden.log.rows()[-40:]
    by = warden.log.con.execute("select decision, count(*) from decisions group by 1").fetchall()
    m = Path(__file__).resolve().parent.parent / "eval/results/metrics.json"
    return {"recent": [{k: r[k] for k in ("ts", "principal_user", "agent_id", "action", "resource", "decision", "reason", "risk_score")} for r in rows],
            "counts": dict(by), "eval": json.loads(m.read_text())["summary"] if m.exists() else None,
            "chain_ok": warden.log.verify_chain()}


@app.get("/dashboard")
def dashboard():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(DASH)


DASH = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Warden</title>
<style>:root{--bg:#fcfcfb;--ink:#0b0b0b;--mut:#52514e;--line:#e6e5e1;--ok:#1baf7a;--bad:#eb6834}
@media(prefers-color-scheme:dark){:root{--bg:#1a1a19;--ink:#f0efec;--mut:#c3c2b7;--line:#33322f}}
body{font:14px system-ui;margin:0;padding:16px;background:var(--bg);color:var(--ink);max-width:980px;margin:auto}
h1{font-size:18px}table{border-collapse:collapse;width:100%}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
th{color:var(--mut);font-weight:500}.allow{color:var(--ok)}.deny{color:var(--bad)}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.card{border:1px solid var(--line);border-radius:6px;padding:10px 14px;min-width:130px}.card b{display:block;font-size:22px}.card span{color:var(--mut);font-size:12px}</style>
<h1>Warden: live decisions</h1><div class=cards id=cards></div><table id=t></table>
<script>
async function load(){const d=await (await fetch('dashboard/data')).json();
const c=d.counts, e=d.eval; const card=(a,b)=>`<div class=card><b>${a}</b><span>${b}</span></div>`;
document.getElementById('cards').innerHTML=card(c.allow||0,'allowed')+card(c.deny||0,'denied')+card(c.pending_approval||0,'pending approval')
 +(e?card(e.v1.attack_success+'/'+e.v1.attacks,'attacks executed (v1, eval)')+card(e.v1.false_blocks+'/'+e.v1.benign,'benign broken (v1)')+card(e.v0.attack_success+'/'+e.v0.attacks,'attacks executed (authz only)'):'')
 +card(d.chain_ok?'intact':'BROKEN','log hash chain');
document.getElementById('t').innerHTML='<tr><th>who<th>action<th>resource<th>decision<th>reason<th>risk</tr>'+d.recent.slice().reverse().map(r=>
 `<tr><td>${r.agent_id?r.agent_id+' for ':''}${r.principal_user||'-'}<td>${r.action}<td>${r.resource||''}<td class=${r.decision=='allow'?'allow':'deny'}>${r.decision}<td>${r.reason}<td>${r.risk_score??''}</tr>`).join('')}
load();setInterval(load,2000);
</script>"""
