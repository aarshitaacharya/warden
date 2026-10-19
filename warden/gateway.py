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
