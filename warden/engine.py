"""The policy enforcement point: authenticate -> decide -> (guardrails) -> execute -> log."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import acme, tools
from .decisionlog import DecisionLog
from .identity import STS, AuthError, DevIdP, Identity, Verifier, build_dev_stack
from .policy import PolicyEngine, ref, uid

VERSIONS_FILE = Path(__file__).resolve().parent.parent / "policies" / "versions.json"


def load_versions() -> dict:
    return json.loads(VERSIONS_FILE.read_text())


@dataclass
class Response:
    status: int
    decision: str                  # allow | deny | pending_approval
    reason: str
    request_id: str
    data: dict | None = None
    approval_id: str | None = None
    guardrails: list = field(default_factory=list)


def business_hours(now: float) -> bool:
    return 7 <= time.localtime(now).tm_hour < 19


class Warden:
    def __init__(self, version: str = "v1", db_path: str = ":memory:", store: acme.Store | None = None,
                 stack: tuple[DevIdP, Verifier, STS] | None = None):
        self.versions = load_versions()
        self.version = version
        self.config = self.versions[version]
        self.store = store or acme.fresh_store()
        self.policy = PolicyEngine()
        self.log = DecisionLog(db_path)
        self.idp, self.verifier, self.sts = stack or build_dev_stack()
        self.guard = None          # set by guardrails.attach() (Phase 3)

    # -- identity helpers -------------------------------------------------
    def principals(self, ident: Identity) -> list[tuple[str, dict, str]]:
        """(side, cedar principal uid, side name) evaluated for this identity."""
        if ident.kind == "user":
            return [("user", uid("User", ident.subject), "user")]
        if ident.kind == "service":
            return [("service", uid("Service", ident.subject), "service")]
        return [("agent", uid("Agent", ident.agent_id), "agent"), ("user", uid("User", ident.subject), "user")]

    def _entities(self, ident: Identity) -> list[dict]:
        roles = {ident.subject: ident.roles} if ident.kind in ("user", "agent") and ident.roles else None
        ents = self.policy.base_entities(roles)
        if ident.kind == "service":
            ents.append({"uid": uid("Service", ident.subject), "attrs": {"scopes": sorted(ident.scopes)}, "parents": []})
        elif ident.kind == "agent":
            ents.append({"uid": uid("Agent", ident.agent_id),
                         "attrs": {"scopes": sorted(ident.scopes), "acts_for": ref("User", ident.subject)}, "parents": []})
        return ents

    # -- main entry -------------------------------------------------------
    def handle(self, token: str, action: str, args: dict | None = None, *, session_id: str | None = None,
               cert_thumbprint: str | None = None, now: float | None = None,
               approval_id: str | None = None) -> Response:
        t0 = time.perf_counter()
        now = now if now is not None else time.time()
        args = args or {}
        rid = uuid.uuid4().hex[:12]
        session_id = session_id or f"anon-{rid}"
        rec = {"ts": now, "request_id": rid, "session_id": session_id, "policy_version": self.version,
               "action": action, "guardrails": [], "risk_signals": []}

        def finish(status, decision, reason, data=None, **kw):
            rec.update(decision=decision, status=status, reason=reason)
            rec["latency_ms"] = (time.perf_counter() - t0) * 1000
            self.log.write(rec)
            return Response(status, decision, reason, rid, data, guardrails=rec["guardrails"], **kw)

        if action not in acme.ACTIONS:
            return finish(404, "deny", "unknown_action")
        try:
            ident = self.verifier.decode(token, cert_thumbprint=cert_thumbprint)
        except AuthError as e:
            rec.update(principal_kind="unauthenticated", deciding_policies=["authn"])
            return finish(401, "deny", f"authn:{e.code}")
        rec.update(principal_kind=ident.kind, principal_user=ident.subject if ident.kind != "service" else None,
                   agent_id=ident.agent_id, token_jti=ident.jti, device_id=ident.device_id)
        if ident.kind == "service":
            rec["principal_user"] = ident.subject

        resource, record = tools.resource_entity(action, args, self.store)
        rid_str = f'{resource["uid"]["type"]}::{resource["uid"]["id"]}'
        rec.update(resource=rid_str, sensitivity=resource["attrs"].get("sensitivity"))

        # --- risk (guardrail) ---
        risk, signals = (0.0, [])
        if self.guard and self.config.get("risk_scoring"):
            risk, signals = self.guard.risk(ident, action, session_id, now)
        rec.update(risk_score=risk, risk_signals=signals)

        # --- authorization: every principal side must allow ---
        ctx = {"risk_score": int(risk), "device_trusted": ident.device_trusted, "stepped_up": ident.stepped_up,
               "business_hours": business_hours(now)}
        ents = self._entities(ident)
        sides, failed = {}, None
        for side, principal, _ in self.principals(ident):
            ev = self.policy.evaluate(principal, action, resource, ctx, ents)
            sides[side] = ev
            if not ev.allowed and failed is None:
                failed = (side, ev)
        rec["user_decision"] = "allow" if sides.get("user", None) and sides["user"].allowed else ("deny" if "user" in sides else None)
        rec["agent_decision"] = ("allow" if sides["agent"].allowed else "deny") if "agent" in sides else None
        policies = [p for ev in sides.values() for p in ev.policies]
        rec["deciding_policies"] = policies
        if failed:
            side, ev = failed
            why = ",".join(ev.policies) or "default_deny"
            if ev.errors:
                why = "policy_error"
            return finish(403, "deny", f"authz:{side}:{why}")

        # --- guardrails that act before execution ---
        if self.guard:
            verdict = self.guard.pre(self, ident, action, args, resource, session_id, now, approval_id, rec)
            if verdict is not None:
                return finish(verdict["status"], verdict["decision"], verdict["reason"],
                              approval_id=verdict.get("approval_id"))

        # --- execute ---
        try:
            data = tools.execute(action, args, self.store, ident.label)
        except tools.ToolError as e:
            return finish(e.status, "allow", f"tool_error:{e.msg}")

        if self.guard:
            data, note = self.guard.post(self, ident, action, args, resource, data, session_id, now, rec)
            if note:
                return finish(200, "allow", note, data)
        return finish(200, "allow", "ok", data)
