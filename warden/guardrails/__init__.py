"""Guardrails: risk scoring, approvals, exfiltration control, injection scanning."""
from __future__ import annotations

from .. import acme, tools
from .approvals import ApprovalQueue
from .injection import get_detector
from .risk import RiskModel
from .taint import TaintState

__all__ = ["Guardrails"]


class Guardrails:
    def __init__(self, warden):
        self.cfg = warden.config
        self.detector = get_detector(self.cfg["injection_detector"])
        self.risk_model = RiskModel()
        self.risk_model.seed_devices({u: {"laptop-1"} for u in acme.USERS})
        self.taints: dict[str, TaintState] = {}
        self.restricted_reads: dict[str, list[float]] = {}
        self.approvals = ApprovalQueue()
        warden.approvals = self.approvals

    @staticmethod
    def key(ident) -> str:
        return f"{ident.subject}|{ident.agent_id or ''}"

    def taint(self, ident) -> TaintState:
        return self.taints.setdefault(self.key(ident), TaintState())

    # -- called before authorization -------------------------------------
    def risk(self, ident, action, session_id, now):
        user = ident.subject if ident.kind != "service" else None
        return self.risk_model.score(self.key(ident), user, ident.device_id, action,
                                     self.taint(ident).last_sensitive_ts, now)

    def observe(self, ident, decision: str, now: float):
        if decision == "deny":
            self.risk_model.record_denial(self.key(ident), now)

    # -- called after authorization, before execution --------------------
    def pre(self, warden, ident, action, args, resource, session_id, now, approval_id, rec):
        gl = rec["guardrails"]

        if self.cfg.get("risk_scoring"):
            stepup = rec["risk_score"] >= 50 and not ident.stepped_up
            gl.append({"name": "risk", "fired": stepup, "score": rec["risk_score"], "signals": rec["risk_signals"]})
            if stepup:
                return {"status": 401, "decision": "deny", "reason": "risk:step_up_required"}

        external = False
        payload = ""
        if action in acme.OUTBOUND_ACTIONS:
            external = bool(resource["attrs"].get("external"))
            payload = " ".join(str(args.get(k, "")) for k in ("to", "url", "subject", "body"))
            if self.cfg.get("exfil_control"):
                sources = self.taint(ident).overlap(payload, now, self.cfg.get("taint_normalization", False)) if external else []
                fired = bool(sources)
                gl.append({"name": "exfil", "fired": fired, "sources": sources})
                if fired:
                    return {"status": 403, "decision": "deny", "reason": "guardrail:exfil_blocked:" + ",".join(sources)}

        if self.cfg.get("approvals"):
            needs = action in acme.HIGH_RISK_ACTIONS or (external and ident.kind in ("agent", "service"))
            detail = "high_risk"
            if not needs and external and self.cfg.get("tainted_external_approval") and self.taint(ident).recent(now):
                needs, detail = True, "tainted_external"
            if not needs and self.cfg.get("bulk_read_approval") and int(resource["attrs"].get("sensitivity") or 0) >= 3 \
                    and action.endswith("read_record"):
                recent = [t for t in self.restricted_reads.get(self.key(ident), []) if now - t < 900]
                if len(recent) >= 20:
                    needs, detail = True, "bulk_sensitive_read"
            if needs:
                requester = ident.label
                if approval_id:
                    why = self.approvals.consume(approval_id, action, args, requester, now)
                    gl.append({"name": "approval", "fired": why is not None, "detail": why or "approved"})
                    if why:
                        return {"status": 403, "decision": "deny", "reason": f"approval:{why}"}
                else:
                    a = self.approvals.request(action, args, requester, now)
                    gl.append({"name": "approval", "fired": True, "detail": f"pending:{detail}", "approval_id": a.id})
                    return {"status": 202, "decision": "pending_approval", "reason": "approval:required",
                            "approval_id": a.id}
        return None

    # -- called after execution ------------------------------------------
    def post(self, warden, ident, action, args, resource, data, session_id, now, rec):
        text = tools.output_text(data)
        sens = int(resource["attrs"].get("sensitivity") or 0)
        gl = rec["guardrails"]
        note = None
        if ident.kind == "agent" and action not in acme.OUTBOUND_ACTIONS:
            det = self.detector.scan(text)
            if self.cfg["injection_detector"] != "none":
                gl.append({"name": "injection", "fired": det.flagged, "detector": det.detector,
                           "score": round(det.score, 3), "evidence": det.evidence[:3]})
            if det.flagged:
                self.risk_model.record_injection(self.key(ident), now)
                data = {"quarantined": True,
                        "notice": "Content withheld by Warden: possible prompt injection detected in tool output."}
                note = "output_quarantined:injection"
        if note is None and sens >= 2 and action not in acme.OUTBOUND_ACTIONS:
            self.taint(ident).add(rec["resource"], data, sens, now, self.cfg.get("taint_normalization", False))
            if sens >= 3:
                self.restricted_reads.setdefault(self.key(ident), []).append(now)
        return data, note
