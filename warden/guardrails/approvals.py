"""Human approval for high-risk actions."""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass

TTL = 900
APPROVER_ROLES = {"manager"}


def fingerprint(action: str, args: dict, requester: str) -> str:
    return hashlib.sha256(json.dumps([action, args, requester], sort_keys=True).encode()).hexdigest()


@dataclass
class Approval:
    id: str
    action: str
    args: dict
    requester: str
    fp: str
    created: float
    status: str = "pending"           # pending | approved | rejected | used
    approver: str | None = None
    approver_acr: str | None = None


class ApprovalError(Exception):
    pass


class ApprovalQueue:
    def __init__(self):
        self.items: dict[str, Approval] = {}

    def request(self, action: str, args: dict, requester: str, now: float) -> Approval:
        fp = fingerprint(action, args, requester)
        for a in self.items.values():
            if a.fp == fp and a.status == "pending" and now - a.created < TTL:
                return a
        a = Approval(uuid.uuid4().hex[:10], action, args, requester, fp, now)
        self.items[a.id] = a
        return a

    def decide(self, approval_id: str, approver, approve: bool = True) -> Approval:
        a = self.items.get(approval_id)
        if not a or a.status != "pending":
            raise ApprovalError("no such pending approval")
        if approver.kind != "user" or not (APPROVER_ROLES & set(approver.roles)):
            raise ApprovalError("approver lacks an approver role")
        if approver.subject == a.requester.split("->")[-1].split(":")[-1]:
            raise ApprovalError("requester cannot approve their own request")
        if approve and not approver.stepped_up:
            raise ApprovalError("approver must authenticate with a passkey")
        a.status = "approved" if approve else "rejected"
        a.approver, a.approver_acr = approver.subject, approver.acr
        return a

    def consume(self, approval_id: str, action: str, args: dict, requester: str, now: float) -> str | None:
        """Return None if the approval is valid and consumed, else the reason it is not."""
        a = self.items.get(approval_id)
        if not a:
            return "approval_unknown"
        if a.status != "approved":
            return f"approval_{a.status}"
        if now - a.created > TTL:
            return "approval_expired"
        if a.fp != fingerprint(action, args, requester):
            return "approval_mismatch"
        a.status = "used"
        return None
