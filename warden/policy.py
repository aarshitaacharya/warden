"""Cedar policy engine wrapper: entity building, evaluation, policy-id mapping."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import cedarpy

from . import acme

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies" / "cedar"


def ref(t: str, i: str) -> dict:
    return {"__entity": {"type": t, "id": i}}


def uid(t: str, i: str) -> dict:
    return {"type": t, "id": i}


@dataclass
class Eval:
    allowed: bool
    policies: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PolicyEngine:
    def __init__(self, policy_dir: Path = POLICY_DIR):
        texts = [p.read_text() for p in sorted(Path(policy_dir).glob("*.cedar"))]
        self.text = "\n".join(texts)
        # cedarpy numbers policies policy0..N in file order; recover our @id names.
        self.ids = re.findall(r'@id\("([^"]+)"\)', self.text)
        n = len(re.findall(r"^(?:permit|forbid)\s*\(", self.text, re.M))
        if n != len(self.ids):
            raise ValueError(f"every policy needs an @id ({n} policies, {len(self.ids)} ids)")

    def _name(self, pid: str) -> str:
        m = re.fullmatch(r"policy(\d+)", pid)
        return self.ids[int(m.group(1))] if m else pid

    def base_entities(self, principal_roles: dict[str, list[str]] | None = None) -> list[dict]:
        """Users (with roles and manager), roles. Roles for named users can be overridden from a token."""
        principal_roles = principal_roles or {}
        roles = {"employee"} | {r for ro in acme.ROLE_ACTIONS for r in [ro]}
        out = [{"uid": uid("Role", r), "attrs": {}, "parents": []} for r in sorted(roles)]
        for u, meta in acme.USERS.items():
            rs = principal_roles.get(u) or (["employee"] + meta["roles"])
            attrs = {"dept": meta["dept"]}
            if meta["manager"]:
                attrs["manager"] = ref("User", meta["manager"])
            out.append({"uid": uid("User", u), "attrs": attrs, "parents": [uid("Role", r) for r in sorted(set(rs))]})
        return out

    def evaluate(self, principal: dict, action: str, resource: dict, context: dict,
                 extra_entities: list[dict]) -> Eval:
        req = {
            "principal": f'{principal["type"]}::"{principal["id"]}"',
            "action": f'Action::"{action}"',
            "resource": f'{resource["uid"]["type"]}::"{resource["uid"]["id"]}"',
            "context": {**context, "action_id": action},
        }
        res = cedarpy.is_authorized(req, self.text, extra_entities + [resource])
        pols = [self._name(p) for p in res.diagnostics.reasons]
        errs = [str(e) for e in res.diagnostics.errors]
        return Eval(allowed=(str(res.decision).endswith("Allow") and not errs), policies=pols, errors=errs)
