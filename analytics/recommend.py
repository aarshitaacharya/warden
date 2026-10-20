"""Least-privilege recommendations from observed usage, validated by log replay."""
from __future__ import annotations

import difflib
import json
import shutil
import tempfile
from pathlib import Path

import duckdb

from warden import acme, tools
from warden.policy import POLICY_DIR, PolicyEngine, uid

DAY = 86400


def used_actions(con, before_ts: float) -> dict[str, set[str]]:
    rows = con.execute("""SELECT CASE WHEN agent_id IS NOT NULL THEN 'agent:' || agent_id ELSE principal_user END AS ident,
                                 action FROM decisions WHERE decision='allow' AND status=200 AND ts < ? GROUP BY 1, 2""", [before_ts]).fetchall()
    out: dict[str, set[str]] = {}
    for i, a in rows:
        out.setdefault(i, set()).add(a)
    return out


def propose(used: dict[str, set[str]]) -> dict:
    """Keep only what was used. Roles are pruned by the union of their holders' usage."""
    roles = {}
    for role, actions in acme.ROLE_ACTIONS.items():
        holders = [u for u, m in acme.USERS.items() if role == "employee" or role in m["roles"]]
        keep = [a for a in actions if any(a in used.get(h, set()) for h in holders)]
        roles[role] = keep
    agents = {a: sorted(set(m["scopes"]) & used.get(f"agent:{a}", set())) for a, m in acme.AGENTS.items()}
    services = {s: sorted(set(m["scopes"]) & used.get(s, set())) for s, m in acme.SERVICES.items()}
    return {"roles": roles, "agents": agents, "services": services}


def render_rbac(role_actions: dict[str, list[str]]) -> str:
    out = ["// RBAC: roles map to actions. Default deny for anything not listed.\n"]
    for role, actions in role_actions.items():
        if not actions:
            out.append(f"// role {role}: no observed use, rule removed\n")
            continue
        acts = ", ".join(f'Action::"{a}"' for a in actions)
        out.append(f'@id("rbac-{role}")\npermit(principal in Role::"{role}",\n       action in [{acts}],\n       resource);\n')
    return "\n".join(out)


def diff(a: str, b: str, name: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True), f"a/{name}", f"b/{name}"))


def policy_diffs(proposal: dict) -> dict[str, str]:
    cur_roles = {r: list(a) for r, a in acme.ROLE_ACTIONS.items()}
    cur_agents = {a: sorted(m["scopes"]) for a, m in acme.AGENTS.items()}
    cur_services = {s: sorted(m["scopes"]) for s, m in acme.SERVICES.items()}
    return {
        "rbac.cedar.diff": diff(render_rbac(cur_roles), render_rbac(proposal["roles"]), "policies/cedar/rbac.cedar"),
        "agents.json.diff": diff(json.dumps(cur_agents, indent=2) + "\n", json.dumps(proposal["agents"], indent=2) + "\n", "agent-scopes.json")
                            + diff(json.dumps(cur_services, indent=2) + "\n", json.dumps(proposal["services"], indent=2) + "\n", "service-scopes.json"),
    }


# ---- replay ---------------------------------------------------------------------------
def _engine_with(role_actions: dict[str, list[str]]) -> PolicyEngine:
    d = Path(tempfile.mkdtemp())
    for f in POLICY_DIR.glob("*.cedar"):
        shutil.copy(f, d / f.name)
    (d / "rbac.cedar").write_text(render_rbac(role_actions))
    return PolicyEngine(d)


_ARG_KEY = {"Ticket": "id", "HRRecord": "user", "Doc": "id", "FinanceReport": "id"}


def replay(con, since_ts: float, role_actions: dict, agent_scopes: dict, service_scopes: dict) -> dict:
    eng = _engine_with(role_actions)
    store = acme.fresh_store()
    rows = con.execute("""SELECT principal_kind, principal_user, agent_id, action, resource, decision, status, ts
                          FROM decisions WHERE ts >= ? AND status IN (200, 403)""", [since_ts]).fetchall()
    broken, replayed = {}, 0
    for kind, user, agent, action, res, decision, status, ts in rows:
        rtype, _, rid = (res or "").partition("::")
        args = {_ARG_KEY[rtype]: rid} if rtype in _ARG_KEY else {}
        if action not in acme.ACTIONS or rtype not in _ARG_KEY:
            continue
        resource, _ = tools.resource_entity(action, args, store)
        ctx = {"risk_score": 0, "device_trusted": True, "stepped_up": True, "business_hours": True}
        ents = eng.base_entities()
        sides = []
        if kind == "service":
            ents.append({"uid": uid("Service", user), "attrs": {"scopes": service_scopes.get(user, [])}, "parents": []})
            sides.append(uid("Service", user))
        else:
            sides.append(uid("User", user))
            if agent:
                ents.append({"uid": uid("Agent", agent), "attrs": {"scopes": agent_scopes.get(agent, [])}, "parents": []})
                sides.append(uid("Agent", agent))
        ok = all(eng.evaluate(p, action, resource, ctx, ents).allowed for p in sides)
        was_allowed = decision == "allow" and status == 200
        replayed += 1
        if was_allowed and not ok:
            key = (agent and f"agent:{agent}" or user, action)
            broken[key] = broken.get(key, 0) + 1
        elif not was_allowed and ok:
            broken[("WIDENED", action)] = broken.get(("WIDENED", action), 0) + 1
    return {"replayed": replayed, "broken": [{"identity": k[0], "action": k[1], "requests": v} for k, v in sorted(broken.items())],
            "broken_requests": sum(broken.values())}


def baseline_fidelity(con, since_ts: float) -> dict:
    cur_roles = {r: list(a) for r, a in acme.ROLE_ACTIONS.items()}
    r = replay(con, since_ts, cur_roles, {a: m["scopes"] for a, m in acme.AGENTS.items()},
               {s: m["scopes"] for s, m in acme.SERVICES.items()})
    return r
