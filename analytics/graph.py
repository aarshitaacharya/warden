"""Attack-path graph: identity -> role -> action -> data, with agent delegation and exfil sinks."""
from __future__ import annotations

import networkx as nx

from warden import acme

SENSITIVE = {                       # data node -> (sensitivity, actions that read it)
    "hr_records": (3, ["hr:read_record"]),
    "payroll_summary": (3, ["finance:read_report"]),
    "board_deck": (3, ["docs:read"]),
    "roadmap": (2, ["docs:read"]),
    "q3_revenue": (2, ["finance:read_report"]),
}
SINK = "sink:external"
OUTBOUND = ["comms:send_email", "comms:http_post"]


def user_actions(u: str, role_actions: dict | None = None) -> set[str]:
    ra = role_actions or acme.ROLE_ACTIONS
    acts = {a for r in ["employee"] + acme.USERS[u]["roles"] for a in ra.get(r, [])}
    if any(acme.USERS[x]["manager"] == u for x in acme.USERS):
        acts.add("hr:read_record")      # ReBAC: managers read their direct reports
    return acts


def build(role_actions: dict | None = None, agent_scopes: dict | None = None) -> nx.DiGraph:
    g = nx.DiGraph()
    ascopes = agent_scopes or {a: m["scopes"] for a, m in acme.AGENTS.items()}
    for d, (sens, readers) in SENSITIVE.items():
        g.add_node(f"data:{d}", kind="data", sensitivity=sens)
        for a in readers:
            g.add_edge(f"action:{a}", f"data:{d}", rel="reads")
    g.add_node(SINK, kind="sink")
    for a in OUTBOUND:
        g.add_edge(f"action:{a}", SINK, rel="sends")
    ra = role_actions or acme.ROLE_ACTIONS
    for u, meta in acme.USERS.items():
        g.add_node(f"user:{u}", kind="user")
        for r in ["employee"] + meta["roles"]:
            g.add_edge(f"user:{u}", f"role:{r}", rel="has_role")
        perms = user_actions(u, ra)
        for a in perms:
            g.add_edge(f"user:{u}", f"action:{a}", rel="effective")
        # Delegation: the agent node for this user only reaches actions in the intersection.
        for ag, scopes in ascopes.items():
            eff = set(scopes) & perms
            if eff:
                node = f"agent:{ag}@{u}"
                g.add_node(node, kind="agent", agent=ag, user=u)
                g.add_edge(f"user:{u}", node, rel="delegates")
                for a in eff:
                    g.add_edge(node, f"action:{a}", rel="effective")
    for r, acts in ra.items():
        for a in acts:
            g.add_edge(f"role:{r}", f"action:{a}", rel="permits")
    return g


def paths_to_sensitive(g: nx.DiGraph, min_sens: int = 3):
    out = []
    for n, d in g.nodes(data=True):
        if d.get("kind") == "data" and d["sensitivity"] >= min_sens:
            for src in (x for x, dd in g.nodes(data=True) if dd.get("kind") in ("user", "agent")):
                if nx.has_path(g, src, n):
                    out.append((src, n))
    return out


def toxic_agent_paths(g: nx.DiGraph, min_sens: int = 2):
    """Agent instances that can both read sensitive data and send it outside."""
    res = []
    for n, d in g.nodes(data=True):
        if d.get("kind") != "agent" or not nx.has_path(g, n, SINK):
            continue
        reach = [x for x in nx.descendants(g, n) if g.nodes[x].get("kind") == "data" and g.nodes[x]["sensitivity"] >= min_sens]
        if reach:
            res.append({"agent": d["agent"], "user": d["user"], "data": sorted(r.split(":", 1)[1] for r in reach)})
    return res


def check_intersection_invariant(g: nx.DiGraph) -> list[tuple]:
    """No agent node may reach data its user cannot reach. Returns violations."""
    bad = []
    for n, d in g.nodes(data=True):
        if d.get("kind") == "agent":
            u = f"user:{d['user']}"
            for x in nx.descendants(g, n):
                if g.nodes[x].get("kind") == "data" and not nx.has_path(g, u, x):
                    bad.append((n, x))
    return bad
