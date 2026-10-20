"""Phase 5 pipeline: simulate a month of traffic, analyse it, propose least privilege,
validate by replay, and map attack paths.

    python -m analytics.run
"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb

from . import graph, queries as q, recommend as rec, sim

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "analytics" / "out"
DB = ROOT / "data" / "warden.duckdb"


def table(rows, cols=None):
    if not rows:
        return "_none_\n"
    cols = cols or list(rows[0])
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        out.append("| " + " | ".join("" if r[c] is None else str(r[c]) for c in cols) + " |")
    return "\n".join(out) + "\n"


def main():
    OUT.mkdir(exist_ok=True)
    DB.parent.mkdir(exist_ok=True)
    DB.unlink(missing_ok=True)
    w = sim.simulate(str(DB))
    con = w.log.con
    t_min, t_max = con.execute("select min(ts), max(ts) from decisions").fetchone()
    cutoff = t_min + 0.7 * (t_max - t_min)       # learn from the first 70%, replay the rest
    n = con.execute("select count(*) from decisions").fetchone()[0]

    util = q.run(con, q.UTILISATION)
    dormant = q.run(con, q.DORMANT, [14])
    unused = q.run(con, q.UNUSED_ROLE_ACTIONS)
    anomalies = q.run(con, q.ANOMALIES)
    devices = q.run(con, q.NEW_DEVICES)

    used = rec.used_actions(con, cutoff)
    proposal = rec.propose(used)
    diffs = rec.policy_diffs(proposal)
    for name, text in diffs.items():
        (OUT / name).write_text(text)
    (OUT / "proposal.json").write_text(json.dumps(proposal, indent=2) + "\n")

    fidelity = rec.baseline_fidelity(con, cutoff)
    replay = rec.replay(con, cutoff, proposal["roles"], proposal["agents"], proposal["services"])

    g0 = graph.build()
    g1 = graph.build(proposal["roles"], proposal["agents"])
    toxic0, toxic1 = graph.toxic_agent_paths(g0), graph.toxic_agent_paths(g1)
    sens0, sens1 = graph.paths_to_sensitive(g0), graph.paths_to_sensitive(g1)
    viol = graph.check_intersection_invariant(g0)

    L = ["# Access analytics report\n",
         f"Source: {n} decisions from `analytics.sim` (30 simulated days). Proposal learned from the first 70% "
         f"({int((cutoff - t_min) / 86400)} days) and replayed on the remaining days.\n",
         "## Granted vs used\n", table(util),
         "## Dormant identities (idle 14 days or more)\n", table(dormant),
         "## Role actions nobody used\n", "Actions granted through roles that no holder exercised in the whole window.\n",
         table(unused),
         "## Anomalies\n", "Daily volume more than 3 standard deviations above the identity's own baseline, or 10 or more denials in a day.\n",
         table(anomalies),
         "### Identities seen on a second, low-volume device\n", table(devices),
         "## Least-privilege proposal\n",
         "```diff\n" + diffs["rbac.cedar.diff"] + diffs["agents.json.diff"] + "```\n",
         "## Validation by replay\n",
         f"Baseline fidelity: replaying {fidelity['replayed']} held-out requests against the **current** policy "
         f"reproduces history with {fidelity['broken_requests']} mismatches (this checks the replay itself).\n",
         f"Proposed policy: **{replay['broken_requests']} of {replay['replayed']}** held-out requests would have broken.\n",
         table(replay["broken"]) if replay["broken"] else "_Nothing would have broken._\n",
         "These are legitimate behaviours that began after the learning window. Reviewing this list before rollout is the point: "
         "ship with the missing grants added back, or accept the break.\n",
         "## Attack paths\n",
         f"- Identities with a path to restricted data (sensitivity 3): **{len(sens0)}** now, **{len(sens1)}** after the proposal.",
         f"- Intersection invariant (an agent never reaches data its user cannot): **{'holds' if not viol else 'VIOLATED ' + str(viol)}**.",
         f"- Agent instances that can read sensitive data and send it outside: **{len(toxic0)}** now, **{len(toxic1)}** after the proposal.\n",
         table([{"agent": t["agent"], "acting for": t["user"], "can reach": ", ".join(t["data"])} for t in toxic0[:12]]),
         ("_(first 12 shown)_\n" if len(toxic0) > 12 else "")]
    (ROOT / "analytics" / "report.md").write_text("\n".join(L))
    print(f"decisions={n} replayed={replay['replayed']} broken={replay['broken_requests']} "
          f"toxic_before={len(toxic0)} toxic_after={len(toxic1)}")
    _draw(g0)


def _draw(g):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx
    sub_nodes = set()
    toxic = {f"agent:{t['agent']}@{t['user']}" for t in graph.toxic_agent_paths(g)}
    focus = [n for n in g if n.startswith("agent:") and n in toxic and n.endswith("@carol")] + \
            [n for n in g if n.startswith("agent:") and n in toxic and n.endswith("@grace")]
    for a in focus:
        sub_nodes |= {a, graph.SINK} | nx.descendants(g, a) | {f"user:{a.split('@')[1]}"}
    s = g.subgraph(sub_nodes).copy()
    layer = {"user": 0, "agent": 1, "role": 1, "action": 2, "data": 3, "sink": 3}
    for n, d in s.nodes(data=True):
        s.nodes[n]["layer"] = layer[d["kind"]]
    pos = nx.multipartite_layout(s, subset_key="layer")
    col = {"user": "#2a78d6", "agent": "#eb6834", "action": "#8d8c85", "role": "#1baf7a", "data": "#c0392b", "sink": "#6250d6"}
    plt.figure(figsize=(9, 6), facecolor="#fcfcfb")
    nx.draw_networkx_edges(s, pos, edge_color="#c8c7c1", arrows=True, arrowsize=8, width=0.8)
    nx.draw_networkx_nodes(s, pos, node_color=[col[d["kind"]] for _, d in s.nodes(data=True)], node_size=260)
    nx.draw_networkx_labels(s, pos, labels={n: n.split(":", 1)[1] for n in s}, font_size=6.5, verticalalignment="bottom")
    plt.title("Effective access: carol and grace via agents to sensitive data and the outside", loc="left", fontsize=10)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(ROOT / "docs/img/attack_paths.png", dpi=150)
    plt.close()


if __name__ == "__main__":
    main()
