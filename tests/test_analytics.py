from analytics import graph, recommend
from warden import acme


def test_agents_never_extend_user_reach():
    assert graph.check_intersection_invariant(graph.build()) == []


def test_toxic_agents_found_and_removed_by_least_privilege():
    toxic = graph.toxic_agent_paths(graph.build())
    assert {t["agent"] for t in toxic} >= {"hr-assistant", "research-agent"}
    scopes = {a: [s for s in m["scopes"] if not s.startswith("comms:")] for a, m in acme.AGENTS.items()}
    assert graph.toxic_agent_paths(graph.build(agent_scopes=scopes)) == []


def test_proposal_prunes_unused_and_keeps_used():
    used = {"alice": {"tickets:read"}, "agent:support-agent": {"tickets:read"}}
    p = recommend.propose(used)
    assert p["agents"]["support-agent"] == ["tickets:read"]
    assert p["roles"]["engineer"] == ["tickets:read"]
    assert p["roles"]["finance"] == []
