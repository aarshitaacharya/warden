"""Policy unit tests: the role/relationship matrix and the agent intersection rule."""
import time

import pytest

from warden import acme
from warden.engine import Warden

NOON = time.mktime(time.strptime("2026-03-03 12:00", "%Y-%m-%d %H:%M"))
NIGHT = time.mktime(time.strptime("2026-03-03 23:00", "%Y-%m-%d %H:%M"))

ARGS = {
    "tickets:read": {"id": "T-100"}, "tickets:create": {"title": "t", "body": "b"},
    "tickets:update": {"id": "T-100", "body": "x"}, "tickets:delete": {"id": "T-100"},
    "hr:read_record": {"user": "dave"}, "hr:update_record": {"user": "dave", "field": "review", "value": "ok"},
    "hr:delete_record": {"user": "dave"},
    "docs:read": {"id": "eng-runbook"}, "docs:write": {"id": "eng-runbook", "body": "x"},
    "finance:read_report": {"id": "q3-revenue"}, "finance:create_payment": {"payee": "Vendor", "amount": 100},
    "comms:send_email": {"to": "bob@acme.test", "subject": "s", "body": "b"},
    "comms:http_post": {"url": "https://api.acme.test/x", "body": "b"},
}


@pytest.fixture()
def w():
    return Warden(version="v0")      # authorization only


def call(w, token, action, args=None, now=NOON):
    return w.handle(token, action, args if args is not None else ARGS[action], now=now)


def agent(w, user, agent_id, scope="", **kw):
    sub = w.idp.user_token(user, **kw)
    act = w.idp.agent_client_token(agent_id, acme.AGENTS[agent_id]["secret"])
    return w.sts.exchange(subject_token=sub, actor_token=act, scope=scope)["access_token"]


# --- RBAC -----------------------------------------------------------------
# Expected: for the given user (passkey + trusted device), which actions are allowed on ARGS.
RBAC_EXPECTED = {
    "alice": {"tickets:read", "tickets:create", "tickets:update", "docs:read", "docs:write", "comms:send_email", "comms:http_post"},
    "carol": {"tickets:read", "tickets:create", "docs:read", "comms:send_email", "hr:read_record", "hr:update_record"},
    "erin": {"tickets:create", "docs:read", "comms:send_email", "finance:read_report", "finance:create_payment"},
}


@pytest.mark.parametrize("user", sorted(RBAC_EXPECTED))
def test_rbac_matrix(w, user):
    tok = w.idp.user_token(user, passkey=True)
    allowed = {a for a in acme.ACTIONS if call(w, tok, a).decision == "allow"}
    assert allowed == RBAC_EXPECTED[user]


def test_default_deny_unknown_action(w):
    assert call(w, w.idp.user_token("alice"), "tickets:purge", {}).status == 404


def test_missing_or_bad_token_is_401(w):
    r = call(w, "garbage", "tickets:read")
    assert r.status == 401 and r.reason.startswith("authn:")


# --- ReBAC ----------------------------------------------------------------
def test_manager_reads_direct_report_hr(w):
    # grace manages alice; she has no hr role, only the relationship.
    assert call(w, w.idp.user_token("grace"), "hr:read_record", {"user": "alice"}).decision == "allow"


def test_manager_cannot_read_non_report_hr(w):
    r = call(w, w.idp.user_token("grace"), "hr:read_record", {"user": "erin"})
    assert r.decision == "deny" and "authz:user" in r.reason


def test_self_read_hr_but_not_peer(w):
    tok = w.idp.user_token("bob")
    assert call(w, tok, "hr:read_record", {"user": "bob"}).decision == "allow"
    assert call(w, tok, "hr:read_record", {"user": "alice"}).decision == "deny"


def test_engineer_cannot_read_hr(w):
    assert call(w, w.idp.user_token("alice"), "hr:read_record", {"user": "carol"}).decision == "deny"


# --- ABAC -----------------------------------------------------------------
def test_restricted_needs_trusted_device(w):
    tok = w.idp.user_token("carol", device_trusted=False)
    r = call(w, tok, "hr:read_record", {"user": "dave"})
    assert r.decision == "deny" and "abac-restricted-needs-trusted-device" in r.reason


def test_payment_needs_stepup(w):
    assert call(w, w.idp.user_token("erin"), "finance:create_payment").decision == "deny"
    assert call(w, w.idp.user_token("erin", passkey=True), "finance:create_payment").decision == "allow"


def test_hr_write_needs_stepup(w):
    assert call(w, w.idp.user_token("carol"), "hr:update_record").decision == "deny"
    assert call(w, w.idp.user_token("carol", passkey=True), "hr:update_record").decision == "allow"


def test_confidential_after_hours_denied_for_users(w):
    tok = w.idp.user_token("alice")
    assert call(w, tok, "docs:read", {"id": "roadmap"}, now=NOON).decision == "allow"
    assert call(w, tok, "docs:read", {"id": "roadmap"}, now=NIGHT).decision == "deny"
    assert call(w, tok, "docs:read", {"id": "eng-runbook"}, now=NIGHT).decision == "allow"


# --- services -------------------------------------------------------------
def test_service_scopes(w):
    tok = w.idp.service_token("ticket-sync-svc", "sync-dev-secret")
    assert call(w, tok, "tickets:read").decision == "allow"
    assert call(w, tok, "finance:read_report").decision == "deny"


def test_service_payment_needs_stepup_even_with_scope(w):
    tok = w.idp.service_token("billing-svc", "billing-dev-secret")
    assert call(w, tok, "finance:read_report").decision == "allow"
    assert call(w, tok, "finance:create_payment").decision == "deny"     # abac-payments-need-stepup


# --- agents: intersection of agent scope and user permission ---------------
def test_agent_allowed_when_both_sides_allow(w):
    tok = agent(w, "alice", "support-agent")
    r = call(w, tok, "tickets:read")
    assert r.decision == "allow"


def test_agent_denied_when_user_lacks_permission(w):
    # support-agent holds hr:read_record scope, alice does not. Confused deputy.
    tok = agent(w, "alice", "support-agent", scope="hr:read_record")
    r = call(w, tok, "hr:read_record", {"user": "carol"})
    assert r.decision == "deny" and r.reason.startswith("authz:user")


def test_agent_denied_when_agent_lacks_scope(w):
    # carol may read HR, but the support-agent token is scoped to tickets only.
    tok = agent(w, "carol", "support-agent", scope="tickets:read")
    r = call(w, tok, "hr:read_record", {"user": "dave"})
    assert r.decision == "deny" and r.reason.startswith("authz:agent")


def test_agent_hr_assistant_acts_for_hr_user(w):
    tok = agent(w, "carol", "hr-assistant", scope="hr:read_record", passkey=True)
    assert call(w, tok, "hr:read_record", {"user": "dave"}).decision == "allow"


def test_agent_never_destructive(w):
    tok = agent(w, "grace", "support-agent")
    assert call(w, tok, "tickets:delete").decision == "deny"
    assert acme.AGENTS["support-agent"]["scopes"].count("tickets:delete") == 0


def test_agent_inherits_untrusted_device(w):
    tok = agent(w, "carol", "hr-assistant", scope="hr:read_record", device_trusted=False)
    r = call(w, tok, "hr:read_record", {"user": "dave"})
    assert r.decision == "deny" and "abac-restricted-needs-trusted-device" in r.reason


def test_decision_log_records_both_sides(w):
    tok = agent(w, "alice", "support-agent", scope="hr:read_record")
    call(w, tok, "hr:read_record", {"user": "carol"})
    row = w.log.rows()[-1]
    assert (row["user_decision"], row["agent_decision"], row["decision"]) == ("deny", "allow", "deny")
    assert row["agent_id"] == "support-agent" and row["principal_user"] == "alice"


def test_log_hash_chain_detects_tampering(w):
    tok = w.idp.user_token("alice")
    call(w, tok, "tickets:read"); call(w, tok, "docs:read")
    assert w.log.verify_chain()
    w.log.con.execute("UPDATE decisions SET decision='allow' WHERE rowid = (SELECT min(rowid) FROM decisions)")
    w.log.con.execute("UPDATE decisions SET reason='edited' WHERE rowid = (SELECT min(rowid) FROM decisions)")
    assert not w.log.verify_chain()


def test_every_denied_request_has_a_reason(w):
    tok = w.idp.user_token("alice")
    for a in acme.ACTIONS:
        r = call(w, tok, a)
        if r.decision == "deny":
            assert r.reason
