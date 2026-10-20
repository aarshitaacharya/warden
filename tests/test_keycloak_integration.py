"""Runs against a live Keycloak (docker compose up keycloak). Skipped when it is not reachable."""
import httpx
import pytest

from warden import acme, identity as idn
from warden.engine import Warden
from tests.test_policy import NOON

BASE = "http://localhost:8080/realms/acme"
TOKEN = f"{BASE}/protocol/openid-connect/token"


def _up():
    try:
        return httpx.get(f"{BASE}/.well-known/openid-configuration", timeout=2).status_code == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _up(), reason="Keycloak not running on localhost:8080")


def user_token(u):
    r = httpx.post(TOKEN, data={"grant_type": "password", "client_id": "warden-gateway", "client_secret": "gateway-dev-secret",
                                "username": u, "password": f"{u}-dev-pass", "scope": "openid"})
    r.raise_for_status()
    return r.json()["access_token"]


def client_token(cid):
    secret = (acme.SERVICES.get(cid) or acme.AGENTS[cid])["secret"]
    r = httpx.post(TOKEN, data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret})
    r.raise_for_status()
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def w():
    verifier = idn.Verifier()
    verifier.trust_jwks(BASE, httpx.get(f"{BASE}/protocol/openid-connect/certs").json())
    return Warden("v0", stack=(idn.DevIdP(), verifier, idn.STS(verifier)))


def test_real_user_token_is_verified_and_authorized(w):
    i = w.verifier.decode(user_token("carol"))
    assert (i.kind, i.subject) == ("user", "carol") and "hr" in i.roles and i.device_trusted
    assert w.handle(user_token("carol"), "hr:read_record", {"user": "dave"}, now=NOON).decision == "allow"
    assert w.handle(user_token("alice"), "hr:read_record", {"user": "dave"}, now=NOON).decision == "deny"


def test_real_service_account(w):
    t = client_token("billing-svc")
    assert w.verifier.decode(t).kind == "service"
    assert w.handle(t, "finance:read_report", {"id": "q3-revenue"}, now=NOON).decision == "allow"
    assert w.handle(t, "tickets:read", {"id": "T-100"}, now=NOON).decision == "deny"


def test_agent_credential_alone_rejected_and_exchange_works(w):
    actor = client_token("hr-assistant")
    r = w.handle(actor, "hr:read_record", {"user": "dave"}, now=NOON)
    assert r.status == 401 and "agent_credential_not_accepted" in r.reason
    tok = w.sts.exchange(subject_token=user_token("carol"), actor_token=actor, scope="hr:read_record")["access_token"]
    assert w.handle(tok, "hr:read_record", {"user": "dave"}, now=NOON).decision == "allow"
    # same agent acting for an engineer: confused deputy is denied on the user side
    tok2 = w.sts.exchange(subject_token=user_token("alice"), actor_token=actor, scope="hr:read_record")["access_token"]
    assert w.handle(tok2, "hr:read_record", {"user": "dave"}, now=NOON).reason.startswith("authz:user")
