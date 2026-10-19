import time

import jwt
import pytest

from warden import identity as idn
from warden.identity import AuthError


@pytest.fixture()
def stack():
    return idn.build_dev_stack()


def agent_token(idp, sts, user="alice", agent="support-agent", scope="", **kw):
    subject = idp.user_token(user, **kw)
    actor = idp.agent_client_token(agent, f"{agent.split('-')[0]}-dev-secret")
    return sts.exchange(subject_token=subject, actor_token=actor, scope=scope)["access_token"]


def test_user_token_verifies(stack):
    idp, ver, _ = stack
    i = ver.decode(idp.user_token("alice"))
    assert (i.kind, i.subject) == ("user", "alice")
    assert "engineer" in i.roles and "employee" in i.roles
    assert not i.stepped_up


def test_passkey_sets_stepup(stack):
    idp, ver, _ = stack
    assert ver.decode(idp.user_token("alice", passkey=True)).stepped_up


def test_service_token(stack):
    idp, ver, _ = stack
    i = ver.decode(idp.service_token("billing-svc", "billing-dev-secret"))
    assert i.kind == "service" and "finance:create_payment" in i.scopes


def test_bad_service_secret(stack):
    idp, _, _ = stack
    with pytest.raises(AuthError):
        idp.service_token("billing-svc", "nope")


def test_delegation_claims(stack):
    idp, ver, sts = stack
    i = ver.decode(agent_token(idp, sts, scope="tickets:read docs:read"))
    assert i.kind == "agent" and i.subject == "alice" and i.agent_id == "support-agent"
    assert i.scopes == {"tickets:read", "docs:read"}


def test_scope_is_narrowed_to_agent_maximum(stack):
    idp, ver, sts = stack
    i = ver.decode(agent_token(idp, sts, scope="tickets:read finance:create_payment"))
    assert i.scopes == {"tickets:read"}


def test_no_overlap_scope_rejected(stack):
    idp, _, sts = stack
    with pytest.raises(AuthError) as e:
        agent_token(idp, sts, scope="finance:create_payment")
    assert e.value.code == "invalid_scope"


def test_agent_token_is_short_lived(stack):
    idp, ver, sts = stack
    i = ver.decode(agent_token(idp, sts))
    assert i.exp - time.time() <= idn.MAX_AGENT_TTL


def test_agent_credential_alone_is_not_accepted(stack):
    idp, ver, _ = stack
    with pytest.raises(AuthError) as e:
        ver.decode(idp.agent_client_token("support-agent", "support-dev-secret"))
    assert e.value.code == "agent_credential_not_accepted"


def test_delegation_does_not_upgrade_assurance(stack):
    idp, ver, sts = stack
    i = ver.decode(agent_token(idp, sts, passkey=False, device_trusted=False))
    assert not i.stepped_up and not i.device_trusted


def test_exchange_rejects_service_as_subject(stack):
    idp, _, sts = stack
    with pytest.raises(AuthError):
        sts.exchange(subject_token=idp.service_token("billing-svc", "billing-dev-secret"),
                     actor_token=idp.agent_client_token("support-agent", "support-dev-secret"))


def test_user_token_cannot_be_actor(stack):
    idp, _, sts = stack
    with pytest.raises(AuthError):
        sts.exchange(subject_token=idp.user_token("alice"), actor_token=idp.user_token("bob"))


def test_expired_token(stack):
    idp, ver, _ = stack
    with pytest.raises(AuthError) as e:
        ver.decode(idp.user_token("alice", ttl=-5))
    assert e.value.code == "token_expired"


def test_untrusted_issuer_and_alg_none(stack):
    _, ver, _ = stack
    forged = jwt.encode({"iss": "https://evil", "aud": idn.AUDIENCE, "sub": "alice", "typ": "user",
                         "iat": 1, "exp": 9999999999, "jti": "x"}, key=None, algorithm="none")
    with pytest.raises(AuthError):
        ver.decode(forged)


def test_wrong_key_same_issuer(stack):
    _, ver, _ = stack
    rogue = idn.DevIdP(idn.Keyring("dev-idp-1"))   # same kid, different key
    with pytest.raises(AuthError):
        ver.decode(rogue.user_token("alice"))


def test_revoke_token_user_agent(stack):
    idp, ver, sts = stack
    t = agent_token(idp, sts)
    jti = ver.decode(t).jti
    ver.revocations.revoke_token(jti)
    with pytest.raises(AuthError) as e:
        ver.decode(t)
    assert e.value.code == "token_revoked"

    t2 = agent_token(idp, sts)
    time.sleep(1.1)
    ver.revocations.revoke_agent("support-agent")
    with pytest.raises(AuthError) as e:
        ver.decode(t2)
    assert e.value.code == "agent_revoked"

    u = idp.user_token("bob")
    time.sleep(1.1)
    ver.revocations.revoke_user("bob")
    with pytest.raises(AuthError):
        ver.decode(u)


def test_cert_binding(stack):
    idp, ver, _ = stack
    t = idp.service_token("billing-svc", "billing-dev-secret", cert_thumbprint="abc")
    assert ver.decode(t, cert_thumbprint="abc").subject == "billing-svc"
    with pytest.raises(AuthError):
        ver.decode(t, cert_thumbprint="other")
    with pytest.raises(AuthError):
        ver.decode(t)
