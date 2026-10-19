from fastapi.testclient import TestClient

from warden import gateway


def test_http_flow_with_agent_exchange():
    c = TestClient(gateway.app)
    w = gateway.warden
    sub = w.idp.user_token("alice")
    act = w.idp.agent_client_token("support-agent", "support-dev-secret")
    r = c.post("/sts/exchange", data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                                      "subject_token": sub, "actor_token": act, "scope": "tickets:read"})
    assert r.status_code == 200
    tok = r.json()["access_token"]
    ok = c.post("/v1/tools/tickets:read", json={"args": {"id": "T-100"}}, headers={"Authorization": f"Bearer {tok}"})
    assert ok.status_code == 200 and ok.json()["data"]["id"] == "T-100"
    no = c.post("/v1/tools/hr:read_record", json={"args": {"user": "carol"}}, headers={"Authorization": f"Bearer {tok}"})
    assert no.status_code == 403
    assert c.post("/v1/tools/tickets:read", json={"args": {"id": "T-100"}}).status_code == 401


def test_bad_exchange_is_400():
    c = TestClient(gateway.app)
    w = gateway.warden
    r = c.post("/sts/exchange", data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                                      "subject_token": w.idp.user_token("alice"), "actor_token": w.idp.user_token("bob")})
    assert r.status_code == 400
