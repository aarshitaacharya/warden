from incident import simulate


def test_incident_is_contained_and_log_intact():
    s = simulate.main()
    assert s["external_messages_delivered"] == 0
    assert s["chain_intact"]
    assert {"DET-001"} <= {a["rule"] for a in s["alerts"]}
    from warden import acme
    assert "comms:send_email" in acme.AGENTS["hr-assistant"]["scopes"]     # registry restored
