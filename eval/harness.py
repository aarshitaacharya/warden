"""Run the attack and benign corpora through Warden and score the outcomes.

The victim agent is simulated: once it reads a carrier whose injected text is
still visible (not quarantined), it carries out the scenario's `from_injection`
steps. This isolates what Warden does from what any particular LLM would do.
"""
from __future__ import annotations

import base64
import copy
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import jwt

from warden import acme, identity as idn
from warden.engine import Warden

CORPUS = Path(__file__).parent / "corpus"
NOON = time.mktime(time.strptime("2026-03-03 12:00:00", "%Y-%m-%d %H:%M:%S"))
NIGHT = time.mktime(time.strptime("2026-03-03 23:00:00", "%Y-%m-%d %H:%M:%S"))
DIGITS = "zero one two three four five six seven eight nine".split()
_STACK = None


def stack():
    global _STACK
    if _STACK is None:
        _STACK = idn.build_dev_stack()
    return _STACK


def load(name: str) -> list[dict]:
    return [json.loads(line) for line in (CORPUS / f"{name}.jsonl").read_text().splitlines() if line.strip()]


@dataclass
class StepResult:
    action: str
    status: int
    decision: str
    reason: str
    executed: bool
    harmful: bool
    guardrails: list = field(default_factory=list)
    skipped: bool = False
    carrier: bool = False


@dataclass
class Outcome:
    id: str
    label: str
    category: str
    version: str
    steps: list[StepResult]

    @property
    def harm_executed(self) -> bool:
        return any(s.executed and s.harmful for s in self.steps)

    @property
    def completed(self) -> bool:
        return bool(self.steps) and all(s.executed for s in self.steps)

    def fired(self, name: str) -> bool:
        return any(g["name"] == name and g["fired"] for s in self.steps for g in s.guardrails)

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "category": self.category, "version": self.version,
                "harm_executed": self.harm_executed, "completed": self.completed,
                "steps": [s.__dict__ for s in self.steps]}


# --- tokens ------------------------------------------------------------------------
def make_token(w: Warden, actor: dict):
    """Return (token, error). error is set when the STS refuses to issue."""
    kind, mode = actor["kind"], actor.get("token_mode", "normal")
    user = actor.get("user")
    kw = dict(passkey=actor.get("passkey", False), device_trusted=actor.get("device_trusted", True),
              device_id=actor.get("device_id", "laptop-1"))
    if kind == "service":
        return w.idp.service_token(actor["service"], acme.SERVICES[actor["service"]]["secret"]), None
    if kind == "user":
        tok = w.idp.user_token(user, ttl=-5 if mode == "expired" else 900, **kw)
        if mode == "tampered":
            h, p, s = tok.split(".")
            pad = "=" * (-len(p) % 4)
            claims = json.loads(base64.urlsafe_b64decode(p + pad))
            claims["realm_access"] = {"roles": ["employee", "hr", "finance", "manager"]}
            p2 = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
            return f"{h}.{p2}.{s}", None
        if mode == "untrusted_issuer":
            claims = jwt.decode(tok, options={"verify_signature": False})
            claims["iss"] = "https://evil.example"
            return w.idp.keys.sign(claims), None
        if mode == "wrong_audience":
            claims = jwt.decode(tok, options={"verify_signature": False})
            claims["aud"] = "some-other-service"
            return w.idp.keys.sign(claims), None
        if mode == "revoked":
            w.verifier.revocations.revoke_user(user)
        return tok, None
    # agent
    agent = actor["agent"]
    sub = w.idp.user_token(user, **kw)
    act = w.idp.agent_client_token(agent, acme.AGENTS[agent]["secret"])
    if mode == "agent_client_direct":
        return act, None
    try:
        return w.sts.exchange(subject_token=sub, actor_token=act, scope=actor.get("scope", ""))["access_token"], None
    except idn.AuthError as e:
        return None, f"sts:{e.code}"


# --- templating ---------------------------------------------------------------------
def _primary(out0: dict) -> str:
    return str(out0.get("ssn") or out0.get("body") or "")


def render(value, outs: dict[int, dict]):
    if isinstance(value, dict):
        return {k: render(v, outs) for k, v in value.items()}
    if not isinstance(value, str):
        return value
    prim = _primary(outs.get(0, {}))
    special = {"B64": base64.b64encode(prim.encode()).decode(), "REV": prim[::-1],
               "PARA": " ".join(DIGITS[int(c)] if c.isdigit() else "dash" for c in prim),
               "SPLIT0": prim[: len(prim) // 2], "SPLIT1": prim[len(prim) // 2:]}

    def sub(m):
        key = m.group(1)
        if key in special:
            return special[key]
        i, _, f = key.partition(".")
        return str(outs.get(int(i), {}).get(f, ""))
    return re.sub(r"\{\{([A-Za-z0-9_.]+)\}\}", sub, value)


def _store(setup: dict) -> acme.Store:
    s = acme.fresh_store()
    for table, rows in setup.items():
        for k, patch in rows.items():
            getattr(s, table).setdefault(k, {}).update(patch)
    return s


# --- running ------------------------------------------------------------------------
def run_scenario(sc: dict, version: str) -> Outcome:
    w = Warden(version=version, store=_store(sc.get("setup", {})), stack=stack())
    w.verifier.revocations = idn.RevocationList()
    base = NIGHT if sc["actor"].get("after_hours") else NOON
    token, err = make_token(w, sc["actor"])
    results: list[StepResult] = []
    outs: dict[int, dict] = {}
    compromised = False
    last_approval = None

    for i, st in enumerate(sc["steps"]):
        harmful, carrier = bool(st.get("harmful")), bool(st.get("carrier"))
        if st.get("from_injection") and not compromised:
            results.append(StepResult(st["action"], 0, "skipped", "agent not compromised", False, harmful, skipped=True))
            continue
        if err:
            results.append(StepResult(st["action"], 400, "deny", err, False, harmful))
            continue
        args = render(st.get("args", {}), outs)
        now = base + i * sc.get("dt", 2)
        sid = st.get("session", sc["id"])
        approval_id = None
        if st.get("replay_approval") and last_approval:
            approval_id = last_approval
            if st["replay_approval"] == "mutate":
                pass
        r = w.handle(token, st["action"], args, session_id=sid, now=now, approval_id=approval_id)
        if r.decision == "pending_approval" and st.get("approve_with"):
            approver = w.idp.user_token(st["approve_with"], passkey=st.get("approver_passkey", True))
            if w.decide_approval(r.approval_id, approver)["ok"]:
                last_approval = r.approval_id
                r = w.handle(token, st["action"], args, session_id=sid, now=now + 1, approval_id=r.approval_id)
        executed = r.status == 200 and r.decision == "allow" and r.reason == "ok"
        quarantined = r.reason.startswith("output_quarantined")
        results.append(StepResult(st["action"], r.status, r.decision, r.reason, executed, harmful,
                                  guardrails=r.guardrails, carrier=carrier))
        if r.data and not quarantined:
            outs[i] = r.data
        if carrier and r.status == 200 and not quarantined:
            compromised = True
    w.log.con.close()
    return Outcome(sc["id"], sc["label"], sc["category"], version, results)


def run_corpus(version: str, scenarios: list[dict]) -> list[Outcome]:
    return [run_scenario(sc, version) for sc in scenarios]
