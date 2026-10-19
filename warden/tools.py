"""Acme tool handlers and resource modelling. These sit behind the gateway."""
from __future__ import annotations

from . import acme
from .policy import ref, uid


class ToolError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _need(args: dict, *keys):
    for k in keys:
        if k not in args:
            raise ToolError(400, f"missing argument: {k}")


def domain_of(address: str) -> str:
    addr = address.split("@")[-1] if "@" in address else address
    addr = addr.split("://")[-1].split("/")[0].split(":")[0]
    return addr.lower()


def is_external(dest: str) -> bool:
    d = domain_of(dest)
    return not (d == acme.INTERNAL_DOMAIN or d.endswith("." + acme.INTERNAL_DOMAIN))


def resource_entity(action: str, args: dict, store: acme.Store) -> tuple[dict, dict | None]:
    """Return (cedar resource entity, underlying record or None)."""
    tool = acme.ACTIONS[action]
    if tool == "tickets":
        tid = args.get("id", "NEW")
        rec = store.tickets.get(tid)
        return {"uid": uid("Ticket", tid), "attrs": {"sensitivity": (rec or {}).get("sensitivity", 1)}, "parents": []}, rec
    if tool == "hr":
        u = args.get("user", "")
        rec = store.hr.get(u)
        attrs = {"sensitivity": 3}
        if rec:
            attrs["subject"] = ref("User", rec["subject"])
            if rec["subject_manager"]:
                attrs["subject_manager"] = ref("User", rec["subject_manager"])
        return {"uid": uid("HRRecord", u or "unknown"), "attrs": attrs, "parents": []}, rec
    if tool == "docs":
        did = args.get("id", "")
        rec = store.docs.get(did)
        return {"uid": uid("Doc", did or "unknown"), "attrs": {"sensitivity": (rec or {}).get("sensitivity", 1)}, "parents": []}, rec
    if tool == "finance":
        if action == "finance:create_payment":
            return {"uid": uid("Payment", "new"), "attrs": {"sensitivity": 2, "amount": int(args.get("amount", 0))}, "parents": []}, None
        fid = args.get("id", "")
        rec = store.finance.get(fid)
        return {"uid": uid("FinanceReport", fid or "unknown"), "attrs": {"sensitivity": (rec or {}).get("sensitivity", 2)}, "parents": []}, rec
    dest = args.get("to") or args.get("url") or ""
    return {"uid": uid("Outbound", domain_of(dest) or "unknown"),
            "attrs": {"external": is_external(dest), "sensitivity": 0}, "parents": []}, None


def execute(action: str, args: dict, store: acme.Store, actor: str) -> dict:
    """Run the tool. Raises ToolError for 4xx conditions."""
    if action == "tickets:read":
        _need(args, "id")
        t = store.tickets.get(args["id"]) or _missing()
        return {"id": args["id"], **t}
    if action == "tickets:create":
        _need(args, "title", "body")
        tid = f"T-{100 + len(store.tickets)}"
        store.tickets[tid] = {"title": args["title"], "body": args["body"], "reporter": actor, "sensitivity": 1}
        return {"id": tid}
    if action == "tickets:update":
        _need(args, "id", "body")
        (store.tickets.get(args["id"]) or _missing())["body"] = args["body"]
        return {"id": args["id"], "updated": True}
    if action == "tickets:delete":
        _need(args, "id")
        store.tickets.pop(args["id"], None) or _missing()
        return {"deleted": args["id"]}
    if action == "hr:read_record":
        _need(args, "user")
        return dict(store.hr.get(args["user"]) or _missing())
    if action == "hr:update_record":
        _need(args, "user", "field", "value")
        rec = store.hr.get(args["user"]) or _missing()
        if args["field"] in {"subject", "subject_manager", "sensitivity"}:
            raise ToolError(400, "field is not editable")
        rec[args["field"]] = args["value"]
        return {"updated": args["user"]}
    if action == "hr:delete_record":
        _need(args, "user")
        store.hr.pop(args["user"], None) or _missing()
        return {"deleted": args["user"]}
    if action == "docs:read":
        _need(args, "id")
        return {"id": args["id"], **(store.docs.get(args["id"]) or _missing())}
    if action == "docs:write":
        _need(args, "id", "body")
        d = store.docs.setdefault(args["id"], {"title": args["id"], "body": "", "sensitivity": 1})
        d["body"] = args["body"]
        return {"id": args["id"], "written": True}
    if action == "finance:read_report":
        _need(args, "id")
        return {"id": args["id"], **(store.finance.get(args["id"]) or _missing())}
    if action == "finance:create_payment":
        _need(args, "payee", "amount")
        store.payments.append({"payee": args["payee"], "amount": args["amount"], "by": actor})
        return {"payment": len(store.payments), "status": "submitted"}
    if action == "comms:send_email":
        _need(args, "to", "subject", "body")
        store.outbox.append({"kind": "email", **args, "by": actor})
        return {"queued": True}
    if action == "comms:http_post":
        _need(args, "url", "body")
        store.outbox.append({"kind": "http", **args, "by": actor})
        return {"status": 200}
    raise ToolError(404, f"unknown action {action}")


def _missing():
    raise ToolError(404, "not found")


def output_text(data) -> str:
    """Flatten a tool result to the text a model would see."""
    if isinstance(data, dict):
        return " ".join(output_text(v) for v in data.values())
    if isinstance(data, (list, tuple)):
        return " ".join(output_text(v) for v in data)
    return "" if data is None else str(data)
