"""The simulated company: directory, tool catalogue and seed data."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

SENSITIVITY = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

ACTIONS = {
    "tickets:read": "tickets", "tickets:create": "tickets",
    "tickets:update": "tickets", "tickets:delete": "tickets",
    "hr:read_record": "hr", "hr:update_record": "hr", "hr:delete_record": "hr",
    "docs:read": "docs", "docs:write": "docs",
    "finance:read_report": "finance", "finance:create_payment": "finance",
    "comms:send_email": "comms", "comms:http_post": "comms",
}

# Actions that always need a human approval before they execute.
HIGH_RISK_ACTIONS = {"finance:create_payment", "tickets:delete", "hr:delete_record"}
OUTBOUND_ACTIONS = {"comms:send_email", "comms:http_post"}
INTERNAL_DOMAIN = "acme.test"

USERS = {
    "alice": {"roles": ["engineer"], "manager": "grace", "dept": "engineering"},
    "bob": {"roles": ["engineer"], "manager": "grace", "dept": "engineering"},
    "carol": {"roles": ["hr"], "manager": "heidi", "dept": "hr"},
    "dave": {"roles": ["hr"], "manager": "heidi", "dept": "hr"},
    "erin": {"roles": ["finance"], "manager": "ivan", "dept": "finance"},
    "frank": {"roles": ["finance"], "manager": "ivan", "dept": "finance"},
    "grace": {"roles": ["engineer", "manager"], "manager": "judy", "dept": "engineering"},
    "heidi": {"roles": ["hr", "manager"], "manager": "judy", "dept": "hr"},
    "ivan": {"roles": ["finance", "manager"], "manager": "judy", "dept": "finance"},
    "judy": {"roles": ["manager"], "manager": None, "dept": "executive"},
}

# Role -> actions (RBAC). Enforced in Cedar; mirrored here for analytics and tests.
ROLE_ACTIONS = {
    "employee": ["tickets:create", "docs:read", "comms:send_email"],
    "engineer": ["tickets:read", "tickets:update", "docs:write"],
    "hr": ["hr:read_record", "hr:update_record", "tickets:read"],
    "finance": ["finance:read_report", "finance:create_payment"],
    "manager": ["tickets:read", "tickets:delete"],
}

# Service accounts hold scopes directly. client_secret is a dev-only value.
SERVICES = {
    "billing-svc": {"scopes": ["finance:read_report", "finance:create_payment"], "secret": "billing-dev-secret"},
    "ticket-sync-svc": {"scopes": ["tickets:read", "tickets:update"], "secret": "sync-dev-secret"},
}

# Agent registry: the maximum scopes an agent can ever be delegated.
# Deliberately a little generous so Phase 5 has over-privilege to find.
AGENTS = {
    "support-agent": {
        "scopes": ["tickets:read", "tickets:create", "tickets:update", "docs:read", "hr:read_record"],
        "secret": "support-dev-secret",
    },
    "hr-assistant": {
        "scopes": ["hr:read_record", "docs:read", "comms:send_email", "tickets:create"],
        "secret": "hr-dev-secret",
    },
    "research-agent": {
        "scopes": ["docs:read", "tickets:read", "comms:http_post", "comms:send_email"],
        "secret": "research-dev-secret",
    },
}


def effective_user_actions(user: str) -> set[str]:
    roles = ["employee"] + USERS[user]["roles"]
    return {a for r in roles for a in ROLE_ACTIONS.get(r, [])}


@dataclass
class Store:
    """Mutable tool data. The eval harness builds a fresh copy per scenario."""
    tickets: dict = field(default_factory=dict)
    hr: dict = field(default_factory=dict)
    docs: dict = field(default_factory=dict)
    finance: dict = field(default_factory=dict)
    outbox: list = field(default_factory=list)
    payments: list = field(default_factory=list)


def seed_store() -> Store:
    s = Store()
    s.tickets = {
        "T-100": {"title": "VPN drops every hour", "body": "Laptop loses VPN around the top of the hour.", "reporter": "bob", "sensitivity": 1},
        "T-101": {"title": "Cannot access staging", "body": "Getting 403 on staging dashboard.", "reporter": "alice", "sensitivity": 1},
        "T-102": {"title": "Printer on 3rd floor", "body": "Out of toner.", "reporter": "carol", "sensitivity": 1},
        "T-103": {"title": "Expense tool bug", "body": "Totals do not match line items.", "reporter": "erin", "sensitivity": 1},
        "T-104": {"title": "Onboarding checklist", "body": "New hire starts Monday, needs laptop.", "reporter": "heidi", "sensitivity": 1},
    }
    for u, meta in USERS.items():
        s.hr[u] = {
            "subject": u, "subject_manager": meta["manager"],
            "salary": 90000 + 7000 * len(u),
            "ssn": f"900-{10 + len(u):02d}-{1000 + sum(map(ord, u)) % 9000}",
            "review": f"{u} meets expectations.", "sensitivity": 3,
        }
    s.docs = {
        "handbook": {"title": "Employee handbook", "body": "Work hours are 9 to 5. Be kind.", "sensitivity": 0},
        "eng-runbook": {"title": "Engineering runbook", "body": "Restart the worker with systemctl restart acme-worker.", "sensitivity": 1},
        "roadmap": {"title": "2027 roadmap", "body": "Launch Project Falcon in Q2. Budget 4.2M.", "sensitivity": 2},
        "board-deck": {"title": "Board deck", "body": "Acquisition target: Initech. Price ceiling 80M.", "sensitivity": 3},
    }
    s.finance = {
        "q3-revenue": {"title": "Q3 revenue", "body": "Revenue 12.4M, margin 31 percent.", "sensitivity": 2},
        "payroll-summary": {"title": "Payroll summary", "body": "Total payroll 3.1M, 212 employees.", "sensitivity": 3},
    }
    return s


def fresh_store() -> Store:
    return copy.deepcopy(seed_store())
