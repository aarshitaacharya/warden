"""MCP front end for agents. Each Acme tool is an MCP tool; every call is routed
through the Warden enforcement point using the caller's delegated token.

    WARDEN_TOKEN=<agent token> python -m warden.mcp_server

A real deployment would run the gateway as a separate service and this proxy
would call it over HTTP; here it calls the engine in process.
"""
from __future__ import annotations

import json
import os

from mcp.server.mcpserver import MCPServer

from . import acme
from .engine import Warden


def build_server(warden: Warden, token_provider=lambda: os.environ.get("WARDEN_TOKEN", ""),
                 session_id: str | None = None) -> MCPServer:
    server = MCPServer("acme-tools-via-warden")

    def make(action: str):
        def call(args: dict) -> str:
            r = warden.handle(token_provider(), action, args, session_id=session_id)
            if r.decision != "allow":
                return json.dumps({"error": r.decision, "reason": r.reason, "request_id": r.request_id,
                                   "approval_id": r.approval_id})
            return json.dumps(r.data)
        call.__name__ = action.replace(":", "_")
        return call

    for action in acme.ACTIONS:
        server.tool(name=action.replace(":", "_"), description=f"Acme tool {action}; arguments go in `args`.")(make(action))
    return server


if __name__ == "__main__":
    build_server(Warden(version=os.environ.get("WARDEN_POLICY_VERSION", "v1"))).run()
