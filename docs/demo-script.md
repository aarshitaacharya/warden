# Demo script (3 to 5 minutes)

Record the terminal on the left and `http://localhost:8000/dashboard` on the right.

1. **Setup (20s).** `uvicorn warden.gateway:app` in one terminal. Open the dashboard. Say: five tools, ten people, three agents, everything through one gateway.
2. **The attack (60s).** `python scripts/demo.py`. First block, policy v0 (authorization only): the agent reads a support ticket that hides an instruction, follows it, reads the roadmap and posts it to an attacker's server. "Everything it did was individually permitted."
3. **Same attack, full Warden (45s).** Second block: the ticket output is quarantined, the agent never sees the instruction. Show the decision row.
4. **Delegation (45s).** In a Python shell: ask `hr-assistant` for a salary as an engineer. Denied with `authz:user`, even though the agent itself has the scope. Explain the intersection rule.
5. **Exfiltration and approval (45s).** Agent reads an HR record then emails it externally: `guardrail:exfil_blocked`. Agent emails a partner with clean content: `pending_approval`, approve with a manager passkey token.
6. **Metrics (45s).** Open `eval/report.md`: 51% of attacks execute with authorization alone, 0% with Warden, 5 to 8% of benign tasks broken. Show the per-guardrail table and say which layer misses what.
7. **Incident (30s).** `python -m incident.simulate`, show the timeline and the postmortem.
