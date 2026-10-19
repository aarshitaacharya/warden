"""Adaptive risk score from behavioural signals."""
from __future__ import annotations

from collections import defaultdict, deque

BURST_WINDOW = 10.0
INJECTION_MEMORY = 600.0
DENIAL_WINDOW = 300.0


class RiskModel:
    def __init__(self):
        self.requests: dict[str, deque] = defaultdict(deque)
        self.denials: dict[str, deque] = defaultdict(deque)
        self.known_devices: dict[str, set] = defaultdict(set)
        self.injection_ts: dict[str, float] = {}

    def seed_devices(self, devices: dict[str, set]):
        for k, v in devices.items():
            self.known_devices[k] |= set(v)

    def score(self, key: str, user: str | None, device_id: str | None, action: str,
              last_sensitive_ts: float, now: float) -> tuple[float, list[str]]:
        from ..acme import OUTBOUND_ACTIONS
        sig, score = [], 0.0
        q = self.requests[key]
        while q and now - q[0] > BURST_WINDOW:
            q.popleft()
        q.append(now)
        if len(q) > 50:
            sig.append("burst_severe"); score += 60
        elif len(q) > 20:
            sig.append("burst"); score += 30
        if user and device_id and self.known_devices[user] and device_id not in self.known_devices[user]:
            sig.append("new_device"); score += 25
        if action in OUTBOUND_ACTIONS and last_sensitive_ts and now - last_sensitive_ts < 600:
            sig.append("sensitive_read_then_outbound"); score += 35
        if now - self.injection_ts.get(key, -1e9) < INJECTION_MEMORY:
            sig.append("recent_injection"); score += 40
        d = self.denials[key]
        while d and now - d[0] > DENIAL_WINDOW:
            d.popleft()
        if len(d) >= 6:
            sig.append("many_denials"); score += 40
        elif len(d) >= 3:
            sig.append("repeat_denials"); score += 20
        return min(100.0, score), sig

    def record_denial(self, key: str, now: float):
        self.denials[key].append(now)

    def record_injection(self, key: str, now: float):
        self.injection_ts[key] = now
