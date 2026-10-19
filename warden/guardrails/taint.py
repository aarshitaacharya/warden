"""Taint tracking: remember what sensitive data an actor has seen, detect it leaving."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

TTL = 3600
MIN_FINGERPRINT = 5


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower()).strip()


def _leaf_values(data) -> list[str]:
    if isinstance(data, dict):
        return [v for x in data.values() for v in _leaf_values(x)]
    if isinstance(data, (list, tuple)):
        return [v for x in data for v in _leaf_values(x)]
    return [] if data is None else [str(data)]


def _shingles(text: str, n: int = 3) -> set[str]:
    w = re.findall(r"[a-z0-9]+", _norm(text))
    return {" ".join(w[i:i + n]) for i in range(len(w) - n + 1)}


def _decoded_variants(payload: str) -> list[str]:
    out = []
    for tok in re.findall(r"[A-Za-z0-9+/=_-]{16,}", payload):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(fn(tok + "=" * (-len(tok) % 4)).decode("utf-8", "ignore"))
            except Exception:
                pass
        try:
            out.append(bytes.fromhex(tok).decode("utf-8", "ignore"))
        except Exception:
            pass
    return out


@dataclass
class TaintState:
    values: dict[str, tuple[str, float]] = field(default_factory=dict)   # fingerprint -> (source, ts)
    shingles: dict[str, tuple[str, float]] = field(default_factory=dict)
    max_sensitivity: int = 0
    last_sensitive_ts: float = 0.0

    def add(self, source: str, data, sensitivity: int, now: float):
        self.max_sensitivity = max(self.max_sensitivity, sensitivity)
        self.last_sensitive_ts = now
        for v in _leaf_values(data):
            n = _norm(v)
            if len(n) >= MIN_FINGERPRINT:
                self.values[n] = (source, now)
            for sh in _shingles(v):
                self.shingles[sh] = (source, now)

    def active(self, now: float) -> bool:
        return self.max_sensitivity >= 2 and now - self.last_sensitive_ts < TTL

    def overlap(self, payload: str, now: float) -> list[str]:
        """Sources whose tainted values appear in payload, including simple encodings."""
        if not self.active(now):
            return []
        sources = set()
        for variant in [payload] + _decoded_variants(payload):
            n = _norm(variant)
            for fp, (src, ts) in self.values.items():
                if now - ts < TTL and fp in n:
                    sources.add(src)
            ps = _shingles(variant)
            for sh in ps:
                hit = self.shingles.get(sh)
                if hit and now - hit[1] < TTL:
                    sources.add(hit[0])
        return sorted(sources)
