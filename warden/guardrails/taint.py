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


_WORDS = {w: str(i) for i, w in enumerate("zero one two three four five six seven eight nine".split())}
_WORDS.update({w: str(i) for i, w in enumerate("cero uno dos tres cuatro cinco seis siete ocho nueve".split())})
_WORD_RE = re.compile(r"\b(" + "|".join(_WORDS) + r")\b", re.I)
_RUN_RE = re.compile(r"\d(?:[\s.,_/-]*\d)+")
MIN_DIGITS = 6


def digits_of(value: str) -> str:
    return re.sub(r"\D", "", value)


def digit_runs(payload: str) -> list[str]:
    """Digit sequences in the payload with separators removed, after spelling digits out as numerals."""
    text = _WORD_RE.sub(lambda m: " " + _WORDS[m.group(1).lower()] + " ", payload)
    return [digits_of(r) for r in _RUN_RE.findall(text)]


@dataclass
class TaintState:
    values: dict[str, tuple[str, float]] = field(default_factory=dict)   # fingerprint -> (source, ts)
    digits: dict[str, tuple[str, float]] = field(default_factory=dict)   # normalised digit strings
    shingles: dict[str, tuple[str, float]] = field(default_factory=dict)
    max_sensitivity: int = 0
    last_sensitive_ts: float = 0.0

    def add(self, source: str, data, sensitivity: int, now: float, normalize: bool = False):
        self.max_sensitivity = max(self.max_sensitivity, sensitivity)
        self.last_sensitive_ts = now
        for v in _leaf_values(data):
            n = _norm(v)
            if len(n) >= MIN_FINGERPRINT:
                self.values[n] = (source, now)
            for sh in _shingles(v):
                self.shingles[sh] = (source, now)
            if normalize and len(digits_of(v)) >= MIN_DIGITS:
                self.digits[digits_of(v)] = (source, now)

    def active(self, now: float) -> bool:
        return self.max_sensitivity >= 2 and now - self.last_sensitive_ts < TTL

    def recent(self, now: float, window: float = 600.0) -> bool:
        return self.max_sensitivity >= 2 and now - self.last_sensitive_ts < window

    def overlap(self, payload: str, now: float, normalize: bool = False) -> list[str]:
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
        if normalize:
            for run in digit_runs(payload):
                for fp, (src, ts) in self.digits.items():
                    if now - ts < TTL and fp in run:
                        sources.add(src)
        return sorted(sources)
