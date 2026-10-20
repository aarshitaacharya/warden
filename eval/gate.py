"""CI gate: fail if recall drops or false blocks rise past eval/thresholds.json.

    python -m eval.gate
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import harness as h

THRESH = json.loads((Path(__file__).parent / "thresholds.json").read_text())


def main() -> int:
    failures = []
    for key, t in THRESH.items():
        v, hard = key.removesuffix("-hard"), key.endswith("-hard")
        atk, ben = (h.load("attacks_hard"), h.load("benign_hard")) if hard else (h.load("attacks"), h.load("benign"))
        a, b = h.run_corpus(v, atk), h.run_corpus(v, ben)
        asr = sum(o.harm_executed for o in a) / len(a)
        fbr = sum(not o.completed for o in b) / len(b)
        inj = [o for o in a if o.category == "injection"]
        rec = sum(any(g["name"] == "injection" and g["fired"] for s in o.steps if s.carrier for g in s.guardrails) for o in inj) / len(inj)
        min_rec = t.get("min_injection_recall", 0.0)
        print(f"{key}: attack_success={asr:.3f} (max {t['max_attack_success_rate']})  "
              f"false_block={fbr:.3f} (max {t['max_false_block_rate']})  injection_recall={rec:.3f} (min {min_rec})")
        if asr > t["max_attack_success_rate"]:
            failures.append(f"{key}: attack success rate {asr:.3f} > {t['max_attack_success_rate']}")
        if fbr > t["max_false_block_rate"]:
            failures.append(f"{key}: false block rate {fbr:.3f} > {t['max_false_block_rate']}")
        if rec < min_rec:
            failures.append(f"{key}: injection recall {rec:.3f} < {min_rec}")
    for f in failures:
        print("FAIL", f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
