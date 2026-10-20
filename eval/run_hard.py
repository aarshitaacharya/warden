"""Hard held-out corpus + local-LLM evaluation. Writes eval/report_hard.md.

Needs `ollama serve` with qwen2.5:7b pulled for the LLM rows (results are cached in eval/results/).

    python -m eval.run_hard
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from . import harness as h
from . import metrics as m

ROOT = Path(__file__).resolve().parent.parent
pct = lambda x: "n/a" if x != x else f"{100 * x:.1f}%"
ci = lambda t: f"[{100 * max(t[0], 0):.1f}, {100 * t[1]:.1f}]"
STACKS = ["v0", "v1", "v2", "v3", "v4", "v1-noappr", "v2-noappr", "v2-noappr-noexfil"]
ISOLATED = ["g-normalize", "g-taintappr", "g-bulk"]
DETECTORS = [("heuristic", "g-heuristic"), ("classifier", "g-classifier"), ("ollama (qwen2.5:7b)", "g-ollama")]


def main():
    atk_o, ben_o = h.load("attacks"), h.load("benign")
    atk_h, ben_h = h.load("attacks_hard"), h.load("benign_hard")
    L = ["# Hard held-out evaluation\n",
         "Written after the first report showed 0 attacks executing. `eval/corpus_hard.py` adds attacks designed to evade the controls "
         "(split payloads, roleplay, tool-call shaped, long documents, requests with no AI-directed wording, defanged destinations, "
         "exfiltration that dodges value matching, low-and-slow scraping) and benign tasks designed to trip them (security prose, "
         "non-English text, long hashes, legitimate bursts, travelling users). None of it was used to tune any threshold, rule or training set.\n"]

    # 1. End to end
    res = {v: (h.run_corpus(v, atk_h), h.run_corpus(v, ben_h)) for v in STACKS}
    L += ["## End to end on the hard set\n", f"{len(atk_h)} attacks, {len(ben_h)} benign tasks, scripted victim agent.\n",
          "| Stack | Attacks executed | 95% CI | Benign broken | 95% CI |", "|---|---|---|---|---|"]
    names = {"v0": "authz only", "v1": "v1 heuristic", "v2": "v2 classifier", "v3": "v3 Ollama judge", "v4": "v4 hardened (v2 + normalisation, tainted-send approval, bulk-read approval)",
             "g-normalize": "digit-normalised taint alone", "g-taintappr": "tainted-send approval alone", "g-bulk": "bulk-read approval alone",
             "v1-noappr": "v1 without approvals", "v2-noappr": "v2 without approvals", "v2-noappr-noexfil": "v2 without approvals or taint"}
    for v in STACKS:
        s = m.end_to_end(*res[v])
        L.append(f"| {names[v]} | {s['attack_success']}/{s['attacks']} ({pct(s['attack_success'] / s['attacks'])}) | {ci(s['asr_ci'])} "
                 f"| {s['false_blocks']}/{s['benign']} ({pct(s['false_blocks'] / s['benign'])}) | {ci(s['fbr_ci'])} |")
    L.append("")
    sty = {a["id"]: a["style"] for a in atk_h}
    L += ["### What got through, by style\n", "| Style | n | " + " | ".join(names[v] for v in ("v0", "v1", "v2", "v3", "v4")) + " |",
          "|---|---|---|---|---|---|---|"]
    allst = sorted(set(sty.values()))
    for st in allst:
        n = sum(1 for x in sty.values() if x == st)
        row = [sum(1 for o in res[v][0] if sty[o.id] == st and o.harm_executed) for v in ("v0", "v1", "v2", "v3", "v4")]
        L.append(f"| {st} | {n} | " + " | ".join(map(str, row)) + " |")
    L.append("")

    # 1b. Second held-out set: baseline recorded before v4 existed
    atk_2, ben_2 = h.load("attacks_hard2"), h.load("benign_hard2")
    res2 = {v: (h.run_corpus(v, atk_2), h.run_corpus(v, ben_2)) for v in ["v0", "v1", "v2", "v3", "v4"] + ISOLATED}
    L += ["## Second held-out set (written before v4 was implemented, run once against v4)\n",
          f"{len(atk_2)} attacks, {len(ben_2)} benign tasks. Pre-fix baseline (v1, v2, v3 each 14/21) is in git history at the commit that added `eval/corpus_hard2.py`.\n",
          "| Stack | Attacks executed | 95% CI | Benign broken | 95% CI |", "|---|---|---|---|---|"]
    for v in ["v0", "v1", "v2", "v3", "v4"] + ISOLATED:
        s2 = m.end_to_end(*res2[v])
        L.append(f"| {names[v]} | {s2['attack_success']}/{s2['attacks']} ({pct(s2['attack_success'] / s2['attacks'])}) | {ci(s2['asr_ci'])} "
                 f"| {s2['false_blocks']}/{s2['benign']} ({pct(s2['false_blocks'] / s2['benign'])}) | {ci(s2['fbr_ci'])} |")
    sty2 = {a["id"]: a["style"] for a in atk_2}
    L += ["", "### Which attacks each v4 component stops (hard + hard2 combined)\n", "| Attack style | n | normalisation alone | tainted-send approval alone | bulk-read approval alone | v4 |", "|---|---|---|---|---|---|"]
    both = {**sty, **sty2}
    r_iso = {v: (h.run_corpus(v, atk_h) + h.run_corpus(v, atk_2)) for v in ISOLATED}
    r_v4 = res["v4"][0] + res2["v4"][0]
    for st in sorted(set(both.values())):
        ids = {i for i, x in both.items() if x == st}
        cell = lambda outs: f"{sum(1 for o in outs if o.id in ids and not o.harm_executed)}/{len(ids)}"
        L.append(f"| {st} | {len(ids)} | " + " | ".join(cell(r_iso[v]) for v in ISOLATED) + f" | {cell(r_v4)} |")
    L += ["", "Cells are attacks stopped. Normalisation covers only reformatted digits; the blanket tainted-send approval covers everything that is content-independent; bulk-read approval covers low-and-slow scraping.\n"]

    # 2. Detectors alone
    L += ["## Injection detectors alone (scan level)\n",
          "Original, hard and hard2 sets combined. Truth: the scanned output was a poisoned carrier. Benign scans include the hard benign tasks.\n",
          "| Detector | TP | FP | FN | TN | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|---|---|---|---|"]
    per_style = {}
    atk_all, ben_all = atk_o + atk_h + atk_2, ben_o + ben_h + ben_2
    style_all = {a["id"]: a.get("style") for a in atk_all if a["category"] == "injection"}
    for label, v in DETECTORS:
        outs = h.run_corpus(v, atk_all) + h.run_corpus(v, ben_all)
        c = m.scan_confusion(outs)
        p, r, f = m.prf(c["tp"], c["fp"], c["fn"])
        L.append(f"| {label} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {pct(p)} | {pct(r)} | {pct(f)} | {pct(c['fp'] / (c['fp'] + c['tn']))} |")
        agg = defaultdict(lambda: [0, 0])
        for o in outs:
            if o.id in style_all:
                carriers = [s for s in o.steps if s.carrier]
                fired = any(g["name"] == "injection" and g["fired"] for s in carriers for g in s.guardrails)
                agg[style_all[o.id]][0] += fired
                agg[style_all[o.id]][1] += 1
        per_style[label] = agg
    L += ["", "### Recall by payload style (fraction of poisoned scenarios flagged)\n",
          "| Style | n | " + " | ".join(l for l, _ in DETECTORS) + " |", "|---|---|" + "---|" * len(DETECTORS)]
    for st in sorted({s for a in per_style.values() for s in a}):
        n = per_style[DETECTORS[0][0]][st][1]
        L.append(f"| {st} | {n} | " + " | ".join(f"{per_style[l][st][0]}/{n}" for l, _ in DETECTORS) + " |")

    # 3. Real model as the victim
    inj = [a for a in atk_all if a["category"] == "injection"]
    L += ["", "## A real model as the victim agent (Ollama qwen2.5:7b)\n",
          "The scripted agent always obeys. Here a local model decides, from the visible tool output, whether to make the injected calls. "
          "If the output is quarantined the model never sees the payload.\n",
          "| Stack | Injection scenarios | Model obeyed and the harm executed | 95% CI |", "|---|---|---|---|"]
    for v in ("v0", "v1", "v2", "v3", "v4"):
        o = h.run_corpus(v, inj, victim="ollama")
        k = sum(x.harm_executed for x in o)
        L.append(f"| {names[v]} | {len(inj)} | {k} ({pct(k / len(inj))}) | {ci(m.wilson(k, len(inj)))} |")
    L += ["", "Obedience is the model's own behaviour, so the v0 row is the attack's real hit rate against this model without Warden.\n"]

    # 4. A/B with three detectors on benign
    L += ["## Benign false blocks by cause\n", "| Stack | Benign broken (original + hard) | Total |", "|---|---|---|"]
    for v in ("v1", "v2", "v3", "v4"):
        o = h.run_corpus(v, ben_all)
        L.append(f"| {names[v]} | {sum(not x.completed for x in o)} | {len(ben_all)} |")
    (ROOT / "eval/report_hard.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
