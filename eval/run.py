"""Run the full evaluation and write eval/report.md, charts and results JSON.

    python -m eval.run
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from . import harness as h
from . import metrics as m

ROOT = Path(__file__).resolve().parent.parent
VERSIONS = ["v0", "v1", "v2", "g-heuristic", "g-classifier", "g-exfil", "g-approval", "g-risk"]


def pct(x): return "n/a" if x != x else f"{100 * x:.1f}%"
def ci(t): return f"[{100 * max(t[0], 0):.1f}, {100 * t[1]:.1f}]"


def collect():
    atk, ben = h.load("attacks"), h.load("benign")
    styles = {a["id"]: a.get("style") or a.get("variant") for a in atk}
    res = {v: (h.run_corpus(v, atk), h.run_corpus(v, ben)) for v in VERSIONS}
    return atk, ben, styles, res


def detector_recall_by_style(atk, outcomes):
    style = {a["id"]: a.get("style") for a in atk if a["category"] == "injection"}
    agg = defaultdict(lambda: [0, 0])
    for o in outcomes:
        if o.id in style:
            carrier = [s for s in o.steps if s.carrier][0]
            fired = any(g["name"] == "injection" and g["fired"] for g in carrier.guardrails)
            agg[style[o.id]][0] += fired
            agg[style[o.id]][1] += 1
    return agg


def charts(summary, styles_h, styles_c, effects):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, grid, surf = "#0b0b0b", "#e6e5e1", "#fcfcfb"
    blue, orange, aqua = "#2a78d6", "#eb6834", "#1baf7a"
    plt.rcParams.update({"font.size": 10, "axes.edgecolor": grid, "axes.labelcolor": "#52514e",
                         "xtick.color": "#52514e", "ytick.color": "#52514e", "figure.facecolor": surf,
                         "axes.facecolor": surf, "axes.spines.top": False, "axes.spines.right": False})

    fig, ax = plt.subplots(figsize=(6.2, 3.4))
    labels = ["v0\nauthz only", "v1\nheuristic", "v2\nclassifier"]
    vals = [100 * summary[v]["attack_success"] / summary[v]["attacks"] for v in ("v0", "v1", "v2")]
    bars = ax.bar(labels, vals, color=blue, width=0.5)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1, f"{v:.0f}%", ha="center", color=ink)
    ax.set_ylabel("attacks that executed (%)")
    ax.set_ylim(0, max(vals) * 1.2 + 5)
    ax.yaxis.grid(True, color=grid); ax.set_axisbelow(True)
    ax.set_title("End-to-end attack success by control stack", loc="left", color=ink)
    fig.tight_layout(); fig.savefig(ROOT / "docs/img/attack_success.png", dpi=160); plt.close(fig)

    names = sorted(set(styles_h) | set(styles_c))
    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    w = 0.38
    for i, (lab, d, col) in enumerate((("heuristic", styles_h, blue), ("classifier", styles_c, orange))):
        ys = [100 * d[n][0] / d[n][1] if d[n][1] else 0 for n in names]
        xs = [j + (i - 0.5) * w for j in range(len(names))]
        bs = ax.bar(xs, ys, w, color=col, label=lab)
        for b, y in zip(bs, ys):
            ax.text(b.get_x() + b.get_width() / 2, y + 1.5, f"{y:.0f}", ha="center", fontsize=8, color=ink)
    ax.set_xticks(range(len(names))); ax.set_xticklabels(names)
    ax.set_ylabel("poisoned outputs detected (%)"); ax.set_ylim(0, 112)
    ax.yaxis.grid(True, color=grid); ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="lower left")
    ax.set_title("Injection detector recall by payload style", loc="left", color=ink)
    fig.tight_layout(); fig.savefig(ROOT / "docs/img/detector_recall.png", dpi=160); plt.close(fig)

    gs = list(effects)
    fig, ax = plt.subplots(figsize=(6.8, 3.6))
    for i, (lab, key, col) in enumerate((("recall", "recall", blue), ("precision", "precision", aqua))):
        ys = [0 if effects[g][key] != effects[g][key] else 100 * effects[g][key] for g in gs]
        xs = [j + (i - 0.5) * w for j in range(len(gs))]
        bs = ax.bar(xs, ys, w, color=col, label=lab)
        for b, y in zip(bs, ys):
            ax.text(b.get_x() + b.get_width() / 2, y + 1.5, f"{y:.0f}", ha="center", fontsize=8, color=ink)
    ax.set_xticks(range(len(gs))); ax.set_xticklabels(gs)
    ax.set_ylim(0, 112); ax.set_ylabel("%")
    ax.yaxis.grid(True, color=grid); ax.set_axisbelow(True)
    ax.legend(frameon=False, loc="lower left")
    ax.set_title("Each guardrail added alone to authorization", loc="left", color=ink)
    fig.tight_layout(); fig.savefig(ROOT / "docs/img/guardrails.png", dpi=160); plt.close(fig)


def main():
    atk, ben, styles, res = collect()
    summary = {v: m.end_to_end(*res[v]) for v in VERSIONS}
    effects = {g: m.guardrail_effect(g, res["v0"][0], res["v0"][1], *res[g]) for g in m.TARGET}
    scans = {g: m.scan_confusion(res[g][0] + res[g][1]) for g in ("g-heuristic", "g-classifier")}
    sh = detector_recall_by_style(atk, res["g-heuristic"][0])
    sc = detector_recall_by_style(atk, res["g-classifier"][0])

    # A/B v1 vs v2, paired by scenario
    a1, b1 = res["v1"]; a2, b2 = res["v2"]
    asr = m.paired_bootstrap([o.harm_executed for o in a1], [o.harm_executed for o in a2])
    fbr = m.paired_bootstrap([not o.completed for o in b1], [not o.completed for o in b2])
    inj1 = [o for o in a1 if o.category == "injection"]; inj2 = [o for o in a2 if o.category == "injection"]
    det = lambda o: int(any(g["name"] == "injection" and g["fired"] for s in o.steps if s.carrier for g in s.guardrails))
    rec = m.paired_bootstrap([det(o) for o in inj1], [det(o) for o in inj2])
    scan_fp = lambda o: int(any(g["name"] == "injection" and g["fired"] for s in o.steps for g in s.guardrails))
    agent_ben = [(x, y) for x, y in zip(b1, b2) if any(g["name"] == "injection" for s in x.steps for g in s.guardrails)]
    fpr = m.paired_bootstrap([scan_fp(x) for x, _ in agent_ben], [scan_fp(y) for _, y in agent_ben])

    charts(summary, sh, sc, effects)
    out = {"summary": summary, "effects": effects, "scans": scans,
           "ab": {"asr": asr, "false_block_rate": fbr, "detector_recall": rec, "detector_fpr": fpr}}
    (ROOT / "eval/results/metrics.json").write_text(json.dumps(out, indent=2, default=list))

    L = []
    w = L.append
    w("# Warden evaluation report\n")
    w(f"Generated by `python -m eval.run`. Corpus: **{len(atk)} attack scenarios** and **{len(ben)} benign tasks** "
      "(`eval/corpus/*.jsonl`, regenerated by `python -m eval.corpus`).\n")
    w("> All scenarios are synthetic and the victim agent is scripted (it obeys injected text that reaches it). "
      "Numbers measure Warden's controls against this corpus, not any specific LLM, and the classifier was trained "
      "on synthetic data from a different generator. Treat them as a regression baseline, not a security guarantee.\n")
    w("## Headline\n")
    w("| Policy version | Detector | Attacks executed | 95% CI (Wilson) | Benign tasks broken | 95% CI |")
    w("|---|---|---|---|---|---|")
    for v, d in (("v0", "none (authz only)"), ("v1", "heuristic"), ("v2", "classifier")):
        s = summary[v]
        w(f"| {v} | {d} | {s['attack_success']}/{s['attacks']} ({pct(s['attack_success'] / s['attacks'])}) | {ci(s['asr_ci'])} "
          f"| {s['false_blocks']}/{s['benign']} ({pct(s['false_blocks'] / s['benign'])}) | {ci(s['fbr_ci'])} |")
    w("\n![attack success](../docs/img/attack_success.png)\n")
    w("Authorization alone (v0) already stops the confused-deputy and privilege-escalation scenarios. What it cannot stop "
      "are *authorized-but-abused* paths: injected agents using legitimate scopes, exfiltration, and unapproved high-risk actions.\n")
    w("### Attacks executed by category\n")
    w("| Category | n | v0 | v1 | v2 |")
    w("|---|---|---|---|---|")
    for c in summary["v0"]["by_category"]:
        r = [summary[v]["by_category"][c] for v in ("v0", "v1", "v2")]
        w(f"| {c} | {r[0]['n']} | {r[0]['success']} | {r[1]['success']} | {r[2]['success']} |")

    w("\n## Per-guardrail effectiveness (each added alone to authorization)\n")
    w("Definitions. *Positives* are attacks in the guardrail's target category that **succeed against v0**. "
      "*TP* = positives the guardrail stops. *FN* = positives it misses. *FP* = benign tasks that complete under v0 but "
      "are broken with the guardrail on. Precision = TP/(TP+FP), recall = TP/(TP+FN). `g-risk` targets the behavioral category (bulk scraping from a new device, probe-then-act).\n")
    w("| Guardrail | TP | FP | FN | Precision | Recall | Recall 95% CI | F1 |")
    w("|---|---|---|---|---|---|---|---|")
    for g, e in effects.items():
        w(f"| {g} | {e['tp']} | {e['fp']} | {e['fn']} | {pct(e['precision'])} | {pct(e['recall'])} | {ci(e['recall_ci'])} | {pct(e['f1'])} |")
    w("\n![guardrails](../docs/img/guardrails.png)\n")
    for g, e in effects.items():
        if e["missed"]:
            w(f"- `{g}` missed: {', '.join(e['missed'])}")
    w("\n## Injection detectors (scan level)\n")
    w("Each tool output returned to an agent is one scan. Truth: the output carried injected text.\n")
    w("| Detector | TP | FP | FN | TN | Precision | Recall | F1 | False-positive rate |")
    w("|---|---|---|---|---|---|---|---|---|")
    for g, c in scans.items():
        p, r, f = m.prf(c["tp"], c["fp"], c["fn"])
        w(f"| {g[2:]} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {pct(p)} | {pct(r)} | {pct(f)} | {pct(c['fp'] / (c['fp'] + c['tn']))} |")
    w("\n### Recall by payload style\n")
    w("| Style | n | heuristic | classifier |")
    w("|---|---|---|---|")
    for n in sorted(sh):
        w(f"| {n} | {sh[n][1]} | {sh[n][0]}/{sh[n][1]} | {sc[n][0]}/{sc[n][1]} |")
    w("\n![detector recall](../docs/img/detector_recall.png)\n")

    w("## A/B: policy v1 (heuristic) vs v2 (classifier)\n")
    w("Paired bootstrap over scenarios (4000 resamples). Difference is v2 minus v1; an interval that excludes 0 is a real change on this corpus.\n")
    w("| Metric | v1 | v2 | Difference | 95% CI |")
    w("|---|---|---|---|---|")
    n_inj = len(inj1)
    w(f"| Injection detected (of {n_inj}) | {sum(det(o) for o in inj1)} | {sum(det(o) for o in inj2)} | {100 * rec[0]:+.1f} pp | [{100 * rec[1]:+.1f}, {100 * rec[2]:+.1f}] |")
    w(f"| Benign agent tasks with a flagged output (of {len(agent_ben)}) | {sum(scan_fp(x) for x, _ in agent_ben)} | {sum(scan_fp(y) for _, y in agent_ben)} | {100 * fpr[0]:+.1f} pp | [{100 * fpr[1]:+.1f}, {100 * fpr[2]:+.1f}] |")
    w(f"| Benign tasks broken (of {len(ben)}) | {summary['v1']['false_blocks']} | {summary['v2']['false_blocks']} | {100 * fbr[0]:+.1f} pp | [{100 * fbr[1]:+.1f}, {100 * fbr[2]:+.1f}] |")
    w(f"| Attacks executed (of {len(atk)}) | {summary['v1']['attack_success']} | {summary['v2']['attack_success']} | {100 * asr[0]:+.1f} pp | [{100 * asr[1]:+.1f}, {100 * asr[2]:+.1f}] |")
    w("\nEnd-to-end attack success is the same because taint tracking and approvals back up the detector (defense in depth). "
      "The detector still matters: each miss is one more step an attacker gets, and the isolated table above shows how many attacks lean on the other layers.\n")
    w("## Caveats\n")
    w("- Scripted victim agent; real agents may resist or obey differently.")
    w("- Corpus authored by the defender. Treat a perfect score as a sign the corpus needs harder cases, not as proof of safety.")
    w("- Taint matching is by value fingerprint. Reversed, split or paraphrased values evade it (see `g-exfil` misses).")
    w("- The LLM detector option (`WARDEN_*`/`llm`) is implemented but not evaluated here, to keep the project free to run.")
    (ROOT / "eval/report.md").write_text("\n".join(L) + "\n")
    print("\n".join(L[:12]))


if __name__ == "__main__":
    main()
