from eval import harness as h
from eval import metrics as m


def test_corpus_sizes():
    assert len(h.load("attacks")) >= 75
    assert len(h.load("benign")) >= 150


def test_ids_unique():
    ids = [s["id"] for s in h.load("attacks") + h.load("benign")]
    assert len(ids) == len(set(ids))


def test_authz_only_blocks_privilege_attacks():
    atk = [a for a in h.load("attacks") if a["category"] in ("confused_deputy", "priv_esc")]
    assert not any(o.harm_executed for o in h.run_corpus("v0", atk))


def test_benign_all_complete_without_guardrails():
    assert all(o.completed for o in h.run_corpus("v0", h.load("benign")[:40]))


def test_wilson_and_bootstrap():
    lo, hi = m.wilson(0, 99)
    assert lo == 0 and 0.03 < hi < 0.05
    d, lo, hi = m.paired_bootstrap([0] * 50, [1] * 10 + [0] * 40)
    assert abs(d - 0.2) < 1e-9 and lo <= d <= hi
