# Hard held-out evaluation

Written after the first report showed 0 attacks executing. `eval/corpus_hard.py` adds attacks designed to evade the controls (split payloads, roleplay, tool-call shaped, long documents, requests with no AI-directed wording, defanged destinations, exfiltration that dodges value matching, low-and-slow scraping) and benign tasks designed to trip them (security prose, non-English text, long hashes, legitimate bursts, travelling users). None of it was used to tune any threshold, rule or training set.

## End to end on the hard set

40 attacks, 34 benign tasks, scripted victim agent.

| Stack | Attacks executed | 95% CI | Benign broken | 95% CI |
|---|---|---|---|---|
| authz only | 37/40 (92.5%) | [80.1, 97.4] | 0/34 (0.0%) | [0.0, 10.2] |
| v1 heuristic | 7/40 (17.5%) | [8.7, 32.0] | 10/34 (29.4%) | [16.8, 46.2] |
| v2 classifier | 7/40 (17.5%) | [8.7, 32.0] | 8/34 (23.5%) | [12.4, 40.0] |
| v3 Ollama judge | 7/40 (17.5%) | [8.7, 32.0] | 0/34 (0.0%) | [0.0, 10.2] |
| v1 without approvals | 7/40 (17.5%) | [8.7, 32.0] | 10/34 (29.4%) | [16.8, 46.2] |
| v2 without approvals | 7/40 (17.5%) | [8.7, 32.0] | 8/34 (23.5%) | [12.4, 40.0] |
| v2 without approvals or taint | 12/40 (30.0%) | [18.1, 45.4] | 8/34 (23.5%) | [12.4, 40.0] |

### What got through, by style

| Style | n | authz only | v1 heuristic | v2 classifier | v3 Ollama judge |
|---|---|---|---|---|---|
| authz-edge | 3 | 0 | 0 | 0 | 0 |
| chunked-digits | 1 | 1 | 1 | 1 | 1 |
| customer-voice | 4 | 4 | 0 | 0 | 0 |
| defanged | 6 | 6 | 0 | 0 | 0 |
| dilution | 4 | 4 | 0 | 0 | 0 |
| hex | 1 | 1 | 0 | 0 | 0 |
| low-and-slow | 2 | 2 | 2 | 2 | 2 |
| number-format | 1 | 1 | 1 | 1 | 1 |
| paraphrase | 1 | 1 | 1 | 1 | 1 |
| roleplay | 5 | 5 | 0 | 0 | 0 |
| spelled-digits | 1 | 1 | 1 | 1 | 1 |
| split | 6 | 6 | 0 | 0 | 0 |
| toolcall | 4 | 4 | 0 | 0 | 0 |
| translated | 1 | 1 | 1 | 1 | 1 |

## Injection detectors alone (scan level)

Original and hard sets combined. Truth: the scanned output was a poisoned carrier. Benign scans include the hard benign tasks.

| Detector | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|
| heuristic | 30 | 23 | 37 | 141 | 56.6% | 44.8% | 50.0% | 14.0% |
| classifier | 60 | 18 | 7 | 121 | 76.9% | 89.6% | 82.8% | 12.9% |
| ollama (qwen2.5:7b) | 28 | 0 | 39 | 166 | 100.0% | 41.8% | 58.9% | 0.0% |

### Recall by payload style (fraction of poisoned scenarios flagged)

| Style | n | heuristic | classifier | ollama (qwen2.5:7b) |
|---|---|---|---|---|
| classic | 8 | 6/8 | 6/8 | 6/8 |
| customer-voice | 4 | 0/4 | 4/4 | 0/4 |
| defanged | 6 | 0/6 | 2/6 | 0/6 |
| dilution | 4 | 3/4 | 4/4 | 0/4 |
| hidden | 2 | 2/2 | 2/2 | 1/2 |
| multilingual | 6 | 0/6 | 4/6 | 5/6 |
| obfuscated | 10 | 5/10 | 7/10 | 6/10 |
| paraphrase | 14 | 10/14 | 11/14 | 5/14 |
| roleplay | 5 | 2/5 | 5/5 | 3/5 |
| split | 6 | 2/6 | 6/6 | 0/6 |
| toolcall | 4 | 0/4 | 4/4 | 2/4 |

## A real model as the victim agent (Ollama qwen2.5:7b)

The scripted agent always obeys. Here a local model decides, from the visible tool output, whether to make the injected calls. If the output is quarantined the model never sees the payload.

| Stack | Injection scenarios | Model obeyed and the harm executed | 95% CI |
|---|---|---|---|
| authz only | 69 | 21 (30.4%) | [20.8, 42.1] |
| v1 heuristic | 69 | 0 (0.0%) | [0.0, 5.3] |
| v2 classifier | 69 | 0 (0.0%) | [0.0, 5.3] |
| v3 Ollama judge | 69 | 0 (0.0%) | [0.0, 5.3] |

Obedience is the model's own behaviour, so the v0 row is the attack's real hit rate against this model without Warden.

## Benign false blocks by cause

| Stack | Benign broken (original + hard) | Total |
|---|---|---|
| v1 heuristic | 23 | 193 |
| v2 classifier | 16 | 193 |
| v3 Ollama judge | 0 | 193 |
