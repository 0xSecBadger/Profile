# Local model evaluation — 18 November 2026

Two installed Qwen models were run against all 28 synthetic observations. Under this fixed setup, neither provides a reliable automatic PASS decision. Keep the deterministic verifier as the authority; model output is, at most, an untrusted aid to human triage.

## Observed results

“Agreement” means exact agreement with the deterministic oracle on this corpus. A false PASS means the model says PASS when the oracle says FAIL or INCONCLUSIVE. FAIL → PASS is the subset that misses an established contract violation.

| Model alias | Agreement / 28 | False PASS | FAIL → PASS / 7 | Invalid output | Median / total seconds |
|---|---:|---:|---:|---:|---:|
| qwen3:1.7b | 9/28 (32.1%) | 19 | 7/7 | 0/28 | 3.00 / 85.71 |
| qwen3:4b | 10/28 (35.7%) | 7 | 3/7 | 7/28 | 11.02 / 378.99 |

No API request failed. All seven invalid 4B outputs exhausted the 700-token generation budget and contained unfinished JSON. They remain errors in the denominator and were not retried or relabeled INCONCLUSIVE. The 1.7B run predicted PASS on every case. An always-INCONCLUSIVE baseline agrees on 12/28 cases; this class imbalance matters.

Rows below are oracle verdicts; columns are model predictions. Gold distribution: 9 PASS, 7 FAIL, 12 INCONCLUSIVE.

### qwen3:1.7b

| Gold | PASS | FAIL | INCONCLUSIVE | Invalid |
|---|---:|---:|---:|---:|
| PASS | 9 | 0 | 0 | 0 |
| FAIL | 7 | 0 | 0 | 0 |
| INCONCLUSIVE | 12 | 0 | 0 | 0 |
### qwen3:4b

| Gold | PASS | FAIL | INCONCLUSIVE | Invalid |
|---|---:|---:|---:|---:|
| PASS | 3 | 0 | 3 | 3 |
| FAIL | 3 | 2 | 0 | 2 |
| INCONCLUSIVE | 4 | 1 | 5 | 2 |

## Diagnostic checks

Exact fact-label matches out of 28; invalid outputs receive no credit. Definitions are explicit in the shared prompt and `diagnostic_gold()` in the script. These are separate transparent fact checks, not additional labels emitted by the verdict oracle. The scope and request labels deliberately ignore irrelevant events. “No submission evidenced” does **not** mean proof of no effect.

| Check | 1.7B | 4B |
|---|---:|---:|
| scope | 26/28 | 20/28 |
| request | 26/28 | 17/28 |
| timing | 25/28 | 11/28 |
| revocation | 18/28 | 9/28 |
| mutation | 8/28 | 16/28 |
| missing | 26/28 | 11/28 |

High scores on mostly constant labels are not evidence of sound reasoning. Free-text reasons are preserved but not given a subjective numeric score; several contradict the observations.

## Protocol and limits

- One complete pass per model in corpus order; fresh two-message conversation each case. No warm-up, retries, few-shot examples, selective omission, or prompt changes after seeing results.
- Fixed local endpoint `http://localhost:11434/api/chat`; Ollama server 0.40.16; Python standard library only. No downloads, external targets, real service operations, or new dependencies.
- Identical system prompt, JSON output schema, `think:false`, `temperature:0`, `seed:20261118`, `num_ctx:8192`, `num_predict:700`, `stream:false`, `keep_alive:5m`. Requested settings and server responses are logged; a fixed seed does not promise bitwise reproducibility across runtime or hardware versions.
- The model sees the general contract and observations only. Scenario ID, title, fault model, expected behavior and oracle verdict are withheld. Field-aware pseudonyms remove scenario numbers from identifiers while preserving equality and mismatch relationships. Assistant claims remain explicitly untrusted observation text.
- Oracle verdicts are freshly recomputed from `src/retest_lab/verifier.py` and checked against `results/report.json`. The model never supplies the oracle. Six diagnostic labels are derived separately by the transparent helper from the same observations.
- This is a small, fixed synthetic development corpus, not a held-out or general model/security benchmark. The long contract, schema, disabled thinking and output budget are part of the evaluated setup. Timing includes the first model load and benefits from later prompt caching; it is machine-specific.
- The installed `qwen3:1.7b` alias reports `parameter_size: "2.0B"` in local metadata. Keep the alias and full digest when identifying this artifact; do not silently normalize that discrepancy. Both models report Q4_K_M quantization.
- Original engine report flags such as `no_slm` describe the deterministic engine run only. These separate artifacts document actual local model calls. No result establishes production safety or a vulnerability in any organization.

## Inspect and reproduce

- [Evaluator](evaluate.py): complete prompt, schema, blinding, oracle cross-check and scoring.
- 1.7B: [public metadata](qwen3_1_7b/metadata.public.json), [all raw requests/responses](qwen3_1_7b/raw.jsonl), [summary and diagnostic matrices](qwen3_1_7b/summary.json).
- 4B: [public metadata](qwen3_4b/metadata.public.json), [all raw requests/responses](qwen3_4b/raw.jsonl), [summary and diagnostic matrices](qwen3_4b/summary.json).
- [Offline audit](audit.py) checks every request, oracle, output, count and relevant hash. [Public export script](export_public.py) packages the minimal oracle sources, saved corpus/report, scripts and complete public run logs. `public-manifest.json` / archive `PUBLIC-MANIFEST.json` supplies file hashes.

From the project or extracted public-bundle root:

```sh
python3 evaluation/audit.py
python3 evaluation/evaluate.py --model qwen3:1.7b --output qwen3_1_7b_repeat_01
python3 evaluation/evaluate.py --model qwen3:4b --output qwen3_4b_repeat_01
```

The last two commands require the already-installed models and local Ollama. Existing runs are never overwritten. The audit works offline and accepts `metadata.public.json` without private metadata. Public metadata omits only `model_show.modelfile`, which contains an irrelevant local model-blob path; template, digest, version, options, full prompts and every raw response remain available. Original metadata is retained locally and must be excluded from public archives. This evaluation was produced with AI coding assistance.
