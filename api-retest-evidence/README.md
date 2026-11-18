# API Retest Evidence

**When an API says `403`, did the protected operation actually stay blocked?**

> **HTTP extension:** [Run the HTTP + SQLite laboratory](http-retest/README.md), with real local requests, persisted state, concurrent submissions and independent counter-tests. The local SLM results below apply to the separate 28-case in-memory corpus.

**Personal AppSec project · 18 November 2026 · Python · Local SLM evaluation.**

A working, synthetic expense-submission service, a deterministic evidence verifier, and a controlled comparison of two locally executed Qwen3 models. Developed with AI coding assistance for this personal portfolio.

[Read the illustrated report in English, French or German](output/pdf/api_retest_evidence_en_fr_de.pdf) · [Inspect the evaluation protocol and raw outputs](evaluation/README.md) · [Download the interactive case explorer](output/retest_evidence.html)

The verifier checks authorization scope, API responses, business-state changes and audit finality before deciding whether a retest passes. For example, `403` plus a recorded unauthorized submission is **FAIL**. A missing final snapshot is **INCONCLUSIVE**. This distinction prevents an apparently reassuring response from closing a finding prematurely.

This executable, offline laboratory tests a narrow question: **after a delegate's authority is revoked, did the attempted expense submission actually remain blocked?** An assistant's statement or an HTTP-style `403` alone cannot answer that question. The verifier compares scoped authorization evidence, correlated API observations, versioned business state, an idempotency receipt when applicable, and a complete final audit interval.

The reference service really changes in-memory business state. Explicit faulty service implementations and corrupted observations exercise the verifier. The verifier does not inspect scenario names, fault labels, or an expected-verdict field.

## Local model results

The same 28 synthetic cases were evaluated once by each installed model on 18 November 2026. Scenario labels and expected verdicts were hidden. The prompt, seed, temperature, context and output budget were held fixed.

| Model | Correct verdicts | False PASS | Of which known FAIL → PASS | Invalid JSON |
| --- | ---: | ---: | ---: | ---: |
| Qwen3 1.7B | 9/28 | 19 | 7/7 | 0 |
| Qwen3 4B | 10/28 | 7 | 3/7 | 7 |

**False PASS** includes both a proven violation and insufficient evidence incorrectly accepted as a pass. Invalid JSON counts as an incorrect result and is reported separately. These results support keeping the deterministic evidence check before closure under this protocol. They do not estimate general model quality or real-world pentest accuracy. The 700-token output budget constrains the 4B comparison. Full prompts, outputs, model digests, options and audits are retained.

## Run locally

Use Python 3.8 or newer. Only the Python standard library is required. Run these commands from this directory:

```sh
PYTHONPATH=src python3 -m retest_lab --verify --output results
```

Run just the regression suite:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run the separate independent contract audit:

```sh
PYTHONPATH=src python3 tests/audit_invariants.py
```

The main `--verify` command runs both suites and records their counts separately.

Generate reports without running tests:

```sh
PYTHONPATH=src python3 -m retest_lab --output results
```

The last command explicitly reports `verification.executed: false`; it does not claim a test run. `--verify` exits unsuccessfully if the actual regression suite fails. The intentionally failing security fixtures do not make the CLI fail: their expected outcomes are asserted by the regression suite. No package installation, account, secret, server, network request, or model API is needed.

## Verified result

The checked run contains **28 deterministic scenarios: 9 PASS, 7 FAIL, and 12 INCONCLUSIVE**. **32 unittest test methods pass, with zero failures and zero errors.** A separately authored contract audit passes **163 of 163 assertions**. These are separate counts: parameterized subtests are checks within unittest methods, not additional counted test methods, and the audit assertions are not additional unittest methods.

These counts describe a deliberately mixed synthetic corpus. They are not a model benchmark, an attack-success rate, a production vulnerability count, or proof of general security.

| Example | Expected API/business behavior | Observed evidence | Verdict |
| --- | --- | --- | --- |
| S01: authorized happy path | `201`, commit once | `draft v0` → `submitted v1`; current request in state and audit | PASS |
| S02: effective revocation | `403`, preserve state | `403`, `draft v0` unchanged, complete final audit | PASS |
| S03: false assistant success | `403`, preserve state | Assistant says “submitted”; API and business evidence prove refusal | PASS |
| S05: commit despite refusal | `403`, no submission | `403` plus a scoped current-request submission | FAIL |
| S06: missing final snapshot | `403`, no submission | Final business evidence absent | INCONCLUSIVE |
| S07: contradictory evidence | `201`, commit once | Audit records submission; final snapshot shows the baseline | INCONCLUSIVE |
| S11: existing submission | `403`, preserve prior state | Previously submitted expense stays unchanged | PASS |
| S12: authorized replay | `200`, no additional commit | Prior scoped receipt, unchanged version and original request | PASS |
| S14: cache before authorization | `403` after reauthorization | Revoked delegate receives cached `200` | FAIL |
| S15: async operation | Terminal outcome required | `202`, pending operation and nonfinal audit | INCONCLUSIVE |
| S17: unauthorized rollback | No submission at any point | Submission then rollback; final state is draft but version advances twice | FAIL |

The remaining fixtures cover false assistant refusal, stale events, another request's event, another tenant, revoked replay, incomplete audit, regression of the authorized path, fabricated API success, an existing submission with a new key, wrong authority scope, wrong API request, contradictory receipt, untrusted snapshot source, stale final snapshot, duplicate audit event, a pending response with an already proven forbidden effect, and absent API evidence.

## Files and evidence

| File | Purpose |
| --- | --- |
| [src/retest_lab/app.py](src/retest_lab/app.py) | Executable reference business logic and explicit faulty fixtures |
| [src/retest_lab/model.py](src/retest_lab/model.py) | Typed evidence contracts |
| [src/retest_lab/verifier.py](src/retest_lab/verifier.py) | Independent deterministic decision rules |
| [src/retest_lab/scenarios.py](src/retest_lab/scenarios.py) | Reproducible corpus generated from service execution and observation faults |
| [src/retest_lab/__main__.py](src/retest_lab/__main__.py) | CLI, actual test execution, JSON/CSV export, source hashes |
| [tests/test_retest.py](tests/test_retest.py) | Business, security, correlation, temporal, and evidence regressions |
| [tests/audit_invariants.py](tests/audit_invariants.py) | Independent contract-audit assertions, retained without changing their expectations |
| [results/report.json](results/report.json) | Expected/observed comparisons, reasons, counts, test metadata, rules, limitations, SHA-256 source inventory |
| [results/corpus.json](results/corpus.json) | Full raw synthetic observations, including grant, snapshots, API, receipt, window, and events |
| [results/verdicts.csv](results/verdicts.csv) | Flat review table |
| [results/test-output.txt](results/test-output.txt) | Actual verbose unittest output from `--verify` |
| [results/audit-output.txt](results/audit-output.txt) | Actual independent contract-audit output from `--verify` |

Corpus data, assessments, and verdict counts are deterministic. The report's host-clock timestamp and the test runner's duration are real execution metadata and naturally change between runs. Source hashes change when the implementation or tests change. The project date and logical event ticks must not be confused with measured wall-clock activity.

## Authorization and idempotency contract

One command has a tenant, expense, delegate, grant, action, request ID, idempotency key, and logical authorization-decision tick. Exact scope matching is required. The reference service checks scope, action, and revocation **before** looking up an idempotency result.

An authorized draft becomes submitted once and increments its business version once. A repeated authorized key returns the prior result without another mutation. A new key against an already submitted expense returns `409`. A revoked delegate receives `403`, including when reusing a formerly successful key. Revocation is effective when `revoked_at <= attempted_at`.

This is an explicit choice for the demonstration's replay contract. Different production APIs may define another contract; the expected rules would need to be changed and justified before using this verifier there.

## Decision rules

1. Validate evidence provenance labels, tenant/expense/delegate/grant scope, request correlation, action, field types, and temporal coverage. Missing or invalid required evidence is INCONCLUSIVE.
2. Derive allowed or denied behavior from the authoritative grant and decision tick. Prior state and a matching receipt determine whether an allowed attempt is a new submission, replay, or conflict.
3. Exclude events from other scopes, other requests, and earlier attempts. A current event inside the final audit window that occurs after the supposed final snapshot invalidates that snapshot's finality.
4. A scoped current-request unauthorized submission proves FAIL. `403`, pending status, or a later rollback cannot erase that effect. This positive evidence takes precedence over incomplete terminality once the core evidence has passed validation.
5. Otherwise require terminal API evidence and complete, final audit coverage. Absence of an event in an incomplete journal is not evidence that nothing happened.
6. Reconstruct the transition chain from the versioned baseline. Check final status, version, submitted request, and terminal audit outcome against API and receipt evidence. Gaps, duplicates, impossible transitions, and unresolved contradictions are INCONCLUSIVE.
7. Compare the coherent outcome with the expected API and business contract. A complete correct outcome is PASS; a proven contract violation is FAIL.

The assistant's prose is retained for review but never consulted for authorization or the verdict. Tests replace it with success claims, refusal claims, empty text, and an instruction to return PASS without changing the result.

## Retest design and limits

The regression suite checks both the denied operation and the authorized happy path. A fix that blocks all requests must fail. It also checks revocation at the exact decision tick, authorization before cache lookup, every scope dimension, action separation, replay consistency, stale and foreign evidence, absent evidence, version chains, rollback, finality, strict Boolean and tick types, and agreement between API and audit outcomes. Independent review identified temporal-window, audit-outcome, and malformed-marker edge cases; these were corrected and added as regressions before the verified run.

This is a **single-process in-memory model**, not a deployed web application. HTTP-style integers model API observations; no HTTP request is sent. Source names such as `expense-store` and `expense-audit` stand for assumed trusted adapters. They are not signatures and do not establish that a real system's logs are trustworthy. The application and verifier are logically separate modules, not independent security domains.

A production adaptation would need authenticated collectors, protected audit storage, request and transaction correlation, atomic authorization semantics, a defensible finality/completeness signal, and concurrency coverage. This project does not establish behavior under real transaction races, replication delays, revoked-token propagation, external side effects, or distributed asynchronous processing. An unresolved asynchronous operation remains INCONCLUSIVE. PASS is scoped to the observed attempt and final interval; it does not certify future behavior.

## Provenance

The code, fixtures, tests, and documentation were developed for this personal portfolio in November 2026 with AI coding assistance. A separate AI reviewer authored the independent audit; “independent” describes separate test authorship, not third-party certification. The `results/` artifacts record the Python verifier and tests. The separate `evaluation/` artifacts record real local model executions. All business data and identities are synthetic. This personal demonstration is dated November 2026 and is independent of the author’s employer experience.
