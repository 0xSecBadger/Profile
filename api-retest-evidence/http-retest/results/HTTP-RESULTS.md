# Executed HTTP retest results

Personal laboratory · 18 November 2026 · AI-assisted.

| Case | Mode | Verdict | HTTP requests | Security assertions |
|---|---|---|---:|---:|
| H01 — Authorized submission commits one business effect | fixed | PASS | 1 | 5 |
| H02 — Corrected implementation refuses without mutation | fixed | PASS | 2 | 3 |
| H03 — Vulnerable implementation returns403 after committing | vulnerable | FAIL | 2 | 3 |
| H04 — Authorized idempotent replay | fixed | PASS | 2 | 6 |
| H05 — Reauthorization takes precedence over cached replay | fixed | PASS | 3 | 4 |
| H06 — Vulnerable cache bypasses revoked permission | vulnerable | FAIL | 3 | 4 |
| H07 — Other tenant cannot be modified | fixed | PASS | 1 | 3 |
| H08 — View permission does not authorize submit | fixed | PASS | 1 | 3 |
| H09 — Twelve concurrent submissions with one idempotency key | fixed | PASS | 12 | 7 |
| H10 — Twelve concurrent submissions with different keys | fixed | PASS | 12 | 6 |
| H11 — SQLite state and receipts survive server restart | fixed | PASS | 2 | 6 |
| H12 — Unknown laboratory identity cannot mutate | fixed | PASS | 1 | 2 |
| H13 — Delegate cannot revoke a grant | fixed | PASS | 1 | 3 |
| H14 — Repeated correlation ID is rejected before replay | fixed | PASS | 2 | 4 |

Two intentional failures demonstrate the faulty implementation. The other cases use the corrected implementation.

All 14 expected fixture outcomes were observed. These are bounded synthetic tests, not a general security certification.
