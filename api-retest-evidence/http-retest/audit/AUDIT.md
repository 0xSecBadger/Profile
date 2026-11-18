# Independent HTTP/SQLite contract audit

Recorded 2026-11-18T18:34:04.337934+00:00. Personal laboratory developed with AI assistance in November 2026. The audit script was authored separately from the service and the demonstration runner; this is independent test authorship, not third-party certification.

**21 test methods passed, zero failures and zero errors. 67 actual localhost HTTP exchanges were observed.** The tests also inspected SQLite directly. All requests used synthetic identities. Proxy handling is disabled for the HTTP client.

## Reproduce

From this directory:

```sh
python3 independent_http_audit.py
```

Or from the repository root:

```sh
python3 api-retest-evidence/http-retest/audit/independent_http_audit.py
```

Python standard library only, targeting Python 3.12 or newer. No model, package installation, credential or external network service is needed. Servers bind to `127.0.0.1` on ephemeral ports. Each test creates and removes a temporary SQLite database.

The command regenerates only `independent-results.json` and `independent-test-output.txt` in this audit directory. It exits unsuccessfully if a test fails or `server.py` changes during the audit. It does not alter the earlier deterministic or SLM evaluation artifacts.

## What was exercised

- Authorized submission, direct state/version checks, receipt and audit correlation.
- Unknown identities, foreign tenants, view-only grants and forbidden revocation.
- Fresh submission and historical-key replay after a committed revocation.
- Isolation of idempotency receipts across actors, tenants and resources.
- Duplicate request identifiers, including eight concurrent copies.
- Twelve simultaneous submissions with one key and exactly one business effect.
- A concurrent revocation versus twelve submissions, checking committed audit order for subsequent denials.
- Graceful server restarts preserving the business effect, receipt and revoked permission.
- SQLite failure injected while storing a receipt, proving rollback of the preceding business-state and request-ledger writes, with no receipt or audit event persisted.
- Intentional vulnerable fixtures that commit despite `403` and replay a cached result after revocation.
- Homonymous actors and identical request IDs in different tenants, retaining both authenticated and target tenant in the audit.
- An incomplete HTTP body, receiving `408` after the configured idle timeout and preserving the business state.

## Findings corrected before the final run

1. **Listen backlog configured after activation.** Assigning `request_queue_size` on an already-created `ThreadingHTTPServer` did not change the listening socket's initial backlog. It is now declared on a subclass before server construction.
2. **Foreign-tenant audit provenance ambiguous.** The first schema recorded only the target tenant. `principal_tenant` now records the authenticated tenant separately, and the homonymous-actor test verifies the distinction.
3. **Incomplete body could hold shutdown open.** The initial service had no read timeout. A local client announcing 100 bytes and sending one byte kept `server.close()` blocked until that client disconnected. The service now sets a two-second socket idle timeout and responds `408`. In the recorded run the response arrived after approximately 2.003 seconds and shutdown completed in 0.007 seconds. This is an idle timeout, not a total deadline against a client that continually sends small fragments.

## Evidence

- [Executed test output](independent-test-output.txt)
- [Raw HTTP responses and final SQL observations](independent-results.json)
- [Audit source](independent_http_audit.py)

Audited server SHA-256: `b3cbaa7e012e4f4e9d114cd1f70e24eabf6a1fba533b7ebd7244a45e7b1b986f`. Audit script SHA-256: `8d9e78e9b22e3168f0ffd7177312f17750cc292484aedcbfcbb12fdfe66d5cf7`. The server source was unchanged during the final run.

## Scope limits

The results cover one threaded local process and SQLite transaction serialization. Graceful restarts demonstrate persistence, not power-loss durability. TLS, OAuth/OIDC, distributed transactions, replicated state, protected production collectors and adversarial tampering with the observer are outside this extension. The separate earlier SLM evaluation was not rerun against these HTTP cases. Concurrent scheduling and elapsed timings can vary; the business invariants must still hold. No employer deployment or professional performance is established by this personal demonstration.
