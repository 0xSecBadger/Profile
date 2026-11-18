"""Run actual localhost HTTP requests and retain their business-state evidence."""
import argparse
import concurrent.futures
import hashlib
import json
import platform
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from server import LabServer, connect, seed_database, snapshot_database


def request(server, request_id, *, tenant="alpha", expense="expense-1", actor="alice",
            token=None, key="key-1", revoke=None):
    token = token or "lab-%s-token" % actor
    path = ("/tenants/%s/grants/%s/%s/revoke" % (tenant, expense, revoke)
            if revoke else "/tenants/%s/expenses/%s/submit" % (tenant, expense))
    headers = {"Authorization": "Bearer " + token, "X-Request-ID": request_id,
               "Idempotency-Key": key, "Content-Type": "application/json"}
    req = urllib.request.Request(server.base_url + path, data=b"{}", headers=headers, method="POST")
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=15)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        status, body = response.status, json.loads(response.read())
    return {"request": {"method": "POST", "path": path, "request_id": request_id,
                        "laboratory_actor": actor, "idempotency_key": key, "body": {}},
            "response": {"status": status, "body": body}}


def expense(snapshot, tenant="alpha", identity="expense-1"):
    return next(row for row in snapshot["expenses"] if row["tenant"] == tenant and row["id"] == identity)


def checks(**values):
    return [{"assertion": key.replace("_", " "), "holds": bool(value)} for key, value in values.items()]


def denied_checks(before, after, calls):
    return checks(HTTP_denial=calls[-1]["response"]["status"] == 403,
                  business_state_unchanged=before["expenses"] == after["expenses"],
                  no_receipt_created=before["receipts"] == after["receipts"])


def parallel(server, prefix, same_key=True, count=12):
    barrier = threading.Barrier(count)
    def once(number):
        barrier.wait(timeout=10)
        return request(server, "%s-%02d" % (prefix, number),
                       key="parallel-key" if same_key else "parallel-%02d" % number)
    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(once, range(count)))


def run_suite(output=None):
    cases = []
    with tempfile.TemporaryDirectory(prefix="http-retest-") as tmp:
        def case(identity, title, mode, procedure, verify, expected="PASS", setup=None):
            path = Path(tmp) / (identity + ".sqlite")
            seed_database(path)
            if setup:
                setup(path)
            with LabServer(path, mode) as server:
                before = snapshot_database(path)
                calls = procedure(server)
                after = snapshot_database(path)
                assertions = verify(before, after, calls)
            observed = "PASS" if all(c["holds"] for c in assertions) else "FAIL"
            cases.append({"id": identity, "title": title, "mode": mode,
                          "transport": "actual HTTP over localhost TCP",
                          "before": before, "http_exchanges": calls, "after": after,
                          "security_assertions": assertions, "expected_verdict": expected,
                          "observed_verdict": observed, "fixture_verified": observed == expected})

        case("H01", "Authorized submission commits one business effect", "fixed",
             lambda s: [request(s, "h01-submit")],
             lambda b, a, c: checks(HTTP_created=c[0]["response"]["status"] == 201,
                 submitted_once=expense(a)["status"] == "submitted" and expense(a)["version"] == 1,
                 request_correlated=expense(a)["last_request"] == "h01-submit",
                 receipt_recorded=len(a["receipts"]) == 1,
                 audit_committed=a["audit"][-1]["outcome"] == "committed"))

        def revoke_then_submit(s):
            return [request(s, "revoke-first", actor="owner", revoke="alice"),
                    request(s, "submit-after-revoke")]
        case("H02", "Corrected implementation refuses without mutation", "fixed",
             revoke_then_submit, denied_checks)
        case("H03", "Vulnerable implementation returns403 after committing", "vulnerable",
             revoke_then_submit, denied_checks, "FAIL")

        def replay(s):
            return [request(s, "initial-submit"), request(s, "authorized-replay")]
        case("H04", "Authorized idempotent replay", "fixed", replay,
             lambda b, a, c: checks(statuses_correct=[x["response"]["status"] for x in c] == [201, 200],
                 exactly_one_version=expense(a)["version"] == 1,
                 exactly_one_receipt=len(a["receipts"]) == 1,
                 original_request_preserved=expense(a)["last_request"] == "initial-submit",
                 replay_identified=c[-1]["response"]["body"].get("replayed") is True,
                 audit_records_replay=a["audit"][-1]["outcome"] == "authorized_replay"))

        def revoked_replay(s):
            return [request(s, "initial-submit"),
                    request(s, "revoke-after-submit", actor="owner", revoke="alice"),
                    request(s, "replay-after-revoke")]
        def revoked_replay_checks(b, a, c):
            return checks(initial_submission_created=c[0]["response"]["status"] == 201,
                          replay_reauthorized_and_denied=c[-1]["response"]["status"] == 403,
                          no_second_effect=expense(a)["version"] == 1,
                          original_request_preserved=expense(a)["last_request"] == "initial-submit")
        case("H05", "Reauthorization takes precedence over cached replay", "fixed",
             revoked_replay, revoked_replay_checks)
        case("H06", "Vulnerable cache bypasses revoked permission", "vulnerable",
             revoked_replay, revoked_replay_checks, "FAIL")

        case("H07", "Other tenant cannot be modified", "fixed",
             lambda s: [request(s, "wrong-tenant", tenant="beta")], denied_checks)
        case("H08", "View permission does not authorize submit", "fixed",
             lambda s: [request(s, "view-is-not-submit", actor="bob")], denied_checks)

        def same_key_checks(b, a, c):
            statuses = [x["response"]["status"] for x in c]
            committed = [r for r in a["audit"] if r["outcome"] == "committed"]
            return checks(twelve_responses=len(c) == 12,
                          one_created=statuses.count(201) == 1,
                          eleven_replays=statuses.count(200) == 11,
                          one_business_version=expense(a)["version"] == 1,
                          one_receipt=len(a["receipts"]) == 1,
                          one_commit_audited=len(committed) == 1,
                          all_requests_correlated=len(a["audit"]) == 12)
        case("H09", "Twelve concurrent submissions with one idempotency key", "fixed",
             lambda s: parallel(s, "same-key"), same_key_checks)

        def different_key_checks(b, a, c):
            statuses = [x["response"]["status"] for x in c]
            return checks(twelve_responses=len(c) == 12,
                          one_created=statuses.count(201) == 1,
                          eleven_conflicts=statuses.count(409) == 11,
                          one_business_version=expense(a)["version"] == 1,
                          one_receipt=len(a["receipts"]) == 1,
                          one_commit_audited=sum(r["outcome"] == "committed" for r in a["audit"]) == 1)
        case("H10", "Twelve concurrent submissions with different keys", "fixed",
             lambda s: parallel(s, "different-key", same_key=False), different_key_checks)

        path = Path(tmp) / "H11.sqlite"
        seed_database(path)
        before = snapshot_database(path)
        with LabServer(path) as first:
            first_call = request(first, "before-restart")
            first_port = first.httpd.server_port
        persisted = snapshot_database(path)
        with LabServer(path) as second:
            second_call = request(second, "after-restart")
        after = snapshot_database(path)
        assertions = checks(first_submission_created=first_call["response"]["status"] == 201,
                            receipt_replayed_after_restart=second_call["response"]["status"] == 200,
                            persisted_business_state=expense(persisted) == expense(after),
                            original_request_retained=expense(after)["last_request"] == "before-restart",
                            persisted_receipt=persisted["receipts"] == after["receipts"],
                            both_requests_in_audit=len(after["audit"]) == 2)
        observed = "PASS" if all(c["holds"] for c in assertions) else "FAIL"
        cases.append({"id": "H11", "title": "SQLite state and receipts survive server restart",
                      "mode": "fixed", "transport": "actual HTTP over localhost TCP",
                      "before": before, "http_exchanges": [first_call, second_call],
                      "snapshot_after_shutdown": persisted, "after": after,
                      "security_assertions": assertions, "expected_verdict": "PASS",
                      "observed_verdict": observed, "fixture_verified": observed == "PASS"})

        case("H12", "Unknown laboratory identity cannot mutate", "fixed",
             lambda s: [request(s, "unknown-identity", token="lab-unknown-token", actor="unknown")],
             lambda b, a, c: checks(HTTP_unauthorized=c[0]["response"]["status"] == 401,
                                   full_snapshot_unchanged=b == a))
        case("H13", "Delegate cannot revoke a grant", "fixed",
             lambda s: [request(s, "delegate-revoke", revoke="alice")],
             lambda b, a, c: checks(HTTP_denied=c[0]["response"]["status"] == 403,
                                   grants_unchanged=b["grants"] == a["grants"],
                                   expenses_unchanged=b["expenses"] == a["expenses"]))
        case("H14", "Repeated correlation ID is rejected before replay", "fixed",
             lambda s: [request(s, "same-request-id"), request(s, "same-request-id")],
             lambda b, a, c: checks(statuses_correct=[x["response"]["status"] for x in c] == [201, 409],
                                   one_effect=expense(a)["version"] == 1,
                                   one_audit_record=len(a["audit"]) == 1,
                                   one_request_record=len(a["requests"]) == 1))

    report = {
        "project": "HTTP authorization retest laboratory",
        "created_for": "Personal portfolio, 18 November 2026, developed with AI coding assistance",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                        "transport": "localhost TCP HTTP/1.1", "host": "127.0.0.1"},
        "summary": {"cases": len(cases), "fixed_cases": sum(c["mode"] == "fixed" for c in cases),
                    "intentional_vulnerable_cases": sum(c["mode"] == "vulnerable" for c in cases),
                    "PASS": sum(c["observed_verdict"] == "PASS" for c in cases),
                    "FAIL": sum(c["observed_verdict"] == "FAIL" for c in cases),
                    "fixtures_verified": sum(c["fixture_verified"] for c in cases),
                    "http_requests": sum(len(c["http_exchanges"]) for c in cases),
                    "security_assertions": sum(len(c["security_assertions"]) for c in cases)},
        "limitations": ["Synthetic identities and business data; bearer fixtures are not an OAuth/OIDC implementation.",
                        "Single host, thread-per-request server and SQLite transaction serialization.",
                        "Concurrent requests test local interleavings; distributed races and crash recovery are not covered.",
                        "A graceful server restart tests persistence, not power-loss durability.",
                        "Before/after SQL snapshots are collected by a trusted laboratory observer after requests complete.",
                        "The earlier 28-case SLM evaluation is separate and has not been rerun on this HTTP extension."],
        "cases": cases,
        "source_sha256": {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                          for f in sorted(Path(__file__).parent.glob("*.py"))}}
    if output:
        output = Path(output)
        output.mkdir(parents=True, exist_ok=True)
        (output / "http-report.json").write_text(json.dumps(report, indent=2) + "\n")
        rows = ["# Executed HTTP retest results", "", "Personal laboratory · 18 November 2026 · AI-assisted.", "",
                "| Case | Mode | Verdict | HTTP requests | Security assertions |", "|---|---|---|---:|---:|"]
        rows += ["| %s — %s | %s | %s | %d | %d |" % (c["id"], c["title"], c["mode"], c["observed_verdict"],
                 len(c["http_exchanges"]), len(c["security_assertions"])) for c in cases]
        rows += ["", "Two intentional failures demonstrate the faulty implementation. The other cases use the corrected implementation.",
                 "", "All %d expected fixture outcomes were observed. These are bounded synthetic tests, not a general security certification." % report["summary"]["fixtures_verified"]]
        (output / "HTTP-RESULTS.md").write_text("\n".join(rows) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="results")
    args = parser.parse_args()
    result = run_suite(args.output)
    print(json.dumps(result["summary"], indent=2))
    if result["summary"]["fixtures_verified"] != result["summary"]["cases"]:
        raise SystemExit(1)
