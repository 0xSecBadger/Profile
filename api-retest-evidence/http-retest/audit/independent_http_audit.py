"""Independent contract checks using real HTTP and direct SQLite observations.

Run with Python from any directory. Only localhost laboratory fixtures are used.
This file was authored separately from server.py and the author's test runner.
"""
import concurrent.futures
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("audited_http_lab_server", ROOT / "server.py")
SERVICE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SERVICE)
OBSERVATIONS = []
DATABASE_OBSERVATIONS = []
SERVER_HASH_BEFORE = hashlib.sha256((ROOT / "server.py").read_bytes()).hexdigest()


class HttpContractAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="http-contract-audit-")
        self.db = Path(self.tmp.name) / "evidence.sqlite"
        SERVICE.seed_database(self.db)
        self.servers = []
        self._sequence = 0
        self._lock = threading.Lock()

    def tearDown(self):
        for server in reversed(self.servers):
            server.close()
        DATABASE_OBSERVATIONS.append({"test": self.id().rsplit(".", 1)[-1], "tables": {
            table: self.rows(table) for table in ("expenses", "grants", "receipts", "requests", "audit")}})
        self.tmp.cleanup()

    def start(self, mode="fixed"):
        server = SERVICE.LabServer(self.db, mode=mode)
        self.servers.append(server)
        return server

    def stop(self, server):
        server.close()
        self.servers.remove(server)

    def rows(self, table):
        with sqlite3.connect(self.db) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute("SELECT * FROM " + table)]

    def expense(self, tenant="alpha", name="expense-1"):
        return next(row for row in self.rows("expenses") if row["tenant"] == tenant and row["id"] == name)

    def add_second_expense(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO expenses VALUES('alpha','expense-2','draft',0,NULL)")
            db.execute("INSERT INTO grants VALUES('alpha','alice','expense-2','submit',1)")

    def post(self, server, path, token="lab-alice-token", key="audit-key", request_id=None, raw=b"{}"):
        with self._lock:
            self._sequence += 1
            request_id = request_id or "audit-request-%d" % self._sequence
        headers = {"Authorization": "Bearer " + token, "X-Request-ID": request_id,
                   "Idempotency-Key": key, "Content-Type": "application/json"}
        request = urllib.request.Request(server.base_url + path, data=raw, headers=headers, method="POST")
        try:
            response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.status
            payload = json.loads(response.read())
        with self._lock:
            OBSERVATIONS.append({"test": self.id().rsplit(".", 1)[-1], "method": "POST", "path": path,
                                 "identity_fixture": token, "request_id": request_id, "idempotency_key": key,
                                 "request_body": raw.decode("utf-8"), "status": status, "response": payload})
        return status, payload

    def submit(self, server, tenant="alpha", expense="expense-1", **kwargs):
        return self.post(server, "/tenants/%s/expenses/%s/submit" % (tenant, expense), **kwargs)

    def revoke(self, server, actor="alice", **kwargs):
        return self.post(server, "/tenants/alpha/grants/expense-1/%s/revoke" % actor,
                         token="lab-owner-token", **kwargs)

    def test_authorized_effect_is_persisted_and_correlated(self):
        server = self.start()
        before = self.expense()
        status, body = self.submit(server, request_id="authorized")
        after = self.expense()
        self.assertEqual(status, 201)
        self.assertEqual((before["status"], before["version"]), ("draft", 0))
        self.assertEqual((after["status"], after["version"], after["last_request"]), ("submitted", 1, "authorized"))
        self.assertEqual(body["request_id"], "authorized")
        self.assertEqual(len(self.rows("receipts")), 1)
        event = self.rows("audit")[0]
        self.assertEqual((event["request_id"], event["outcome"], event["before_version"], event["after_version"]),
                         ("authorized", "committed", 0, 1))

    def test_unknown_identity_has_no_business_or_audit_effect(self):
        server = self.start()
        before = self.rows("expenses")
        status, _ = self.submit(server, token="unknown-test-identity")
        self.assertEqual(status, 401)
        self.assertEqual(self.rows("expenses"), before)
        self.assertEqual(self.rows("receipts"), [])
        self.assertEqual(self.rows("requests"), [])
        self.assertEqual(self.rows("audit"), [])

    def test_foreign_tenant_is_denied_without_changing_either_tenant(self):
        server = self.start()
        before = self.rows("expenses")
        status, _ = self.submit(server, tenant="beta", request_id="foreign-target")
        self.assertEqual(status, 403)
        self.assertEqual(self.rows("expenses"), before)
        self.assertEqual(self.rows("receipts"), [])
        event = self.rows("audit")[0]
        self.assertEqual((event["request_id"], event["tenant"], event["outcome"]),
                         ("foreign-target", "beta", "tenant_denied"))

    def test_view_permission_does_not_allow_submit_and_positive_control_still_works(self):
        server = self.start()
        self.assertEqual(self.submit(server, token="lab-bob-token")[0], 403)
        self.assertEqual(self.expense()["version"], 0)
        self.assertEqual(self.submit(server)[0], 201)
        self.assertEqual(self.expense()["version"], 1)

    def test_homonymous_actors_keep_authenticated_and_target_tenants_distinct(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO principals VALUES('lab-beta-alice-token','alice','beta','delegate')")
            db.execute("INSERT INTO grants VALUES('beta','alice','expense-1','submit',1)")
        server = self.start()
        self.assertEqual(self.submit(server, tenant="beta", request_id="same-correlation-id")[0], 403)
        self.assertEqual(self.submit(server, tenant="beta", token="lab-beta-alice-token",
                                     request_id="same-correlation-id")[0], 201)
        events = self.rows("audit")
        self.assertEqual([(e["principal_tenant"], e["tenant"], e["actor"], e["request_id"], e["outcome"]) for e in events],
                         [("alpha", "beta", "alice", "same-correlation-id", "tenant_denied"),
                          ("beta", "beta", "alice", "same-correlation-id", "committed")])

    def test_delegate_cannot_revoke_another_delegate(self):
        server = self.start()
        before = self.rows("grants")
        status, _ = self.post(server, "/tenants/alpha/grants/expense-1/alice/revoke", token="lab-bob-token")
        self.assertEqual(status, 403)
        self.assertEqual(self.rows("grants"), before)
        self.assertEqual(self.submit(server)[0], 201)

    def test_fresh_operation_after_revocation_is_denied(self):
        server = self.start()
        self.assertEqual(self.revoke(server, request_id="revoke-first")[0], 200)
        self.assertEqual(self.submit(server, request_id="denied-after-revoke")[0], 403)
        self.assertEqual((self.expense()["status"], self.expense()["version"]), ("draft", 0))
        self.assertEqual(self.rows("receipts"), [])
        self.assertEqual([x["outcome"] for x in self.rows("audit")], ["grant_revoked", "authorization_denied"])

    def test_successful_key_does_not_override_later_revocation(self):
        server = self.start()
        self.assertEqual(self.submit(server, key="historical-key", request_id="first-success")[0], 201)
        self.assertEqual(self.revoke(server)[0], 200)
        status, _ = self.submit(server, key="historical-key", request_id="revoked-replay")
        self.assertEqual(status, 403)
        self.assertEqual(self.expense()["version"], 1)
        self.assertEqual(self.rows("receipts")[0]["original_request"], "first-success")
        self.assertEqual(self.rows("audit")[-1]["outcome"], "authorization_denied")

    def test_same_key_in_two_tenants_does_not_share_receipts(self):
        server = self.start()
        self.assertEqual(self.submit(server, key="shared-key", request_id="alpha-request")[0], 201)
        self.assertEqual(self.submit(server, tenant="beta", token="lab-beta-token", key="shared-key", request_id="beta-request")[0], 201)
        receipts = self.rows("receipts")
        self.assertEqual({(r["tenant"], r["actor"], r["original_request"]) for r in receipts},
                         {("alpha", "alice", "alpha-request"), ("beta", "bea", "beta-request")})
        self.assertEqual([e["version"] for e in self.rows("expenses")], [1, 1])

    def test_receipt_does_not_cross_actor_scope(self):
        with sqlite3.connect(self.db) as db:
            db.execute("INSERT INTO grants VALUES('alpha','bob','expense-1','submit',1)")
        server = self.start()
        self.assertEqual(self.submit(server, key="same-key")[0], 201)
        status, body = self.submit(server, token="lab-bob-token", key="same-key")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "expense already submitted")
        self.assertEqual(len(self.rows("receipts")), 1)

    def test_same_key_in_two_resources_has_independent_effects(self):
        self.add_second_expense()
        server = self.start()
        self.assertEqual(self.submit(server, key="shared-key")[0], 201)
        self.assertEqual(self.submit(server, expense="expense-2", key="shared-key")[0], 201)
        self.assertEqual(self.expense(name="expense-2")["version"], 1)
        self.assertEqual({r["expense_id"] for r in self.rows("receipts")}, {"expense-1", "expense-2"})

    def test_reused_request_identifier_cannot_hide_another_operation(self):
        self.add_second_expense()
        server = self.start()
        self.assertEqual(self.submit(server, request_id="duplicate-id")[0], 201)
        status, _ = self.submit(server, expense="expense-2", request_id="duplicate-id")
        self.assertEqual(status, 409)
        self.assertEqual(self.expense(name="expense-2")["version"], 0)
        self.assertEqual(len(self.rows("audit")), 1)

    def test_concurrent_same_key_changes_state_once(self):
        server = self.start()
        count = 12
        barrier = threading.Barrier(count)
        def attempt(index):
            barrier.wait(timeout=10)
            return self.submit(server, key="concurrent-key", request_id="parallel-%02d" % index)
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            responses = list(pool.map(attempt, range(count)))
        statuses = [status for status, _ in responses]
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(200), count - 1)
        self.assertEqual(self.expense()["version"], 1)
        self.assertEqual(len(self.rows("receipts")), 1)
        events = self.rows("audit")
        self.assertEqual(sum(e["outcome"] == "committed" for e in events), 1)
        self.assertEqual(len({e["request_id"] for e in events}), count)
        winner = self.rows("receipts")[0]["original_request"]
        for status, body in responses:
            if status == 200:
                self.assertEqual(body["original_request"], winner)

    def test_concurrent_duplicate_request_id_is_rejected(self):
        server = self.start()
        barrier = threading.Barrier(8)
        def attempt(_):
            barrier.wait(timeout=10)
            return self.submit(server, request_id="one-request-id")[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(attempt, range(8)))
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(statuses.count(409), 7)
        self.assertEqual(self.expense()["version"], 1)
        self.assertEqual(len(self.rows("requests")), 1)
        self.assertEqual(len(self.rows("audit")), 1)

    def test_revocation_race_has_no_authorized_effect_after_revocation_commit(self):
        server = self.start()
        count = 12
        barrier = threading.Barrier(count + 1)
        def attempt(index):
            barrier.wait(timeout=10)
            if index == count:
                return self.revoke(server, request_id="race-revoke")
            return self.submit(server, key="race-key", request_id="race-submit-%02d" % index)
        with concurrent.futures.ThreadPoolExecutor(max_workers=count + 1) as pool:
            responses = list(pool.map(attempt, range(count + 1)))
        self.assertEqual(responses[-1][0], 200)
        self.assertTrue(all(status in (200, 201, 403) for status, _ in responses[:-1]))
        events = self.rows("audit")
        revoke_seq = next(e["seq"] for e in events if e["request_id"] == "race-revoke")
        self.assertEqual(len(events), count + 1)
        for event in events:
            if event["seq"] > revoke_seq:
                self.assertEqual(event["outcome"], "authorization_denied")
                self.assertEqual(event["before_version"], event["after_version"])
        self.assertLessEqual(sum(e["outcome"] == "committed" for e in events), 1)
        self.assertEqual(self.expense()["version"], sum(e["outcome"] == "committed" for e in events))

    def test_incomplete_body_times_out_and_server_shutdown_completes(self):
        server = self.start()
        connection = socket.create_connection(("127.0.0.1", server.httpd.server_port), timeout=5)
        connection.settimeout(5)
        connection.sendall(b"POST /tenants/alpha/expenses/expense-1/submit HTTP/1.1\r\n"
                           b"Host: localhost\r\nAuthorization: Bearer lab-alice-token\r\n"
                           b"X-Request-ID: incomplete-body\r\nIdempotency-Key: incomplete-key\r\n"
                           b"Content-Length: 100\r\n\r\n{")
        # Waiting for the real response avoids guessing whether the server has accepted the socket.
        started = time.monotonic()
        try:
            data = bytearray()
            while True:
                part = connection.recv(4096)
                if not part:
                    break
                data.extend(part)
            response_seconds = time.monotonic() - started
            self.assertIn(b" 408 ", data.split(b"\r\n", 1)[0])
            self.assertEqual(self.expense()["version"], 0)
            self.assertEqual(self.rows("requests"), [])
        finally:
            connection.close()
        shutdown_started = time.monotonic()
        self.stop(server)
        OBSERVATIONS.append({"test": self.id().rsplit(".", 1)[-1], "transport": "raw local TCP/HTTP",
                             "request_id": "incomplete-body", "declared_body_bytes": 100, "sent_body_bytes": 1,
                             "status": 408, "response_seconds": round(response_seconds, 3),
                             "shutdown_seconds": round(time.monotonic() - shutdown_started, 3),
                             "scope": "Idle body reader, not a total slow-stream deadline"})

    def test_server_restart_preserves_effect_receipt_and_revocation(self):
        server = self.start()
        self.assertEqual(self.submit(server, key="persist-key", request_id="persist-original")[0], 201)
        self.stop(server)
        restarted = self.start()
        status, body = self.submit(restarted, key="persist-key", request_id="after-first-restart")
        self.assertEqual(status, 200)
        self.assertEqual(body["original_request"], "persist-original")
        self.assertEqual(self.expense()["version"], 1)
        self.assertEqual(self.revoke(restarted)[0], 200)
        self.stop(restarted)
        restarted_again = self.start()
        self.assertEqual(self.submit(restarted_again, key="persist-key", request_id="after-second-restart")[0], 403)
        self.assertEqual(self.expense()["version"], 1)

    def test_vulnerable_fixture_has_forbidden_persisted_effect_despite_403(self):
        server = self.start(mode="vulnerable")
        before = self.expense()
        status, _ = self.submit(server, token="lab-bob-token", request_id="hidden-forbidden-effect")
        after = self.expense()
        self.assertEqual(status, 403)
        self.assertEqual((before["status"], before["version"]), ("draft", 0))
        self.assertEqual((after["status"], after["version"], after["last_request"]),
                         ("submitted", 1, "hidden-forbidden-effect"))
        event = self.rows("audit")[0]
        self.assertEqual((event["outcome"], event["request_id"], event["before_version"], event["after_version"]),
                         ("unauthorized_commit", "hidden-forbidden-effect", 0, 1))

    def test_vulnerable_cache_fixture_reproduces_revocation_bypass(self):
        server = self.start(mode="vulnerable")
        self.assertEqual(self.submit(server, key="cache-key")[0], 201)
        self.assertEqual(self.revoke(server)[0], 200)
        status, body = self.submit(server, key="cache-key")
        self.assertEqual(status, 200)
        self.assertTrue(body["replayed"])
        self.assertEqual(self.rows("audit")[-1]["outcome"], "cached_before_authorization")

    def test_unexpected_payload_is_rejected_before_business_effect(self):
        server = self.start()
        self.assertEqual(self.submit(server, raw=b'{"amount":100000}')[0], 400)
        self.assertEqual(self.expense()["version"], 0)
        self.assertEqual(self.rows("audit"), [])
        self.assertEqual(self.rows("requests"), [])

    def test_storage_error_rolls_back_business_effect_and_correlation_record(self):
        with sqlite3.connect(self.db) as db:
            db.execute("""CREATE TRIGGER refuse_receipt BEFORE INSERT ON receipts
                          BEGIN SELECT RAISE(ABORT,'synthetic receipt storage fault'); END""")
        server = self.start()
        before = self.expense()
        status, _ = self.submit(server, request_id="storage-fault")
        self.assertEqual(status, 503)
        self.assertEqual(self.expense(), before)
        self.assertEqual(self.rows("requests"), [])
        self.assertEqual(self.rows("receipts"), [])
        self.assertEqual(self.rows("audit"), [])
        with sqlite3.connect(self.db) as db:
            db.execute("DROP TRIGGER refuse_receipt")
        self.assertEqual(self.submit(server, request_id="storage-recovered")[0], 201)
        self.assertEqual(self.expense()["version"], 1)


def main():
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HttpContractAudit)
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    source_unchanged = SERVER_HASH_BEFORE == hashlib.sha256((ROOT / "server.py").read_bytes()).hexdigest()
    summary = {"scope": "Independent localhost HTTP/SQLite contract audit", "test_methods": result.testsRun,
               "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
               "failures": len(result.failures), "errors": len(result.errors), "passed": result.wasSuccessful() and source_unchanged,
               "http_observations": len(OBSERVATIONS), "observations": OBSERVATIONS,
               "final_database_observations": DATABASE_OBSERVATIONS,
               "server_sha256": SERVER_HASH_BEFORE,
               "server_unchanged_during_audit": source_unchanged,
               "audit_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "limits": ["Synthetic identities and local-only targets", "Single-process threaded server and local SQLite",
                          "No TLS, OIDC, distributed state, crash-durability or general security certification",
                          "The vulnerable fixture intentionally reproduces forbidden effects and cache ordering errors"]}
    out = ROOT / "audit"
    (out / "independent-results.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    (out / "independent-test-output.txt").write_text(stream.getvalue())
    print(stream.getvalue(), end="")
    print("Observed HTTP exchanges:", len(OBSERVATIONS))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
