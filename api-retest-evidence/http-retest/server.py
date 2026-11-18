"""Local, deliberately bounded HTTP/SQLite authorization laboratory.

All identities and bearer strings are synthetic fixtures. Never deploy this
server outside the local laboratory. The vulnerable mode is intentional.
"""
import json
import re
import socket
import sqlite3
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


SCHEMA = """
CREATE TABLE principals(token TEXT PRIMARY KEY, actor TEXT NOT NULL,
 tenant TEXT NOT NULL, role TEXT NOT NULL);
CREATE TABLE expenses(tenant TEXT NOT NULL, id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('draft','submitted')),
 version INTEGER NOT NULL CHECK(version>=0), last_request TEXT,
 PRIMARY KEY(tenant,id));
CREATE TABLE grants(tenant TEXT NOT NULL, actor TEXT NOT NULL,
 expense_id TEXT NOT NULL, action TEXT NOT NULL,
 active INTEGER NOT NULL CHECK(active IN (0,1)),
 PRIMARY KEY(tenant,actor,expense_id,action));
CREATE TABLE receipts(tenant TEXT NOT NULL, actor TEXT NOT NULL,
 expense_id TEXT NOT NULL, action TEXT NOT NULL, idem_key TEXT NOT NULL,
 original_request TEXT NOT NULL, version INTEGER NOT NULL,
 PRIMARY KEY(tenant,actor,expense_id,action,idem_key));
CREATE TABLE requests(tenant TEXT NOT NULL, actor TEXT NOT NULL,
 request_id TEXT NOT NULL, PRIMARY KEY(tenant,actor,request_id));
CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,
 request_id TEXT NOT NULL, tenant TEXT NOT NULL, actor TEXT NOT NULL,
 principal_tenant TEXT NOT NULL,
 expense_id TEXT NOT NULL, action TEXT NOT NULL, outcome TEXT NOT NULL,
 before_version INTEGER, after_version INTEGER);
"""


def connect(path):
    db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("PRAGMA foreign_keys=ON")
    return db


def seed_database(path):
    """Create a fresh fixture database. Fails if it already has these tables."""
    db = connect(path)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(SCHEMA)
        db.executemany("INSERT INTO principals VALUES(?,?,?,?)", [
            ("lab-alice-token", "alice", "alpha", "delegate"),
            ("lab-bob-token", "bob", "alpha", "delegate"),
            ("lab-owner-token", "owner", "alpha", "owner"),
            ("lab-beta-token", "bea", "beta", "delegate"),
        ])
        db.executemany("INSERT INTO expenses VALUES(?,?,'draft',0,NULL)",
                       [("alpha", "expense-1"), ("beta", "expense-1")])
        db.executemany("INSERT INTO grants VALUES(?,?,?,?,1)", [
            ("alpha", "alice", "expense-1", "submit"),
            ("alpha", "bob", "expense-1", "view"),
            ("beta", "bea", "expense-1", "submit"),
        ])
    finally:
        db.close()


def snapshot_database(path):
    db = connect(path)
    try:
        # A consistent read snapshot across tables; called after requests finish.
        db.execute("BEGIN")
        return {table: [dict(r) for r in db.execute(query)] for table, query in [
            ("expenses", "SELECT * FROM expenses ORDER BY tenant,id"),
            ("grants", "SELECT * FROM grants ORDER BY tenant,actor,expense_id,action"),
            ("receipts", "SELECT * FROM receipts ORDER BY tenant,actor,expense_id,action,idem_key"),
            ("requests", "SELECT * FROM requests ORDER BY tenant,actor,request_id"),
            ("audit", "SELECT * FROM audit ORDER BY seq"),
        ]}
    finally:
        db.rollback()
        db.close()


@contextmanager
def transaction(path):
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def record(db, request_id, tenant, actor, expense, action, outcome, before, after,
           principal_tenant=None):
    db.execute("""INSERT INTO audit(request_id,tenant,actor,principal_tenant,expense_id,action,
               outcome,before_version,after_version) VALUES(?,?,?,?,?,?,?,?,?)""",
               (request_id, tenant, actor, principal_tenant or tenant, expense, action, outcome, before, after))


IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
SUBMIT = re.compile(r"^/tenants/([A-Za-z0-9_-]+)/expenses/([A-Za-z0-9_-]+)/submit$")
REVOKE = re.compile(r"^/tenants/([A-Za-z0-9_-]+)/grants/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/revoke$")


class LabServer:
    def __init__(self, path, mode="fixed"):
        if mode not in ("fixed", "vulnerable"):
            raise ValueError("mode must be fixed or vulnerable")
        self.path, self.mode = str(path), mode
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                # Bound idle socket reads, including an incomplete request body.
                self.connection.settimeout(2.0)

            def log_message(self, *_):
                pass

            def respond(self, status, payload):
                body = json.dumps(payload, sort_keys=True).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_POST(self):
                request_id = self.headers.get("X-Request-ID", "")
                idem_key = self.headers.get("Idempotency-Key", "")
                if not IDENTIFIER.fullmatch(request_id):
                    return self.respond(400, {"error": "invalid request identifier"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > 4096:
                        raise ValueError()
                    raw = self.rfile.read(length)
                    if raw and json.loads(raw) != {}:
                        raise ValueError()
                except socket.timeout:
                    return self.respond(408, {"error": "request body timeout", "request_id": request_id})
                except (ValueError, json.JSONDecodeError):
                    return self.respond(400, {"error": "expected empty JSON object"})
                target = urlsplit(self.path)
                submit, revoke = SUBMIT.fullmatch(target.path), REVOKE.fullmatch(target.path)
                if target.query or not (submit or revoke):
                    return self.respond(404, {"error": "route not found"})
                if submit and not IDENTIFIER.fullmatch(idem_key):
                    return self.respond(400, {"error": "invalid idempotency key"})
                auth = self.headers.get("Authorization", "")
                token = auth[7:] if auth.startswith("Bearer ") else ""
                try:
                    with transaction(outer.path) as db:
                        principal = db.execute("SELECT * FROM principals WHERE token=?", (token,)).fetchone()
                        if principal is None:
                            status, payload = 401, {"error": "unknown laboratory identity"}
                        elif db.execute("SELECT 1 FROM requests WHERE tenant=? AND actor=? AND request_id=?",
                                        (principal["tenant"], principal["actor"], request_id)).fetchone():
                            status, payload = 409, {"error": "request identifier already used"}
                        else:
                            db.execute("INSERT INTO requests VALUES(?,?,?)",
                                       (principal["tenant"], principal["actor"], request_id))
                            status, payload = self.apply(db, principal, submit, revoke, request_id, idem_key)
                    # Response is sent only after the complete state/audit transaction commits.
                    return self.respond(status, dict(payload, request_id=request_id))
                except sqlite3.Error:
                    return self.respond(503, {"error": "database operation failed", "request_id": request_id})

            def apply(self, db, principal, submit, revoke, request_id, idem_key):
                tenant, expense = (submit or revoke).group(1, 2)
                actor = principal["actor"]
                action = "submit" if submit else "revoke"
                if tenant != principal["tenant"]:
                    record(db, request_id, tenant, actor, expense, action, "tenant_denied", None, None,
                           principal_tenant=principal["tenant"])
                    return 403, {"error": "tenant denied"}
                row = db.execute("SELECT * FROM expenses WHERE tenant=? AND id=?", (tenant, expense)).fetchone()
                if row is None:
                    return 404, {"error": "expense not found"}
                version = row["version"]
                if revoke:
                    if principal["role"] != "owner":
                        record(db, request_id, tenant, actor, expense, action, "role_denied", version, version)
                        return 403, {"error": "owner role required"}
                    delegate = revoke.group(3)
                    changed = db.execute("""UPDATE grants SET active=0 WHERE tenant=? AND actor=?
                                           AND expense_id=? AND action='submit'""", (tenant, delegate, expense)).rowcount
                    record(db, request_id, tenant, actor, expense, action, "grant_revoked", version, version)
                    return 200, {"revoked_grants": changed, "delegate": delegate}
                scope = (tenant, actor, expense, "submit", idem_key)
                receipt_query = """SELECT * FROM receipts WHERE tenant=? AND actor=? AND
                                   expense_id=? AND action=? AND idem_key=?"""
                receipt = (db.execute(receipt_query, scope).fetchone()
                           if outer.mode == "vulnerable" else None)
                if outer.mode == "vulnerable" and receipt:
                    record(db, request_id, tenant, actor, expense, action, "cached_before_authorization", version, version)
                    return 200, {"status": "submitted", "version": receipt["version"], "replayed": True,
                                 "original_request": receipt["original_request"]}
                allowed = db.execute("""SELECT 1 FROM grants WHERE tenant=? AND actor=? AND
                                     expense_id=? AND action='submit' AND active=1""",
                                     (tenant, actor, expense)).fetchone() is not None
                if not allowed:
                    if outer.mode == "vulnerable" and row["status"] == "draft":
                        db.execute("""UPDATE expenses SET status='submitted',version=version+1,last_request=?
                                   WHERE tenant=? AND id=?""", (request_id, tenant, expense))
                        record(db, request_id, tenant, actor, expense, action, "unauthorized_commit", version, version+1)
                    else:
                        record(db, request_id, tenant, actor, expense, action, "authorization_denied", version, version)
                    return 403, {"error": "submit permission denied"}
                if outer.mode == "fixed":
                    receipt = db.execute(receipt_query, scope).fetchone()
                if receipt:
                    record(db, request_id, tenant, actor, expense, action, "authorized_replay", version, version)
                    return 200, {"status": "submitted", "version": receipt["version"], "replayed": True,
                                 "original_request": receipt["original_request"]}
                if row["status"] != "draft":
                    record(db, request_id, tenant, actor, expense, action, "already_submitted", version, version)
                    return 409, {"error": "expense already submitted"}
                db.execute("""UPDATE expenses SET status='submitted',version=version+1,last_request=?
                           WHERE tenant=? AND id=?""", (request_id, tenant, expense))
                db.execute("INSERT INTO receipts VALUES(?,?,?,?,?,?,?)", scope+(request_id, version+1))
                record(db, request_id, tenant, actor, expense, action, "committed", version, version+1)
                return 201, {"status": "submitted", "version": version+1, "replayed": False}

        class LocalHTTPServer(ThreadingHTTPServer):
            request_queue_size = 64

        self.httpd = LocalHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = False
        self.base_url = "http://127.0.0.1:%d" % self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("HTTP server did not stop")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
