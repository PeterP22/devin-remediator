"""SQLite state store.

Three tables:
  webhook_deliveries — idempotency for GitHub redeliveries (delivery GUID PK)
  remediations       — one row per issue being remediated (issue number UNIQUE)
  events             — append-only audit trail; the dashboard's funnel is
                       computed from here, never from agent self-reports
"""
import sqlite3
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_guid TEXT PRIMARY KEY,
    received_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS remediations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_number  INTEGER NOT NULL UNIQUE,
    package       TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,
    cve           TEXT,
    session_id    TEXT,
    session_url   TEXT,
    state         TEXT NOT NULL DEFAULT 'DETECTED',
    pr_url        TEXT,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_number   INTEGER NOT NULL,
    ts             REAL NOT NULL,
    kind           TEXT NOT NULL,
    detail         TEXT
);
"""

# Remediation lifecycle. Validation/merge/verification are judged by GitHub
# (checks API, merge state, scanner re-scan) — the orchestrator only records
# what it can observe.
STATES = (
    "DETECTED", "SESSION_CREATED", "PR_OPENED",
    "NEEDS_ATTENTION",  # session blocked / waiting without a PR
    "FAILED",           # session errored or ACU-capped without a PR
    "VERIFIED",         # scanner rescan confirmed finding gone (issue closed)
)


class Store:
    def __init__(self, path: str):
        self._path = path
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- idempotency ---------------------------------------------------
    def record_delivery(self, guid: str) -> bool:
        """True if this delivery is new; False if it's a redelivery."""
        with self._conn() as c:
            try:
                c.execute(
                    "INSERT INTO webhook_deliveries (delivery_guid, received_at) VALUES (?, ?)",
                    (guid, time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # -- remediations ---------------------------------------------------
    def create_remediation(self, issue_number: int, package: str, vuln_id: str, cve: str | None) -> bool:
        """True if created; False if the issue already has a remediation."""
        now = time.time()
        with self._conn() as c:
            try:
                c.execute(
                    "INSERT INTO remediations (issue_number, package, vuln_id, cve, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (issue_number, package, vuln_id, cve, now, now),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def set_session(self, issue_number: int, session_id: str, session_url: str):
        self._update(issue_number, "state='SESSION_CREATED', session_id=?, session_url=?", (session_id, session_url))

    def set_state(self, issue_number: int, state: str):
        assert state in STATES, state
        self._update(issue_number, "state=?", (state,))

    def set_pr(self, issue_number: int, pr_url: str):
        self._update(issue_number, "state='PR_OPENED', pr_url=?", (pr_url,))

    def _update(self, issue_number: int, set_clause: str, params: tuple):
        with self._conn() as c:
            c.execute(
                f"UPDATE remediations SET {set_clause}, updated_at=? WHERE issue_number=?",
                (*params, time.time(), issue_number),
            )

    def get(self, issue_number: int) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM remediations WHERE issue_number=?", (issue_number,)).fetchone()
            return dict(row) if row else None

    def active(self) -> list[dict]:
        """Remediations whose sessions still need polling."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM remediations WHERE state IN ('SESSION_CREATED', 'NEEDS_ATTENTION')"
            ).fetchall()
            return [dict(r) for r in rows]

    def all(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM remediations ORDER BY created_at").fetchall()]

    # -- audit trail ------------------------------------------------------
    def log(self, issue_number: int, kind: str, detail: str = ""):
        with self._conn() as c:
            c.execute(
                "INSERT INTO events (issue_number, ts, kind, detail) VALUES (?, ?, ?, ?)",
                (issue_number, time.time(), kind, detail),
            )

    def events(self, issue_number: int | None = None) -> list[dict]:
        q = "SELECT * FROM events"
        params: tuple = ()
        if issue_number is not None:
            q += " WHERE issue_number=?"
            params = (issue_number,)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY ts", params).fetchall()]
