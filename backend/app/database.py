"""SQLite persistence layer.

Schema, connection management and helpers.  SQLite is chosen so the product
runs zero-configuration out of the box; every table uses explicit indexes and
timestamps so the same model can be lifted to PostgreSQL later without
redesign.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from .config import settings

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id         INTEGER NOT NULL REFERENCES organizations(id),
    email          TEXT NOT NULL UNIQUE,
    full_name      TEXT NOT NULL DEFAULT '',
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL DEFAULT 'EMPLOYEE'
                   CHECK (role IN ('EMPLOYEE','SECURITY_ANALYST','ADMIN','SUPER_ADMIN')),
    status         TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
    created_at     TEXT NOT NULL,
    last_login_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_users_org   ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS trusted_domains (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id              INTEGER NOT NULL REFERENCES organizations(id),
    domain              TEXT NOT NULL,
    normalized_domain   TEXT NOT NULL,
    category            TEXT NOT NULL DEFAULT 'Corporate',
    is_critical         INTEGER NOT NULL DEFAULT 0,
    allowed_subdomains  TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    added_by            INTEGER REFERENCES users(id),
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_trusted_org_domain
    ON trusted_domains(org_id, normalized_domain);
CREATE INDEX IF NOT EXISTS idx_trusted_org ON trusted_domains(org_id);

CREATE TABLE IF NOT EXISTS url_scans (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id            INTEGER NOT NULL REFERENCES organizations(id),
    user_id           INTEGER REFERENCES users(id),
    url               TEXT NOT NULL,
    hostname          TEXT NOT NULL DEFAULT '',
    registered_domain TEXT NOT NULL DEFAULT '',
    punycode_domain   TEXT NOT NULL DEFAULT '',
    classification    TEXT NOT NULL,
    risk_score        INTEGER NOT NULL DEFAULT 0,
    matched_domain    TEXT,
    signals           TEXT NOT NULL DEFAULT '[]',
    reasons           TEXT NOT NULL DEFAULT '[]',
    details           TEXT NOT NULL DEFAULT '{}',
    source            TEXT NOT NULL DEFAULT 'EMPLOYEE',
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_org_time ON url_scans(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_class    ON url_scans(classification);
CREATE INDEX IF NOT EXISTS idx_scans_regdom   ON url_scans(registered_domain);
CREATE INDEX IF NOT EXISTS idx_scans_user     ON url_scans(user_id);

CREATE TABLE IF NOT EXISTS threat_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        INTEGER NOT NULL REFERENCES organizations(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),
    url           TEXT NOT NULL,
    analysis      TEXT NOT NULL DEFAULT '{}',
    comment       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'NEW'
                  CHECK (status IN ('NEW','INVESTIGATING','CONFIRMED_THREAT','FALSE_POSITIVE','RESOLVED')),
    reviewed_by   INTEGER REFERENCES users(id),
    reviewed_at   TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_org_time ON threat_reports(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_reports_status   ON threat_reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_user     ON threat_reports(user_id);

CREATE TABLE IF NOT EXISTS threat_intel_results (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url_scan_id INTEGER REFERENCES url_scans(id),
    provider   TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    score      INTEGER NOT NULL DEFAULT 0,
    payload    TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ti_scan ON threat_intel_results(url_scan_id);

CREATE TABLE IF NOT EXISTS known_threats (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES organizations(id),
    domain     TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT 'MANUAL',
    category   TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_known_threats_org_domain
    ON known_threats(org_id, domain);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id      INTEGER REFERENCES organizations(id),
    actor_id    INTEGER REFERENCES users(id),
    actor_email TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    entity      TEXT NOT NULL DEFAULT '',
    entity_id   TEXT,
    prev        TEXT NOT NULL DEFAULT '{}',
    new         TEXT NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT '',
    result      TEXT NOT NULL DEFAULT 'SUCCESS',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_logs(action);

CREATE TABLE IF NOT EXISTS system_settings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     INTEGER NOT NULL REFERENCES organizations(id),
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_by INTEGER REFERENCES users(id),
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_org_key
    ON system_settings(org_id, key);
"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _get_conn() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect(settings.database_path)
        _local.conn = conn
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    """Yield a thread-local connection with a transaction."""
    conn = _get_conn()
    try:
        conn.execute("BEGIN")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def fetchone(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    with db() as conn:
        return conn.execute(sql, params).fetchone()


def fetchall(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> int:
    """Execute and return lastrowid."""
    with db() as conn:
        cur = conn.execute(sql, params)
        return int(cur.lastrowid)


def execute_many(sql: str, seq: list[tuple]) -> None:
    with db() as conn:
        conn.executemany(sql, seq)


def init_db(path: Optional[Path | str] = None) -> None:
    """Create schema.  Callable on any connection path (tests use tmp dirs)."""
    if path is not None:
        saved, settings_db = settings.database_path, path  # type: ignore[misc]
        settings.database_path = path  # type: ignore[misc]
        try:
            conn = _connect(path)
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
            conn.close()
        finally:
            settings.database_path = saved  # type: ignore[misc]
        return
    conn = _connect(settings.database_path)
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()
    conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive migrations for databases created by older versions."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(known_threats)")}
    if "category" not in cols:
        conn.execute(
            "ALTER TABLE known_threats ADD COLUMN category TEXT NOT NULL DEFAULT ''"
        )


class Config:
    """JSON wrapper for values stored in system_settings."""

    @staticmethod
    def get_risk_thresholds(org_id: int) -> dict[str, int]:
        defaults = {
            "low": settings.low_risk_threshold,
            "moderate": settings.moderate_risk_threshold,
            "high": settings.high_risk_threshold,
        }
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM system_settings WHERE org_id=? AND key=?",
                (org_id, "risk_thresholds"),
            ).fetchone()
        if not row:
            return defaults
        try:
            merged = dict(defaults)
            merged.update({k: int(v) for k, v in json.loads(row["value"]).items()})
            return merged
        except (ValueError, TypeError, json.JSONDecodeError):
            return defaults

    @staticmethod
    def set_risk_thresholds(org_id: int, values: dict, actor_id: Any) -> str:
        """Persist thresholds; returns the previous stored JSON for audit."""
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM system_settings WHERE org_id=? AND key=?",
                (org_id, "risk_thresholds"),
            ).fetchone()
            prev = row["value"] if row else "{}"
            conn.execute(
                """
                INSERT INTO system_settings (org_id, key, value, updated_by, updated_at)
                VALUES (?, 'risk_thresholds', ?, ?, ?)
                ON CONFLICT(org_id, key) DO UPDATE SET
                    value=excluded.value, updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at
                """,
                (org_id, json.dumps(values), actor_id, utcnow_iso()),
            )
            return prev

    # Content-policy: categories whose sites are blocked for the whole org.
    DEFAULT_BLOCKED_CATEGORIES: tuple[str, ...] = ("GAMBLING", "ADULT")

    @staticmethod
    def get_content_policy(org_id: int) -> list[str]:
        """Categories that are actively blocked for the org."""
        defaults = list(Config.DEFAULT_BLOCKED_CATEGORIES)
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM system_settings WHERE org_id=? AND key=?",
                (org_id, "content_policy"),
            ).fetchone()
        if not row:
            return defaults
        try:
            values = json.loads(row["value"])
            return [c for c in values if isinstance(c, str)] if isinstance(values, list) else defaults
        except (ValueError, TypeError, json.JSONDecodeError):
            return defaults

    @staticmethod
    def set_content_policy(org_id: int, categories: list[str], actor_id: Any) -> str:
        """Persist blocked categories; returns the previous stored JSON."""
        with db() as conn:
            row = conn.execute(
                "SELECT value FROM system_settings WHERE org_id=? AND key=?",
                (org_id, "content_policy"),
            ).fetchone()
            prev = row["value"] if row else "{}"
            conn.execute(
                """
                INSERT INTO system_settings (org_id, key, value, updated_by, updated_at)
                VALUES (?, 'content_policy', ?, ?, ?)
                ON CONFLICT(org_id, key) DO UPDATE SET
                    value=excluded.value, updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at
                """,
                (org_id, json.dumps(categories), actor_id, utcnow_iso()),
            )
            return prev