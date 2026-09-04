"""Initial data seeding: default org, super-admin, trusted domains, sample
known threats and a small set of demo scans/reports so dashboards are useful
immediately.  Idempotent — safe to run on every startup.
"""
from __future__ import annotations

import logging

from . import database
from .config import settings
from .hashing import hash_password

log = logging.getLogger("seed")

DEFAULT_ORG = "company-example"
DEFAULT_ORG_NAME = "Example Corp"

DEFAULT_TRUSTED_DOMAINS = [
    {"domain": "maybank2u.com", "category": "Banking", "critical": True},
    {"domain": "citibank.com", "category": "Banking", "critical": True},
    {"domain": "microsoft.com", "category": "Software", "critical": True},
    {"domain": "google.com", "category": "Software", "critical": True},
    {"domain": "company-example.com", "category": "Corporate", "critical": True},
    {"domain": "example.com", "category": "Corporate", "critical": False},
]

DEFAULT_KNOWN_THREATS = [
    # (domain, category) — uncategorized = confirmed malware; categorized =
    # content-policy rows blocked only while that category is enabled.
    ("paypa1-secure.com", ""),
    ("microsoft-support-alerts.net", ""),
    ("webmail-microsoft-login.com", ""),
    ("bet-demo-casino.com", "GAMBLING"),
    ("adult-demo-content.net", "ADULT"),
]

DEMO_SCANS = [
    ("https://maybank2u.com/", "SAFE", "maybank2u.com"),
    ("https://www.google.com/", "SAFE", "google.com"),
    ("https://secure-company-example-login.com/", "MALICIOUS",
     "company-example.com"),
    ("https://maybanк2u.com/", "MALICIOUS", "maybank2u.com"),  # Cyrillic к
    ("https://c1tibank.com/secure/login", "SUSPICIOUS", "citibank.com"),
    ("https://microsoft-account-verify.net/", "MALICIOUS", "microsoft.com"),
]


def seed() -> None:
    org = database.fetchone(
        "SELECT id FROM organizations WHERE slug=?", (DEFAULT_ORG,)
    )
    if org is None:
        org_id = database.execute(
            "INSERT INTO organizations (name, slug, created_at) VALUES (?,?,?)",
            (DEFAULT_ORG_NAME, DEFAULT_ORG, database.utcnow_iso()),
        )
    else:
        org_id = org["id"]

    admin = database.fetchone(
        "SELECT id FROM users WHERE email=lower(?)", (settings.default_admin_email,)
    )
    admin_id = admin["id"] if admin else None
    if admin is None:
        password = settings.default_admin_password or "ChangeMe_123!"
        admin_id = database.execute(
            """
            INSERT INTO users (org_id, email, full_name, password_hash, role, status, created_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                org_id,
                settings.default_admin_email.lower(),
                "System Administrator",
                hash_password(password),
                "SUPER_ADMIN",
                "ACTIVE",
                database.utcnow_iso(),
            ),
        )
        log.warning("Created super-admin %s with default password. CHANGE IT.",
                    settings.default_admin_email)

    # Trusted domains
    for td in DEFAULT_TRUSTED_DOMAINS:
        norm = td["domain"].rstrip(".").lower()
        exists = database.fetchone(
            "SELECT id FROM trusted_domains WHERE org_id=? AND normalized_domain=?",
            (org_id, norm),
        )
        if exists is None:
            database.execute(
                """
                INSERT INTO trusted_domains
                    (org_id, domain, normalized_domain, category, is_critical,
                     allowed_subdomains, notes, added_by, created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    org_id, td["domain"], norm, td["category"],
                    1 if td["critical"] else 0,
                    "*." + norm if td.get("wildcard") else "",
                    "Automatically seeded trusted domain",
                    admin_id, database.utcnow_iso(), database.utcnow_iso(),
                ),
            )

    for threat, category in DEFAULT_KNOWN_THREATS:
        exists = database.fetchone(
            "SELECT id FROM known_threats WHERE org_id=? AND domain=?",
            (org_id, threat),
        )
        if exists is None:
            database.execute(
                """
                INSERT INTO known_threats
                    (org_id, domain, note, source, category, created_at)
                VALUES (?,?,?,?,?,?)
                """,
                (org_id, threat, "Seeded known-bad domain", "SEED", category,
                 database.utcnow_iso()),
            )

    # Sample scans (only when table is empty so real data is never polluted)
    count = database.fetchone(
        "SELECT COUNT(*) AS c FROM url_scans WHERE org_id=?", (org_id,)
    )["c"]
    if count == 0 and settings.seed_on_startup:
        from .services.analyzer import UrlAnalyzer

        analyzer = UrlAnalyzer(org_id=org_id, user_id=admin_id, persist=True)
        for url, _cls, _match in DEMO_SCANS:
            try:
                analyzer.analyze(url, source="SEED")
            except Exception:  # never let seeding break startup
                log.exception("seed scan failed for %s", url)

    # Default risk thresholds
    row = database.fetchone(
        "SELECT id FROM system_settings WHERE org_id=? AND key=?",
        (org_id, "risk_thresholds"),
    )
    if row is None:
        database.execute(
            """
            INSERT INTO system_settings (org_id, key, value, updated_by, updated_at)
            VALUES (?, 'risk_thresholds', ?, ?, ?)
            """,
            (
                org_id,
                '{"low":20,"moderate":50,"high":75}',
                admin_id, database.utcnow_iso(),
            ),
        )


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    database.init_db()
    seed()
    print("Seeding complete.")