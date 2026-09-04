"""Application configuration.

All secrets and tunables come from environment variables (or a local .env
file loaded via python-dotenv).  Nothing secret is ever hard-coded in the
source tree.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(_BASE_DIR / ".env")
_env_file = os.environ.get("APP_ENV_FILE", "").strip()
if _env_file:
    _load_dotenv(Path(_env_file).expanduser())


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "Anti-Phishing URL Protection Platform"
    env: str = os.environ.get("APP_ENV", "development")
    debug: bool = _bool("APP_DEBUG", False)

    # --- paths / database -----------------------------------------------
    backend_dir: Path = _BASE_DIR
    database_path: Path = Path(
        os.environ.get("DATABASE_PATH", str(_BASE_DIR / "data" / "antiphishing.db"))
    )
    seed_on_startup: bool = _bool("SEED_ON_STARTUP", True)

    # --- auth -------------------------------------------------------------
    token_ttl_hours: int = _int("TOKEN_TTL_HOURS", 24 * 7)
    pbkdf2_rounds: int = _int("PBKDF2_ROUNDS", 310000)
    default_admin_email: str = os.environ.get(
        "DEFAULT_ADMIN_EMAIL", "admin@company-example.com"
    )
    default_admin_password: str = os.environ.get(
        "DEFAULT_ADMIN_PASSWORD", ""
    )

    # --- rate limiting -----------------------------------------------------
    rate_limit_enabled: bool = _bool("RATE_LIMIT_ENABLED", True)
    analyze_rate_limit: str = os.environ.get("ANALYZE_RATE_LIMIT", "30/minute")
    generic_rate_limit: str = os.environ.get("GENERIC_RATE_LIMIT", "120/minute")
    auth_rate_limit: str = os.environ.get("AUTH_RATE_LIMIT", "10/minute")

    # --- risk thresholds (0-100, configurable) -----------------------------
    low_risk_threshold: int = _int("LOW_RISK_THRESHOLD", 20)
    moderate_risk_threshold: int = _int("MODERATE_RISK_THRESHOLD", 50)
    high_risk_threshold: int = _int("HIGH_RISK_THRESHOLD", 75)
    # boundaries above map classification: <=low SAFE, <=moderate SUSPICIOUS,
    # <=high MALICIOUS, above MALICIOUS(critical). "UNKNOWN" is a separate,
    # signal-driven classification (see risk_scorer).

    # --- threat intelligence ----------------------------------------------
    enable_external_ti: bool = _bool("ENABLE_EXTERNAL_TI", False)
    ti_fetch_timeout_s: float = float(os.environ.get("TI_FETCH_TIMEOUT_S", "5"))
    virustotal_api_key: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
    virustotal_base_url: str = os.environ.get(
        "VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"
    )
    google_safebrowsing_api_key: str = os.environ.get(
        "GOOGLE_SAFEBROWSING_API_KEY", ""
    )
    google_safebrowsing_client_id: str = os.environ.get(
        "GOOGLE_SAFEBROWSING_CLIENT_ID", "antiphishing-platform"
    )
    google_safebrowsing_base_url: str = os.environ.get(
        "GOOGLE_SAFEBROWSING_BASE_URL",
        "https://safebrowsing.googleapis.com/v4/",
    )
    urlhaus_base_url: str = os.environ.get(
        "URLHAUS_BASE_URL", "https://urlhaus-api.abuse.ch/v1"
    )

    # --- live threat-intel feed (keyless bulk sync) -----------------------
    # Pulls fresh malicious hosts from the public abuse.ch URLhaus hostfile
    # into known_threats on a schedule. Independent of the per-scan providers.
    ti_sync_enabled: bool = _bool("TI_SYNC_ENABLED", False)
    ti_sync_interval_min: int = _int("TI_SYNC_INTERVAL_MIN", 30)
    ti_sync_max_items: int = _int("TI_SYNC_MAX_ITEMS", 5000)
    ti_sync_max_total: int = _int("TI_SYNC_MAX_TOTAL", 100000)

    # --- email analysis ----------------------------------------------------
    email_keywords: tuple[str, ...] = field(
        default=(
            "verify", "verification", "confirm", "password", "credential",
            "invoice", "payment", "urgent", "suspended", "locked", "security",
            "account", "update", "wallet", "refund", "wire", "lottery",
            "gift card", "bonus", "irs", "tax refund", "login",
        )
    )

    # --- static / UI -------------------------------------------------------
    static_dir: Path = Path(
        os.environ.get(
            "STATIC_DIR", str(_BASE_DIR.parent / "frontend")
        )
    )


settings = Settings()