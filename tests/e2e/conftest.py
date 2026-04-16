"""Shared fixtures for e2e tests: .env loading, credential checks, bridge builder.

Loads environment variables from ``.env.tests`` or ``.env`` at the project
root on import.  Per-site credential fixtures raise ``pytest.skip`` when
the required variables are missing — so running ``pytest -m e2e`` without
any credentials is a no-op, not a failure.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from web_auth_bridge import Credentials, WebAuthBridge

if TYPE_CHECKING:
    from collections.abc import Callable

    from web_auth_bridge.auth.protocols import AuthCallback


# ---------------------------------------------------------------------------
# .env loading
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_env_file(path: Path) -> None:
    """Load ``KEY=VALUE`` pairs from *path* into ``os.environ``.

    Does not override variables already set in the environment (CI wins
    over committed .env files).  Silently returns if the file is absent.
    """
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# Load on module import so collection-time skips can inspect values.
# Preference order: ``.env.tests`` (explicit test config) > ``.env``.
_load_env_file(_PROJECT_ROOT / ".env.tests")
_load_env_file(_PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------------
# Shared configuration
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


@pytest.fixture(scope="session")
def e2e_headless() -> bool:
    """Whether e2e tests should run their browser in headless mode."""
    return _env_bool("WEB_AUTH_BRIDGE_E2E_HEADLESS", default=True)


@pytest.fixture(scope="session")
def e2e_channel() -> str:
    """Playwright browser channel for e2e tests (defaults to ``"chrome"``).

    Using a real Chrome install (``"chrome"`` or ``"msedge"``) is strongly
    preferred over bundled Chromium — most WAFs can fingerprint the
    bundled build even with the bridge's stealth patches applied.
    """
    return os.environ.get("WEB_AUTH_BRIDGE_E2E_CHANNEL", "chrome")


# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------


def _require_credentials(email_var: str, password_var: str, site: str) -> Credentials:
    """Return ``Credentials`` from env vars or skip the test."""
    email = os.environ.get(email_var, "").strip()
    password = os.environ.get(password_var, "").strip()
    if not email or not password:
        pytest.skip(f"{site} e2e test skipped: set {email_var} and {password_var} in environment or .env to enable.")
    return Credentials(username=email, password=password)


@pytest.fixture
def garmin_credentials() -> Credentials:
    return _require_credentials("GARMIN_EMAIL", "GARMIN_PASSWORD", "Garmin")


@pytest.fixture
def rouvy_credentials() -> Credentials:
    return _require_credentials("ROUVY_EMAIL", "ROUVY_PASSWORD", "Rouvy")


# ---------------------------------------------------------------------------
# Bridge factory
# ---------------------------------------------------------------------------


@pytest.fixture
def make_bridge(
    tmp_path: Path,
    e2e_headless: bool,
    e2e_channel: str,
) -> Callable[..., WebAuthBridge]:
    """Return a factory that builds a WebAuthBridge for e2e use.

    Each test gets its own isolated cache directory under ``tmp_path`` so
    tests don't contaminate each other via cached auth state.
    """

    def _make(
        *,
        auth_callback: AuthCallback,
        credentials: Credentials | None,
        cache_subdir: str = "default",
    ) -> WebAuthBridge:
        return WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=tmp_path / cache_subdir,
            credentials=credentials,
            headless=e2e_headless,
            launch_kwargs={"channel": e2e_channel} if e2e_channel else None,
        )

    return _make
