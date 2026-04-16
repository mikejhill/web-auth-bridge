"""Garmin Connect live e2e test.

Reuses the ``GarminAuthCallback`` from ``examples/garmin_connect.py`` —
so this test doubles as a contract test for the example implementation.

Skipped automatically when ``GARMIN_EMAIL`` / ``GARMIN_PASSWORD`` are
not set in the environment or ``.env`` file.

Install prerequisites
~~~~~~~~~~~~~~~~~~~~~
The Garmin callback needs the ``tls-impersonation`` extra because
Garmin's ``diauth.garmin.com`` endpoint blocks non-browser TLS
fingerprints::

    uv sync --extra tls-impersonation

Run just these tests::

    pytest -m "e2e and garmin"
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from web_auth_bridge import AuthResult, WebAuthBridge

if TYPE_CHECKING:
    from collections.abc import Callable

    from web_auth_bridge import Credentials

pytestmark = [pytest.mark.e2e, pytest.mark.garmin, pytest.mark.asyncio]


# ---------------------------------------------------------------------------
# Load GarminAuthCallback from the examples directory (not a package)
# ---------------------------------------------------------------------------


def _load_garmin_module() -> object:
    """Import ``examples/garmin_connect.py`` directly as a module."""
    example_path = Path(__file__).resolve().parents[2] / "examples" / "garmin_connect.py"
    if not example_path.is_file():
        pytest.skip(f"Garmin example script not found at {example_path}")

    spec = importlib.util.spec_from_file_location("garmin_connect_example", example_path)
    assert spec is not None, f"Failed to build import spec for {example_path}"
    assert spec.loader is not None, f"Import spec for {example_path} has no loader"
    module = importlib.util.module_from_spec(spec)
    sys.modules["garmin_connect_example"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def garmin_module() -> object:
    # Prerequisite: the example depends on curl_cffi (tls-impersonation extra).
    try:
        import curl_cffi  # noqa: F401
    except ImportError:
        pytest.skip("Garmin e2e requires the tls-impersonation extra. Install with: uv sync --extra tls-impersonation")
    return _load_garmin_module()


@pytest.fixture
def garmin_callback(garmin_module: object) -> object:
    return garmin_module.GarminAuthCallback()  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGarminLiveAuth:
    async def test_authenticates_and_returns_populated_result(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        garmin_callback: object,
        garmin_credentials: Credentials,
    ) -> None:
        bridge = make_bridge(
            auth_callback=garmin_callback,
            credentials=garmin_credentials,
            cache_subdir="garmin-auth",
        )

        result = await bridge.ensure_authenticated()

        assert isinstance(result, AuthResult), f"ensure_authenticated must return AuthResult, got {type(result)}"

        cookie_names = {c.name for c in result.cookies}
        assert "JWT_WEB" in cookie_names, (
            f"Expected JWT_WEB cookie after Garmin auth, got cookies: {sorted(cookie_names)}"
        )

        assert "di_token" in result.tokens, (
            f"Expected DI Bearer token under 'di_token', got token keys: {list(result.tokens.keys())}"
        )
        assert result.tokens["di_token"], "DI token must not be empty"

    async def test_di_token_reaches_connectapi(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        garmin_callback: object,
        garmin_credentials: Credentials,
    ) -> None:
        """End-to-end proof: the extracted DI token actually grants API access.

        Hits ``connectapi.garmin.com/userprofile-service/userprofile/user-settings``
        — the canonical smoke test for native Garmin mobile API auth.
        """
        bridge = make_bridge(
            auth_callback=garmin_callback,
            credentials=garmin_credentials,
            cache_subdir="garmin-api",
        )
        result = await bridge.ensure_authenticated()
        di_token = result.tokens.get("di_token")
        assert di_token, "Cannot test API access without a DI token"

        headers = {
            "Authorization": f"Bearer {di_token}",
            "User-Agent": "GCM-Android-5.23",
            "X-Garmin-User-Agent": (
                "com.garmin.android.apps.connectmobile/5.23; ; Google/sdk_gphone64_arm64/google; "
                "Android/33; Dalvik/2.1.0"
            ),
            "X-App-Ver": "10861",
            "X-Lang": "en",
        }
        async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
            resp = await client.get("https://connectapi.garmin.com/userprofile-service/userprofile/user-settings")

        assert resp.status_code == 200, (
            f"connectapi user-settings call failed: status={resp.status_code}, body={resp.text[:300]!r}"
        )
        payload = resp.json()
        assert "id" in payload, f"Expected user-settings response to include 'id', got keys: {sorted(payload.keys())}"

    async def test_cache_reuse_skips_second_browser_launch(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        garmin_callback: object,
        garmin_credentials: Credentials,
    ) -> None:
        """Second bridge instance sharing the cache directory must NOT re-authenticate.

        This is the central value proposition of the library — proves the
        auth-then-reuse flow works end-to-end against a real WAF-protected site.
        """
        first = make_bridge(
            auth_callback=garmin_callback,
            credentials=garmin_credentials,
            cache_subdir="garmin-reuse",
        )
        first_result = await first.ensure_authenticated()
        first_jwt = next((c.value for c in first_result.cookies if c.name == "JWT_WEB"), None)
        assert first_jwt, "Precondition: first auth must yield JWT_WEB"

        # Second bridge hits the same cache_dir — no credentials supplied
        # to prove the reload path, not re-auth.
        second = make_bridge(
            auth_callback=garmin_callback,
            credentials=None,
            cache_subdir="garmin-reuse",
        )
        second_result = await second.ensure_authenticated()
        second_jwt = next((c.value for c in second_result.cookies if c.name == "JWT_WEB"), None)

        assert second_jwt == first_jwt, (
            f"Expected second bridge to reuse cached JWT_WEB ({first_jwt[:12] if first_jwt else None}...), "
            f"got different value ({second_jwt[:12] if second_jwt else None}...) — cache not consulted"
        )
