"""Credential-free regression tests for example authentication boundaries."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, Mock

import pytest

from web_auth_bridge import AuthResult, CookieData

if TYPE_CHECKING:
    from types import ModuleType


def _load_source(relative: str) -> ModuleType:
    """Load example/test source without invoking live credential fixtures."""
    spec = importlib.util.spec_from_file_location("boundary_subject", Path(__file__).parents[1] / relative)
    assert spec is not None, "Expected importable regression subject"
    assert spec.loader is not None, "Expected source loader"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ROUVY = _load_source("tests/e2e/test_rouvy_live.py")
_GARMIN = _load_source("examples/garmin_connect.py")


class TestRouvyDomainBoundary:
    """Authenticate only cookies on the intended DNS domain."""

    @pytest.mark.parametrize("domain", ["rouvy.com", ".rouvy.com", "riders.rouvy.com", ".Riders.ROUVY.COM"])
    async def test_accepts_exact_host_and_subdomains(self, domain: str) -> None:
        """Host-only and subdomain cookies remain accepted, ignoring DNS case."""
        cookie = CookieData(name="session", value="synthetic", domain=domain)
        result = await _ROUVY.RouvyAuthCallback().is_authenticated(AuthResult(cookies=[cookie]))
        assert result is True, f"Expected Rouvy domain {domain!r} to authenticate"

    @pytest.mark.parametrize("domain", ["evilrouvy.com", ".evilrouvy.com", "rouvy.com.evil.invalid", "", "rouvyXcom"])
    async def test_rejects_suffix_impostors(self, domain: str) -> None:
        """A textual suffix without a DNS label boundary is not Rouvy."""
        cookie = CookieData(name="session", value="synthetic", domain=domain)
        result = await _ROUVY.RouvyAuthCallback().is_authenticated(AuthResult(cookies=[cookie]))
        assert result is False, f"Unrelated domain {domain!r} must not authenticate"


class TestGarminResponseDiagnostics:
    """Authentication response secrets never enter logs or exception messages."""

    async def test_success_returns_response_without_logging_body(self, caplog: pytest.LogCaptureFixture) -> None:
        """Callers still receive the token while debug output contains only status."""
        page = AsyncMock()
        page.evaluate.return_value = {"status": 200, "body": '{"serviceTicketId":"synthetic-secret"}'}
        with caplog.at_level(logging.DEBUG, logger="garmin_connect"):
            result = await _GARMIN._js_fetch_json(page, "https://example.invalid/auth", {})
        assert result == {"serviceTicketId": "synthetic-secret"}, "Parsed authentication response must be preserved"
        assert "synthetic-secret" not in caplog.text, "Debug logs must not disclose the service ticket"

    @pytest.mark.parametrize("statuses", [(403,), (429, 429), (429, 403), (200,)])
    async def test_errors_and_retries_do_not_disclose_body(
        self, statuses: tuple[int, ...], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Both initial and retry failure diagnostics exclude raw response data."""
        page = AsyncMock()
        page.evaluate.side_effect = [{"status": status, "body": "synthetic-secret"} for status in statuses]
        with caplog.at_level(logging.DEBUG, logger="garmin_connect"), pytest.raises(RuntimeError) as caught:
            await _GARMIN._js_fetch_json(page, "https://example.invalid/auth", {})
        assert "synthetic-secret" not in str(caught.value), "Exceptions must not disclose response body"
        assert "synthetic-secret" not in caplog.text, "Retry and failure logs must not disclose response body"


class TestGarminTokenDiagnostics:
    """Failure bodies from token and authenticated API responses stay private."""

    @pytest.mark.parametrize("operation", ["_exchange_di_tokens", "_verify_profile", "_demo_api_calls"])
    @pytest.mark.parametrize("status", [200, 403])
    def test_raw_response_never_enters_diagnostics(
        self, operation: str, status: int, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Malformed success and HTTP error bodies may contain credentials or user data."""
        transport = SimpleNamespace(post=Mock(), get=Mock())
        transport.post.return_value = SimpleNamespace(status_code=status, text="synthetic-private-response")
        transport.get.return_value = SimpleNamespace(status_code=status, text="synthetic-private-response")
        monkeypatch.setitem(sys.modules, "curl_cffi", SimpleNamespace(requests=transport))
        argument = {"di_token": "synthetic-token"} if operation == "_demo_api_calls" else "synthetic-token"
        with caplog.at_level(logging.DEBUG, logger="garmin_connect"):
            result = getattr(_GARMIN, operation)(argument)
        assert result == (None if operation == "_demo_api_calls" else {}), "Failed responses must not yield tokens"
        assert "synthetic-private-response" not in caplog.text, "Raw authenticated responses must not enter logs"

    def test_successful_exchange_preserves_tokens_without_logging_them(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Removing diagnostics must not change successful token exchange."""
        transport = SimpleNamespace(
            post=Mock(
                return_value=SimpleNamespace(
                    status_code=200, text='{"access_token":"synthetic-access","refresh_token":"synthetic-refresh"}'
                )
            )
        )
        monkeypatch.setitem(sys.modules, "curl_cffi", SimpleNamespace(requests=transport))
        with caplog.at_level(logging.DEBUG, logger="garmin_connect"):
            result = _GARMIN._exchange_di_tokens("synthetic-ticket")
        assert result == {"di_token": "synthetic-access", "di_refresh_token": "synthetic-refresh"}, (
            "Successful exchange must still return access and refresh tokens"
        )
        assert "synthetic-" not in caplog.text, "Authentication artifacts must not enter diagnostics"
