"""Tests for the exception hierarchy."""

from __future__ import annotations

from web_auth_bridge.exceptions import (
    AuthError,
    BrowserError,
    CacheError,
    SessionRenewalError,
    WebAuthBridgeError,
)


class TestExceptionHierarchy:
    """Verify all exceptions inherit from the base."""

    def test_auth_error_is_base(self) -> None:
        assert issubclass(AuthError, WebAuthBridgeError)

    def test_cache_error_is_base(self) -> None:
        assert issubclass(CacheError, WebAuthBridgeError)

    def test_browser_error_is_base(self) -> None:
        assert issubclass(BrowserError, WebAuthBridgeError)

    def test_session_renewal_error_is_base(self) -> None:
        assert issubclass(SessionRenewalError, WebAuthBridgeError)

    def test_base_is_exception(self) -> None:
        assert issubclass(WebAuthBridgeError, Exception)

    def test_catch_all(self) -> None:
        """All concrete exceptions are caught by the base."""
        for exc_class in (AuthError, CacheError, BrowserError, SessionRenewalError):
            try:
                raise exc_class("test")
            except WebAuthBridgeError:
                pass  # Expected
