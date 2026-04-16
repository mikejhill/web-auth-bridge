"""Tests for Authenticator (mocked Playwright)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

from web_auth_bridge._types import AuthResult, CookieData
from web_auth_bridge.auth.authenticator import Authenticator
from web_auth_bridge.auth.cache import AuthCache
from web_auth_bridge.exceptions import AuthError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "auth-cache"


@pytest.fixture
def auth_cache(cache_dir: Path) -> AuthCache:
    return AuthCache(cache_dir)


def _make_mock_browser_manager() -> MagicMock:
    """Create a mock BrowserManager with chained async context/page."""
    manager = MagicMock()
    mock_page = AsyncMock()
    mock_context = AsyncMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_context.cookies = AsyncMock(return_value=[])
    mock_context.close = AsyncMock()
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    manager.launch = AsyncMock(return_value=mock_browser)
    manager.context_kwargs = MagicMock(return_value={})
    manager.apply_stealth = AsyncMock()
    return manager


class TestAuthenticatorEnsureAuthenticated:
    """Tests for the ensure_authenticated flow."""

    @pytest.mark.asyncio
    async def test_uses_cache_when_valid(self, auth_cache: AuthCache) -> None:
        cached = AuthResult(
            cookies=[CookieData(name="c", value="v", domain="d")],
            tokens={"jwt": "cached-token"},
        )
        auth_cache.save(cached)

        callback = AsyncMock()
        callback.is_authenticated = AsyncMock(return_value=True)
        manager = _make_mock_browser_manager()

        auth = Authenticator(callback=callback, browser_manager=manager, cache=auth_cache)
        result = await auth.ensure_authenticated()

        assert result.tokens["jwt"] == "cached-token"
        # Browser should NOT have been launched
        manager.launch.assert_not_called()

    @pytest.mark.asyncio
    async def test_authenticates_when_no_cache(self, auth_cache: AuthCache) -> None:
        fresh_result = AuthResult(
            cookies=[CookieData(name="new", value="val", domain="d")],
            tokens={"jwt": "fresh-token"},
        )
        callback = AsyncMock()
        callback.authenticate = AsyncMock(return_value=fresh_result)
        manager = _make_mock_browser_manager()

        auth = Authenticator(callback=callback, browser_manager=manager, cache=auth_cache)
        result = await auth.ensure_authenticated()

        assert result.tokens["jwt"] == "fresh-token"
        callback.authenticate.assert_called_once()

    @pytest.mark.asyncio
    async def test_auth_error_on_none_result(self, auth_cache: AuthCache) -> None:
        callback = AsyncMock()
        callback.authenticate = AsyncMock(return_value=None)
        manager = _make_mock_browser_manager()

        auth = Authenticator(callback=callback, browser_manager=manager, cache=auth_cache)
        with pytest.raises(AuthError, match="returned None"):
            await auth.ensure_authenticated()

    @pytest.mark.asyncio
    async def test_callback_exception_wrapped(self, auth_cache: AuthCache) -> None:
        callback = AsyncMock()
        callback.authenticate = AsyncMock(side_effect=RuntimeError("network failure"))
        manager = _make_mock_browser_manager()

        auth = Authenticator(callback=callback, browser_manager=manager, cache=auth_cache)
        with pytest.raises(AuthError, match="network failure"):
            await auth.ensure_authenticated()


class TestAuthenticatorForceAuthenticate:
    """Tests for force_authenticate."""

    @pytest.mark.asyncio
    async def test_ignores_cache(self, auth_cache: AuthCache) -> None:
        auth_cache.save(AuthResult(tokens={"jwt": "old"}))

        fresh_result = AuthResult(tokens={"jwt": "new"})
        callback = AsyncMock()
        callback.authenticate = AsyncMock(return_value=fresh_result)
        manager = _make_mock_browser_manager()

        auth = Authenticator(callback=callback, browser_manager=manager, cache=auth_cache)
        result = await auth.force_authenticate()

        assert result.tokens["jwt"] == "new"
        callback.authenticate.assert_called_once()
