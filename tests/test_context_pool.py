"""Tests for BrowserContextPool (mocked Playwright)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from web_auth_bridge._types import AuthResult, CookieData
from web_auth_bridge.browser.context_pool import BrowserContextPool
from web_auth_bridge.exceptions import BrowserError, SessionRenewalError


def _make_mock_manager() -> MagicMock:
    """Create a mock BrowserManager."""
    manager = MagicMock()
    contexts_created: list[AsyncMock] = []

    def make_context(**_kwargs: object) -> AsyncMock:
        ctx = AsyncMock()
        ctx.add_cookies = AsyncMock()
        ctx.close = AsyncMock()
        mock_page = AsyncMock()
        mock_page.close = AsyncMock()
        ctx.new_page = AsyncMock(return_value=mock_page)
        contexts_created.append(ctx)
        return ctx

    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(side_effect=make_context)
    manager.launch = AsyncMock(return_value=mock_browser)
    manager.context_kwargs = MagicMock(return_value={})
    manager.apply_stealth = AsyncMock()
    manager._contexts_created = contexts_created
    return manager


@pytest.fixture
def sample_result() -> AuthResult:
    return AuthResult(
        cookies=[CookieData(name="auth", value="token", domain=".example.com")],
    )


class TestBrowserContextPool:
    """Tests for parallel context creation."""

    @pytest.mark.asyncio
    async def test_creates_requested_contexts(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        pool = BrowserContextPool(browser_manager=manager, auth_result=sample_result)
        async with pool.contexts(3) as contexts:
            assert len(contexts) == 3

    @pytest.mark.asyncio
    async def test_cookies_injected(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        pool = BrowserContextPool(browser_manager=manager, auth_result=sample_result)
        async with pool.contexts(2) as contexts:
            for ctx in contexts:
                ctx.add_cookies.assert_called_once()  # ty: ignore[unresolved-attribute]
                cookie_arg = ctx.add_cookies.call_args[0][0]  # ty: ignore[unresolved-attribute]
                assert len(cookie_arg) == 1
                assert cookie_arg[0]["name"] == "auth"

    @pytest.mark.asyncio
    async def test_contexts_closed_on_exit(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        pool = BrowserContextPool(browser_manager=manager, auth_result=sample_result)
        async with pool.contexts(2) as contexts:
            pass
        for ctx in contexts:
            ctx.close.assert_called_once()  # ty: ignore[unresolved-attribute]

    @pytest.mark.asyncio
    async def test_zero_count_raises(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        pool = BrowserContextPool(browser_manager=manager, auth_result=sample_result)
        with pytest.raises(BrowserError, match="at least 1"):
            async with pool.contexts(0):
                pass

    @pytest.mark.asyncio
    async def test_session_renewal_called(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        renewal = AsyncMock()
        renewal.renew = AsyncMock()
        pool = BrowserContextPool(
            browser_manager=manager,
            auth_result=sample_result,
            session_renewal=renewal,
        )
        async with pool.contexts(2):
            assert renewal.renew.call_count == 2

    @pytest.mark.asyncio
    async def test_session_renewal_failure_raises(self, sample_result: AuthResult) -> None:
        manager = _make_mock_manager()
        renewal = AsyncMock()
        renewal.renew = AsyncMock(side_effect=RuntimeError("session expired"))
        pool = BrowserContextPool(
            browser_manager=manager,
            auth_result=sample_result,
            session_renewal=renewal,
        )
        with pytest.raises(SessionRenewalError, match="session expired"):
            async with pool.contexts(1):
                pass
