"""Parallel browser context pool with cookie cloning."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

from web_auth_bridge.exceptions import BrowserError, SessionRenewalError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from playwright._impl._api_structures import SetCookieParam
    from playwright.async_api import BrowserContext

    from web_auth_bridge._types import AuthResult
    from web_auth_bridge.auth.protocols import SessionRenewalCallback
    from web_auth_bridge.browser.manager import BrowserManager

logger = logging.getLogger(__name__)


class BrowserContextPool:
    """Manage a pool of parallel Playwright ``BrowserContext`` instances.

    Each context is initialized with the authentication cookies from a
    completed auth flow.  An optional ``SessionRenewalCallback`` runs once
    per context to obtain unique session identifiers for stateful websites.

    Usage::

        async with pool.contexts(count=4) as contexts:
            # contexts is a list of 4 BrowserContext instances
            pages = [await ctx.new_page() for ctx in contexts]
            # drive each page in parallel...

    Args:
        browser_manager: Manages the shared Playwright browser.
        auth_result: The authentication result whose cookies to clone.
        session_renewal: Optional callback to renew session per context.
    """

    def __init__(
        self,
        *,
        browser_manager: BrowserManager,
        auth_result: AuthResult,
        session_renewal: SessionRenewalCallback | None = None,
    ) -> None:
        self._browser_manager = browser_manager
        self._auth_result = auth_result
        self._session_renewal = session_renewal

    @asynccontextmanager
    async def contexts(self, count: int, **context_kwargs: Any) -> AsyncIterator[list[BrowserContext]]:
        """Create *count* parallel browser contexts with auth cookies cloned in.

        Each context gets the full set of authentication cookies.  If a
        ``SessionRenewalCallback`` was provided, it runs once per context
        (sequentially, to avoid thundering-herd on the server) to obtain
        unique session cookies.

        Args:
            count: Number of parallel browser contexts to create.
            **context_kwargs: Extra arguments forwarded to ``browser.new_context()``.

        Yields:
            A list of *count* initialized ``BrowserContext`` instances.

        Raises:
            BrowserError: If context creation fails.
            SessionRenewalError: If the session renewal callback fails.
        """
        if count < 1:
            raise BrowserError("Context count must be at least 1")

        browser = await self._browser_manager.launch()
        raw_cookie_dicts = [c.to_playwright_dict() for c in self._auth_result.cookies]
        cookie_dicts = cast("Sequence[SetCookieParam]", raw_cookie_dicts)

        created_contexts: list[BrowserContext] = []
        try:
            for i in range(count):
                ctx_kwargs = self._browser_manager.context_kwargs(**context_kwargs)
                ctx = await browser.new_context(**ctx_kwargs)
                await ctx.add_cookies(cookie_dicts)
                logger.debug("Context %d/%d created with %d cookies", i + 1, count, len(cookie_dicts))

                if self._session_renewal is not None:
                    page = await ctx.new_page()
                    try:
                        await self._session_renewal.renew(ctx, page, raw_cookie_dicts)
                        logger.debug("Session renewal completed for context %d/%d", i + 1, count)
                    except Exception as exc:
                        raise SessionRenewalError(f"Session renewal failed for context {i + 1}: {exc}") from exc
                    finally:
                        await page.close()

                created_contexts.append(ctx)

            logger.info("Browser context pool ready: %d contexts", count)
            yield created_contexts
        finally:
            for ctx in created_contexts:
                try:
                    await ctx.close()
                except Exception:
                    logger.debug("Error closing context", exc_info=True)
            logger.debug("All pool contexts closed")
