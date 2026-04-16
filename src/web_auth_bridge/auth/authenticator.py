"""Core authentication orchestrator."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from web_auth_bridge._types import AuthResult, CookieData, Credentials
from web_auth_bridge.exceptions import AuthError

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

    from web_auth_bridge.auth.cache import AuthCache
    from web_auth_bridge.auth.protocols import AuthCallback
    from web_auth_bridge.browser.manager import BrowserManager

logger = logging.getLogger(__name__)


class Authenticator:
    """Orchestrate browser-based authentication.

    Manages the full lifecycle: launch browser → create context → call
    consumer's ``AuthCallback`` → extract cookies/tokens → persist to
    cache → close browser.

    Args:
        callback: Consumer-provided authentication driver.
        browser_manager: Manages the Playwright browser lifecycle.
        cache: File-backed auth cache.
        credentials: Stored credentials for headless login, or ``None``
            for manual entry in a visible browser.
    """

    def __init__(
        self,
        *,
        callback: AuthCallback,
        browser_manager: BrowserManager,
        cache: AuthCache,
        credentials: Credentials | None = None,
    ) -> None:
        self._callback = callback
        self._browser_manager = browser_manager
        self._cache = cache
        self._credentials = credentials

    async def ensure_authenticated(self) -> AuthResult:
        """Return a valid ``AuthResult``, authenticating if necessary.

        1. Check the cache for a valid, non-expired result.
        2. If valid, return it immediately.
        3. Otherwise, launch a browser, run the auth callback, cache the
           result, and return it.

        Returns:
            A valid ``AuthResult`` with cookies, tokens, and/or localStorage.

        Raises:
            AuthError: If authentication fails.
        """
        cached = self._cache.load()
        if cached is not None:
            if await self._cache.is_valid(cached, self._callback):
                logger.info("Using cached authentication")
                return cached
            logger.info("Cached authentication is invalid or expired; re-authenticating")
            self._cache.invalidate()

        return await self._authenticate()

    async def force_authenticate(self) -> AuthResult:
        """Force a fresh authentication, ignoring any cached result.

        Returns:
            A fresh ``AuthResult``.

        Raises:
            AuthError: If authentication fails.
        """
        self._cache.invalidate()
        return await self._authenticate()

    async def _authenticate(self) -> AuthResult:
        """Run the browser-based authentication flow.

        Returns:
            The ``AuthResult`` from the consumer callback.

        Raises:
            AuthError: If the callback fails or returns an invalid result.
        """
        browser = await self._browser_manager.launch()
        context = await browser.new_context(**self._browser_manager.context_kwargs())
        await self._browser_manager.apply_stealth(context)
        page = await context.new_page()

        try:
            logger.info("Running authentication callback")
            result = await self._callback.authenticate(page, self._credentials)
            if result is None:
                raise AuthError("AuthCallback.authenticate() returned None")

            # If the callback did not extract cookies, extract them from the context
            if not result.cookies:
                result = await self._enrich_from_context(result, context)

            self._cache.save(result)
            logger.info(
                "Authentication successful: %d cookies, %d tokens",
                len(result.cookies),
                len(result.tokens),
            )
            return result
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError(f"Authentication failed: {exc}") from exc
        finally:
            await context.close()

    async def _enrich_from_context(
        self,
        result: AuthResult,
        context: BrowserContext,
    ) -> AuthResult:
        """Extract cookies from the browser context if not already present.

        Args:
            result: The auth result from the callback (may have empty cookies).
            context: The Playwright BrowserContext.

        Returns:
            A new AuthResult with cookies populated from the browser context.
        """
        browser_cookies = await context.cookies()
        cookies = [CookieData.from_playwright_dict(c) for c in browser_cookies]
        logger.debug("Extracted %d cookies from browser context", len(cookies))
        return AuthResult(
            cookies=cookies,
            local_storage=result.local_storage,
            tokens=result.tokens,
            expires_at=result.expires_at,
            created_at=result.created_at,
        )
