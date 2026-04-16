"""Main entry point facade: ``WebAuthBridge``."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any

from web_auth_bridge.auth.authenticator import Authenticator
from web_auth_bridge.auth.cache import AuthCache
from web_auth_bridge.browser.context_pool import BrowserContextPool
from web_auth_bridge.browser.manager import BrowserManager, StealthConfig
from web_auth_bridge.http.client import HttpClientFactory

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    import httpx
    from playwright.async_api import BrowserContext

    from web_auth_bridge._types import AuthResult, Credentials
    from web_auth_bridge.auth.protocols import AuthCallback, SessionRenewalCallback

logger = logging.getLogger(__name__)


class WebAuthBridge:
    """Orchestrate browser-based authentication, caching, and execution.

    This is the primary public API.  It ties together:

    - **Authenticator**: runs the consumer's ``AuthCallback`` in a Playwright browser
    - **AuthCache**: persists extracted cookies/tokens to disk
    - **HttpClientFactory**: builds ``httpx`` clients with auth injected
    - **BrowserContextPool**: spawns parallel browser contexts with cloned cookies

    Example::

        bridge = WebAuthBridge(
            auth_callback=MyAuthCallback(),
            cache_dir=Path("~/.config/my-skill/cache"),
            credentials=Credentials(username="user", password="pass"),
        )
        result = await bridge.ensure_authenticated()

        # Option A: Fast HTTP calls (no browser)
        async with bridge.http_client() as client:
            resp = await client.get("https://api.example.com/data")

        # Option B: Parallel browser sessions
        async with bridge.browser_pool(count=4) as contexts:
            pages = [await ctx.new_page() for ctx in contexts]
            ...

    Args:
        auth_callback: Consumer-provided authentication driver.
        cache_dir: Directory for the auth token cache file.
        credentials: Stored credentials for headless login.  ``None`` means
            the user enters credentials manually in a visible browser.
        headless: Whether to run the authentication browser in headless mode.
        browser_type: Playwright browser type (``"chromium"``, ``"firefox"``, ``"webkit"``).
        stealth: Anti-detection configuration, or ``None`` for defaults.
        launch_kwargs: Extra keyword arguments for ``browser_type.launch()``.
    """

    def __init__(
        self,
        *,
        auth_callback: AuthCallback,
        cache_dir: Path,
        credentials: Credentials | None = None,
        headless: bool = True,
        browser_type: str = "chromium",
        stealth: StealthConfig | None = None,
        launch_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._auth_callback = auth_callback
        self._cache_dir = Path(cache_dir).expanduser()
        self._credentials = credentials
        self._headless = headless
        self._browser_type = browser_type
        self._stealth = stealth
        self._launch_kwargs = launch_kwargs or {}

        self._cache = AuthCache(self._cache_dir)
        self._auth_result: AuthResult | None = None

    async def ensure_authenticated(self) -> AuthResult:
        """Authenticate if needed, returning a valid ``AuthResult``.

        Uses the cache when possible.  Only launches a browser if no valid
        cached auth exists.

        Returns:
            A valid ``AuthResult`` with cookies, tokens, and/or localStorage.

        Raises:
            AuthError: If authentication fails.
        """
        manager = BrowserManager(
            browser_type=self._browser_type,
            headless=self._headless,
            stealth=self._stealth,
            launch_kwargs=self._launch_kwargs,
        )
        authenticator = Authenticator(
            callback=self._auth_callback,
            browser_manager=manager,
            cache=self._cache,
            credentials=self._credentials,
        )
        try:
            self._auth_result = await authenticator.ensure_authenticated()
            return self._auth_result
        finally:
            await manager.close()

    async def force_authenticate(self) -> AuthResult:
        """Force a fresh authentication, ignoring any cached result.

        Returns:
            A fresh ``AuthResult``.

        Raises:
            AuthError: If authentication fails.
        """
        manager = BrowserManager(
            browser_type=self._browser_type,
            headless=self._headless,
            stealth=self._stealth,
            launch_kwargs=self._launch_kwargs,
        )
        authenticator = Authenticator(
            callback=self._auth_callback,
            browser_manager=manager,
            cache=self._cache,
            credentials=self._credentials,
        )
        try:
            self._auth_result = await authenticator.force_authenticate()
            return self._auth_result
        finally:
            await manager.close()

    def _require_auth_result(self) -> AuthResult:
        """Return the cached auth result, raising if not authenticated."""
        if self._auth_result is None:
            # Try loading from disk
            cached = self._cache.load()
            if cached is not None:
                self._auth_result = cached
                return cached
            msg = "Not authenticated. Call ensure_authenticated() first."
            raise RuntimeError(msg)
        return self._auth_result

    def http_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Return an ``httpx.AsyncClient`` with auth cookies/headers injected.

        Args:
            **kwargs: Additional keyword arguments forwarded to ``httpx.AsyncClient()``.

        Returns:
            A configured async HTTP client.
        """
        result = self._require_auth_result()
        factory = HttpClientFactory(result)
        return factory.async_client(**kwargs)

    def http_client_sync(self, **kwargs: Any) -> httpx.Client:
        """Return an ``httpx.Client`` with auth cookies/headers injected.

        Args:
            **kwargs: Additional keyword arguments forwarded to ``httpx.Client()``.

        Returns:
            A configured sync HTTP client.
        """
        result = self._require_auth_result()
        factory = HttpClientFactory(result)
        return factory.sync_client(**kwargs)

    def cookies(self) -> list[dict[str, Any]]:
        """Return raw cookies as a list of dicts.

        Each dict matches the Playwright cookie format.  Useful for consumers
        who need full control over how cookies are applied.
        """
        result = self._require_auth_result()
        return [c.to_playwright_dict() for c in result.cookies]

    def tokens(self) -> dict[str, str]:
        """Return raw token key-value pairs (e.g., JWT, Bearer, CSRF)."""
        result = self._require_auth_result()
        return dict(result.tokens)

    @asynccontextmanager
    async def browser_pool(
        self,
        count: int,
        *,
        session_renewal: SessionRenewalCallback | None = None,
        **context_kwargs: Any,
    ) -> AsyncIterator[list[BrowserContext]]:
        """Spin up parallel browser contexts with auth cookies cloned in.

        Creates a fresh browser instance (separate from the auth browser)
        and spawns *count* contexts with the authenticated cookies.

        Args:
            count: Number of parallel browser contexts.
            session_renewal: Optional callback for stateful session renewal.
            **context_kwargs: Extra arguments for ``browser.new_context()``.

        Yields:
            A list of initialized ``BrowserContext`` instances.
        """
        result = self._require_auth_result()
        manager = BrowserManager(
            browser_type=self._browser_type,
            headless=True,  # Execution browsers are always headless
            stealth=self._stealth,
            launch_kwargs=self._launch_kwargs,
        )
        pool = BrowserContextPool(
            browser_manager=manager,
            auth_result=result,
            session_renewal=session_renewal,
        )
        try:
            async with pool.contexts(count, **context_kwargs) as contexts:
                yield contexts
        finally:
            await manager.close()

    def invalidate_cache(self) -> None:
        """Delete the auth cache, forcing re-authentication on next call."""
        self._cache.invalidate()
        self._auth_result = None
        logger.info("Auth cache invalidated")
