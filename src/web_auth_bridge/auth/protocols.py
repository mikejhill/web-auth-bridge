"""Protocols defining the contracts consumers implement."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext, Page

    from web_auth_bridge._types import AuthResult, Credentials


@runtime_checkable
class AuthCallback(Protocol):
    """Consumer-provided authentication driver.

    Implementations drive the login page of a specific website.  The bridge
    calls ``authenticate()`` with a Playwright ``Page`` already navigated to
    nothing (about:blank).  The callback is responsible for:

    1. Navigating to the login page.
    2. Filling in credentials (from *credentials* if provided, or waiting for
       manual user entry when *credentials* is ``None``).
    3. Handling any MFA, CAPTCHA, or WAF challenges.
    4. Returning an ``AuthResult`` with the extracted cookies, tokens, and
       localStorage entries needed for subsequent API calls.

    Example::

        class MyAuthCallback:
            async def authenticate(self, page, credentials):
                await page.goto("https://example.com/login")
                if credentials:
                    await page.fill("#email", credentials.username)
                    await page.fill("#password", credentials.password)
                    await page.click("#submit")
                else:
                    # Wait for user to log in manually
                    await page.wait_for_url("**/dashboard**", timeout=120_000)
                cookies = await page.context.cookies()
                return AuthResult(
                    cookies=[CookieData.from_playwright_dict(c) for c in cookies],
                )
    """

    async def authenticate(self, page: Page, credentials: Credentials | None) -> AuthResult:
        """Drive the login flow and return extracted auth artifacts.

        Args:
            page: A Playwright page in a fresh browser context.
            credentials: Stored credentials for headless login, or ``None``
                for manual entry in a visible browser.

        Returns:
            An ``AuthResult`` containing cookies, tokens, and/or localStorage
            entries extracted after successful authentication.

        Raises:
            AuthError: If authentication fails for any reason.
        """
        ...

    async def is_authenticated(self, auth_result: AuthResult) -> bool:
        """Check whether a cached ``AuthResult`` is still valid.

        The default implementation (when not overridden) checks
        ``auth_result.is_expired``.  Consumers can override this to perform
        an active check (e.g., make a lightweight API call).

        Args:
            auth_result: A previously cached authentication result.

        Returns:
            ``True`` if the cached auth is still usable.
        """
        ...


@runtime_checkable
class SessionRenewalCallback(Protocol):
    """Optional callback to obtain unique session cookies per browser context.

    Some websites (notably ASP.NET portals) use stateful server-side sessions.
    Sharing the same session cookie across parallel browser contexts causes
    conflicts.  This callback runs once per context after auth cookies are
    injected, giving the consumer a chance to navigate to an endpoint that
    issues a fresh, unique session identifier.

    Example::

        class AspNetSessionRenewal:
            async def renew(self, context, page, auth_cookies):
                await page.goto("https://portal.example.com/session/init")
                await page.wait_for_load_state("networkidle")
                # The server sets a new ASP.NET_SessionId cookie automatically.
    """

    async def renew(
        self,
        context: BrowserContext,
        page: Page,
        auth_cookies: list[dict[str, object]],
    ) -> None:
        """Navigate or interact to establish a unique session for this context.

        Args:
            context: The Playwright browser context with auth cookies already set.
            page: A page within the context, navigated to about:blank.
            auth_cookies: The auth cookies that were injected (as Playwright dicts).

        Raises:
            SessionRenewalError: If session renewal fails.
        """
        ...
