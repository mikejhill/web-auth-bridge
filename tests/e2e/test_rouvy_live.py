"""Rouvy live e2e test.

Skipped automatically when ``ROUVY_EMAIL`` / ``ROUVY_PASSWORD`` are not
set in the environment or ``.env`` file.

The Rouvy login flow is a standard HTML form on ``my.rouvy.com/login``.
Unlike Garmin, it does not sit behind Cloudflare, so the bundled
Chromium works fine and no TLS impersonation is required.

Run just these tests::

    pytest -m "e2e and rouvy"
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from web_auth_bridge import AuthResult, CookieData, WebAuthBridge

if TYPE_CHECKING:
    from collections.abc import Callable

    from playwright.async_api import Page

    from web_auth_bridge import Credentials

pytestmark = [pytest.mark.e2e, pytest.mark.rouvy, pytest.mark.asyncio]

LOGIN_URL = "https://riders.rouvy.com/login"
DASHBOARD_URL = "https://riders.rouvy.com/feed"


# ---------------------------------------------------------------------------
# AuthCallback
# ---------------------------------------------------------------------------


class RouvyAuthCallback:
    """AuthCallback for Rouvy's web login.

    Rouvy's rider portal at ``riders.rouvy.com/login`` is a standard
    email/password form that sets an httpOnly session cookie on success.
    A Cookiebot consent banner may be rendered on top of the form; we
    dismiss it defensively before submission.
    """

    async def authenticate(self, page: Page, credentials: Credentials | None) -> AuthResult:
        if credentials is None:
            msg = "Rouvy AuthCallback requires credentials (manual mode not implemented)"
            raise RuntimeError(msg)

        await page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=30_000)
        await page.wait_for_selector("form#sign-in-form", timeout=15_000)

        # Dismiss Cookiebot consent banner if present — it can intercept clicks.
        import contextlib

        for selector in (
            "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
            "#CybotCookiebotDialogBodyButtonAccept",
            "#CybotCookiebotDialogBodyLevelButtonAccept",
        ):
            with contextlib.suppress(Exception):
                await page.locator(selector).click(timeout=2_000)
                break

        await page.fill('input[data-cy="email-input"]', credentials.username)
        await page.fill('input[data-cy="password-input"]', credentials.password)

        async with page.expect_navigation(wait_until="domcontentloaded", timeout=30_000):
            await page.locator('button[data-cy="submit-button"]').click()

        # Successful login redirects away from /login (typically to /feed).
        if "/login" in page.url:
            error_text = ""
            with contextlib.suppress(Exception):
                error_text = (
                    await page.locator('[data-cy="error"], [role="alert"]').first.text_content(
                        timeout=2_000,
                    )
                    or ""
                )
            msg = (
                f"Rouvy login did not redirect away from /login "
                f"(URL: {page.url}, error: {error_text!r}) — check credentials"
            )
            raise RuntimeError(msg)

        raw_cookies = await page.context.cookies()
        cookies = [CookieData.from_playwright_dict(c) for c in raw_cookies]
        return AuthResult(cookies=cookies)

    async def is_authenticated(self, auth_result: AuthResult) -> bool:
        return not auth_result.is_expired and any(c.domain.endswith("rouvy.com") for c in auth_result.cookies)


@pytest.fixture
def rouvy_callback() -> RouvyAuthCallback:
    return RouvyAuthCallback()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRouvyLiveAuth:
    async def test_authenticates_and_extracts_rouvy_cookies(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        rouvy_callback: RouvyAuthCallback,
        rouvy_credentials: Credentials,
    ) -> None:
        bridge = make_bridge(
            auth_callback=rouvy_callback,
            credentials=rouvy_credentials,
            cache_subdir="rouvy-auth",
        )

        result = await bridge.ensure_authenticated()

        assert isinstance(result, AuthResult), f"Expected AuthResult, got {type(result).__name__}"
        rouvy_cookies = [c for c in result.cookies if c.domain.endswith("rouvy.com")]
        assert rouvy_cookies, (
            f"Expected at least one cookie on a .rouvy.com domain after login; "
            f"got cookies from domains: {sorted({c.domain for c in result.cookies})}"
        )

    async def test_cookies_authenticate_http_requests(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        rouvy_callback: RouvyAuthCallback,
        rouvy_credentials: Credentials,
    ) -> None:
        """End-to-end proof: the dashboard loads with the extracted cookies.

        An unauthenticated request to ``my.rouvy.com/`` either 302s to
        ``/login`` or returns the login HTML body.  With the right cookies
        we must stay on the dashboard.
        """
        bridge = make_bridge(
            auth_callback=rouvy_callback,
            credentials=rouvy_credentials,
            cache_subdir="rouvy-http",
        )
        await bridge.ensure_authenticated()

        async with bridge.http_client(follow_redirects=False, timeout=30.0) as client:
            resp = await client.get(DASHBOARD_URL)

        # Accept any 2xx — Rouvy may serve a dashboard HTML or JSON payload.
        # A redirect to /login means the cookies did not authenticate us.
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            assert "/login" not in location, (
                f"Authenticated request to {DASHBOARD_URL} redirected to login ({location}) "
                f"— extracted cookies did not establish an authenticated session"
            )
        else:
            assert 200 <= resp.status_code < 300, (
                f"Expected 2xx from authenticated dashboard request, got {resp.status_code}: {resp.text[:300]!r}"
            )

    async def test_cache_reuse_avoids_second_login(
        self,
        make_bridge: Callable[..., WebAuthBridge],
        rouvy_callback: RouvyAuthCallback,
        rouvy_credentials: Credentials,
    ) -> None:
        first = make_bridge(
            auth_callback=rouvy_callback,
            credentials=rouvy_credentials,
            cache_subdir="rouvy-reuse",
        )
        first_result = await first.ensure_authenticated()

        second = make_bridge(
            auth_callback=rouvy_callback,
            credentials=None,  # Prove the cache path, not re-auth
            cache_subdir="rouvy-reuse",
        )
        second_result = await second.ensure_authenticated()

        first_cookies = {(c.name, c.value) for c in first_result.cookies if c.domain.endswith("rouvy.com")}
        second_cookies = {(c.name, c.value) for c in second_result.cookies if c.domain.endswith("rouvy.com")}
        assert first_cookies == second_cookies, (
            "Second bridge should have reused cached cookies verbatim, "
            f"but they differ: {first_cookies.symmetric_difference(second_cookies)}"
        )
