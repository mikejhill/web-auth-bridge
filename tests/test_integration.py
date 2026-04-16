"""Integration tests using real Playwright browsers against a local HTTP server."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from werkzeug.wrappers import Request, Response

from web_auth_bridge import AuthCache, AuthResult, CookieData, Credentials, WebAuthBridge

if TYPE_CHECKING:
    from pathlib import Path

    from playwright.async_api import BrowserContext, Page
    from pytest_httpserver import HTTPServer

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

# ---------------------------------------------------------------------------
# HTTP server handlers
# ---------------------------------------------------------------------------

_VALID_USERNAME = "testuser"
_VALID_PASSWORD = "testpass"

_LOGIN_HTML = """\
<!DOCTYPE html>
<html>
<body>
  <form method="POST" action="/login">
    <input name="username" id="username" />
    <input name="password" id="password" type="password" />
    <button type="submit" id="submit">Login</button>
  </form>
</body>
</html>
"""


def _response(body: str, status: int = 200, content_type: str = "application/json") -> Response:
    """Build a Response with ``Connection: close`` to prevent keep-alive stalls."""
    resp = Response(body, status=status, content_type=content_type)
    resp.headers["Connection"] = "close"
    return resp


def _handle_login_get(_request: Request) -> Response:
    resp = Response(_LOGIN_HTML, status=200, content_type="text/html")
    resp.headers["Connection"] = "close"
    return resp


def _handle_login_post(request: Request) -> Response:
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == _VALID_USERNAME and password == _VALID_PASSWORD:
        resp = _response(json.dumps({"status": "ok"}))
        resp.set_cookie("session_id", "sess-" + uuid.uuid4().hex[:8], path="/")
        return resp
    return _response("Unauthorized", status=401, content_type="text/plain")


def _handle_api_data(request: Request) -> Response:
    session_id = request.cookies.get("session_id", "")
    if not session_id.startswith("sess-"):
        return _response("Forbidden", status=403, content_type="text/plain")
    return _response(json.dumps({"data": "secret-payload", "session": session_id}))


def _handle_session_init(_request: Request) -> Response:
    """Issue a unique session cookie for session-renewal tests."""
    resp = _response(json.dumps({"renewed": True}))
    resp.set_cookie("unique_sid", "sid-" + uuid.uuid4().hex[:8], path="/")
    return resp


def _configure_server(httpserver: HTTPServer) -> None:
    """Register all handlers on the pytest-httpserver instance."""
    httpserver.expect_request("/login", method="GET").respond_with_handler(_handle_login_get)
    httpserver.expect_request("/login", method="POST").respond_with_handler(_handle_login_post)
    httpserver.expect_request("/api/data", method="GET").respond_with_handler(_handle_api_data)
    httpserver.expect_request("/session/init", method="GET").respond_with_handler(_handle_session_init)


# ---------------------------------------------------------------------------
# Auth callback / session renewal stubs
# ---------------------------------------------------------------------------


class AuthCallbackStub:
    """AuthCallback that drives the local test login page."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url
        self.authenticate_call_count = 0

    async def authenticate(self, page: Page, credentials: Credentials | None) -> AuthResult:
        self.authenticate_call_count += 1
        await page.goto(f"{self._base_url}/login")
        if credentials:
            await page.fill("#username", credentials.username)
            await page.fill("#password", credentials.password)
            await page.click("#submit")
        await page.wait_for_load_state("load")
        raw_cookies = await page.context.cookies()
        cookies = [CookieData.from_playwright_dict(c) for c in raw_cookies]
        return AuthResult(cookies=cookies)

    async def is_authenticated(self, auth_result: AuthResult) -> bool:
        return not auth_result.is_expired


class SessionRenewalStub:
    """SessionRenewalCallback that navigates to /session/init to get a unique cookie."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    async def renew(
        self,
        context: BrowserContext,  # noqa: ARG002
        page: Page,
        auth_cookies: list[dict[str, object]],  # noqa: ARG002
    ) -> None:
        await page.goto(f"{self._base_url}/session/init", wait_until="domcontentloaded")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def server(httpserver: HTTPServer) -> HTTPServer:
    """Return a configured test HTTP server."""
    _configure_server(httpserver)
    return httpserver


@pytest.fixture
def base_url(server: HTTPServer) -> str:
    return server.url_for("")[:-1]  # strip trailing slash


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    return tmp_path / "auth-cache"


@pytest.fixture
def credentials() -> Credentials:
    return Credentials(username=_VALID_USERNAME, password=_VALID_PASSWORD)


@pytest.fixture
def auth_callback(base_url: str) -> AuthCallbackStub:
    return AuthCallbackStub(base_url)


@pytest.fixture
def bridge(auth_callback: AuthCallbackStub, cache_dir: Path, credentials: Credentials) -> WebAuthBridge:
    return WebAuthBridge(
        auth_callback=auth_callback,
        cache_dir=cache_dir,
        credentials=credentials,
        headless=True,
    )


# ---------------------------------------------------------------------------
# Tests — full WebAuthBridge flow
# ---------------------------------------------------------------------------


class TestFullAuthFlow:
    """End-to-end: authenticate → access API → check accessors."""

    async def test_ensure_authenticated_returns_auth_result(self, bridge: WebAuthBridge) -> None:
        result = await bridge.ensure_authenticated()

        assert isinstance(result, AuthResult)
        assert len(result.cookies) >= 1
        session_cookies = [c for c in result.cookies if c.name == "session_id"]
        assert len(session_cookies) == 1
        assert session_cookies[0].value.startswith("sess-")

    async def test_http_client_has_cookies_injected(self, bridge: WebAuthBridge) -> None:
        result = await bridge.ensure_authenticated()
        session_value = next(c.value for c in result.cookies if c.name == "session_id")

        async with bridge.http_client() as client:
            jar_values = dict(client.cookies.items())

        assert "session_id" in jar_values
        assert jar_values["session_id"] == session_value

    async def test_http_client_reaches_api(self, bridge: WebAuthBridge, base_url: str) -> None:
        """Verify authenticated HTTP call via httpx.

        Python's ``http.cookiejar`` does not domain-match ``localhost``, so we
        set cookies without a domain to prove the end-to-end request flow.
        """
        import httpx

        result = await bridge.ensure_authenticated()
        session_value = next(c.value for c in result.cookies if c.name == "session_id")

        async with httpx.AsyncClient(cookies={"session_id": session_value}) as client:
            resp = await client.get(f"{base_url}/api/data")

        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == "secret-payload"
        assert body["session"].startswith("sess-")

    async def test_cookies_accessor(self, bridge: WebAuthBridge) -> None:
        await bridge.ensure_authenticated()

        raw_cookies = bridge.cookies()
        assert isinstance(raw_cookies, list)
        assert any(c["name"] == "session_id" for c in raw_cookies)

    async def test_tokens_accessor(self, bridge: WebAuthBridge) -> None:
        await bridge.ensure_authenticated()

        # The test login flow doesn't produce tokens, so dict should be empty
        assert bridge.tokens() == {}


# ---------------------------------------------------------------------------
# Tests — cache persistence
# ---------------------------------------------------------------------------


class TestCachePersistence:
    """Verify cache saves, reloads, and invalidation triggers re-auth."""

    async def test_second_call_uses_cache(
        self, auth_callback: AuthCallbackStub, cache_dir: Path, credentials: Credentials
    ) -> None:
        bridge = WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=cache_dir,
            credentials=credentials,
            headless=True,
        )
        first_result = await bridge.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 1

        # Second bridge instance shares the same cache_dir — should hit cache
        bridge2 = WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=cache_dir,
            credentials=credentials,
            headless=True,
        )
        second_result = await bridge2.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 1  # no new browser auth

        assert first_result.cookies[0].value == second_result.cookies[0].value

    async def test_invalidation_triggers_reauth(
        self, auth_callback: AuthCallbackStub, cache_dir: Path, credentials: Credentials
    ) -> None:
        bridge = WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=cache_dir,
            credentials=credentials,
            headless=True,
        )
        await bridge.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 1

        bridge.invalidate_cache()

        second_result = await bridge.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 2  # re-authenticated
        assert isinstance(second_result, AuthResult)

    async def test_expired_cache_triggers_reauth(
        self, auth_callback: AuthCallbackStub, cache_dir: Path, credentials: Credentials
    ) -> None:
        bridge = WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=cache_dir,
            credentials=credentials,
            headless=True,
        )
        result = await bridge.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 1

        # Manually expire the cached result by rewriting the cache file
        result.expires_at = datetime.now(UTC) - timedelta(hours=1)
        cache = AuthCache(cache_dir)
        cache.save(result)

        bridge2 = WebAuthBridge(
            auth_callback=auth_callback,
            cache_dir=cache_dir,
            credentials=credentials,
            headless=True,
        )
        await bridge2.ensure_authenticated()
        assert auth_callback.authenticate_call_count == 2


# ---------------------------------------------------------------------------
# Tests — browser context pool
# ---------------------------------------------------------------------------


class TestBrowserPool:
    """Verify parallel browser contexts receive cloned auth cookies."""

    async def test_pool_contexts_have_cookies(self, bridge: WebAuthBridge) -> None:
        await bridge.ensure_authenticated()

        async with bridge.browser_pool(count=2) as contexts:
            assert len(contexts) == 2
            for ctx in contexts:
                ctx_cookies = await ctx.cookies()
                session_cookies = [c for c in ctx_cookies if c["name"] == "session_id"]
                assert len(session_cookies) == 1
                assert session_cookies[0]["value"].startswith("sess-")

    async def test_pool_contexts_can_access_authenticated_endpoint(self, bridge: WebAuthBridge, base_url: str) -> None:
        await bridge.ensure_authenticated()

        async with bridge.browser_pool(count=2) as contexts:
            for ctx in contexts:
                page = await ctx.new_page()
                resp = await page.goto(f"{base_url}/api/data", wait_until="domcontentloaded")
                assert resp is not None
                assert resp.status == 200
                body = json.loads(await resp.body())
                assert body["data"] == "secret-payload"


# ---------------------------------------------------------------------------
# Tests — session renewal
# ---------------------------------------------------------------------------


class TestSessionRenewalFlow:
    """Verify session renewal callback gives each context its own cookie."""

    async def test_each_context_gets_unique_session(self, bridge: WebAuthBridge, base_url: str) -> None:
        await bridge.ensure_authenticated()
        renewal = SessionRenewalStub(base_url)

        async with bridge.browser_pool(count=2, session_renewal=renewal) as contexts:
            unique_sids: list[str] = []
            for ctx in contexts:
                ctx_cookies = await ctx.cookies()
                sid_cookies = [c for c in ctx_cookies if c["name"] == "unique_sid"]
                assert len(sid_cookies) == 1, "Each context should have a unique_sid cookie"
                unique_sids.append(sid_cookies[0]["value"])

            # Each context should have a different unique session id
            assert len(set(unique_sids)) == 2, f"Expected 2 unique SIDs, got: {unique_sids}"
