"""Shared fixtures for web-auth-bridge tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from web_auth_bridge._types import AuthResult, CookieData, Credentials

if TYPE_CHECKING:
    from collections.abc import Generator

    from pytest_httpserver import HTTPServer


@pytest.fixture(scope="session")
def make_httpserver(
    httpserver_listen_address: tuple[str | None, int | None],
    httpserver_ssl_context: None,
) -> Generator[HTTPServer, None, None]:
    """Override default pytest-httpserver factory with ``threaded=True``.

    The default server is single-threaded, which causes Playwright browser
    contexts to block waiting for keep-alive connections to close.
    """
    from pytest_httpserver import HTTPServer as _HTTPServer

    host, port = httpserver_listen_address
    server = _HTTPServer(
        host=host or _HTTPServer.DEFAULT_LISTEN_HOST,
        port=port or _HTTPServer.DEFAULT_LISTEN_PORT,
        ssl_context=httpserver_ssl_context,
        threaded=True,
    )
    server.start()
    yield server
    server.clear()
    if server.is_running():
        server.stop()


@pytest.fixture
def sample_credentials() -> Credentials:
    """Return a set of test credentials."""
    return Credentials(username="testuser", password="testpass")


@pytest.fixture
def sample_cookie() -> CookieData:
    """Return a single test cookie."""
    return CookieData(
        name="session_id",
        value="abc123",
        domain=".example.com",
        path="/",
        secure=True,
        http_only=True,
    )


@pytest.fixture
def sample_auth_result(sample_cookie: CookieData) -> AuthResult:
    """Return a test auth result with one cookie and one token."""
    return AuthResult(
        cookies=[sample_cookie],
        tokens={"jwt_web": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test", "csrf": "csrf-token-123"},
        local_storage={"user_id": "12345"},
    )
