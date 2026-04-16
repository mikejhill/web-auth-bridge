"""Tests for HttpClientFactory."""

from __future__ import annotations

from web_auth_bridge._types import AuthResult, CookieData
from web_auth_bridge.http.client import HttpClientFactory


class TestHttpClientFactory:
    """Tests for creating httpx clients from AuthResult."""

    def test_sync_client_cookies(self, sample_auth_result: AuthResult) -> None:
        factory = HttpClientFactory(sample_auth_result)
        client = factory.sync_client()
        try:
            # Check that cookies were injected
            cookie_jar = client.cookies
            assert "session_id" in {c.name for c in cookie_jar.jar}
        finally:
            client.close()

    def test_sync_client_bearer_header(self) -> None:
        result = AuthResult(tokens={"di_token": "my-bearer-token"})
        factory = HttpClientFactory(result)
        client = factory.sync_client()
        try:
            assert client.headers.get("authorization") == "Bearer my-bearer-token"
        finally:
            client.close()

    def test_sync_client_csrf_header(self) -> None:
        result = AuthResult(tokens={"csrf": "csrf-val"})
        factory = HttpClientFactory(result)
        client = factory.sync_client()
        try:
            assert client.headers.get("x-csrf-token") == "csrf-val"
        finally:
            client.close()

    def test_sync_client_custom_token_header(self) -> None:
        result = AuthResult(tokens={"my_custom": "val"})
        factory = HttpClientFactory(result)
        client = factory.sync_client()
        try:
            assert client.headers.get("x-my_custom") == "val"
        finally:
            client.close()

    def test_sync_client_extra_kwargs(self) -> None:
        result = AuthResult(
            cookies=[CookieData(name="c", value="v", domain="example.com")],
        )
        factory = HttpClientFactory(result)
        client = factory.sync_client(base_url="https://api.example.com")
        try:
            assert str(client.base_url) == "https://api.example.com"
        finally:
            client.close()

    def test_async_client_cookies(self, sample_auth_result: AuthResult) -> None:
        factory = HttpClientFactory(sample_auth_result)
        client = factory.async_client()
        try:
            cookie_jar = client.cookies
            assert "session_id" in {c.name for c in cookie_jar.jar}
        finally:
            pass  # async client close is async, but we just check config here

    def test_sync_client_extra_headers_merge(self) -> None:
        result = AuthResult(tokens={"csrf": "abc"})
        factory = HttpClientFactory(result)
        client = factory.sync_client(headers={"X-Custom": "custom-val"})
        try:
            assert client.headers.get("x-csrf-token") == "abc"
            assert client.headers.get("x-custom") == "custom-val"
        finally:
            client.close()
