"""Unit tests for :class:`web_auth_bridge.bridge.WebAuthBridge`.

These tests verify bridge orchestration without launching a real browser.
The ``Authenticator`` and ``BrowserManager`` classes are swapped in as
fakes, so every test runs in milliseconds and needs no Playwright binary.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock

import httpx
import pytest

from web_auth_bridge import AuthResult, CookieData, Credentials, WebAuthBridge
from web_auth_bridge.auth.cache import AuthCache

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Test data builders
# ---------------------------------------------------------------------------


def make_auth_result(**overrides: Any) -> AuthResult:
    """Build an ``AuthResult`` with representative defaults.

    Tests override only the fields they care about.  Field names match
    the production ``AuthResult`` dataclass exactly.
    """
    defaults: dict[str, Any] = {
        "cookies": [CookieData(name="session", value="sess-abc", domain=".example.com")],
        "tokens": {"csrf_token": "csrf-value"},
        "local_storage": {"user_id": "42"},
    }
    return replace(AuthResult(**defaults), **overrides)


def make_credentials(**overrides: Any) -> Credentials:
    """Build a ``Credentials`` instance with representative defaults."""
    defaults: dict[str, Any] = {"username": "alice", "password": "hunter2"}
    defaults.update(overrides)
    return Credentials(**defaults)


class _FakeAuthenticator:
    """In-memory substitute for :class:`Authenticator` used by the bridge.

    Captures call counts so tests can assert on whether the bridge
    delegated correctly.
    """

    def __init__(self, result: AuthResult) -> None:
        self._result = result
        self.ensure_calls = 0
        self.force_calls = 0

    async def ensure_authenticated(self) -> AuthResult:
        self.ensure_calls += 1
        return self._result

    async def force_authenticate(self) -> AuthResult:
        self.force_calls += 1
        return self._result


class _FakeBrowserManager:
    """In-memory substitute for :class:`BrowserManager`.

    Only ``close()`` is ever invoked by the bridge after the authenticator
    returns, so that is the only behavior we need to simulate.
    """

    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


@pytest.fixture
def bridge_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    """Return a factory that builds a WebAuthBridge wired to fakes.

    The returned factory yields ``(bridge, authenticator_fake, manager_fake)``
    so each test can inspect how the bridge interacted with its collaborators.
    """

    def _make(result: AuthResult | None = None) -> tuple[WebAuthBridge, _FakeAuthenticator, _FakeBrowserManager]:
        auth_result = result if result is not None else make_auth_result()
        authenticator = _FakeAuthenticator(auth_result)
        manager = _FakeBrowserManager()

        def _fake_auth_cls(**_kwargs: Any) -> _FakeAuthenticator:
            return authenticator

        def _fake_manager_cls(**_kwargs: Any) -> _FakeBrowserManager:
            return manager

        monkeypatch.setattr("web_auth_bridge.bridge.Authenticator", _fake_auth_cls)
        monkeypatch.setattr("web_auth_bridge.bridge.BrowserManager", _fake_manager_cls)

        bridge = WebAuthBridge(
            auth_callback=AsyncMock(),
            cache_dir=tmp_path / "cache",
            credentials=make_credentials(),
        )
        return bridge, authenticator, manager

    return _make


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestWebAuthBridgeInit:
    def test_expands_user_home_in_cache_dir(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """cache_dir beginning with ``~`` must be expanded to a real path."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))

        from pathlib import Path as _Path

        bridge = WebAuthBridge(
            auth_callback=AsyncMock(),
            cache_dir=_Path("~/cache"),
        )

        resolved = bridge._cache.cache_file.parent
        assert "~" not in str(resolved), f"Expected ~ to be expanded, got '{resolved}'"
        assert resolved.is_absolute(), f"Expected absolute path after expansion, got '{resolved}'"

    def test_credentials_default_none(self, tmp_path: Path) -> None:
        """When no credentials are provided, the bridge stores ``None``."""
        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path)

        assert bridge._credentials is None, "Credentials should default to None for manual-entry flows"


# ---------------------------------------------------------------------------
# ensure_authenticated / force_authenticate
# ---------------------------------------------------------------------------


class TestEnsureAuthenticated:
    @pytest.mark.asyncio
    async def test_returns_result_from_authenticator(self, bridge_factory: Any) -> None:
        expected = make_auth_result(tokens={"jwt": "xyz"})
        bridge, authenticator, _manager = bridge_factory(expected)

        result = await bridge.ensure_authenticated()

        assert result is expected, "ensure_authenticated should return the authenticator's result unchanged"
        assert authenticator.ensure_calls == 1, "ensure_authenticated() was not delegated"

    @pytest.mark.asyncio
    async def test_closes_browser_manager_on_success(self, bridge_factory: Any) -> None:
        bridge, _authenticator, manager = bridge_factory()

        await bridge.ensure_authenticated()

        assert manager.close_calls == 1, (
            f"BrowserManager.close() must be called exactly once after auth, got {manager.close_calls}"
        )

    @pytest.mark.asyncio
    async def test_closes_browser_manager_when_authenticator_raises(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manager = _FakeBrowserManager()

        class _ExplodingAuth:
            async def ensure_authenticated(self) -> AuthResult:
                msg = "boom"
                raise RuntimeError(msg)

        monkeypatch.setattr(
            "web_auth_bridge.bridge.Authenticator",
            lambda **_k: _ExplodingAuth(),
        )
        monkeypatch.setattr("web_auth_bridge.bridge.BrowserManager", lambda **_k: manager)

        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path / "cache")

        with pytest.raises(RuntimeError, match="boom"):
            await bridge.ensure_authenticated()

        assert manager.close_calls == 1, "BrowserManager.close() must run in the finally block even when auth fails"

    @pytest.mark.asyncio
    async def test_caches_result_on_instance(self, bridge_factory: Any) -> None:
        """After success, ``_auth_result`` is stored so accessors work without re-auth."""
        bridge, _authenticator, _manager = bridge_factory()

        await bridge.ensure_authenticated()

        assert bridge._auth_result is not None, (
            "Bridge must cache the auth result on the instance for later accessor calls"
        )


class TestForceAuthenticate:
    @pytest.mark.asyncio
    async def test_calls_force_path_not_ensure(self, bridge_factory: Any) -> None:
        bridge, authenticator, _manager = bridge_factory()

        await bridge.force_authenticate()

        assert authenticator.force_calls == 1, "force_authenticate should delegate to authenticator.force_authenticate"
        assert authenticator.ensure_calls == 0, "force_authenticate must NOT call ensure_authenticated"


# ---------------------------------------------------------------------------
# Accessors: cookies(), tokens(), http_client()
# ---------------------------------------------------------------------------


class TestAccessorsBeforeAuth:
    """Accessors must refuse to operate without an authenticated result."""

    def test_cookies_raises_without_auth(self, tmp_path: Path) -> None:
        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path / "cache")

        with pytest.raises(RuntimeError, match="Not authenticated"):
            bridge.cookies()

    def test_tokens_raises_without_auth(self, tmp_path: Path) -> None:
        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path / "cache")

        with pytest.raises(RuntimeError, match="Not authenticated"):
            bridge.tokens()

    def test_http_client_raises_without_auth(self, tmp_path: Path) -> None:
        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path / "cache")

        with pytest.raises(RuntimeError, match="Not authenticated"):
            bridge.http_client()

    def test_accessor_loads_from_cache_when_in_memory_result_missing(self, tmp_path: Path) -> None:
        """If the bridge was constructed after a prior run wrote a cache file,
        accessors should transparently load it on first use."""
        cache_dir = tmp_path / "cache"
        cached = make_auth_result(tokens={"jwt": "from-disk"})
        AuthCache(cache_dir).save(cached)

        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=cache_dir)

        tokens = bridge.tokens()

        assert tokens == {"jwt": "from-disk"}, (
            f"Expected accessors to hydrate from disk cache when no in-memory result exists, got {tokens}"
        )


class TestAccessorsAfterAuth:
    @pytest.mark.asyncio
    async def test_cookies_returns_playwright_dicts(self, bridge_factory: Any) -> None:
        cookie = CookieData(name="sid", value="v1", domain=".example.com", http_only=True)
        bridge, _auth, _mgr = bridge_factory(make_auth_result(cookies=[cookie]))
        await bridge.ensure_authenticated()

        dicts = bridge.cookies()

        assert len(dicts) == 1, f"Expected 1 cookie dict, got {len(dicts)}"
        assert dicts[0] == cookie.to_playwright_dict(), (
            "cookies() must return dicts in Playwright format (httpOnly, sameSite camelCase)"
        )

    @pytest.mark.asyncio
    async def test_tokens_returns_copy(self, bridge_factory: Any) -> None:
        """Mutating the returned dict must not corrupt the cached auth result."""
        original = {"csrf": "abc", "jwt": "def"}
        bridge, _auth, _mgr = bridge_factory(make_auth_result(tokens=dict(original)))
        await bridge.ensure_authenticated()

        returned = bridge.tokens()
        returned["csrf"] = "MUTATED"

        assert bridge.tokens() == original, (
            "tokens() must return an independent copy — mutating it corrupted the cached result"
        )

    @pytest.mark.asyncio
    async def test_http_client_is_async_client(self, bridge_factory: Any) -> None:
        bridge, _auth, _mgr = bridge_factory()
        await bridge.ensure_authenticated()

        client = bridge.http_client()
        try:
            assert isinstance(client, httpx.AsyncClient), (
                f"http_client() must return httpx.AsyncClient, got {type(client).__name__}"
            )
        finally:
            await client.aclose()

    @pytest.mark.asyncio
    async def test_http_client_sync_is_sync_client(self, bridge_factory: Any) -> None:
        bridge, _auth, _mgr = bridge_factory()
        await bridge.ensure_authenticated()

        client = bridge.http_client_sync()
        try:
            assert isinstance(client, httpx.Client), (
                f"http_client_sync() must return httpx.Client, got {type(client).__name__}"
            )
        finally:
            client.close()


# ---------------------------------------------------------------------------
# invalidate_cache
# ---------------------------------------------------------------------------


class TestInvalidateCache:
    @pytest.mark.asyncio
    async def test_removes_cache_file_and_clears_in_memory(self, bridge_factory: Any) -> None:
        bridge, _auth, _mgr = bridge_factory()
        await bridge.ensure_authenticated()
        # Write a cache file manually — the fake authenticator doesn't persist,
        # but the production Authenticator does.  We only need a file to exist
        # so we can verify invalidate_cache() deletes it.
        bridge._cache.save(make_auth_result())
        cache_file = bridge._cache.cache_file
        assert cache_file.exists(), "Precondition setup failed: cache file was not written"

        bridge.invalidate_cache()

        assert not cache_file.exists(), (
            f"invalidate_cache should delete the on-disk cache file at {cache_file}, but it still exists"
        )
        assert bridge._auth_result is None, "invalidate_cache should clear the in-memory auth result"

    def test_no_op_when_nothing_cached(self, tmp_path: Path) -> None:
        bridge = WebAuthBridge(auth_callback=AsyncMock(), cache_dir=tmp_path / "empty-cache")

        bridge.invalidate_cache()  # must not raise
