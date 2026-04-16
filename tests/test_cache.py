"""Tests for AuthCache."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock

import pytest

from web_auth_bridge._types import AuthResult, CookieData
from web_auth_bridge.auth.cache import AuthCache
from web_auth_bridge.exceptions import CacheError

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def cache_dir(tmp_path: Path) -> Path:
    """Return a temporary cache directory."""
    return tmp_path / "test-cache"


@pytest.fixture
def auth_cache(cache_dir: Path) -> AuthCache:
    """Return an AuthCache targeting a temp directory."""
    return AuthCache(cache_dir)


@pytest.fixture
def sample_result() -> AuthResult:
    """Return a test AuthResult."""
    return AuthResult(
        cookies=[CookieData(name="sid", value="v1", domain=".example.com")],
        tokens={"jwt": "token123"},
        local_storage={"key": "val"},
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


class TestAuthCacheSaveLoad:
    """Tests for save and load operations."""

    def test_save_creates_directory(self, auth_cache: AuthCache, sample_result: AuthResult, cache_dir: Path) -> None:
        assert not cache_dir.exists()
        auth_cache.save(sample_result)
        assert cache_dir.exists()
        assert auth_cache.cache_file.exists()

    def test_roundtrip(self, auth_cache: AuthCache, sample_result: AuthResult) -> None:
        auth_cache.save(sample_result)
        loaded = auth_cache.load()
        assert loaded is not None
        assert len(loaded.cookies) == 1
        assert loaded.cookies[0].name == "sid"
        assert loaded.tokens["jwt"] == "token123"
        assert loaded.local_storage["key"] == "val"

    def test_load_nonexistent(self, auth_cache: AuthCache) -> None:
        result = auth_cache.load()
        assert result is None

    def test_load_corrupted(self, auth_cache: AuthCache, cache_dir: Path) -> None:
        cache_dir.mkdir(parents=True)
        auth_cache.cache_file.write_text("not valid json")
        with pytest.raises(CacheError, match="Failed to parse"):
            auth_cache.load()


class TestAuthCacheInvalidate:
    """Tests for cache invalidation."""

    def test_invalidate_existing(self, auth_cache: AuthCache, sample_result: AuthResult) -> None:
        auth_cache.save(sample_result)
        assert auth_cache.cache_file.exists()
        auth_cache.invalidate()
        assert not auth_cache.cache_file.exists()

    def test_invalidate_nonexistent(self, auth_cache: AuthCache) -> None:
        auth_cache.invalidate()  # Should not raise


class TestAuthCacheIsValid:
    """Tests for cache validity checking."""

    @pytest.mark.asyncio
    async def test_expired_result(self, auth_cache: AuthCache) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) - timedelta(hours=1))
        is_valid = await auth_cache.is_valid(result)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_valid_result_no_callback(self, auth_cache: AuthCache) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) + timedelta(hours=1))
        is_valid = await auth_cache.is_valid(result)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_callback_reports_invalid(self, auth_cache: AuthCache) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) + timedelta(hours=1))
        callback = AsyncMock()
        callback.is_authenticated = AsyncMock(return_value=False)
        is_valid = await auth_cache.is_valid(result, callback)
        assert is_valid is False

    @pytest.mark.asyncio
    async def test_callback_reports_valid(self, auth_cache: AuthCache) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) + timedelta(hours=1))
        callback = AsyncMock()
        callback.is_authenticated = AsyncMock(return_value=True)
        is_valid = await auth_cache.is_valid(result, callback)
        assert is_valid is True

    @pytest.mark.asyncio
    async def test_callback_exception_treated_as_invalid(self, auth_cache: AuthCache) -> None:
        result = AuthResult(expires_at=datetime.now(UTC) + timedelta(hours=1))
        callback = AsyncMock()
        callback.is_authenticated = AsyncMock(side_effect=RuntimeError("network error"))
        is_valid = await auth_cache.is_valid(result, callback)
        assert is_valid is False
