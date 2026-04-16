"""Tests for the CLI module."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from web_auth_bridge._types import AuthResult, CookieData
from web_auth_bridge.auth.cache import AuthCache
from web_auth_bridge.cli import cli_main

if TYPE_CHECKING:
    from pathlib import Path


class TestCacheStatus:
    """Tests for the cache-status command."""

    def test_no_cache(self, tmp_path: Path) -> None:
        exit_code = cli_main(["cache-status", str(tmp_path / "nonexistent")])
        assert exit_code == 1

    def test_with_cache(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache = AuthCache(cache_dir)
        cache.save(
            AuthResult(
                cookies=[CookieData(name="c", value="v", domain="d")],
                tokens={"jwt": "tok"},
            )
        )
        exit_code = cli_main(["cache-status", str(cache_dir)])
        assert exit_code == 0


class TestCacheClear:
    """Tests for the cache-clear command."""

    def test_clear_existing(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cache"
        cache = AuthCache(cache_dir)
        cache.save(AuthResult())
        assert cache.cache_file.exists()
        exit_code = cli_main(["cache-clear", str(cache_dir)])
        assert exit_code == 0
        assert not cache.cache_file.exists()

    def test_clear_nonexistent(self, tmp_path: Path) -> None:
        exit_code = cli_main(["cache-clear", str(tmp_path / "nonexistent")])
        assert exit_code == 0


class TestVersion:
    """Tests for the --version flag."""

    def test_version(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["--version"])
        assert exc_info.value.code == 0
