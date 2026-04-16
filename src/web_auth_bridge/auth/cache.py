"""Authentication cache: persist and reload AuthResult to/from disk."""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from typing import TYPE_CHECKING

from web_auth_bridge._types import AuthResult
from web_auth_bridge.exceptions import CacheError

if TYPE_CHECKING:
    from pathlib import Path

    from web_auth_bridge.auth.protocols import AuthCallback

logger = logging.getLogger(__name__)

_CACHE_FILENAME = "auth_cache.json"


class AuthCache:
    """File-backed authentication cache.

    Stores a serialized ``AuthResult`` as JSON at ``{cache_dir}/auth_cache.json``
    with restrictive file permissions (owner-only on all platforms).

    Args:
        cache_dir: Directory where the cache file is stored.  Created on first write.
    """

    def __init__(self, cache_dir: Path) -> None:
        self._cache_dir = cache_dir
        self._cache_file = cache_dir / _CACHE_FILENAME

    @property
    def cache_file(self) -> Path:
        """Return the path to the cache file."""
        return self._cache_file

    def save(self, result: AuthResult) -> None:
        """Persist an ``AuthResult`` to disk.

        Creates the cache directory if it does not exist.  Sets file
        permissions to owner-read/write only (600 on Unix, ACL-restricted
        on Windows).

        Args:
            result: The authentication result to cache.

        Raises:
            CacheError: If the file cannot be written.
        """
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            data = json.dumps(result.to_dict(), indent=2)
            self._cache_file.write_text(data, encoding="utf-8")
            self._restrict_permissions()
            logger.info("Auth cache written to %s", self._cache_file)
        except OSError as exc:
            raise CacheError(f"Failed to write auth cache: {exc}") from exc

    def load(self) -> AuthResult | None:
        """Load a cached ``AuthResult`` from disk.

        Returns:
            The deserialized ``AuthResult``, or ``None`` if no cache exists.

        Raises:
            CacheError: If the file exists but cannot be parsed.
        """
        if not self._cache_file.exists():
            logger.debug("No auth cache found at %s", self._cache_file)
            return None
        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            result = AuthResult.from_dict(data)
            logger.info("Auth cache loaded from %s", self._cache_file)
            return result
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise CacheError(f"Failed to parse auth cache: {exc}") from exc

    async def is_valid(self, result: AuthResult, callback: AuthCallback | None = None) -> bool:
        """Check whether a cached result is still valid.

        First checks ``result.is_expired``.  If the result has no expiry or
        is not expired, and a *callback* is provided, delegates to
        ``callback.is_authenticated()`` for an active check.

        Args:
            result: The cached authentication result.
            callback: Optional auth callback for active validation.

        Returns:
            ``True`` if the cached result is still usable.
        """
        if result.is_expired:
            logger.info("Auth cache expired (expires_at=%s)", result.expires_at)
            return False
        if callback is not None:
            try:
                valid = await callback.is_authenticated(result)
                if not valid:
                    logger.info("Auth callback reports cached auth is no longer valid")
                return valid
            except Exception:
                logger.warning("is_authenticated check failed; treating cache as invalid", exc_info=True)
                return False
        return True

    def invalidate(self) -> None:
        """Delete the cache file if it exists.

        Raises:
            CacheError: If the file exists but cannot be deleted.
        """
        if not self._cache_file.exists():
            return
        try:
            self._cache_file.unlink()
            logger.info("Auth cache invalidated: %s", self._cache_file)
        except OSError as exc:
            raise CacheError(f"Failed to delete auth cache: {exc}") from exc

    def _restrict_permissions(self) -> None:
        """Set owner-only read/write permissions on the cache file."""
        if sys.platform == "win32":
            self._restrict_permissions_windows()
        else:
            self._cache_file.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def _restrict_permissions_windows(self) -> None:
        """Restrict NTFS ACL to the current user on Windows."""
        try:
            import subprocess

            username = os.environ.get("USERNAME", "")
            if not username:
                logger.debug("Cannot determine USERNAME for ACL restriction")
                return
            # Disable inheritance and remove all inherited ACEs
            subprocess.run(
                ["icacls", str(self._cache_file), "/inheritance:r"],
                capture_output=True,
                check=True,
            )
            # Grant only the current user full control
            subprocess.run(
                ["icacls", str(self._cache_file), "/grant:r", f"{username}:(R,W)"],
                capture_output=True,
                check=True,
            )
            logger.debug("Windows ACL restricted to %s on %s", username, self._cache_file)
        except Exception:
            logger.warning("Could not restrict Windows ACL on %s", self._cache_file, exc_info=True)
