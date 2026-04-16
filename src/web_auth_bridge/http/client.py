"""HTTP client factory with pre-injected authentication."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from web_auth_bridge._types import AuthResult

logger = logging.getLogger(__name__)


class HttpClientFactory:
    """Create ``httpx`` clients pre-configured with authentication cookies and headers.

    After browser-based authentication extracts cookies and tokens, this factory
    builds HTTP clients that carry those credentials — enabling fast API calls
    without a browser.

    Args:
        auth_result: The authentication result containing cookies and tokens.
    """

    def __init__(self, auth_result: AuthResult) -> None:
        self._auth_result = auth_result

    def async_client(self, **kwargs: Any) -> httpx.AsyncClient:
        """Create an ``httpx.AsyncClient`` with auth cookies and headers injected.

        Args:
            **kwargs: Additional keyword arguments forwarded to ``httpx.AsyncClient()``.
                These override any defaults set by this factory.

        Returns:
            A configured ``httpx.AsyncClient``.
        """
        cookies = self._build_cookie_jar()
        headers = self._build_headers(kwargs.pop("headers", None))
        client = httpx.AsyncClient(cookies=cookies, headers=headers, **kwargs)
        logger.debug(
            "Created async httpx client with %d cookies, %d extra headers",
            len(cookies),
            len(headers),
        )
        return client

    def sync_client(self, **kwargs: Any) -> httpx.Client:
        """Create an ``httpx.Client`` with auth cookies and headers injected.

        Args:
            **kwargs: Additional keyword arguments forwarded to ``httpx.Client()``.
                These override any defaults set by this factory.

        Returns:
            A configured ``httpx.Client``.
        """
        cookies = self._build_cookie_jar()
        headers = self._build_headers(kwargs.pop("headers", None))
        client = httpx.Client(cookies=cookies, headers=headers, **kwargs)
        logger.debug(
            "Created sync httpx client with %d cookies, %d extra headers",
            len(cookies),
            len(headers),
        )
        return client

    def _build_cookie_jar(self) -> httpx.Cookies:
        """Build an httpx-compatible cookie jar from the auth result."""
        jar = httpx.Cookies()
        for cookie in self._auth_result.cookies:
            jar.set(cookie.name, cookie.value, domain=cookie.domain, path=cookie.path)
        return jar

    def _build_headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        """Build default headers from tokens, merged with any extras.

        Tokens named ``authorization``, ``bearer``, or ``access_token`` are
        added as an ``Authorization: Bearer <value>`` header.  Tokens named
        ``csrf`` or ``x-csrf-token`` are added as their corresponding header.
        All other tokens are added as ``X-<Key>`` headers.

        Args:
            extra: Additional headers provided by the caller.

        Returns:
            Merged header dict.
        """
        headers: dict[str, str] = {}
        for key, value in self._auth_result.tokens.items():
            lower_key = key.lower().replace("-", "_")
            if lower_key in ("authorization", "bearer", "access_token", "di_token"):
                headers["Authorization"] = f"Bearer {value}"
            elif lower_key in ("csrf", "csrf_token", "x_csrf_token"):
                headers["X-CSRF-Token"] = value
            else:
                headers[f"X-{key}"] = value
        if extra:
            headers.update(extra)
        return headers
