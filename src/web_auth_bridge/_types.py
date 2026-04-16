"""Shared type definitions for web-auth-bridge."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True)
class Credentials:
    """User credentials for authentication.

    Passed to AuthCallback when headless mode needs stored credentials.
    When ``None`` is passed instead, the user enters credentials manually in a visible browser.
    """

    username: str
    password: str
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CookieData:
    """A single browser cookie extracted after authentication."""

    name: str
    value: str
    domain: str
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str = "Lax"
    expires: float | None = None

    def to_playwright_dict(self) -> dict[str, Any]:
        """Convert to the dict format expected by Playwright's ``context.add_cookies()``."""
        cookie: dict[str, Any] = {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "httpOnly": self.http_only,
            "sameSite": self.same_site,
        }
        if self.expires is not None:
            cookie["expires"] = self.expires
        return cookie

    @classmethod
    def from_playwright_dict(cls, data: Mapping[str, Any]) -> CookieData:
        """Create from a Playwright cookie dict (as returned by ``context.cookies()``)."""
        return cls(
            name=data["name"],
            value=data["value"],
            domain=data.get("domain", ""),
            path=data.get("path", "/"),
            secure=data.get("secure", False),
            http_only=data.get("httpOnly", False),
            same_site=data.get("sameSite", "Lax"),
            expires=data.get("expires"),
        )


@dataclass
class AuthResult:
    """The outcome of a successful authentication.

    Consumers populate this from their ``AuthCallback.authenticate()`` implementation.
    The bridge persists it to the cache and uses it to configure HTTP clients and
    browser contexts.
    """

    cookies: list[CookieData] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)
    expires_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_expired(self) -> bool:
        """Return ``True`` if the result has a set expiry that is in the past."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for cache persistence."""
        return {
            "cookies": [
                {
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "http_only": c.http_only,
                    "same_site": c.same_site,
                    "expires": c.expires,
                }
                for c in self.cookies
            ],
            "local_storage": self.local_storage,
            "tokens": self.tokens,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthResult:
        """Deserialize from a cache dict."""
        cookies = [
            CookieData(
                name=c["name"],
                value=c["value"],
                domain=c["domain"],
                path=c.get("path", "/"),
                secure=c.get("secure", False),
                http_only=c.get("http_only", False),
                same_site=c.get("same_site", "Lax"),
                expires=c.get("expires"),
            )
            for c in data.get("cookies", [])
        ]
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])
        created_at = datetime.now(UTC)
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])
        return cls(
            cookies=cookies,
            local_storage=data.get("local_storage", {}),
            tokens=data.get("tokens", {}),
            expires_at=expires_at,
            created_at=created_at,
        )
