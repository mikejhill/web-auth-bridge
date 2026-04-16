"""Exception hierarchy for web-auth-bridge."""

from __future__ import annotations


class WebAuthBridgeError(Exception):
    """Base exception for all web-auth-bridge errors."""


class AuthError(WebAuthBridgeError):
    """Raised when authentication fails."""


class CacheError(WebAuthBridgeError):
    """Raised when cache read/write operations fail."""


class BrowserError(WebAuthBridgeError):
    """Raised when browser lifecycle operations fail."""


class SessionRenewalError(WebAuthBridgeError):
    """Raised when a per-context session renewal callback fails."""
