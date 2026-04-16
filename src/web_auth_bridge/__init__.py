"""web-auth-bridge: Playwright-based browser authentication bridge for HTTP APIs."""

from __future__ import annotations

from web_auth_bridge._types import AuthResult, CookieData, Credentials
from web_auth_bridge.auth.cache import AuthCache
from web_auth_bridge.auth.protocols import AuthCallback, SessionRenewalCallback
from web_auth_bridge.bridge import WebAuthBridge
from web_auth_bridge.browser.context_pool import BrowserContextPool
from web_auth_bridge.browser.manager import BrowserManager, StealthConfig
from web_auth_bridge.exceptions import (
    AuthError,
    BrowserError,
    CacheError,
    SessionRenewalError,
    WebAuthBridgeError,
)
from web_auth_bridge.http.client import HttpClientFactory

__all__ = [
    "AuthCache",
    "AuthCallback",
    "AuthError",
    "AuthResult",
    "BrowserContextPool",
    "BrowserError",
    "BrowserManager",
    "CacheError",
    "CookieData",
    "Credentials",
    "HttpClientFactory",
    "SessionRenewalCallback",
    "SessionRenewalError",
    "StealthConfig",
    "WebAuthBridge",
    "WebAuthBridgeError",
]
