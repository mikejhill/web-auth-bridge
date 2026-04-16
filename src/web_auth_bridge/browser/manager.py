"""Browser lifecycle management via Playwright."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from playwright.async_api import Browser, Playwright, async_playwright

from web_auth_bridge.exceptions import BrowserError

if TYPE_CHECKING:
    from playwright.async_api import BrowserContext

logger = logging.getLogger(__name__)

# Stealth defaults that reduce detection by WAFs and bot-detection systems.
_DEFAULT_VIEWPORT = {"width": 1920, "height": 1080}
_DEFAULT_LOCALE = "en-US"

# Fallback UA when auto-detection is not possible (kept reasonably current).
_FALLBACK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)


def _detect_chromium_version() -> str | None:
    """Try to read the Chrome version from Playwright's bundled browser.

    Returns a version string like ``"145.0.7632.6"`` or ``None``.
    """
    try:
        import platform
        from pathlib import Path as _Path

        # Playwright stores browsers under a platform-specific directory
        system = platform.system()
        if system == "Windows":
            browsers_root = _Path.home() / "AppData" / "Local" / "ms-playwright"
        elif system == "Darwin":
            browsers_root = _Path.home() / "Library" / "Caches" / "ms-playwright"
        else:
            browsers_root = _Path.home() / ".cache" / "ms-playwright"

        if not browsers_root.is_dir():
            return None

        for entry in browsers_root.iterdir():
            if entry.name.startswith("chromium") and entry.is_dir():
                # Look for a version manifest (e.g. "145.0.7632.6.manifest")
                for sub in entry.rglob("*.manifest"):
                    match = re.match(r"(\d+\.\d+\.\d+\.\d+)\.manifest", sub.name)
                    if match:
                        return match.group(1)
    except Exception:
        logger.debug("Could not detect Chromium version", exc_info=True)
    return None


def _build_user_agent(chromium_version: str | None = None) -> str:
    """Build a realistic desktop Chrome user-agent string.

    If *chromium_version* is provided (e.g. ``"145.0.7632.6"``), the major
    version is extracted and used.  Otherwise falls back to a hardcoded
    recent version.
    """
    if chromium_version:
        major = chromium_version.split(".")[0]
        chrome_token = f"Chrome/{major}.0.0.0"
    else:
        chrome_token = "Chrome/136.0.0.0"

    return (
        f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) {chrome_token} Safari/537.36"
    )


# ---------------------------------------------------------------------------
# Stealth init script — injected into every BrowserContext via
# ``add_init_script()`` so that it executes before any page JavaScript.
# Patches the most common headless-detection signals used by Cloudflare,
# Akamai, PerimeterX, and similar WAF systems.
# ---------------------------------------------------------------------------
_STEALTH_JS = """
(() => {
    // 1. Hide navigator.webdriver
    Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined,
        configurable: true,
    });

    // 2. Fake navigator.plugins (real Chrome always has at least a PDF viewer)
    const fakePlugins = {
        0: {
            name: 'PDF Viewer',
            description: 'Portable Document Format',
            filename: 'internal-pdf-viewer',
            length: 1,
            0: { type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format' },
        },
        1: {
            name: 'Chrome PDF Viewer',
            description: 'Portable Document Format',
            filename: 'internal-pdf-viewer',
            length: 1,
            0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
        },
        2: {
            name: 'Chromium PDF Viewer',
            description: 'Portable Document Format',
            filename: 'internal-pdf-viewer',
            length: 1,
            0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
        },
        3: {
            name: 'Microsoft Edge PDF Viewer',
            description: 'Portable Document Format',
            filename: 'internal-pdf-viewer',
            length: 1,
            0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
        },
        4: {
            name: 'WebKit built-in PDF',
            description: 'Portable Document Format',
            filename: 'internal-pdf-viewer',
            length: 1,
            0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
        },
        length: 5,
        item: function(i) { return this[i] || null; },
        namedItem: function(name) {
            for (let i = 0; i < this.length; i++) {
                if (this[i].name === name) return this[i];
            }
            return null;
        },
        refresh: function() {},
        [Symbol.iterator]: function*() {
            for (let i = 0; i < this.length; i++) yield this[i];
        },
    };
    Object.defineProperty(navigator, 'plugins', {
        get: () => fakePlugins,
        configurable: true,
    });

    // 3. Fake navigator.mimeTypes
    const fakeMimeTypes = {
        0: {
            type: 'application/pdf',
            suffixes: 'pdf',
            description: 'Portable Document Format',
            enabledPlugin: fakePlugins[0],
        },
        length: 1,
        item: function(i) { return this[i] || null; },
        namedItem: function(name) {
            for (let i = 0; i < this.length; i++) {
                if (this[i].type === name) return this[i];
            }
            return null;
        },
        [Symbol.iterator]: function*() {
            for (let i = 0; i < this.length; i++) yield this[i];
        },
    };
    Object.defineProperty(navigator, 'mimeTypes', {
        get: () => fakeMimeTypes,
        configurable: true,
    });

    // 4. Ensure navigator.languages is populated
    if (!navigator.languages || navigator.languages.length === 0) {
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true,
        });
    }

    // 5. Fake window.chrome object (present in real Chrome, missing in headless)
    if (!window.chrome) {
        window.chrome = {
            runtime: {
                onMessage: { addListener: function() {}, removeListener: function() {} },
                onConnect: { addListener: function() {}, removeListener: function() {} },
                sendMessage: function() {},
                connect: function() {
                    return {
                        onMessage: { addListener: function() {} },
                        postMessage: function() {},
                        disconnect: function() {},
                    };
                },
            },
            loadTimes: function() { return {}; },
            csi: function() { return {}; },
        };
    }

    // 6. Remove Playwright/ChromeDriver automation indicators
    delete window.__playwright;
    delete window.__pw_manual;

    // 7. Patch permissions API to report 'prompt' for notifications
    //    (headless Chrome often returns 'denied' which is a fingerprint signal)
    const origQuery = window.navigator.permissions?.query?.bind(window.navigator.permissions);
    if (origQuery) {
        window.navigator.permissions.query = (params) => {
            if (params.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission || 'prompt' });
            }
            return origQuery(params);
        };
    }

    // 8. Ensure connection type looks normal (headless sometimes has null)
    if (navigator.connection && !navigator.connection.rtt) {
        Object.defineProperty(navigator.connection, 'rtt', { get: () => 50, configurable: true });
    }
})();
"""


@dataclass(frozen=True)
class StealthConfig:
    """Anti-detection configuration applied to every browser context.

    These settings make the headless browser appear more like a normal
    desktop browser session to WAF systems (Cloudflare, Akamai, etc.).

    The default ``user_agent`` attempts to match the Chrome version
    bundled with the installed Playwright package so that the UA string
    and the browser's JavaScript-visible version are consistent.
    """

    user_agent: str = ""
    viewport: dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_VIEWPORT))
    locale: str = _DEFAULT_LOCALE
    timezone_id: str = "America/New_York"
    color_scheme: str = "light"
    extra_http_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.user_agent:
            detected = _detect_chromium_version()
            ua = _build_user_agent(detected)
            # frozen dataclass — use object.__setattr__
            object.__setattr__(self, "user_agent", ua)
            logger.debug("Stealth user-agent: %s", ua)


class BrowserManager:
    """Manage the Playwright browser lifecycle.

    Handles launching and closing the browser, and provides a factory for
    creating new browser contexts with stealth configuration applied.

    Args:
        browser_type: Playwright browser type (``"chromium"``, ``"firefox"``, ``"webkit"``).
        headless: Whether to run in headless mode.
        stealth: Stealth configuration.  Pass ``None`` to disable stealth settings.
        launch_kwargs: Extra keyword arguments forwarded to ``browser_type.launch()``.
    """

    def __init__(
        self,
        *,
        browser_type: str = "chromium",
        headless: bool = True,
        stealth: StealthConfig | None = None,
        launch_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._browser_type_name = browser_type
        self._headless = headless
        self._stealth = stealth if stealth is not None else StealthConfig()
        self._launch_kwargs = launch_kwargs or {}
        self._channel = self._launch_kwargs.get("channel", "")
        # Ensure anti-automation Blink flag is always disabled
        args = list(self._launch_kwargs.get("args", []))
        if not any("disable-blink-features" in a for a in args):
            args.append("--disable-blink-features=AutomationControlled")
        self._launch_kwargs["args"] = args
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    @property
    def browser(self) -> Browser:
        """Return the active browser instance.

        Raises:
            BrowserError: If the browser has not been launched.
        """
        if self._browser is None:
            raise BrowserError("Browser not launched. Call launch() first.")
        return self._browser

    async def launch(self) -> Browser:
        """Launch the Playwright browser.

        Returns:
            The launched ``Browser`` instance.

        Raises:
            BrowserError: If the browser fails to launch (e.g., binaries not installed).
        """
        if self._browser is not None:
            return self._browser
        try:
            self._playwright = await async_playwright().start()
            browser_type = getattr(self._playwright, self._browser_type_name, None)
            if browser_type is None:
                available = ["chromium", "firefox", "webkit"]
                raise BrowserError(f"Unknown browser type '{self._browser_type_name}'. Available: {available}")
            logger.info(
                "Launching %s (headless=%s)",
                self._browser_type_name,
                self._headless,
            )
            self._browser = await browser_type.launch(
                headless=self._headless,
                **self._launch_kwargs,
            )
            return self._browser
        except BrowserError:
            raise
        except Exception as exc:
            msg = str(exc)
            if "Executable doesn't exist" in msg or "browserType.launch" in msg:
                raise BrowserError(
                    f"Playwright {self._browser_type_name} browser not installed. "
                    f"Run: playwright install {self._browser_type_name}"
                ) from exc
            raise BrowserError(f"Failed to launch browser: {exc}") from exc

    def context_kwargs(self, **overrides: Any) -> dict[str, Any]:
        """Build keyword arguments for ``browser.new_context()`` with stealth applied.

        Args:
            **overrides: Values that override the stealth defaults.

        Returns:
            A dict suitable for ``browser.new_context(**kwargs)``.
        """
        kwargs: dict[str, Any] = {
            "viewport": self._stealth.viewport,
            "locale": self._stealth.locale,
            "timezone_id": self._stealth.timezone_id,
            "color_scheme": self._stealth.color_scheme,
        }
        # Only override user-agent when using bundled Chromium.  Real browser
        # channels (chrome, msedge) already have a legitimate UA string and
        # overriding it risks creating a detectable mismatch.
        if not self._channel:
            kwargs["user_agent"] = self._stealth.user_agent
        if self._stealth.extra_http_headers:
            kwargs["extra_http_headers"] = self._stealth.extra_http_headers
        kwargs.update(overrides)
        return kwargs

    async def apply_stealth(self, context: BrowserContext) -> None:
        """Inject stealth patches into a browser context.

        Must be called *before* creating any pages.  Patches well-known
        headless-detection signals so that WAF systems (Cloudflare, Akamai,
        etc.) treat the browser as a legitimate desktop session.
        """
        await context.add_init_script(script=_STEALTH_JS)
        logger.debug("Stealth init script injected")

    async def close(self) -> None:
        """Close the browser and stop the Playwright instance."""
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                logger.debug("Error closing browser", exc_info=True)
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                logger.debug("Error stopping Playwright", exc_info=True)
            self._playwright = None
        logger.info("Browser closed")
