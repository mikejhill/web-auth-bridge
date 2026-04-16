"""Browser lifecycle management via Playwright."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import Browser, Playwright, async_playwright

from web_auth_bridge.exceptions import BrowserError

logger = logging.getLogger(__name__)

# Stealth defaults that reduce detection by WAFs and bot-detection systems.
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"
)
_DEFAULT_VIEWPORT = {"width": 1920, "height": 1080}
_DEFAULT_LOCALE = "en-US"


@dataclass(frozen=True)
class StealthConfig:
    """Anti-detection configuration applied to every browser context.

    These settings make the headless browser appear more like a normal
    desktop browser session to WAF systems (Cloudflare, Akamai, etc.).
    """

    user_agent: str = _DEFAULT_USER_AGENT
    viewport: dict[str, int] = field(default_factory=lambda: dict(_DEFAULT_VIEWPORT))
    locale: str = _DEFAULT_LOCALE
    timezone_id: str = "America/New_York"
    color_scheme: str = "light"
    extra_http_headers: dict[str, str] = field(default_factory=dict)


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
            "user_agent": self._stealth.user_agent,
            "viewport": self._stealth.viewport,
            "locale": self._stealth.locale,
            "timezone_id": self._stealth.timezone_id,
            "color_scheme": self._stealth.color_scheme,
        }
        if self._stealth.extra_http_headers:
            kwargs["extra_http_headers"] = self._stealth.extra_http_headers
        kwargs.update(overrides)
        return kwargs

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
