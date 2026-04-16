"""Unit tests for :mod:`web_auth_bridge.browser.manager`.

Covers ``StealthConfig``, the user-agent builder, ``BrowserManager.__init__``
argument handling, the ``context_kwargs()`` override rules, and the
pre-launch ``browser`` property guard — all without launching a real
browser.  Live-browser behavior is covered by the integration tier.
"""

from __future__ import annotations

import pytest

from web_auth_bridge.browser.manager import (
    _STEALTH_JS,
    BrowserManager,
    StealthConfig,
    _build_user_agent,
)
from web_auth_bridge.exceptions import BrowserError

# ---------------------------------------------------------------------------
# _build_user_agent
# ---------------------------------------------------------------------------


class TestBuildUserAgent:
    def test_none_version_uses_fallback_chrome_token(self) -> None:
        ua = _build_user_agent(None)

        assert "Chrome/136.0.0.0" in ua, f"Fallback UA must contain a hardcoded Chrome major version; got: {ua}"
        assert "HeadlessChrome" not in ua, "UA must never advertise HeadlessChrome (primary WAF detection signal)"

    def test_explicit_version_uses_major_only(self) -> None:
        """Only the major version is interpolated — real Chrome always uses ``MAJOR.0.0.0``."""
        ua = _build_user_agent("147.0.7632.6")

        assert "Chrome/147.0.0.0" in ua, f"Expected only major version extracted into UA, got: {ua}"
        assert "147.0.7632.6" not in ua, "Full build number must NOT leak into UA (real Chrome emits MAJOR.0.0.0)"

    def test_has_realistic_chrome_shape(self) -> None:
        """UA must match Chrome's structural template — WebKit token, Windows platform, Safari suffix."""
        ua = _build_user_agent("140.0.0.0")

        for required in ("Mozilla/5.0", "Windows NT 10.0", "AppleWebKit/537.36", "Safari/537.36"):
            assert required in ua, f"UA must contain '{required}' to look like desktop Chrome, got: {ua}"


# ---------------------------------------------------------------------------
# StealthConfig
# ---------------------------------------------------------------------------


class TestStealthConfig:
    def test_default_populates_user_agent(self) -> None:
        """An empty user_agent must be auto-filled by __post_init__."""
        config = StealthConfig()

        assert config.user_agent, "Default StealthConfig must auto-populate user_agent"
        assert "Chrome/" in config.user_agent, f"Auto-populated UA must advertise Chrome, got: {config.user_agent}"
        assert "HeadlessChrome" not in config.user_agent, "Auto-populated UA must strip any HeadlessChrome marker"

    def test_explicit_user_agent_respected(self) -> None:
        config = StealthConfig(user_agent="CustomBot/1.0")

        assert config.user_agent == "CustomBot/1.0", (
            f"Explicit user_agent must be preserved exactly, got: {config.user_agent}"
        )

    def test_default_viewport_is_desktop(self) -> None:
        config = StealthConfig()

        assert config.viewport == {"width": 1920, "height": 1080}, (
            f"Default viewport must be 1920x1080 desktop, got {config.viewport}"
        )

    def test_frozen_cannot_mutate_after_construction(self) -> None:
        config = StealthConfig()

        with pytest.raises((AttributeError, Exception), match=r"frozen|cannot assign"):
            config.locale = "de-DE"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BrowserManager.__init__ — argument handling
# ---------------------------------------------------------------------------


class TestBrowserManagerInit:
    def test_default_stealth_when_none(self) -> None:
        """Passing stealth=None must still yield a working StealthConfig."""
        manager = BrowserManager(stealth=None)

        kwargs = manager.context_kwargs()

        assert "user_agent" in kwargs, "Default stealth must inject a user_agent into context kwargs"

    def test_always_appends_disable_blink_features_arg(self) -> None:
        """Every manager adds ``--disable-blink-features=AutomationControlled``."""
        manager = BrowserManager(launch_kwargs={"args": ["--no-sandbox"]})

        args = manager._launch_kwargs["args"]

        assert "--no-sandbox" in args, "Caller-provided launch arg must be preserved"
        joined = " ".join(args)
        assert "disable-blink-features=AutomationControlled" in joined, (
            f"Expected AutomationControlled flag to be appended, got args: {args}"
        )

    def test_does_not_duplicate_blink_features_arg(self) -> None:
        """If the caller already passed a ``--disable-blink-features=...`` flag, don't double it."""
        caller_flag = "--disable-blink-features=AutomationControlled,SomethingElse"
        manager = BrowserManager(launch_kwargs={"args": [caller_flag]})

        args = manager._launch_kwargs["args"]

        blink_args = [a for a in args if "disable-blink-features" in a]
        assert blink_args == [caller_flag], f"Must not duplicate --disable-blink-features flag; got: {blink_args}"

    def test_channel_extracted_from_launch_kwargs(self) -> None:
        manager = BrowserManager(launch_kwargs={"channel": "chrome"})

        assert manager._channel == "chrome", f"Expected channel='chrome', got {manager._channel!r}"

    def test_channel_empty_when_not_set(self) -> None:
        manager = BrowserManager()

        assert manager._channel == "", "Channel must be empty string (truthy-false) when launch_kwargs has no channel"


# ---------------------------------------------------------------------------
# BrowserManager.browser property — pre-launch guard
# ---------------------------------------------------------------------------


class TestBrowserProperty:
    def test_raises_before_launch(self) -> None:
        manager = BrowserManager()

        with pytest.raises(BrowserError, match="not launched"):
            _ = manager.browser


# ---------------------------------------------------------------------------
# context_kwargs() — the critical CF-bypass logic
# ---------------------------------------------------------------------------


class TestContextKwargs:
    def test_bundled_chromium_always_gets_ua_override(self) -> None:
        """With no channel (bundled Chromium), UA must always be overridden.

        The bundled Chromium default UA leaks ``HeadlessChrome`` and is a
        hard giveaway — we replace it regardless of headless flag.
        """
        manager = BrowserManager(headless=False)  # headed bundled

        kwargs = manager.context_kwargs()

        assert "user_agent" in kwargs, (
            "Bundled Chromium (no channel) must always get an override UA, "
            "even in headed mode — its default UA is detectable."
        )
        assert "HeadlessChrome" not in kwargs["user_agent"], (
            f"Injected UA must not contain HeadlessChrome, got: {kwargs['user_agent']}"
        )

    def test_real_channel_headed_skips_ua_override(self) -> None:
        """Real Chrome/Edge in headed mode has a legitimate UA — leave it alone."""
        manager = BrowserManager(headless=False, launch_kwargs={"channel": "chrome"})

        kwargs = manager.context_kwargs()

        assert "user_agent" not in kwargs, (
            "When using a real browser channel in headed mode the bridge must NOT "
            "override UA — real Chrome's UA is authentic and overriding risks a mismatch."
        )

    def test_real_channel_headless_overrides_ua(self) -> None:
        """Regression for Cloudflare headless detection: channel+headless MUST override UA.

        Real Chrome launched headless stamps ``HeadlessChrome`` into its UA.
        Without this override, Cloudflare's managed challenge blocks every
        login attempt with a 403 "Just a moment..." page.
        """
        manager = BrowserManager(headless=True, launch_kwargs={"channel": "chrome"})

        kwargs = manager.context_kwargs()

        assert "user_agent" in kwargs, (
            "REGRESSION: headless + real channel MUST override UA, "
            "otherwise Chrome's 'HeadlessChrome' token leaks through "
            "and Cloudflare blocks the request."
        )
        assert "HeadlessChrome" not in kwargs["user_agent"], (
            f"Override UA must scrub HeadlessChrome; got: {kwargs['user_agent']}"
        )

    def test_overrides_win_over_defaults(self) -> None:
        """Explicit overrides replace stealth defaults."""
        manager = BrowserManager()

        kwargs = manager.context_kwargs(
            locale="de-DE",
            viewport={"width": 800, "height": 600},
        )

        assert kwargs["locale"] == "de-DE", f"Expected locale override 'de-DE', got {kwargs['locale']}"
        assert kwargs["viewport"] == {"width": 800, "height": 600}, (
            f"Expected viewport override, got {kwargs['viewport']}"
        )

    def test_includes_timezone_and_color_scheme_defaults(self) -> None:
        manager = BrowserManager()

        kwargs = manager.context_kwargs()

        assert kwargs["timezone_id"] == "America/New_York", (
            f"Default timezone should be America/New_York, got {kwargs.get('timezone_id')}"
        )
        assert kwargs["color_scheme"] == "light", (
            f"Default color_scheme should be 'light', got {kwargs.get('color_scheme')}"
        )

    def test_extra_http_headers_only_included_when_non_empty(self) -> None:
        """Empty extra_http_headers must not be added (would pin an identifiable header set)."""
        manager_empty = BrowserManager(stealth=StealthConfig(extra_http_headers={}))
        manager_with = BrowserManager(stealth=StealthConfig(extra_http_headers={"X-Trace": "abc"}))

        kwargs_empty = manager_empty.context_kwargs()
        kwargs_with = manager_with.context_kwargs()

        assert "extra_http_headers" not in kwargs_empty, (
            "Empty extra_http_headers dict must be omitted entirely from context kwargs"
        )
        assert kwargs_with["extra_http_headers"] == {"X-Trace": "abc"}, (
            f"Non-empty extra_http_headers must be forwarded verbatim, got {kwargs_with.get('extra_http_headers')}"
        )


# ---------------------------------------------------------------------------
# Stealth init script contents — verify the CF-fingerprint patches are present
# ---------------------------------------------------------------------------


class TestStealthInitScript:
    """Assertions on the injected JavaScript payload.

    These are regression tests for the headless detection fixes — each
    patch below corresponds to a documented Cloudflare/Akamai fingerprint
    leak observed in production.
    """

    @pytest.mark.parametrize(
        ("pattern", "reason"),
        [
            ("navigator.webdriver", "Must patch navigator.webdriver (primary automation marker)"),
            ("window.chrome", "Must stub window.chrome (missing in headless by default)"),
            ("screen.colorDepth", "Must patch screen.colorDepth (headless reports 24 vs 32 for real Chrome)"),
            ("HeadlessChrome", "Must scrub 'HeadlessChrome' from navigator.userAgent as a last line of defense"),
            ("navigator.permissions", "Must patch permissions.query for 'notifications' (headless returns 'denied')"),
            ("navigator.plugins", "Must fake navigator.plugins (real Chrome always has a PDF viewer)"),
        ],
    )
    def test_script_contains_expected_patch(self, pattern: str, reason: str) -> None:
        assert pattern in _STEALTH_JS, f"Stealth init script missing patch for {pattern!r}: {reason}"


# ---------------------------------------------------------------------------
# close() — idempotency
# ---------------------------------------------------------------------------


class TestClose:
    @pytest.mark.asyncio
    async def test_close_without_launch_is_noop(self) -> None:
        manager = BrowserManager()

        await manager.close()  # must not raise

    @pytest.mark.asyncio
    async def test_close_twice_is_idempotent(self) -> None:
        manager = BrowserManager()

        await manager.close()
        await manager.close()  # must not raise
