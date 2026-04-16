"""Garmin Connect authentication example using web-auth-bridge.

Demonstrates how to use ``WebAuthBridge`` to authenticate against
Garmin Connect's SSO portal, cache the session, and make authenticated
API calls — all without manually managing browser lifecycle or cookies.

Authentication flow (driven by ``GarminAuthCallback``):
  1. Navigate to Garmin SSO sign-in page (Cloudflare challenge auto-solved by Playwright).
  2. POST credentials via an in-page ``fetch()`` call to avoid CORS/cookie issues.
  3. Handle MFA if the account requires it (prompts user interactively).
  4. Navigate to the ticket URL to establish a web session (``JWT_WEB`` cookie).
  5. Optionally exchange the service ticket for DI Bearer tokens (native API auth).

Cached sessions are reused automatically on subsequent runs — if the ``JWT_WEB``
cookie is still valid, the browser is never launched.

Configuration
~~~~~~~~~~~~~
Copy ``.env.example`` to ``.env`` in this directory and fill in values.
The ``.env`` file supports three credential modes:

- **auto** — Credentials from ``GARMIN_EMAIL``/``GARMIN_PASSWORD`` are entered
  automatically by the browser. Works in both headless and headed mode.
- **manual** — The browser opens visibly and the user enters credentials by hand.
  Forces headed mode regardless of ``GARMIN_HEADLESS``.
- **prompt** — Credentials are requested interactively in the terminal, then
  entered automatically by the browser.

CLI flags (``--email``, ``--password``, ``--headed``, ``--credential-mode``)
override ``.env`` values.

Usage::

    # Auto mode (headless) — credentials from .env
    python garmin_connect.py

    # Manual mode — user logs in visually
    python garmin_connect.py --credential-mode manual

    # Prompt mode — terminal prompts, then headless
    python garmin_connect.py --credential-mode prompt

    # Override .env with CLI flags
    python garmin_connect.py --email you@example.com --password hunter2 --headed
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Page

from datetime import UTC

from web_auth_bridge import (
    AuthResult,
    CookieData,
    Credentials,
    WebAuthBridge,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-25s %(levelname)-7s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("garmin_connect")
logging.getLogger("httpx").setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# Garmin SSO constants
# ---------------------------------------------------------------------------
SSO_BASE = "https://sso.garmin.com"
CONNECT_BASE = "https://connect.garmin.com"
CONNECTAPI_BASE = "https://connectapi.garmin.com"

PORTAL_CLIENT_ID = "GarminConnect"
PORTAL_SERVICE_URL = "https://connect.garmin.com/app"

SIGNIN_URL = f"{SSO_BASE}/portal/sso/en-US/sign-in?clientId={PORTAL_CLIENT_ID}&service={PORTAL_SERVICE_URL}"
LOGIN_API = f"{SSO_BASE}/portal/api/login?clientId={PORTAL_CLIENT_ID}&locale=en-US&service={PORTAL_SERVICE_URL}"
MFA_API = f"{SSO_BASE}/portal/api/mfa/verifyCode?clientId={PORTAL_CLIENT_ID}&locale=en-US&service={PORTAL_SERVICE_URL}"

# DI OAuth2 token exchange (native mobile API authentication)
DI_TOKEN_URL = "https://diauth.garmin.com/di-oauth2-service/oauth/token"
DI_GRANT_TYPE = "https://connectapi.garmin.com/di-oauth2-service/oauth/grant/service_ticket"
DI_CLIENT_IDS = (
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2025Q2",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI_2024Q4",
    "GARMIN_CONNECT_MOBILE_ANDROID_DI",
)

# Test API endpoint used to verify the session
USER_SETTINGS_URL = f"{CONNECT_BASE}/gc-api/userprofile-service/userprofile/user-settings/"

# Default cache location
DEFAULT_CACHE_DIR = Path("~/.config/garmin-connect/cache")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _js_fetch_json(page: Page, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a ``fetch()`` call inside the browser page context.

    Running the POST from within the page ensures all Cloudflare cookies
    (``cf_clearance``, ``__cf_bm``, etc.) are sent automatically, exactly
    as the real browser would.
    """
    payload_json = json.dumps(payload)
    script = f"""
    async () => {{
        const resp = await fetch("{url}", {{
            method: "POST",
            headers: {{
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
            }},
            body: JSON.stringify({payload_json}),
            credentials: "same-origin",
        }});
        const text = await resp.text();
        return {{ status: resp.status, body: text }};
    }}
    """
    result = await page.evaluate(script)
    status: int = result["status"]
    body_text: str = result["body"]

    log.debug("fetch(%s) → %d: %s", url, status, body_text[:200])

    if status == 429:
        # Retry once after a backoff for rate limiting
        log.warning("Rate limited (429) — waiting 10s and retrying...")
        await page.wait_for_timeout(10_000)
        result = await page.evaluate(script)
        status = result["status"]
        body_text = result["body"]
        log.debug("retry fetch(%s) → %d: %s", url, status, body_text[:200])
        if status == 429:
            msg = f"Rate limited (429) after retry. Response: {body_text[:300]}"
            raise RuntimeError(msg)
    if status == 403:
        msg = f"Forbidden (403). Response: {body_text[:300]}"
        raise RuntimeError(msg)

    try:
        return json.loads(body_text)
    except json.JSONDecodeError as exc:
        msg = f"Non-JSON response (HTTP {status}): {body_text[:300]}"
        raise RuntimeError(msg) from exc


def _build_basic_auth(client_id: str) -> str:
    """Build HTTP Basic auth header for DI token exchange."""
    return "Basic " + base64.b64encode(f"{client_id}:".encode()).decode()


# ---------------------------------------------------------------------------
# AuthCallback implementation
# ---------------------------------------------------------------------------


class GarminAuthCallback:
    """``AuthCallback`` implementation for Garmin Connect SSO.

    Drives the full Garmin login flow inside a Playwright page:
    navigate → post credentials → handle MFA → redeem ticket → extract cookies.
    """

    async def authenticate(self, page: Page, credentials: Credentials | None) -> AuthResult:
        """Drive the Garmin SSO login flow and return extracted auth artifacts.

        Args:
            page: A Playwright page in a fresh browser context.
            credentials: Username/password for headless login, or ``None``
                for manual entry in the visible browser.
        """
        # -- Step 1: Navigate to SSO sign-in page -------------------------
        log.info("Navigating to Garmin SSO sign-in page...")
        await page.goto(SIGNIN_URL, wait_until="domcontentloaded", timeout=30_000)
        log.info("Page loaded: %s", page.url[:80])

        # Wait through Cloudflare challenge if present.  CF can appear as
        # an interstitial ("Just a moment...") or as an invisible JS
        # challenge that sets cookies in the background.
        await self._wait_for_cloudflare(page)

        if not credentials:
            # Manual mode: wait for user to complete login in the visible browser
            log.info("No credentials provided — waiting for manual login...")
            await page.wait_for_url(f"{CONNECT_BASE}/**", timeout=120_000)
            return await self._extract_result(page)

        # -- Step 2: POST credentials via in-page fetch() -----------------
        # Brief delay to mimic human reading the page — submitting
        # credentials < 1s after page load can trigger bot detection.
        await page.wait_for_timeout(2_000)
        log.info("Submitting credentials...")
        login_payload = {
            "username": credentials.username,
            "password": credentials.password,
            "rememberMe": False,
            "captchaToken": "",
        }
        login_result = await _js_fetch_json(page, LOGIN_API, login_payload)
        resp_type = login_result.get("responseStatus", {}).get("type")
        log.info("Login response: %s", resp_type)

        if resp_type == "INVALID_USERNAME_PASSWORD":
            msg = "Invalid username or password."
            raise RuntimeError(msg)

        # -- Step 3: Handle MFA if required --------------------------------
        ticket: str | None = None
        if resp_type == "MFA_REQUIRED":
            mfa_info = login_result.get("customerMfaInfo", {})
            mfa_method = mfa_info.get("mfaLastMethodUsed", "email")
            log.info("MFA required (method: %s). Check your email for the code.", mfa_method)

            mfa_code = input("Enter MFA code: ").strip()
            mfa_payload = {
                "mfaMethod": mfa_method,
                "mfaVerificationCode": mfa_code,
                "rememberMyBrowser": True,
                "reconsentList": [],
                "mfaSetup": False,
            }
            mfa_result = await _js_fetch_json(page, MFA_API, mfa_payload)
            mfa_type = mfa_result.get("responseStatus", {}).get("type")
            if mfa_type != "SUCCESSFUL":
                msg = f"MFA verification failed: {mfa_type}"
                raise RuntimeError(msg)
            ticket = mfa_result.get("serviceTicketId")
        elif resp_type == "SUCCESSFUL":
            ticket = login_result.get("serviceTicketId")
        else:
            msg = f"Unexpected login response type: {resp_type}"
            raise RuntimeError(msg)

        if not ticket:
            msg = "No service ticket received from Garmin SSO."
            raise RuntimeError(msg)

        log.info("Service ticket obtained.")

        # -- Step 4: Redeem ticket for JWT_WEB cookie ----------------------
        ticket_url = f"{CONNECT_BASE}/app?ticket={ticket}"
        await page.goto(ticket_url, wait_until="domcontentloaded", timeout=30_000)
        log.info("Ticket redeemed — session established.")

        # -- Step 5: Optionally exchange ticket for DI Bearer tokens -------
        tokens = await self._exchange_di_tokens(ticket)

        return await self._extract_result(page, tokens=tokens)

    async def _wait_for_cloudflare(self, page: Page, timeout: int = 30_000) -> None:
        """Wait for Cloudflare challenges to resolve before proceeding.

        Cloudflare may present:
        - A visible interstitial (page title = "Just a moment...")
        - An invisible JS challenge that runs in the background

        In both cases, the ``cf_clearance`` cookie must be set before API
        calls will succeed.
        """
        title = await page.title()
        if "Just a moment" in title:
            log.info("Cloudflare challenge page detected — waiting for resolution...")
            try:
                await page.wait_for_function(
                    "document.title !== 'Just a moment...'",
                    timeout=timeout,
                )
                log.info("Cloudflare challenge resolved.")
            except Exception:
                log.warning("Cloudflare challenge did not resolve within %ds", timeout // 1000)

        # Wait for the sign-in form to become interactive.  This covers both
        # the visible interstitial and invisible JS challenge cases.
        log.info("Waiting for sign-in page to be ready...")
        try:
            await page.wait_for_selector(
                'input[name="username"], input[id="username"], form',
                state="visible",
                timeout=timeout,
            )
        except Exception:
            # The selector may not match Garmin's exact DOM — fall back to
            # a simple delay to let CF scripts complete.
            log.debug("Sign-in form selector not found; using timed wait")
            await page.wait_for_timeout(3_000)

        # Final stabilisation delay — lets any remaining CF background
        # scripts finish and set cookies (cf_clearance, __cf_bm, etc.)
        await page.wait_for_timeout(1_000)
        log.info("Page ready.")

    async def is_authenticated(self, auth_result: AuthResult) -> bool:
        """Check whether the cached JWT_WEB cookie is still valid.

        Validates the JWT token's expiry claim (``exp``) without making a
        network request.  This avoids Cloudflare TLS-fingerprint blocks
        that would cause httpx-based validation to fail.
        """
        import base64

        jwt_web = next((c.value for c in auth_result.cookies if c.name == "JWT_WEB"), None)
        if not jwt_web:
            log.debug("No JWT_WEB cookie in cached result")
            return False

        if auth_result.is_expired:
            log.debug("Cached result has expired")
            return False

        # Decode JWT payload to check expiry (no signature verification needed
        # — we just want to know if the token has expired).
        try:
            parts = jwt_web.split(".")
            if len(parts) < 2:
                log.debug("JWT_WEB is not a valid JWT")
                return False
            # JWT base64url decoding (padding may be missing)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp")
            if exp is None:
                log.debug("JWT_WEB has no 'exp' claim — assuming valid")
                return True
            from datetime import datetime

            expiry = datetime.fromtimestamp(exp, tz=UTC)
            now = datetime.now(tz=UTC)
            if now < expiry:
                log.info("Cached JWT_WEB valid until %s", expiry.isoformat())
                return True
            log.info("Cached JWT_WEB expired at %s", expiry.isoformat())
        except Exception:
            log.debug("Failed to decode JWT_WEB", exc_info=True)

        return False

    # -- Private helpers ---------------------------------------------------

    async def _extract_result(
        self,
        page: Page,
        *,
        tokens: dict[str, str] | None = None,
    ) -> AuthResult:
        """Extract cookies and tokens from the browser context."""
        raw_cookies = await page.context.cookies()
        cookies = [CookieData.from_playwright_dict(c) for c in raw_cookies]

        # Also try to grab the CSRF token from the page meta tag
        result_tokens: dict[str, str] = dict(tokens) if tokens else {}
        try:
            csrf = await page.evaluate("() => document.querySelector('meta[name=\"csrf-token\"]')?.content")
            if csrf:
                result_tokens["csrf_token"] = csrf
        except Exception:
            pass

        log.info("Extracted %d cookies, %d tokens", len(cookies), len(result_tokens))
        return AuthResult(cookies=cookies, tokens=result_tokens)

    async def _exchange_di_tokens(self, ticket: str) -> dict[str, str]:
        """Exchange the service ticket for native DI Bearer tokens.

        Tries multiple known client IDs until one succeeds. Returns an
        empty dict if none work (web auth still functions without them).
        """
        import httpx

        for client_id in DI_CLIENT_IDS:
            log.debug("Trying DI token exchange with client_id=%s", client_id)
            headers = {
                "Authorization": _build_basic_auth(client_id),
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
            data = {
                "client_id": client_id,
                "service_ticket": ticket,
                "grant_type": DI_GRANT_TYPE,
                "service_url": PORTAL_SERVICE_URL,
            }

            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        DI_TOKEN_URL,
                        headers=headers,
                        data=data,
                        timeout=30,
                    )

                if resp.status_code == 429:
                    log.warning("DI token exchange rate limited (429)")
                    break

                if resp.is_success:
                    token_data = resp.json()
                    log.info("DI Bearer token obtained (client_id=%s)", client_id)
                    tokens = {"di_token": token_data["access_token"]}
                    if token_data.get("refresh_token"):
                        tokens["di_refresh_token"] = token_data["refresh_token"]
                    return tokens
            except httpx.HTTPError as exc:
                log.debug("DI exchange failed for %s: %s", client_id, exc)
                continue

        log.info("DI token exchange unavailable — web auth only")
        return {}


# ---------------------------------------------------------------------------
# .env loader
# ---------------------------------------------------------------------------


def _load_dotenv(env_path: Path | None = None) -> None:
    """Load key=value pairs from a .env file into ``os.environ``.

    Skips blank lines and comments. Does not override existing env vars.
    """
    path = env_path or Path(__file__).parent / ".env"
    if not path.is_file():
        return
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and key not in os.environ:
                os.environ[key] = value


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the Garmin Connect authentication example."""
    _load_dotenv()

    parser = argparse.ArgumentParser(
        description="Garmin Connect authentication via web-auth-bridge",
        epilog=("Configuration is loaded from .env (copy .env.example). CLI flags override .env values."),
    )
    parser.add_argument("--email", help="Garmin account email (overrides GARMIN_EMAIL)")
    parser.add_argument("--password", help="Garmin account password (overrides GARMIN_PASSWORD)")
    parser.add_argument(
        "--headed",
        action="store_true",
        default=None,
        help="Show the browser window (overrides GARMIN_HEADLESS=false)",
    )
    parser.add_argument(
        "--credential-mode",
        choices=["auto", "manual", "prompt"],
        default=None,
        help="How credentials are provided (overrides GARMIN_CREDENTIAL_MODE)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Auth cache directory (overrides GARMIN_CACHE_DIR)",
    )
    args = parser.parse_args()

    # ── Resolve configuration (CLI > env > defaults) ──────────────────
    credential_mode = args.credential_mode or os.environ.get("GARMIN_CREDENTIAL_MODE", "auto")
    cache_dir = args.cache_dir or Path(os.environ.get("GARMIN_CACHE_DIR", "") or DEFAULT_CACHE_DIR)

    # Headed/headless: CLI --headed wins, then env, then default headless
    if args.headed is not None:
        headless = not args.headed
    else:
        headless = os.environ.get("GARMIN_HEADLESS", "true").lower() in ("true", "1", "yes")

    # Manual mode forces headed browser
    if credential_mode == "manual":
        headless = False

    # ── Resolve credentials based on mode ─────────────────────────────
    credentials: Credentials | None = None

    if credential_mode == "manual":
        log.info("Credential mode: manual — user will log in via the visible browser")
        credentials = None
    elif credential_mode == "prompt":
        log.info("Credential mode: prompt — requesting credentials interactively")
        email = input("Email: ")
        password = getpass.getpass("Password: ")
        credentials = Credentials(username=email, password=password)
    else:
        # auto mode: CLI flags > env vars > interactive fallback
        email = args.email or os.environ.get("GARMIN_EMAIL", "")
        password = args.password or os.environ.get("GARMIN_PASSWORD", "")
        if email and password:
            log.info("Credential mode: auto — using stored credentials")
            credentials = Credentials(username=email, password=password)
        else:
            log.info("Credential mode: auto — no stored credentials, falling back to prompt")
            email = email or input("Email: ")
            password = password or getpass.getpass("Password: ")
            credentials = Credentials(username=email, password=password)

    # ── Set up the bridge ─────────────────────────────────────────────
    # Use real Chrome/Edge via ``channel`` to avoid Cloudflare TLS
    # fingerprint detection that blocks Playwright's bundled Chromium.
    channel = os.environ.get("GARMIN_BROWSER_CHANNEL", "chrome")
    bridge = WebAuthBridge(
        auth_callback=GarminAuthCallback(),
        cache_dir=cache_dir,
        credentials=credentials,
        headless=headless,
        launch_kwargs={"channel": channel},
    )

    # ── Authenticate (uses cache on second run) ───────────────────────
    log.info("=" * 60)
    log.info("Ensuring authenticated session...")
    log.info("=" * 60)
    result = await bridge.ensure_authenticated()
    log.info(
        "Authenticated: %d cookies, %d tokens",
        len(result.cookies),
        len(result.tokens),
    )

    # ── Inspect raw cookies and tokens ────────────────────────────────
    cookie_names = [c["name"] for c in bridge.cookies()]
    log.info("Cookie names: %s", cookie_names)

    tokens = bridge.tokens()
    if tokens:
        log.info("Token keys: %s", list(tokens.keys()))

    # ── Make a test API call using the bridge's HTTP client ───────────
    log.info("=" * 60)
    log.info("Testing authenticated API access...")
    log.info("=" * 60)

    # Method 1: httpx client (fast, no browser — works for APIs without
    #           aggressive TLS fingerprint checks like Cloudflare).
    async with bridge.http_client(headers={"NK": "NT", "X-Requested-With": "XMLHttpRequest"}) as client:
        resp = await client.get(USER_SETTINGS_URL)
        if resp.status_code == 200:
            data = resp.json()
            log.info("[httpx] Display name: %s", data.get("displayName", "N/A"))
            log.info("[httpx] Web API auth: SUCCESS")
        else:
            log.info(
                "[httpx] HTTP %d — Cloudflare TLS block (expected for CF-protected APIs)",
                resp.status_code,
            )

    # Method 2: Browser context (works universally, including CF-protected APIs).
    #           Uses a parallel browser context with the same auth cookies.
    #           Must navigate to the target domain first so that fetch()
    #           runs within the correct origin (same-origin credentials).
    api_success = False
    async with bridge.browser_pool(count=1) as contexts:
        api_page = await contexts[0].new_page()
        try:
            # Navigate to the Garmin Connect app so the page origin matches
            await api_page.goto(f"{CONNECT_BASE}/modern/", wait_until="domcontentloaded", timeout=30_000)

            api_resp = await api_page.evaluate(
                """
                async (url) => {
                    const resp = await fetch(url, {
                        headers: {
                            'NK': 'NT',
                            'X-Requested-With': 'XMLHttpRequest',
                        },
                        credentials: 'same-origin',
                    });
                    const text = await resp.text();
                    return { status: resp.status, body: text };
                }
            """,
                USER_SETTINGS_URL,
            )
            if api_resp["status"] == 200:
                import json

                data = json.loads(api_resp["body"])
                log.info("[browser] Display name: %s", data.get("displayName", "N/A"))
                log.info("[browser] Web API auth: SUCCESS")
                api_success = True
            else:
                log.warning("[browser] HTTP %d", api_resp["status"])
        except Exception:
            log.warning("[browser] API call failed", exc_info=True)
        finally:
            await api_page.close()

    # ── Summary ───────────────────────────────────────────────────────
    jwt_web = next((c.value for c in result.cookies if c.name == "JWT_WEB"), None)
    log.info("=" * 60)
    log.info("AUTHENTICATION SUMMARY")
    log.info("=" * 60)
    log.info("  JWT_WEB:     %s", "OK" if jwt_web else "MISSING")
    log.info("  CSRF Token:  %s", "OK" if tokens.get("csrf_token") else "MISSING")
    log.info("  DI Token:    %s", "OK" if tokens.get("di_token") else "MISSING")
    log.info("  Browser API: %s", "OK" if api_success else "NOT TESTED")
    log.info("  Cache dir:   %s", DEFAULT_CACHE_DIR.expanduser())
    log.info("  Tip: Run again to verify the cached session is reused without a browser.")


if __name__ == "__main__":
    asyncio.run(main())
