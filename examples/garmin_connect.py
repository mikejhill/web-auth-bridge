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

Usage::

    # First run — authenticates via browser, caches result
    python garmin_connect.py --email you@example.com --password hunter2

    # Second run — uses cached session, no browser needed
    python garmin_connect.py --email you@example.com --password hunter2

    # Headed mode for debugging
    python garmin_connect.py --headed
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Page

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
        msg = f"Rate limited (429). Response: {body_text[:300]}"
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
        await page.goto(SIGNIN_URL, wait_until="networkidle", timeout=30_000)
        log.info("Page loaded: %s", page.url[:80])

        # Wait through Cloudflare challenge if present
        title = await page.title()
        if "Just a moment" in title:
            log.info("Cloudflare challenge detected — waiting for resolution...")
            await page.wait_for_function("document.title !== 'Just a moment...'", timeout=15_000)
            log.info("Challenge resolved.")

        if not credentials:
            # Manual mode: wait for user to complete login in the visible browser
            log.info("No credentials provided — waiting for manual login...")
            await page.wait_for_url(f"{CONNECT_BASE}/**", timeout=120_000)
            return await self._extract_result(page)

        # -- Step 2: POST credentials via in-page fetch() -----------------
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
        await page.goto(ticket_url, wait_until="networkidle", timeout=30_000)
        log.info("Ticket redeemed — session established.")

        # -- Step 5: Optionally exchange ticket for DI Bearer tokens -------
        tokens = await self._exchange_di_tokens(ticket)

        return await self._extract_result(page, tokens=tokens)

    async def is_authenticated(self, auth_result: AuthResult) -> bool:
        """Check whether the cached JWT_WEB cookie is still valid.

        Makes a lightweight API call to Garmin Connect. If the server
        returns 200, the session is still good.
        """
        import httpx

        jwt_web = next((c.value for c in auth_result.cookies if c.name == "JWT_WEB"), None)
        if not jwt_web:
            log.debug("No JWT_WEB cookie in cached result")
            return False

        if auth_result.is_expired:
            log.debug("Cached result has expired")
            return False

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    USER_SETTINGS_URL,
                    headers={
                        "Cookie": f"JWT_WEB={jwt_web}",
                        "NK": "NT",
                    },
                    timeout=10,
                )
            if resp.status_code == 200:
                log.info("Cached session is still valid")
                return True
            log.info("Cached session expired (HTTP %d)", resp.status_code)
        except httpx.HTTPError as exc:
            log.warning("Session validation request failed: %s", exc)

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
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    """Run the Garmin Connect authentication example."""
    parser = argparse.ArgumentParser(
        description="Garmin Connect authentication via web-auth-bridge",
        epilog=(
            "On the first run, a browser authenticates against Garmin SSO. "
            "Subsequent runs reuse the cached session automatically."
        ),
    )
    parser.add_argument("--email", help="Garmin account email")
    parser.add_argument("--password", help="Garmin account password")
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Show the browser window (useful for debugging or manual login)",
    )
    args = parser.parse_args()

    # Collect credentials (prompt interactively if not supplied)
    email = args.email or input("Email: ")
    password = args.password or getpass.getpass("Password: ")

    # ── Set up the bridge ─────────────────────────────────────────────
    bridge = WebAuthBridge(
        auth_callback=GarminAuthCallback(),
        cache_dir=DEFAULT_CACHE_DIR,
        credentials=Credentials(username=email, password=password),
        headless=not args.headed,
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

    # Async client example
    async with bridge.http_client(headers={"NK": "NT", "X-Requested-With": "XMLHttpRequest"}) as client:
        resp = await client.get(USER_SETTINGS_URL)
        if resp.status_code == 200:
            data = resp.json()
            log.info("Display name: %s", data.get("displayName", "N/A"))
            log.info("Web API auth: SUCCESS")
        else:
            log.warning("Web API auth: FAILED (HTTP %d)", resp.status_code)

    # Sync client example (useful for simple scripts)
    with bridge.http_client_sync(headers={"NK": "NT", "X-Requested-With": "XMLHttpRequest"}) as client:
        resp = client.get(USER_SETTINGS_URL)
        log.info("Sync client test: HTTP %d", resp.status_code)

    # ── Summary ───────────────────────────────────────────────────────
    jwt_web = next((c.value for c in result.cookies if c.name == "JWT_WEB"), None)
    log.info("=" * 60)
    log.info("AUTHENTICATION SUMMARY")
    log.info("=" * 60)
    log.info("  JWT_WEB:     %s", "OK" if jwt_web else "MISSING")
    log.info("  CSRF Token:  %s", "OK" if tokens.get("csrf_token") else "MISSING")
    log.info("  DI Token:    %s", "OK" if tokens.get("di_token") else "MISSING")
    log.info("  Cache dir:   %s", DEFAULT_CACHE_DIR.expanduser())
    log.info("  Tip: Run again to verify the cached session is reused without a browser.")


if __name__ == "__main__":
    asyncio.run(main())
