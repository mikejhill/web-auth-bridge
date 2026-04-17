# web-auth-bridge

[![CI](https://github.com/mikejhill/web-auth-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/mikejhill/web-auth-bridge/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/web-auth-bridge.svg)](https://pypi.org/project/web-auth-bridge/)
[![Python](https://img.shields.io/pypi/pyversions/web-auth-bridge.svg)](https://pypi.org/project/web-auth-bridge/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Python library for authenticating against HTTP APIs whose login flows
require a real browser — SSO, SAML, Cloudflare, or stateful web portals —
and then reusing the resulting session for fast programmatic access.

## Overview

`web-auth-bridge` separates authentication from execution:

1. A Playwright-driven browser performs the login once.
2. The resulting cookies and tokens are extracted into a typed
   `AuthResult` and cached on disk.
3. Subsequent calls use a plain `httpx` client with those cookies, or,
   when a site requires a browser beyond login, a pool of pre-authenticated
   headless contexts.

The library is intended for CLIs, agents, and integrations that need to
script against sites with complex or interactive authentication.

## Installation

```bash
pip install web-auth-bridge
playwright install chromium
```

For sites that reject Python's default TLS fingerprint (for example,
Garmin's OAuth2 token exchange):

```bash
pip install "web-auth-bridge[tls-impersonation]"
```

## Quick start

```python
import asyncio
from web_auth_bridge import WebAuthBridge, AuthResult, Credentials

class ExampleCallback:
    async def authenticate(self, page, credentials):
        await page.goto("https://example.com/login")
        await page.fill('input[name="email"]', credentials.username)
        await page.fill('input[name="password"]', credentials.password)
        async with page.expect_navigation():
            await page.click('button[type="submit"]')
        return AuthResult()

    async def is_authenticated(self, result):
        return not result.is_expired

async def main():
    bridge = WebAuthBridge(
        app_name="example",
        auth_callback=ExampleCallback(),
        credentials=Credentials(username="me@example.com", password="..."),
    )
    await bridge.ensure_authenticated()

    async with bridge.http_client() as client:
        resp = await client.get("https://example.com/api/me")
        print(resp.json())

asyncio.run(main())
```

On the first run the browser opens to log in. On subsequent runs the
cached session is reused until it expires.

## When to use it

- Sites guarded by Cloudflare or other WAFs that challenge non-browser clients.
- SAML or OAuth portals without a public token endpoint.
- Internal applications requiring MFA or interactive SSO.
- Stateful web portals (for example, ASP.NET) with no HTTP API surface.
- CLI tools for personal or private APIs where reimplementing the auth
  flow would cost more than the tool itself.

If a site already offers a clean API token, use `httpx` directly.

## Alternatives

A managed browser is not always the right tool. Lighter-weight approaches
exist and, when they work, cost a fraction of the memory and startup time:

- **[`cloudscraper`](https://github.com/VeNoMouS/cloudscraper)**,
  **[`curl_cffi`](https://github.com/lexiforest/curl_cffi)**, and
  **[`tls-client`](https://github.com/bogdanfinn/tls-client)** impersonate
  real browser TLS and HTTP/2 fingerprints to defeat fingerprint-based WAFs
  without running a browser.
- **[`hrequests`](https://github.com/daijro/hrequests)** and
  **[`botasaurus`](https://github.com/omkarcloud/botasaurus)** wrap similar
  techniques with higher-level scraping APIs.
- Hand-crafted HTTP flows against documented OAuth, OIDC, or token endpoints
  remain the best option whenever a site exposes them.

`web-auth-bridge` exists for the cases those approaches do not cover:
interactive SSO, MFA, SAML, stateful web portals, JavaScript-rendered
challenges, and WAF rulesets that evolve faster than any fingerprint library
can track. The tradeoff is resource cost for resilience — running an actual
browser is heavier than a spoofed request, but it behaves like a browser
because it is one, and it continues to work when the underlying site
changes.

## Modes

| Mode                    | Credentials source   | Browser visible | Typical use case                           |
| ----------------------- | -------------------- | --------------- | ------------------------------------------ |
| Headless + stored creds | `.env` / config file | No              | Fully automated CLIs and agents            |
| Headed + stored creds   | `.env` / config file | Yes             | Debugging; sites requiring a visible UI    |
| Headed + manual entry   | User types into page | Yes             | Secrets that must not be stored on disk    |
| Headless + no creds     | Cached session       | No              | Every run after the first, while cached    |

## Parallel headless browsers

For sites without a usable API, the bridge can produce a pool of
pre-authenticated browser contexts:

```python
await bridge.ensure_authenticated()

async with bridge.context_pool(size=4) as pool:
    pages = [await ctx.new_page() for ctx in pool]
    ...
```

## Documentation

- [Architecture](docs/architecture.md) — components, flows, and diagrams
- [Design notes](docs/design.md) — decisions, alternatives, and constraints
- [Examples](docs/examples.md) — minimal snippets for common flows
- [Testing](TESTING.md) — unit, integration, and live-site tests
- [Garmin example](examples/garmin_connect.py) — end-to-end Cloudflare-guarded
  SSO plus OAuth2 Bearer token flow

## Development

```bash
git clone https://github.com/mikejhill/web-auth-bridge
cd web-auth-bridge
uv sync --all-extras
uv run playwright install chromium
uv run poe test
uv run poe cov
uv run poe lint
```

Contributions are welcome. Please use
[Conventional Commits](https://www.conventionalcommits.org/); the release
workflow derives versions from commit messages.

## License

MIT
