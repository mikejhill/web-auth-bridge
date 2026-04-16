# web-auth-bridge

[![CI](https://github.com/mikejhill/web-auth-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/mikejhill/web-auth-bridge/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/web-auth-bridge.svg)](https://pypi.org/project/web-auth-bridge/)
[![Python](https://img.shields.io/pypi/pyversions/web-auth-bridge.svg)](https://pypi.org/project/web-auth-bridge/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Browser-assisted authentication for HTTP APIs that fight back.**

Many interesting APIs can't be reached with plain HTTP: they hide behind
SSO, SAML, Cloudflare challenges, or stateful web portals with no JSON
surface.  `web-auth-bridge` uses Playwright to handle the login *once*,
extracts the resulting cookies and tokens as plain data, and hands them
to your consumer code so every subsequent call is a fast `httpx` request.

## What it does

- **Logs in with a real browser** (Playwright / Chromium) so WAFs,
  JS challenges, and SAML redirects all just work.
- **Extracts cookies and tokens** into a typed `AuthResult` — no more
  hairy JSON digging.
- **Caches auth on disk** at `~/.config/<app>/auth_cache.json` so every
  run after the first is cache-warm.
- **Issues parallel authenticated browsers** when a site has no clean
  HTTP API (classic ASP.NET portals, etc.).
- **Runs headless or headed**, with credentials from a file or typed by
  the user into a visible browser.

## Install

```bash
pip install web-auth-bridge
playwright install chromium
```

For sites that reject Python's default TLS fingerprint (e.g. Garmin's
DI OAuth2 exchange):

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
        return AuthResult()  # cookies auto-extracted from the context

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

The first run opens Chromium; the second (within cookie lifetime) doesn't.

## When to use it

Use `web-auth-bridge` when you need to script against a site whose auth
flow you can't or don't want to reimplement by hand:

- **Cloudflare / other WAFs** that challenge non-browser clients.
- **SAML/OAuth portals** where the app doesn't expose a token endpoint.
- **Company intranets** that require MFA or interactive SSO.
- **Scraping portals** with stateful sessions and no API.
- **CLI tools for personal/private APIs** where reimplementing the auth
  dance is more work than the tool is worth.

Don't use it when you already have a clean API token — plain `httpx` is
fine there.

## Modes

| Mode                       | Credentials from      | Browser visible? | Typical use case                                |
| -------------------------- | --------------------- | ---------------- | ----------------------------------------------- |
| Headless + stored creds    | `.env` / file         | No               | Fully automated CLIs and agents                 |
| Headed + stored creds      | `.env` / file         | Yes              | Debugging; sites that require a visible window  |
| Headed + manual entry      | User types into page  | Yes              | Sensitive credentials never written to disk     |
| Headless + no creds        | Previously-cached     | No               | Every post-first run                            |

## Parallel headless browsers

```python
await bridge.ensure_authenticated()

async with bridge.context_pool(size=4) as pool:
    pages = [await ctx.new_page() for ctx in pool]
    # All four pages start already authenticated.
    ...
```

Useful for portals where every read is a full page render.

## Docs

- [Architecture](docs/architecture.md) — components, flows, and diagrams
- [Design notes](docs/design.md) — decisions, alternatives, constraints
- [Examples](docs/examples.md) — minimal snippets for common flows
- [Testing](TESTING.md) — how to run unit, integration, and live-site tests
- [Garmin example](examples/garmin_connect.py) — end-to-end Cloudflare-guarded
  SSO + OAuth2 Bearer token flow

## Development

```bash
git clone https://github.com/mikejhill/web-auth-bridge
cd web-auth-bridge
uv sync --all-extras
uv run playwright install chromium
uv run poe test     # unit + integration
uv run poe cov      # with coverage report
uv run poe lint     # ruff check
```

Contributions welcome.  Please use [Conventional Commits](https://www.conventionalcommits.org/) —
the release workflow derives versions from commit messages.

## License

MIT © Mike Hill
