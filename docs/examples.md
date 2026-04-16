# Examples

## 1. Minimal form login

```python
import asyncio
from web_auth_bridge import WebAuthBridge, AuthResult, Credentials

class MyCallback:
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
        auth_callback=MyCallback(),
        credentials=Credentials(username="me@example.com", password="..."),
    )
    await bridge.ensure_authenticated()

    async with bridge.http_client() as client:
        resp = await client.get("https://example.com/api/me")
        print(resp.json())

asyncio.run(main())
```

## 2. Using cached auth across runs

Running the snippet above twice will hit the network once.  The second
run loads `~/.config/example/auth_cache.json` and goes straight to the
API call.

On 401, invalidate and retry:

```python
resp = await client.get(url)
if resp.status_code == 401:
    bridge.invalidate_cache()
    await bridge.ensure_authenticated()
    async with bridge.http_client() as client:
        resp = await client.get(url)
```

## 3. Non-headless, user-typed credentials

```python
bridge = WebAuthBridge(
    app_name="sensitive-site",
    auth_callback=MyCallback(),
    credentials=None,          # Don't store; prompt in browser instead
    headless=False,            # Show the window
)
await bridge.ensure_authenticated()
```

Your `AuthCallback` should `await page.wait_for_url(...)` (or similar)
to detect when the user has finished logging in.

## 4. Parallel headless scraping for portals without an API

```python
await bridge.ensure_authenticated()

async with bridge.context_pool(size=4) as pool:
    async def scrape_one(ctx, url):
        page = await ctx.new_page()
        await page.goto(url)
        return await page.content()

    results = await asyncio.gather(*[
        scrape_one(ctx, url) for ctx, url in zip(pool, urls, strict=False)
    ])
```

Each `ctx` starts with the authenticated cookies; no re-login happens.

## 5. Garmin Connect end-to-end

See `examples/garmin_connect.py` for the canonical complex example:
Cloudflare-guarded SSO, CAS ticket exchange, DI Bearer token issuance,
and authenticated API calls via `httpx`.  Run it with:

```bash
uv sync --extra tls-impersonation
cp .env.example .env  # fill in GARMIN_EMAIL / GARMIN_PASSWORD
uv run python examples/garmin_connect.py
```

Flags of interest:

| Env var                         | Effect                                                     |
| ------------------------------- | ---------------------------------------------------------- |
| `GARMIN_HEADLESS=false`         | Show the browser (required for manual credential entry)    |
| `GARMIN_CREDENTIAL_MODE=manual` | Don't read creds from env; user types into page            |
| `GARMIN_FORCE_REAUTH=true`      | Bypass cache and re-authenticate now                       |

## 6. Writing an `AuthCallback` for a SAML site

```python
class SamlCallback:
    async def authenticate(self, page, credentials):
        # Service-provider login URL kicks off the SAML redirect dance.
        await page.goto("https://app.company.com/")
        await page.fill('input[name="Email"]', credentials.username)
        await page.click('input[type="submit"]')
        await page.fill('input[type="password"]', credentials.password)
        await page.click('input[type="submit"]')
        # MFA prompt — wait for the user or for TOTP auto-fill
        await page.wait_for_url("https://app.company.com/**", timeout=120_000)
        return AuthResult()
```
