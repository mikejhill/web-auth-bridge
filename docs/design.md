# Design notes

This document captures the design decisions behind `web-auth-bridge` —
what we chose, what we rejected, and why.

## Goal

Give agent skills and CLI tools a one-line way to authenticate against
websites that plain HTTP cannot handle (SSO, SAML, WAF, JS challenges),
while keeping the runtime cost of every subsequent API call at ~zero —
i.e. a fast HTTP call with reusable cookies.

## Design principles

### 1. Separate authentication from execution

Authentication is expensive (browser launch, JS execution, WAF challenge
solving).  Execution should be cheap (a pure HTTP request with cached
cookies).  The library hard-enforces this split: `AuthResult` is a plain
data object containing cookies and tokens, and nothing about it requires
a browser to be alive.

### 2. Cache aggressively, invalidate explicitly

Re-authenticating on every invocation is pathological.  The cache is
on-disk, survives process restarts, and is keyed by app name so multiple
consumers coexist.  Consumers opt into invalidation on 401/403, never
the library — false-positive invalidations destroy performance.

### 3. Headless is the default; headed is the escape hatch

Most sites can be automated headless with proper fingerprint patches.
For those that can't (or when credentials shouldn't be stored at all),
consumers pass `headless=False` and `credentials=None` — the user types
credentials directly into the visible browser.

### 4. Parallel browsers when the API doesn't exist

Some portals (classic ASP.NET, certain LMS/HR systems) have no usable
HTTP API; every action requires a stateful browser.  The `ContextPool`
lets consumers fan out N authenticated browsers from a single login,
slashing the cost of parallel scraping.

## Alternatives considered

### Why a managed browser at all?

Several Python libraries attack the same problem space without running a
browser, and they are excellent choices when they work:

- **TLS / HTTP fingerprint spoofing.**
  [`cloudscraper`](https://github.com/VeNoMouS/cloudscraper),
  [`curl_cffi`](https://github.com/lexiforest/curl_cffi), and
  [`tls-client`](https://github.com/bogdanfinn/tls-client) imitate real
  browser TLS / HTTP&nbsp;2 fingerprints well enough to pass the
  fingerprint-based checks some WAFs apply. Memory footprint is small and
  startup is instant.
- **Scraping wrappers.**
  [`hrequests`](https://github.com/daijro/hrequests) and
  [`botasaurus`](https://github.com/omkarcloud/botasaurus) bundle
  fingerprint spoofing with higher-level scraping APIs.
- **Hand-coded HTTP against documented endpoints.**
  When a site exposes OAuth, OIDC, or a public token endpoint, a direct
  HTTP flow is the cheapest and most reliable option.

These approaches break when the site requires JavaScript execution,
renders the login form dynamically, issues interactive WAF challenges
(Cloudflare Turnstile, hCaptcha), uses SAML redirect chains, relies on
browser storage APIs, or simply changes its detection rules — which
happens often and without notice.

`web-auth-bridge` deliberately picks the heavier tool to trade startup
cost for resilience. A real browser behaves like a real browser because
it is one; when the site changes, the browser keeps passing.

### Why Playwright, not Selenium?

| Dimension | Playwright | Selenium |
|-----------|-----------|----------|
| Async support | Native `asyncio` | Sync or thread-wrapped |
| WAF fingerprint | Fewer default telltales | More bot-detection markers |
| Browser bundling | Downloads pinned Chromium on install | Requires separate driver |
| Parallel contexts | First-class `BrowserContext` | Requires full browser per session |
| Speed | Faster in our benchmarks | Slower on Chrome |

Selenium has broader legacy ecosystem, but for a Python library authored
in 2026 Playwright wins on every axis that matters here.

### Why JSON cache, not a keyring?

OS keyrings are great for credentials but wrong for session cookies: the
Windows credential store has a payload cap that large cookie bundles
exceed.  Plain JSON at `~/.config/<app>/` matches how most CLIs already
store session state and plays well with containerised environments.

### Why no built-in MFA handling?

MFA is site-specific and frequently requires human input (SMS, TOTP,
push).  The `AuthCallback` protocol lets consumers implement whatever
flow the site demands; non-headless mode plus a patient `wait_for_url()`
covers interactive TOTP with zero library complexity.

## Security posture

- **No credential persistence by the library.**  `Credentials` objects
  live only in memory; serialising them is the consumer's decision.
- **`.env` files are git-ignored** by default via the bundled `.gitignore`.
- **No telemetry.**  The library makes no outbound network calls of its
  own; only the consumer-driven Playwright and `httpx` calls.

## Why `AuthCallback` is a `Protocol`, not a base class

Python `Protocol` gives consumers freedom to implement the contract
however they like — inline class, frozen dataclass, module-level
functions wrapped in a lightweight adapter.  Abstract base classes
would bind implementations to inheritance and hinder testing.

## Why cookies are typed (`CookieData`), not dicts

Playwright returns cookie dicts; `httpx` consumes them in yet another
format; browser storage state uses a third.  Converting through a
single typed dataclass catches shape mismatches at the boundary instead
of producing confusing `KeyError`s deep in HTTP client code.

## Known constraints

- **Playwright browser download is ~200 MB.**  Consumers that only need
  the HTTP client path still pay this cost because Playwright is a
  required dependency.
- **Cloudflare Turnstile (interactive) is not solved.**  Most CF
  challenges resolve automatically with stealth patches; interactive
  "click the box" challenges require headed mode.
- **Some sites need TLS impersonation.**  The optional `tls-impersonation`
  extra installs `curl-cffi` for APIs that reject Python's default TLS
  fingerprint (e.g. Garmin's DI OAuth2 exchange).

## Future directions

- Pluggable secret backends (keyring, 1Password, Bitwarden) for
  consumers that want zero plaintext on disk.
- Per-site `AuthCallback` registry so `app_name` auto-selects a
  callback without the consumer wiring one up.
- Built-in TOTP helper for sites whose 2FA is standard RFC 6238.
