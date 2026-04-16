# Testing `web-auth-bridge`

This project has three test tiers, separated by pytest markers so you can
run each independently.

| Tier            | Marker        | Needs credentials | Needs network    | Default run? |
| --------------- | ------------- | ----------------- | ---------------- | ------------ |
| Unit            | _(none)_      | No                | No               | Yes          |
| Integration     | `integration` | No                | Loopback only    | Yes          |
| End-to-end      | `e2e`         | Yes               | External sites   | **No**       |

End-to-end tests are excluded from the default run via `addopts = "-m 'not e2e'"`
in `pyproject.toml`, so `pytest` alone never hits real websites or requires
credentials.

## Running each tier

The most convenient way is via **`poe`** (poethepoet), which exposes named
tasks defined in `pyproject.toml`.  Run `uv run poe` to list them.

```powershell
uv run poe test          # unit + integration (default, no creds)
uv run poe test-unit     # unit tests only, fastest
uv run poe test-int      # integration tests (Playwright + local server)
uv run poe test-e2e      # all live-site e2e (needs .env)
uv run poe test-garmin   # Garmin live e2e only
uv run poe test-rouvy    # Rouvy live e2e only
uv run poe cov           # default tests with coverage report
uv run poe cov-html      # coverage report as HTML in htmlcov/
uv run poe lint          # ruff check
uv run poe check         # lint + default tests (CI gate)
```

Or invoke pytest directly if you prefer:

```powershell
# Unit + integration (the default) — no credentials, no external network.
pytest

# Unit tests only — fastest, no Playwright needed at runtime.
pytest -m "not integration and not e2e"

# Integration tests only — spins up a real Playwright browser against a
# local pytest-httpserver. No credentials, no internet.
pytest -m integration

# End-to-end, all sites — requires .env with every site's credentials.
pytest -m e2e

# Just Garmin e2e.
pytest -m "e2e and garmin"

# Just Rouvy e2e.
pytest -m "e2e and rouvy"
```

## Coverage

```powershell
pytest --cov=web_auth_bridge --cov-report=term-missing
```

Current baseline: **93 %** total, **100 %** on `bridge.py`, `authenticator.py`,
`http/client.py`, and `_types.py`.  `browser/manager.py` sits at 81 %; the
remainder is runtime Playwright launch code exercised only by integration
tests with a real browser.

## Setting up credentials for e2e tests

1. Copy `.env.example` to `.env` at the project root.
2. Fill in credentials for whichever sites you want to test:

   ```
   GARMIN_EMAIL=you@example.com
   GARMIN_PASSWORD=...
   ROUVY_EMAIL=you@example.com
   ROUVY_PASSWORD=...
   ```

3. Optional tuning:

   ```
   WEB_AUTH_BRIDGE_E2E_HEADLESS=true       # false = show the browser
   WEB_AUTH_BRIDGE_E2E_CHANNEL=chrome      # or msedge; empty = bundled chromium
   ```

`.env` is git-ignored.  CI environment variables take precedence over
`.env` entries, so the same tests can run locally and in a pipeline.

If a site's credentials are not set, its e2e tests are **skipped**, not
failed.  This means `pytest -m e2e` is always safe to run.

### Garmin-specific extras

Garmin's `connectapi.garmin.com` blocks non-browser TLS fingerprints.  The
Garmin e2e tests therefore require the `tls-impersonation` extra:

```powershell
uv sync --extra tls-impersonation
```

Without it, the Garmin e2e tests skip with a clear message.

## Adding a new site

1. Add credential vars to `.env.example`.
2. In `tests/e2e/conftest.py`, add a fixture mirroring `garmin_credentials`:

   ```python
   @pytest.fixture
   def mysite_credentials() -> Credentials:
       return _require_credentials("MYSITE_EMAIL", "MYSITE_PASSWORD", "MySite")
   ```

3. Register a marker in `pyproject.toml` under `markers`.
4. Create `tests/e2e/test_mysite_live.py` with `pytestmark = [pytest.mark.e2e, pytest.mark.mysite, pytest.mark.asyncio]`.
5. Write an `AuthCallback` for the site (inline in the test file is fine for
   one-offs; promote to `examples/` when reused).
6. Write the three canonical contract tests: authenticate-and-populate,
   cookies-authenticate-http, and cache-reuse-across-instances.

See `tests/e2e/test_rouvy_live.py` for a minimal template.

## Test layout

```
tests/
├── conftest.py                     # shared fixtures (local-only)
├── test_authenticator.py           # unit
├── test_bridge.py                  # unit
├── test_browser_manager.py         # unit (CF-headless regression)
├── test_cache.py                   # unit
├── test_context_pool.py            # unit
├── test_http_client.py             # unit
├── test_main.py                    # unit (__main__ entry point)
├── test_types.py                   # unit
├── test_cli_integration.py         # integration (pytest-httpserver)
├── test_bridge_integration.py      # integration (Playwright + httpserver)
└── e2e/                            # external-site tests, opt-in only
    ├── conftest.py                 # .env loader, credential fixtures
    ├── test_garmin_live.py
    └── test_rouvy_live.py
```
