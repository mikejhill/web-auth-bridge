"""End-to-end tests against real external websites.

These tests require real credentials and outbound internet access.  They
are excluded from the default pytest collection by ``addopts = -m "not e2e"``
in ``pyproject.toml`` — run them explicitly with ``pytest -m e2e``.

Credentials are loaded from a ``.env`` or ``.env.tests`` file at the
project root.  Tests for sites without credentials are skipped
automatically, not failed.

Per-site tests live in ``test_<site>_live.py``.  They all exercise the
same contract:

1. **Authenticate** a fresh session against the real site.
2. **Validate** the returned ``AuthResult`` (cookies, tokens present).
3. **Exercise** a real authenticated API call using the extracted
   credentials — proves that what was extracted actually grants access.
4. **Round-trip the cache**: a second ``WebAuthBridge`` sharing the same
   cache directory must reuse the credentials without launching a browser.
"""

from __future__ import annotations
