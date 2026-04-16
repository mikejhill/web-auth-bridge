# web-auth-bridge

Playwright-based browser authentication bridge for HTTP APIs with complex auth flows.

Separates browser-based authentication from API execution. Authenticate once via a real browser (handling WAF, SAML, MFA, etc.), extract cookies/tokens, then use them for fast HTTP calls or parallel browser sessions.
