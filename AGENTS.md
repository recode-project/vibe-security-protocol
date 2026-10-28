# Universal AI Agent Rules: Web Security Protocol

All AI coding agents (Antigravity, Cline, Roo Code, Aider, OpenHands, Codex) working on this codebase must adhere to the 9-Layer Security Standard:

## Core Directives:
1. **Database / SQL Injection:** All database queries must use parameterized bindings/prepared statements. Concatenating or interpolating user variables into SQL strings is strictly forbidden.
2. **Network Security:** Production backend servers must bind exclusively to `127.0.0.1`.
3. **CORS & Authentication Cookies:** Require explicit origin whitelists for CORS. All cookies must be configured with `httpOnly: true`, `secure: true`, and `sameSite: 'lax'` or `'strict'`.
4. **Rate Limiting:** Enable reverse proxy real IP parsing via `CF-Connecting-IP` or `X-Forwarded-For`. Restrict authentication attempts to a maximum of 5 requests per minute.
5. **Cross-Site Scripting (XSS):** Never populate DOM nodes using unsanitized `innerHTML`. Use `textContent` or proper entity encoding. Validate redirect targets to only permit `http:` or `https:`.
6. **Information Disclosure:** Ensure `.env`, `.db`, `.sqlite`, `.sql`, `.log`, and `.git` files cannot be retrieved over HTTP.
7. **Credentials & Secrets:** Never commit secret keys or credentials. Load all secrets from `.env`.
8. **HTTP Security Headers:** Suppress version headers (`X-Powered-By`). Add `X-Frame-Options: SAMEORIGIN` and `X-Content-Type-Options: nosniff`.
9. **Webhook Integrity:** Incoming webhooks and financial callbacks must authenticate signatures using timing-safe comparisons (`crypto.timingSafeEqual`).
