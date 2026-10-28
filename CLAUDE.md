# Claude Code Security Directives

When modifying, generating, or reviewing web applications in this repository, you must enforce the **9-Layer Web Security Protocol** (`WEB_SECURITY_PROTOCOL.md`):

1. **SQL Injection Prevention:**
   - Enforce parameterized queries / prepared statements for every database operation (PostgreSQL, SQLite, MySQL).
   - Reject any raw string interpolation into SQL queries.

2. **Network & Binding:**
   - Bind backend servers exclusively to `127.0.0.1`. Never default to `0.0.0.0` in production entry points.

3. **CORS & Cookies:**
   - Use explicit domain whitelists for CORS. Never pair wildcard origins with `credentials: true`.
   - Ensure session cookies use `httpOnly: true`, `secure: true`, and `sameSite: 'lax'` or `'strict'`.

4. **Rate Limiting & Real IP:**
   - Configure `trust proxy` and read client IP via `CF-Connecting-IP` / `X-Forwarded-For`.
   - Enforce rate limits: 5 req/min on login routes, 15 req/min on public write forms, 120 req/min on general GET routes.

5. **Anti-XSS & DOM Hardening:**
   - Avoid `innerHTML` sinks. Default to `.textContent` or sanitized entity encoding.
   - Restrict redirects to validated `http:` and `https:` URLs.

6. **File & Directory Shielding:**
   - Disallow static serving of `.env`, `.db`, `.sqlite`, `.sql`, `.log`, `.sh`, `.bak`, `.yaml`, and `/.git/`.

7. **Secrets Isolation:**
   - Zero hardcoded secrets in source files. All secrets must come from `.env` with a sample `.env.example`.

8. **Security Headers:**
   - Suppress `X-Powered-By`. Apply `helmet` or appropriate security headers (`X-Frame-Options: SAMEORIGIN`, `nosniff`).

9. **Cryptographic Webhook Verification:**
   - Verify webhook signatures using timing-safe comparisons (`crypto.timingSafeEqual`) to prevent CWE-347 and timing attacks.
