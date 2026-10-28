# GitHub Copilot Instructions: Web Security Standard

When generating code or proposing changes in this repository, you must enforce the 12-Layer Web Security Protocol:
1. Always use parameterized queries / prepared statements for SQL (prevent SQL injection).
2. Ensure backend listeners bind strictly to 127.0.0.1 in production.
3. Configure CORS with explicit domain whitelists and set cookies to httpOnly, secure, sameSite.
4. Protect auth routes with rate limiting and real client IP resolution (CF-Connecting-IP).
5. Never use innerHTML with dynamic data; use textContent or safe HTML encoding.
6. Block HTTP access to .env, .db, .sqlite, and config files.
7. Keep secrets in .env files and do not hardcode credentials.
8. Add standard security headers (X-Frame-Options, X-Content-Type-Options: nosniff).
9. Verify webhook cryptographic signatures with timing-safe comparisons (Anti-CWE-347).
10. Validate uploaded file magic bytes, rename to random UUIDs, and store outside web roots (Anti-RCE).
11. Guard outbound HTTP clients against SSRF (block 127.0.0.1, RFC 1918 private IPs, 169.254.169.254).
12. Enforce object-level user ownership checks (Anti-IDOR) and use atomic database operations to prevent race conditions.
