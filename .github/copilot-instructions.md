# GitHub Copilot Instructions: Web Security Standard

When generating code or proposing changes in this repository:
- Always use parameterized queries / prepared statements for SQL (prevent SQL injection).
- Never use innerHTML with dynamic data; use textContent or safe encoding.
- Ensure backend listeners bind to 127.0.0.1 in production.
- Configure CORS with explicit domain whitelists and set cookies to httpOnly, secure, sameSite.
- Protect auth routes with rate limiting and real client IP resolution.
- Keep secrets in .env files and do not hardcode credentials.
- Add standard security headers (X-Frame-Options, X-Content-Type-Options: nosniff).
- Verify webhook cryptographic signatures with timing-safe comparisons.
