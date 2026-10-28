# VIBE CODER WEB SECURITY PROTOCOL
### 9-Layer Production Hardening Standard for AI-Generated Code

> **For Vibe Coders & AI Agents:** AI builds fast, but frequently omits defense-in-depth measures—leaving database queries vulnerable to SQL injection, CORS wide open (`*`), cookies exposed to JavaScript, and internal ports accessible to the public. 
> 
> **How to use with AI:** Drop this file into your repository and instruct your AI coding agent (Cursor, Claude Code, Windsurf, Copilot, Cline, Antigravity, etc.):
> *"Audit this entire codebase and apply the 9 Hardening Layers from WEB_SECURITY_PROTOCOL.md. Fix all SQL injection vulnerabilities, secure CORS and cookies, add rate limiting, block sensitive file access, and eliminate hardcoded secrets."*

---

## The 9 Hardening Layers

```
  +--------------------------------------------------------------+
  |                   INTERNET / REVERSE PROXY                   |
  +--------------------------------------------------------------+
                                 |
  [ LAYER 1 ] Network Isolation  --> Bind strictly to 127.0.0.1, UFW lockdown
  [ LAYER 2 ] Sensitive Files    --> Block .env, .db, .sqlite, .git, .sh, .bak
  [ LAYER 3 ] Rate Limiting      --> Real IP extraction (CF-Connecting-IP) & quotas
  [ LAYER 4 ] CORS & Cookies     --> Explicit origin whitelist, httpOnly + sameSite
  [ LAYER 5 ] SQLi & XSS Defense --> Parameterized queries, textContent/escapeHtml
  [ LAYER 6 ] Internal API Guard --> Shared secret (X-Internal-Key) for private routes
  [ LAYER 7 ] Secrets Isolation  --> Zero hardcoded keys, environment vars (chmod 600)
  [ LAYER 8 ] Security Headers   --> Helmet, server_tokens off, nosniff, frameguard
  [ LAYER 9 ] Cryptographic Sig  --> HMAC-SHA256 timing-safe comparison (CWE-347)
                                 |
  +--------------------------------------------------------------+
  |                    PROTECTED BACKEND & DB                    |
  +--------------------------------------------------------------+
```

---

### LAYER 1: Network & Port Binding (Localhost Isolation)

**Rule:** All backend servers (Express, FastAPI, Next.js standalone, Django, Flask, Go, PHP-FPM) must bind strictly to `127.0.0.1` in production. Never bind to `0.0.0.0` unless running inside an isolated container with private bridge networking.

- **Vulnerability Prevented:** Direct port scanning bypassing Cloudflare, WAF, or reverse proxy.
- **Node.js / Express:**
  ```javascript
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server bound securely to 127.0.0.1:${PORT}`);
  });
  ```
- **Python / FastAPI / Uvicorn:**
  ```bash
  uvicorn main:app --host 127.0.0.1 --port 8000
  ```
- **Firewall Rule (UFW on Linux):**
  ```bash
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow 22/tcp     # SSH (or custom port)
  sudo ufw allow 80/tcp     # HTTP reverse proxy
  sudo ufw allow 443/tcp    # HTTPS reverse proxy
  sudo ufw enable
  ```

---

### LAYER 2: Sensitive Files & Directory Shielding (Web Server Level)

**Rule:** Ensure public visitors cannot download source code, configuration files, SQLite databases, logs, or Git history. Return `HTTP 403 Forbidden` or `HTTP 404 Not Found`.

- **Extensions to Block:** `.env`, `.env.*`, `.db`, `.sqlite`, `.sqlite3`, `.sql`, `.log`, `.sh`, `.md`, `.bak`, `.conf`, `.yaml`, `.yml`.
- **Hidden Directories:** `/.git/`, `/.env/`, `/.vscode/`, `/.idea/`.
- **Nginx Configuration:**
  ```nginx
  # Block hidden files and directories (.git, .env, etc.)
  location ~ /\.(?!well-known) {
      deny all;
      return 404;
  }

  # Block sensitive file extensions
  location ~* \.(env|db|sqlite|sqlite3|sql|log|sh|md|bak|conf|ya?ml)$ {
      deny all;
      return 404;
  }
  ```
- **Express Static Fallback (if serving static assets without Nginx):**
  ```javascript
  app.use(express.static('public', {
    dotfiles: 'ignore', // Never serve hidden files
    index: ['index.html']
  }));
  ```

---

### LAYER 3: Real IP Extraction & Rate Limiting (Anti-Spam & Anti-Brute Force)

**Rule:** When behind Cloudflare, Cloudflare Tunnel, or Nginx, you must trust the proxy so that rate limiters see the client's actual IP, not `127.0.0.1`. Apply tiered rate limits.

- **Rate Limit Tiers:**
  1. **Auth / Login Endpoints:** Max **5 requests / minute** per IP.
  2. **Public Forms / Orders / Comments:** Max **10–15 requests / minute** per IP.
  3. **General Public GET API:** Max **100–120 requests / minute** per IP.
- **Node.js (Express + express-rate-limit):**
  ```javascript
  const rateLimit = require('express-rate-limit');

  // CRITICAL: Trust reverse proxy (Cloudflare / Nginx)
  app.set('trust proxy', 1);

  const authLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5,
    message: { status: 429, error: 'Too many login attempts. Please wait 1 minute.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.headers['cf-connecting-ip'] || req.ip
  });

  const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  });

  app.use('/api/auth/login', authLimiter);
  app.use('/api/', generalLimiter);
  ```
- **Python (FastAPI + SlowAPI):**
  ```python
  from slowapi import Limiter, _rate_limit_exceeded_handler
  from slowapi.util import get_remote_address
  from slowapi.errors import RateLimitExceeded

  def get_real_ip(request):
      return request.headers.get("cf-connecting-ip") or get_remote_address(request)

  limiter = Limiter(key_func=get_real_ip)
  app.state.limiter = limiter
  app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

  @app.post("/api/auth/login")
  @limiter.limit("5/minute")
  async def login(request: Request):
      ...
  ```

---

### LAYER 4: Strict CORS & Session Cookie Hardening

**Rule:** Never use `origin: true` or `origin: '*'` alongside `credentials: true`. Explicitly whitelist allowed domains. Secure all session cookies.

- **CORS Whitelist Rule:**
  ```javascript
  const cors = require('cors');

  const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://mywebsite.com').split(',');

  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl) only if intended
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Blocked by CORS policy'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
  }));
  ```
- **Session Cookie Attributes:**
  ```javascript
  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,                 // Prevents JavaScript access (XSS mitigation)
      secure: process.env.NODE_ENV === 'production', // Only sent over HTTPS
      sameSite: 'lax',                // Protects against CSRF
      maxAge: 1000 * 60 * 60 * 24    // 24 hours
    }
  }));
  ```

---

### LAYER 5: SQL Injection Prevention & DOM Output Encoding (Anti-SQLi & Anti-XSS)

#### A. Zero Unparameterized SQL (Anti-SQL Injection)
**Rule:** Never concatenate, interpolate, or format raw user input into an SQL query string. Always use prepared statements or parameter binding.

- **Vulnerable Code (NEVER DO THIS):**
  ```javascript
  // DANGEROUS!
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
  db.query(query);
  ```
- **Secure Code (Node.js SQLite / Better-SQLite3 / Postgres / MySQL):**
  ```javascript
  // Better-SQLite3 (Parameterized)
  const stmt = db.prepare('SELECT id, password_hash, role FROM users WHERE email = ?');
  const user = stmt.get(email);

  // PostgreSQL (pg)
  const result = await pool.query(
    'SELECT id, password_hash, role FROM users WHERE email = $1',
    [email]
  );

  // MySQL / MariaDB (mysql2)
  const [rows] = await pool.execute(
    'SELECT id, password_hash, role FROM users WHERE email = ?',
    [email]
  );
  ```
- **Secure Code (Python sqlite3 / psycopg2 / SQLAlchemy):**
  ```python
  # sqlite3
  cursor.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
  
  # psycopg2
  cursor.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
  ```

#### B. Safe DOM Output & Anti-XSS
**Rule:** Never insert unsanitized user inputs or URL query params into `innerHTML`. Use `.textContent` or encode HTML entities.

- **Frontend DOM Safe Practice:**
  ```javascript
  // INSECURE:
  // document.getElementById('username').innerHTML = user.name;

  // SECURE:
  document.getElementById('username').textContent = user.name;

  // If HTML rendering is mandatory, escape all special characters:
  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (m) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[m]);
  }
  ```
- **Safe URL Redirects:**
  ```javascript
  function safeRedirect(targetUrl) {
    try {
      const parsed = new URL(targetUrl, window.location.origin);
      // Only allow http: and https: protocols on same-origin or whitelisted domains
      if (['http:', 'https:'].includes(parsed.protocol)) {
        window.location.href = parsed.href;
      }
    } catch {
      window.location.href = '/';
    }
  }
  ```

---

### LAYER 6: Internal API & Service Authorization Guard

**Rule:** Internal maintenance or private microservice endpoints (`/api/internal/*`, `/admin/ops/*`) must not rely solely on IP checks if traffic passes through Cloudflare Tunnel or local proxies. Require an explicit shared authentication secret.

- **Node.js Middleware:**
  ```javascript
  function requireInternalSecret(req, res, next) {
    const key = req.headers['x-internal-key'] || req.headers['authorization'];
    const expected = process.env.INTERNAL_API_SECRET;

    if (!expected || !key || key !== expected) {
      return res.status(403).json({ error: 'Access denied: unauthorized internal route' });
    }
    next();
  }

  app.use('/api/internal', requireInternalSecret);
  ```

---

### LAYER 7: Zero Hardcoded Secrets & Secrets Isolation

**Rule:** Never commit database passwords, JWT secrets, private keys, or API tokens to Git. Use environment files with restricted file system permissions.

1. **Store credentials in `.env` or systemd environment:**
   ```bash
   chmod 600 .env
   ```
2. **Add `.env` and `.env.*` to `.gitignore` immediately.**
3. **Provide `.env.example` with dummy values:**
   ```bash
   DATABASE_URL=sqlite:///path/to/app.db
   SESSION_SECRET=replace_with_64_char_random_hex
   ALLOWED_ORIGINS=https://yourdomain.com
   INTERNAL_API_SECRET=replace_with_random_token
   PORT=3000
   ```
4. **Generate cryptographically secure secrets via CLI:**
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   # or
   openssl rand -hex 32
   ```

---

### LAYER 8: HTTP Security Headers & Banner Suppression

**Rule:** Remove server signature headers that advertise software and versions (`Server`, `X-Powered-By`). Inject security headers on every HTTP response.

- **Node.js (Helmet + Banner Disable):**
  ```javascript
  const helmet = require('helmet');

  // Disable technology footprint banner
  app.disable('x-powered-by');

  // Apply Helmet with hardened policies
  app.use(helmet({
    frameguard: { action: 'sameorigin' }, // Anti-clickjacking
    noSniff: true,                        // Anti-MIME sniffing
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: { maxAge: 31536000, includeSubDomains: true } // 1 year HSTS
  }));
  ```
- **Nginx Response Headers:**
  ```nginx
  server_tokens off;
  add_header X-Frame-Options "SAMEORIGIN" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  ```

---

### LAYER 9: Cryptographic Verification & Signature Integrity (CWE-347 Defense)

**Rule:** Webhooks from payment gateways, bank mutations, or external integrations must always verify the HMAC cryptographic signature using constant-time comparison before trusting the payload.

- **Vulnerability Prevented:** Spoofed payment status, fake webhook callbacks, timing attacks.
- **Node.js Webhook Signature Verification:**
  ```javascript
  const crypto = require('crypto');

  function verifyWebhookSignature(req, res, next) {
    const signature = req.headers['x-signature'] || req.headers['x-callback-signature'];
    const secret = process.env.WEBHOOK_SECRET;

    if (!signature || !secret) {
      return res.status(401).json({ error: 'Signature missing or unconfigured' });
    }

    // Compute expected HMAC SHA-256 over raw request body
    const expected = crypto
      .createHmac('sha256', secret)
      .update(req.rawBody || JSON.stringify(req.body))
      .digest('hex');

    // Timing-safe comparison to prevent timing side-channel attacks
    const sigBuffer = Buffer.from(signature, 'utf8');
    const expBuffer = Buffer.from(expected, 'utf8');

    if (sigBuffer.length !== expBuffer.length || !crypto.timingSafeEqual(sigBuffer, expBuffer)) {
      return res.status(403).json({ error: 'Invalid cryptographic signature' });
    }

    next();
  }
  ```
- **Double Verification (Query-Back) for Financial Events:**
  Never mark an order as "PAID" based solely on an incoming webhook body. Always trigger a secondary out-of-band GET verification request to the gateway's official transaction status API.

---

## AI Agent Verification Checklist (Run Before Ship)

When your AI agent finishes hardening, demand proof against this checklist:

| # | Protection Check | Status | Verification Method |
|---|---|---|---|
| 1 | Backend bound strictly to `127.0.0.1` | [ ] | Check `listen()` or runner command |
| 2 | `.env`, `.db`, `.git` inaccessible via HTTP | [ ] | Test `curl -I http://localhost:PORT/.env` (expect 404/403) |
| 3 | Reverse proxy trust & rate limiting active | [ ] | Verify `trust proxy` and test quota burst |
| 4 | CORS locked & cookies have `httpOnly; SameSite` | [ ] | Inspect response headers & cookie options |
| 5 | All SQL queries parameterized (Zero string concat) | [ ] | Grep for string interpolation in database calls |
| 6 | No `innerHTML` with unsanitized inputs | [ ] | Grep for `.innerHTML =` across frontend code |
| 7 | Internal endpoints protected by `X-Internal-Key` | [ ] | Request without header (expect 403) |
| 8 | `x-powered-by` disabled & security headers active | [ ] | Inspect `curl -I` headers |
| 9 | Webhooks verify HMAC via `timingSafeEqual` | [ ] | Code review payment/webhook endpoints |
