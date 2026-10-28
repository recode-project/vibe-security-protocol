# 🛡️ Vibe Coder Web Security Protocol
### The 12-Layer Production Hardening Standard for AI-Generated Code

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Compatible with Cursor](https://img.shields.io/badge/Cursor-Supported-success.svg)](#)
[![Compatible with Claude Code](https://img.shields.io/badge/Claude%20Code-Supported-orange.svg)](#)
[![Compatible with Windsurf](https://img.shields.io/badge/Windsurf-Supported-purple.svg)](#)
[![Compatible with Copilot](https://img.shields.io/badge/GitHub%20Copilot-Supported-green.svg)](#)

> **For Vibe Coders:** You build features at lightning speed with AI. But AI models frequently ship code with critical security flaws—leaving raw SQL injection, wide-open CORS, exposed `.env` / SQLite database files, missing rate limits, file upload RCE, and SSRF loopholes.
> 
> **The Solution:** Drop this rule pack into your project, paste one prompt to your AI coding agent, and let the AI automatically audit and harden your application across **12 defensive layers**.

---

## ⚡ Quick Start (30 Seconds)

### Option 1: One-Line Installer
Run this inside your project root directory:

```bash
curl -sSL https://raw.githubusercontent.com/recode-project/vibe-security-protocol/main/install.sh | bash
```

### Option 2: Clone or Copy Manually
Clone this repository or copy these files directly into your project root:
- `WEB_SECURITY_PROTOCOL.md` (Master standard)
- `.cursorrules` (For Cursor IDE)
- `CLAUDE.md` (For Claude Code / Claude Desktop)
- `.windsurfrules` (For Windsurf / Codeium)
- `AGENTS.md` (For Antigravity, Cline, Roo Code, Aider, OpenHands)
- `.github/copilot-instructions.md` (For GitHub Copilot)

---

## 🤖 The Magic Prompt (Copy & Paste into Your AI Agent)

Once the files are in your project, open your AI chat (Cursor Composer / Claude Code / Windsurf / Copilot) and send:

```text
Audit this entire codebase and apply the 12 Hardening Layers from WEB_SECURITY_PROTOCOL.md. 

1. Ensure all SQL queries are strictly parameterized (zero string concatenation / zero SQL injection).
2. Bind production backend servers strictly to 127.0.0.1.
3. Lock down CORS to explicit domains and configure cookies with httpOnly: true, secure: true, sameSite: 'lax'.
4. Add rate limiting with trust proxy enabled (CF-Connecting-IP / X-Forwarded-For) on login and public forms.
5. Eliminate innerHTML sinks and sanitize DOM outputs.
6. Block HTTP access to .env, .db, .sqlite, and config files.
7. Verify webhook signatures using timing-safe comparisons (Anti-CWE-347).
8. Secure file upload endpoints with binary magic bytes validation, UUID renames, and private directory storage (Anti-RCE).
9. Guard outbound fetch requests against SSRF (block 127.0.0.1, private IPs, and 169.254.169.254 metadata).
10. Eliminate IDOR by enforcing object-level user ownership checks on all record lookups.
11. Prevent race conditions on balance, coupon, and inventory mutations via atomic database row updates.
12. Provide a summary checklist of all changes made.
```

---

## 🏗️ The 12 Hardening Layers Architecture

```
  +--------------------------------------------------------------+
  |                   INTERNET / REVERSE PROXY                   |
  +--------------------------------------------------------------+
                                 |
  [ LAYER 1  ] Network Isolation   --> Bind strictly to 127.0.0.1, UFW lockdown
  [ LAYER 2  ] Sensitive Files     --> Block .env, .db, .sqlite, .git, .sh, .bak
  [ LAYER 3  ] Rate Limiting       --> Real IP extraction (CF-Connecting-IP) & quotas
  [ LAYER 4  ] CORS & Cookies      --> Explicit origin whitelist, httpOnly + sameSite
  [ LAYER 5  ] SQLi & XSS Defense  --> Parameterized queries, textContent/escapeHtml
  [ LAYER 6  ] Internal API Guard  --> Shared secret (X-Internal-Key) for private routes
  [ LAYER 7  ] Secrets Isolation   --> Zero hardcoded keys, environment vars (chmod 600)
  [ LAYER 8  ] Security Headers    --> Helmet, server_tokens off, nosniff, frameguard
  [ LAYER 9  ] Cryptographic Sig   --> HMAC-SHA256 timing-safe comparison (CWE-347)
  [ LAYER 10 ] Safe File Upload    --> Magic bytes check, UUID renames, storage outside root
  [ LAYER 11 ] Anti-SSRF Defense   --> Private IP / metadata blocking, disable auto-redirect
  [ LAYER 12 ] IDOR & Concurrency  --> Explicit ownership check & ACID atomic row-locks
                                 |
  +--------------------------------------------------------------+
  |                    PROTECTED BACKEND & DB                    |
  +--------------------------------------------------------------+
```

---

## 📋 What the 12 Layers Protect Against

| Layer | Focus Area | Vulnerability Prevented | Core Fix Pattern |
|:---:|---|---|---|
| **1** | **Network & Port** | Direct server port scanning / bypass | Bind listeners exclusively to `127.0.0.1` |
| **2** | **Sensitive Files** | Leaking database, `.env`, or `.git` via URL | Server-level regex block (HTTP 404/403) |
| **3** | **Rate Limiting** | Brute force, credential stuffing, spam | Tiered rate limiter with `CF-Connecting-IP` |
| **4** | **CORS & Cookies** | Cross-Origin data theft & CSRF attacks | Explicit origin whitelist & `httpOnly` cookies |
| **5** | **SQLi & Anti-XSS** | Database takeover & malicious script injection | Parameterized queries + safe DOM encoding |
| **6** | **Internal API** | Unauthorized internal microservice calls | Shared secret header `X-Internal-Key` |
| **7** | **Secrets Isolation**| API keys & passwords leaked in Git | `.env` isolation with `.env.example` |
| **8** | **Security Headers**| Clickjacking, MIME sniffing, tech fingerprinting | Helmet, `server_tokens off`, `nosniff` |
| **9** | **Crypto Signatures**| Spoofed payment callbacks & timing attacks | Timing-safe HMAC verification (`timingSafeEqual`) |
| **10** | **Safe File Upload** | Web shell RCE, double extensions, SVG XSS | Magic bytes detection, UUID renames, private folder |
| **11** | **Anti-SSRF** | Internal network scanning & Cloud metadata theft | Block private IP ranges (`10.0.0.0/8`, `169.254.169.254`) |
| **12** | **IDOR & Race Locks**| Horizontal privilege escalation & double spend | `WHERE user_id = req.user.id` & atomic row operations |

---

## 🎯 Supported Stacks

The rules inside `WEB_SECURITY_PROTOCOL.md` cover implementation patterns for:
- **Node.js**: Express, Fastify, Next.js (API routes / server actions)
- **Python**: FastAPI, Flask, Django
- **PHP**: Modern PHP, Laravel
- **Databases**: SQLite (Better-SQLite3 / sqlite3), PostgreSQL (pg / psycopg2 / Prisma), MySQL / MariaDB (mysql2)
- **Reverse Proxies**: Nginx, Cloudflare Tunnels, Caddy

---

## 🛡️ Self-Audit Verification Checklist

After your AI agent finishes applying the protocol, verify each checkpoint:

- [ ] **1. Port Binding:** Backend `listen()` binds to `127.0.0.1`.
- [ ] **2. File Shielding:** `curl -I http://localhost:PORT/.env` returns `404 Not Found`.
- [ ] **3. Rate Limiting:** Exceeding 5 requests to `/api/auth/login` returns `429 Too Many Requests`.
- [ ] **4. Cookies & CORS:** Session cookie includes `HttpOnly; Secure; SameSite=Lax`.
- [ ] **5. Zero SQL Injection:** Every SQL query uses `?` or `$1` placeholders (zero string interpolation).
- [ ] **6. DOM Safety:** No raw `innerHTML` with user variables.
- [ ] **7. Secrets Hygiene:** Git history has zero hardcoded keys; `.env` is listed in `.gitignore`.
- [ ] **8. Clean Headers:** Response headers contain no `X-Powered-By: Express` or PHP banners.
- [ ] **9. Webhook Integrity:** Webhooks use `crypto.timingSafeEqual` for signature comparisons.
- [ ] **10. File Upload Safety:** Uploaded files validated via magic bytes and renamed with random UUIDs.
- [ ] **11. SSRF Defense:** Outbound HTTP client blocks loopback, private RFC 1918 IPs, and cloud metadata.
- [ ] **12. IDOR & Race Locks:** Record lookups bind `user_id` and balance mutations use atomic operations.

---

## 📄 License

MIT License. Free to use, adapt, and share in your own commercial or open-source projects.
