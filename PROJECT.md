---
project_name: "vibe-security-protocol"
author: "Tuan Eka Harefa"
status: "active"
version: "1.0.0"
last_updated: "2026-10-28"
path: "/mnt/New_Volume/tool untuk github"
---

# PROJECT: VIBE CODER WEB SECURITY PROTOCOL

## 1. Tujuan Proyek
Proyek ini dirancang sebagai paket aturan dan standar pengerasan keamanan (*production hardening rulepack*) siap pakai untuk kalangan **"vibe coder"**—pengembang web yang menggunakan AI assistant (Cursor, Claude Code, Windsurf, Copilot, Cline, Antigravity, dll.). 

AI sering menghasilkan kode yang berfungsi cepat namun mengabaikan pertahanan mendalam (*defense-in-depth*), seperti rentan SQL injection, CORS wildcard, cookie sesi terekspos, port publik terbuka, file `.env` bocor, rate limiting absen, dan callback finansial tanpa validasi tanda tangan HMAC. Repositori ini menyediakan berkas aturan universal dan one-liner installer sehingga pengguna cukup menyalin aturan ini dan memerintahkan AI coder mereka untuk mengeksekusi audit serta perbaikan secara otomatis.

## 2. Struktur Berkas & Komponen
```
.
├── .github/
│   └── copilot-instructions.md   # Panduan hardening otomatis untuk GitHub Copilot
├── .cursorrules                  # Aturan otomatis untuk Cursor IDE
├── .gitignore                    # Pengabaian file lokal, log, dan database
├── .windsurfrules                # Aturan otomatis untuk Windsurf IDE / Codeium
├── AGENTS.md                     # Aturan universal multi-agent (Cline, Roo, Antigravity, Aider)
├── CLAUDE.md                     # Aturan otomatis untuk Claude Code / Claude Desktop
├── install.sh                    # Skrip installer one-liner otomatis (curl | bash)
├── LICENSE                       # Lisensi MIT
├── PROJECT.md                    # Dokumentasi multi-agent ini
├── README.md                     # Dokumentasi utama publik untuk GitHub (tata cara pakai, prompt, checklist)
└── WEB_SECURITY_PROTOCOL.md      # Spesifikasi master 9-lapisan proteksi web lengkap
```

## 3. Cakupan 9 Lapisan Keamanan
1. **Layer 1: Network & Port Binding** — Backend hanya listen di `127.0.0.1` (isolasi dari port scanning publik).
2. **Layer 2: Sensitive Files Shielding** — Blokir HTTP ke `.env`, `.db`, `.sqlite`, `.sql`, `.log`, `.git`, `.sh`, `.bak`.
3. **Layer 3: Real IP & Rate Limiting** — Pembacaan IP di balik reverse proxy (`CF-Connecting-IP`) dan kuota limit bertingkat.
4. **Layer 4: Strict CORS & Session Cookie** — Origin whitelist eksplisit dan atribut cookie `httpOnly`, `secure`, `sameSite`.
5. **Layer 5: Anti-SQLi & Anti-XSS** — Wajib parameterized queries/prepared statements dan eliminasi `innerHTML`.
6. **Layer 6: Internal API Guard** — Rute internal `/api/internal/*` wajib dilindungi shared token `X-Internal-Key`.
7. **Layer 7: Secrets Isolation** — Kredensial murni via `.env` / environment variable dengan `chmod 600`.
8. **Layer 8: Security Headers** — Penekanan banner `X-Powered-By` dan penegakan header `X-Frame-Options`, `nosniff`, `HSTS`.
9. **Layer 9: Cryptographic Verification** — Validasi HMAC timing-safe (`timingSafeEqual`) untuk webhook/callback finansial (CWE-347).

## 4. Cara Penggunaan untuk AI Agent Lain
Jika AI Agent lain membuka repositori ini untuk melanjutkan pengembangan atau integrasi:
1. Baca berkas `WEB_SECURITY_PROTOCOL.md` sebagai sumber kebenaran aturan teknis (*single source of truth*).
2. Perbarui seluruh berkas rule editor (`.cursorrules`, `CLAUDE.md`, `.windsurfrules`, `AGENTS.md`, `copilot-instructions.md`) secara sinkron jika ada penambahan lapisan keamanan baru.
3. Pastikan `install.sh` tetap ringan, idempotensial, dan dapat dijalankan tanpa dependensi eksternal selain `curl`/`wget`.
