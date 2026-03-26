# GhostPortal
**Project-Apocalypse** — Self-Hosted External Bug Bounty Reporting Platform

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub](https://img.shields.io/badge/GitHub-0xspade%2Fghostportal-181717?logo=github)](https://github.com/0xspade/ghostportal)
[![Project: Project-Apocalypse](https://img.shields.io/badge/project-Project--Apocalypse-red)](https://github.com/0xspade/ghostportal)
[![Security: Spade](https://img.shields.io/badge/security-Spade-green)](https://github.com/0xspade)

> A self-hosted, fully passwordless, UUID-native vulnerability disclosure platform for independent security researchers. Submit reports, invite security teams, track bounties, and maintain a full audit trail — all under your control.

---

## Features

- **Fully Passwordless** — magic link + 20-character alphanumeric OTP (62²⁰ entropy). No passwords, ever.
- **Dual-factor within one flow** — URL token in the link + typed OTP code. Both must match.
- **UUID-first** — all primary keys and external IDs are UUID v4. No sequential integers exposed.
- **HUD Admin UI** — dark tactical theme with phosphor green accents, JetBrains Mono/Orbitron fonts, glassmorphism panels.
- **Security Team Invites** — per-report invite links with independent sessions, reply threads, and expiry tracking.
- **Multi-Report Portal** — security team members can access all reports they're invited to from one dashboard.
- **CVSS 4.0 Calculator** — interactive metric builder with live score computation and vector string.
- **AI-Assisted Reports** — Anthropic Claude, OpenAI, Google Gemini, and Ollama (local) support via async Celery jobs.
- **Retest Workflow** — security team can request a retest after deploying a fix; researcher confirms the outcome (fixed / partial / not fixed). Full activity timeline tracking.
- **Bounty Tracking** — PayPal Payouts API integration + manual crypto payment recording with on-chain confirmation. Bank transfer support.
- **Bonus Bounty Payments** — after a retest is confirmed, security team can submit an additional bonus bounty payment, tracked separately with `is_bonus` flag.
- **Export** — PDF (WeasyPrint), JSON, Markdown per-report; AES-256-GCM encrypted full backup ZIP.
- **Full Audit Trail** — immutable `AccessLog` and `InviteActivity` tables for every action.
- **Automatic Follow-Ups** — Celery Beat dispatches 30/60/90-day follow-up emails, skipped if already replied.
- **Open Redirect Prevention** — all external URLs routed through `/go/<token>` interstitial with 5-second countdown.
- **Field Edit Proposals** — security team can propose corrections to title, severity, CVSS, and CWE; owner accepts or rejects.
- **AGPL-3.0** — free to use, not for sale.

---

## Architecture

```
┌─────────────┐     HTTPS      ┌─────────────┐
│   Browser   │◄──────────────►│    Nginx    │
└─────────────┘                └──────┬──────┘
                                      │ proxy
                               ┌──────▼──────┐
                               │  Gunicorn   │  4 workers, gthread
                               │  (Flask)    │
                               └──────┬──────┘
                    ┌─────────────────┼──────────────┐
              ┌─────▼─────┐   ┌──────▼──────┐  ┌────▼────┐
              │ PostgreSQL│   │    Redis    │  │ Celery  │
              │    15     │   │  (sessions  │  │ Worker  │
              │  (UUIDs)  │   │  + limits)  │  │  + Beat │
              └───────────┘   └─────────────┘  └─────────┘
```

**Blueprints**: `auth`, `dashboard`, `reports`, `portal`, `templates_bp`, `security_teams`, `bounty`, `programs`, `webhooks`, `ai_bp`, `legal`, `api`, `settings`

---

## Prerequisites

- Python 3.11+
- PostgreSQL 15 (or SQLite for local dev)
- Redis 7
- Docker + Docker Compose (recommended for production)
- `libmagic` system library (`apt install libmagic1` / `brew install libmagic`)
- WeasyPrint system dependencies (see [WeasyPrint docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html))

---

## Quick Start (Docker — 3 commands)

```bash
cp docker/.env.docker.example .env
# Edit .env — set SECRET_KEY, OWNER_EMAIL, POSTGRES_PASSWORD, REDIS_PASSWORD at minimum
docker compose up -d
docker compose exec app flask db upgrade && docker compose exec app python scripts/seed_db.py
```

Then visit `http://localhost` (Nginx) or `http://localhost:8000` (direct).

Send yourself a magic link: `POST /login` with your `OWNER_EMAIL`.

---

## Manual Setup

```bash
# 1. Clone and create virtualenv
git clone <repo-url> ghostportal
cd ghostportal
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 2. Install dependencies (pinned with hashes)
pip install --require-hashes -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env — see Configuration Reference below

# 4. Run database migrations
flask db upgrade

# 5. Seed built-in report templates and CWE data
python scripts/seed_db.py

# 6. Start Redis (required for sessions and Celery)
redis-server

# 7. Start Celery worker (required for emails, AI, follow-ups)
celery -A celery_worker.celery worker --concurrency=4 --loglevel=info

# 8. Start Celery Beat (required for scheduled follow-ups)
celery -A celery_worker.celery beat --loglevel=info

# 9. Start the application
gunicorn wsgi:app --bind 0.0.0.0:8000 --workers 4 --worker-class gthread --threads 2
```

---

## Configuration Reference (.env)

```env
# === Owner (Single User) ===
OWNER_EMAIL=you@yourdomain.com          # Required. The only owner account.

# === Flask ===
SECRET_KEY=                             # Required. secrets.token_hex(64) — min 64 chars
FLASK_ENV=production                    # production | development
SESSION_COOKIE_SECURE=true              # Must be true in production (HTTPS required)

# === Database ===
DATABASE_URL=postgresql://user:pass@localhost:5432/ghostportal
# SQLite fallback for local dev: sqlite:///ghostportal_dev.db

# === SMTP ===
MAIL_SERVER=smtp.yourdomain.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=ghostportal@yourdomain.com

# === hCaptcha ===
HCAPTCHA_SITE_KEY=                      # Required in production
HCAPTCHA_SECRET_KEY=                    # Required in production

# === Notifications ===
DISCORD_WEBHOOK_URL=                    # Optional
TELEGRAM_BOT_TOKEN=                     # Optional
TELEGRAM_CHAT_ID=                       # Optional

# === Invite & Follow-Up ===
INVITE_EXPIRY_DAYS=90
INVITE_EXTENSION_DAYS=30
FOLLOWUP_SCHEDULE=30,60,90
BASE_URL=https://yourdomain.com

# === File Uploads ===
UPLOAD_FOLDER=./uploads
MAX_CONTENT_LENGTH=52428800             # 50MB
ALLOWED_EXTENSIONS=png,jpg,jpeg,gif,mp4,mov,webm,pdf,txt,log

# === Backup Encryption ===
BACKUP_ENCRYPTION_KEY=                  # Required in production. 32-byte AES key, base64-encoded
                                        # Generate: python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"

# === Redis / Celery ===
REDIS_URL=redis://localhost:6379/0

# === Rate Limiting ===
RATELIMIT_DEFAULT=100 per hour
LOGIN_RATELIMIT=5 per 15 minutes

# === AI Providers (configure at least one) ===
AI_DEFAULT_PROVIDER=anthropic           # anthropic | openai | ollama | gemini

ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-opus-4-5

OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o

GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-pro

OLLAMA_BASE_URL=http://localhost:11434  # Local Ollama instance
OLLAMA_MODEL=llama3.1

# === Read-Only API Key ===
API_KEY=                                # secrets.token_urlsafe(48) — for BountyTracker integration

# === Session Policy ===
IDLE_TIMEOUT_SECONDS=300                # 0 = disabled (not recommended)
SINGLE_SESSION_ENFORCE=true

# === Magic Link OTP ===
MAGIC_LINK_OTP_LENGTH=20                # Min 16, default 20
MAGIC_LINK_EXPIRY_MINUTES=15

# === Security Team Access Expiry ===
RESOLVED_ACCESS_EXPIRY_DAYS=10          # 10–15 days after all reports resolved

# === Platform Identity ===
PLATFORM_NAME=GhostPortal
OPERATOR_NAME=                          # Your legal name or entity
OPERATOR_EMAIL=                         # Public contact email
OPERATOR_COUNTRY=Philippines
PLATFORM_URL=https://yourdomain.com

# === Legal ===
POLICY_VERSION=1.0
POLICY_LAST_UPDATED=2026-01-01

# === PayPal Payouts (owner sends bounties) ===
PAYPAL_CLIENT_ID=
PAYPAL_CLIENT_SECRET=
PAYPAL_MODE=live                        # live | sandbox
PAYPAL_WEBHOOK_ID=
OWNER_PAYPAL_EMAIL=                     # Your PayPal email (shown to security team as payment target)

# === Crypto Payment Addresses (shown to security team in portal) ===
# Leave empty to hide that currency from the portal payment panel.
OWNER_CRYPTO_BTC=                       # Bitcoin (mainnet)
OWNER_CRYPTO_ETH=                       # Ethereum (ERC-20 compatible)
OWNER_CRYPTO_USDT_TRC20=                # USDT on Tron (TRC-20)
OWNER_CRYPTO_USDT_ERC20=                # USDT on Ethereum (ERC-20)
OWNER_CRYPTO_USDC_ERC20=                # USDC on Ethereum (ERC-20)
OWNER_CRYPTO_XMR=                       # Monero
OWNER_CRYPTO_BNB=                       # BNB Smart Chain (BSC)
OWNER_CRYPTO_DOGE=                      # Dogecoin
OWNER_CRYPTO_LTC=                       # Litecoin

# === Bank Transfer Details (shown to security team in portal) ===
# Leave all empty to hide bank transfer option.
OWNER_BANK_ACCOUNT_NAME=
OWNER_BANK_ACCOUNT_NUMBER=
OWNER_BANK_IBAN=
OWNER_BANK_SWIFT=
OWNER_BANK_ROUTING=
OWNER_BANK_NAME=
OWNER_BANK_ADDRESS=
OWNER_BANK_COUNTRY=

# === Blockchain Confirmation (optional, read-only public APIs) ===
CRYPTO_CONFIRM_ENABLED=true
BTC_RPC_URL=https://blockstream.info/api
ETH_RPC_URL=https://eth.llamarpc.com
TRON_API_URL=https://api.trongrid.io
DOGE_API_URL=https://dogechain.info/api/v1
XMR_CHECK_ENABLED=false                 # Monero: no public TX lookup by default

CRYPTO_MIN_CONFIRMATIONS_BTC=3
CRYPTO_MIN_CONFIRMATIONS_ETH=12
CRYPTO_MIN_CONFIRMATIONS_DOGE=6

# === GeoIP (optional) ===
GEOIP_ENABLED=false
GEOIP_DB_PATH=./GeoLite2-Country.mmdb
```

---

## First-Run Checklist

1. **Configure `.env`** — at minimum: `SECRET_KEY`, `OWNER_EMAIL`, `DATABASE_URL`, `REDIS_URL`
2. **Run migrations** — `flask db upgrade`
3. **Seed database** — `python scripts/seed_db.py` (loads 20 built-in templates + CWE data)
4. **Test SMTP** — Settings → SMTP → Test (sends to `OWNER_EMAIL`)
5. **Test AI** — Settings → AI Configuration → Test Generation
6. **Login** — visit `/login`, enter your `OWNER_EMAIL`, click the magic link in your inbox, type the 20-char code
7. **Create first report** — `/reports/new`

---

## Authentication Model

GhostPortal is **fully passwordless**. There are no passwords stored anywhere — not hashed, not encrypted, not at all.

### Magic Link + OTP Flow

```
1. POST /login
   → hCaptcha verified
   → Two independent secrets generated:
       url_token  = secrets.token_urlsafe(48)   → in the clickable link URL
       otp        = 20 random chars (A-Z a-z 0-9) → displayed in email body
   → Both stored as SHA3-256 hashes (raw values never touch the DB)
   → Email sent with both

2. User clicks link → GET /auth/verify/<url_token>
   → URL token hash validated
   → OTP entry page shown (15-minute countdown)

3. User types OTP → POST /auth/verify/<url_token>
   → BOTH hashes validated with hmac.compare_digest()
   → Max 5 attempts before token invalidated
   → On success: session created, token marked used (atomic DB update)
```

**Why 20 characters?** 62²⁰ ≈ 7×10³⁵ possible codes. A 6-digit OTP has 10⁶. GhostPortal OTPs have ~10²⁹× more entropy.

**Security team members** use the same `/login` page after their first portal setup. The system detects their role from their registered email and routes them to the portal dashboard automatically.

---

## Security Architecture

| Layer | Implementation |
|-------|---------------|
| Authentication | Passwordless magic link + OTP (SHA3-256 hashed, single-use, 15-min expiry) |
| CSRF | Flask-WTF on all state-changing forms |
| Bot protection | hCaptcha on `/login` and portal setup |
| Rate limiting | Flask-Limiter + Redis backend |
| Security headers | Flask-Talisman + custom `apply_security_headers()` on every response |
| Content Security Policy | Strict allowlist per-route; violation reporting to `/csp-report` |
| XSS prevention | bleach.clean() on all Markdown before storage AND render |
| SQL injection | SQLAlchemy ORM only — zero raw SQL strings |
| File uploads | python-magic MIME sniff + Pillow re-encode + pypdf validate + quarantine folder |
| Secrets management | All sensitive values env-only; never logged or exposed in responses |
| Open redirect | All external URLs routed through `/go/<token>` with RFC1918 blocking |
| Session security | Regenerated on login; idle timeout; single-session enforcement via Redis |
| Audit trail | Immutable `AccessLog` + `InviteActivity` tables |
| IDs | UUID v4 throughout — no sequential integers in URLs, API responses, or filenames |
| Backup encryption | AES-256-GCM via `cryptography` library |

---

## Report Statuses

| Status | Description |
|--------|-------------|
| `draft` | Created but not yet submitted |
| `submitted` | Submitted to security team |
| `triaged` | Confirmed by security team, queued for remediation |
| `duplicate` | Previously reported issue |
| `informative` | Not a security concern |
| `not_applicable` | Outside scope or not applicable |
| `resolved` | Vulnerability patched/fixed |
| `wont_fix` | Acknowledged but will not be remediated |

---

## Retest Workflow

After a security team marks a report `resolved`, they can request a retest:

1. **Security team** clicks "Request Retest" in the portal — logged as `retest_requested` in the activity timeline.
2. **Researcher (owner)** reviews the fix and confirms via the report detail page, selecting an outcome:
   - `fixed` — vulnerability fully remediated
   - `partial` — partially addressed, further work needed
   - `not_fixed` — fix is insufficient
3. Confirmation is logged as `retest_confirmed` with outcome metadata.
4. If outcome is `fixed`, the security team can optionally submit a **bonus bounty payment** (tracked as `is_bonus=True` on `BountyPayment`).

All retest events appear in the unified discussion thread visible to both parties.

---

## Payment Setup

### PayPal

1. Create a PayPal Business account
2. Go to [developer.paypal.com](https://developer.paypal.com) → My Apps & Credentials
3. Create a new app → copy Client ID and Client Secret
4. Add to `.env`:
   ```env
   PAYPAL_CLIENT_ID=your_client_id
   PAYPAL_CLIENT_SECRET=your_client_secret
   PAYPAL_MODE=live          # or sandbox for testing
   PAYPAL_WEBHOOK_ID=        # from PayPal Developer Dashboard → Webhooks
   OWNER_PAYPAL_EMAIL=you@yourdomain.com
   ```
5. Configure webhook in PayPal Dashboard pointing to `https://yourdomain.com/webhooks/paypal`

### Crypto

GhostPortal does **not** hold or send crypto. The owner sends manually from their own wallet. GhostPortal records the transaction and optionally polls public blockchain APIs for confirmation.

Set the wallet addresses you accept in `.env`:
```env
OWNER_CRYPTO_BTC=bc1q...
OWNER_CRYPTO_ETH=0x...
OWNER_CRYPTO_XMR=4...
```

Only addresses you configure will appear in the security team portal payment panel. Unsupported currencies are hidden automatically.

```env
CRYPTO_CONFIRM_ENABLED=true
BTC_RPC_URL=https://blockstream.info/api
ETH_RPC_URL=https://eth.llamarpc.com
```

Supported: BTC, ETH, USDT (ERC-20/TRC-20), USDC, BNB, DOGE, XMR, LTC

### Bank Transfer

Add your bank details to `.env` (all optional — leave blank to hide):
```env
OWNER_BANK_ACCOUNT_NAME=Your Name
OWNER_BANK_IBAN=GB29NWBK60161331926819
OWNER_BANK_SWIFT=NWBKGB2L
OWNER_BANK_NAME=Your Bank
OWNER_BANK_COUNTRY=GB
```

---

## AI Provider Setup

### Anthropic Claude (recommended)

```env
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-opus-4-5    # or claude-sonnet-4-5, claude-haiku-4-5
AI_DEFAULT_PROVIDER=anthropic
```

Get your API key at [console.anthropic.com](https://console.anthropic.com).

### OpenAI

```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
```

### Google Gemini

```env
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-1.5-pro
```

### Ollama (local, no API key needed)

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.1
ollama serve
```

```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
AI_DEFAULT_PROVIDER=ollama
```

AI generation runs as async Celery jobs. Jobs are polled from the report form. All output is clearly labeled "AI-Generated Draft — Review Before Submit" and fully editable.

---

## Docker Production Deployment

```bash
# 1. Copy and edit environment files
cp .env.example .env
cp docker/.env.docker.example docker/.env

# 2. Generate strong secrets
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(64))"
python -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(48))"
python -c "import base64, os; print('BACKUP_ENCRYPTION_KEY=' + base64.b64encode(os.urandom(32)).decode())"

# 3. Build and start
docker compose build
docker compose up -d

# 4. Run migrations and seed
docker compose exec app flask db upgrade
docker compose exec app python scripts/seed_db.py

# 5. View logs
docker compose logs -f app worker beat
```

**Nginx** is included in the repo at `docker/nginx/ghostportal.conf`. It handles TLS termination (get certs via `certbot`), HSTS, OCSP stapling, and proxies to Gunicorn on `127.0.0.1:8000`.

```bash
# Install certbot and get certs
certbot certonly --nginx -d yourdomain.com
# Then update ghostportal.conf with your domain and restart nginx
```

---

## Backup & Restore

### Create Backup

```bash
# Via UI: Settings → Backup & Restore → Backup Now
# Via CLI:
docker compose exec app python scripts/backup_now.py
```

Output: `ghostportal-backup-<timestamp>.zip` — AES-256-GCM encrypted ZIP containing all reports as JSON + attachment files.

### Restore

```bash
# Via UI: Settings → Backup & Restore → Restore → upload ZIP → enter key → dry-run → confirm
# The dry-run shows exactly what will be imported vs. what already exists before committing.
```

---

## API Reference

The read-only API is for integration with external tools (e.g., BountyTracker).

**Authentication**: `Authorization: Bearer <API_KEY>`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/reports` | List reports (summary only) |
| `GET` | `/api/v1/reports/<uuid>` | Full report JSON |
| `POST` | `/api/v1/reports` | Create draft report |
| `GET` | `/api/v1/stats` | Dashboard analytics JSON |

**Rate limit**: 100 requests per hour per API key (configurable).

**Response format**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "display_id": "GP-2026-0042",
  "title": "Reflected XSS in search parameter",
  "severity": "high",
  "cvss_score": 7.5,
  "status": "triaged",
  "created_at": "2026-03-01T12:00:00Z"
}
```

Note: Security team email addresses are never included in API responses.

---

## Troubleshooting

### SMTP TLS errors

```
Error: STARTTLS extension not supported by server
```

Try `MAIL_USE_TLS=false` and `MAIL_PORT=465` for SSL, or verify your SMTP server supports STARTTLS on port 587.

### Celery not connecting to Redis

```
ERROR/MainProcess] consumer: Cannot connect to redis://localhost:6379/0
```

Ensure Redis is running: `redis-cli ping` should return `PONG`. In Docker, verify the `redis` service is healthy: `docker compose ps`.

### hCaptcha bypass in development

In development (`FLASK_ENV=development`), you can set:
```env
HCAPTCHA_SECRET_KEY=0x0000000000000000000000000000000000000000
HCAPTCHA_SITE_KEY=10000000-ffff-ffff-ffff-000000000001
```
These are hCaptcha's official test keys that always pass.

### WeasyPrint PDF fails

WeasyPrint requires system-level libraries. On Ubuntu/Debian:
```bash
apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
               libffi-dev libjpeg-dev libopenjp2-7-dev
```
On macOS: `brew install pango`

### Magic link not arriving

1. Check spam folder
2. Test SMTP: Settings → SMTP → Test
3. Check Celery worker is running (`docker compose logs worker`)
4. Check the `Notification` table in DB for `status=failed` + `error_message`

### Database migrations fail

```bash
# Reset migration state (dev only — destroys data)
flask db downgrade base
flask db upgrade

# Or stamp current state without running migrations
flask db stamp head
```

### Backup encryption key error

The `BACKUP_ENCRYPTION_KEY` must be a base64-encoded 32-byte value. Generate a fresh key:
```bash
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

---

## Security Disclosure

If you discover a vulnerability in GhostPortal itself, please practice responsible disclosure.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Contact the operator via the email configured in `OPERATOR_EMAIL`. Response target: 72 hours. Researchers will be credited in release notes unless anonymity is requested.

---

## License

GhostPortal is released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

```
Copyright (C) 2026 Spade

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

See [LICENSE](LICENSE) for the full text.

**In plain terms**:
- Use for your own security research
- Modify for your organization (share source)
- Contribute improvements back
- No selling as a proprietary product
- No running modified versions as SaaS without releasing source
- No removing copyright notices

---

## Support

GhostPortal is free and open source under AGPL-3.0. If it saves you time or you find it useful, a small donation is appreciated but never expected.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/robotstxt)

**PayPal**: https://paypal.me/robotstxt

---

## Credits

Built by **Spade** as part of **Project-Apocalypse**.

Third-party libraries used retain their original licenses. See `requirements.txt` and the `/licenses/` directory.
