# GhostPortal
**Project-Apocalypse** — Self-Hosted External Bug Bounty Reporting Platform

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![GitHub](https://img.shields.io/badge/GitHub-0xspade%2Fghostportal-181717?logo=github)](https://github.com/0xspade/ghostportal)
[![Project: Project-Apocalypse](https://img.shields.io/badge/project-Project--Apocalypse-red)](https://github.com/0xspade/ghostportal)

> A self-hosted, fully passwordless, UUID-native vulnerability disclosure platform for independent security researchers.

---

## Features

- **Fully Passwordless** — magic link + 20-character alphanumeric OTP (62²⁰ entropy)
- **UUID-first** — all primary keys and external IDs are UUID v4, no sequential integers
- **HUD Admin UI** — dark tactical theme, phosphor green accents, JetBrains Mono/Orbitron fonts
- **Security Team Invites** — per-report invite links with independent sessions, reply threads, expiry tracking
- **Multi-Report Portal** — security team members access all reports they're invited to from one dashboard
- **CVSS 4.0 Calculator** — interactive metric builder with live score and vector string
- **AI-Assisted Reports** — Ollama (self-hosted local LLM), no data sent to cloud APIs
- **Retest Workflow** — security team requests retest after fix, researcher confirms outcome
- **Bounty Tracking** — PayPal Payouts API + manual crypto recording with on-chain confirmation
- **Export** — PDF, JSON, Markdown per-report; AES-256-GCM encrypted full backup ZIP
- **Full Audit Trail** — immutable `AccessLog` and `InviteActivity` for every action
- **Automatic Follow-Ups** — Celery Beat dispatches 30/60/90-day follow-up emails
- **REST API** — Bearer token API for programmatic access (generate/rotate key from Settings)
- **AGPL-3.0** — free to use, not for sale

---

## Architecture

```
Browser → Nginx (TLS) → Gunicorn (Flask) → PostgreSQL 15 + Redis 7
                                         → Celery Worker + Beat
```

---

## Prerequisites

- Python 3.11+, PostgreSQL 15, Redis 7
- Docker + Docker Compose (recommended)
- `libmagic` system library (`apt install libmagic1`)

---

## Quick Start (Docker)

```bash
cp docker/.env.docker.example .env
# Edit .env — set SECRET_KEY, OWNER_EMAIL, POSTGRES_PASSWORD, REDIS_PASSWORD
docker compose up -d
docker compose exec app flask db upgrade
docker compose exec app python scripts/seed_db.py
```

Visit `http://localhost:8000`. Login via magic link sent to `OWNER_EMAIL`.

---

## Manual Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.txt
cp .env.example .env  # edit as needed
flask db upgrade
python scripts/seed_db.py
redis-server &
celery -A celery_worker.celery worker --concurrency=4 &
celery -A celery_worker.celery beat &
gunicorn wsgi:app --bind 0.0.0.0:8000 --workers 4 --worker-class gthread --threads 2
```

---

## Key Configuration (.env)

```env
# Required
OWNER_EMAIL=you@yourdomain.com
SECRET_KEY=                        # secrets.token_hex(64)
DATABASE_URL=postgresql://user:pass@localhost:5432/ghostportal
REDIS_URL=redis://localhost:6379/0

# SMTP (required for magic links)
MAIL_SERVER=smtp.yourdomain.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=ghostportal@yourdomain.com

# hCaptcha (required in production)
HCAPTCHA_SITE_KEY=
HCAPTCHA_SECRET_KEY=

# Notifications (optional)
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# AI (optional — Ollama recommended for self-hosted)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
AI_DEFAULT_PROVIDER=ollama

# API key (optional — can also generate from Settings UI)
API_KEY=                           # secrets.token_urlsafe(48)

# Platform identity
PLATFORM_NAME=GhostPortal
OPERATOR_NAME=
OPERATOR_EMAIL=
OPERATOR_COUNTRY=Philippines
PLATFORM_URL=https://yourdomain.com

# Session
IDLE_TIMEOUT_SECONDS=300
SINGLE_SESSION_ENFORCE=true
PERMANENT_SESSION_LIFETIME=86400

# File uploads
UPLOAD_FOLDER=./uploads
MAX_CONTENT_LENGTH=52428800        # 50MB

# Backup encryption
BACKUP_ENCRYPTION_KEY=             # base64-encoded 32-byte AES key

# Invite settings
INVITE_EXPIRY_DAYS=90
RESOLVED_ACCESS_EXPIRY_DAYS=10    # 10–15
```

See `.env.example` for the full list including PayPal, crypto addresses, and bank transfer details.

---

## Authentication Model

GhostPortal is **fully passwordless**. Login flow:

1. Enter email → hCaptcha → server sends magic link + 20-char OTP to inbox
2. Click link → enter OTP on verification page
3. Both URL token and OTP must match (two-factor within one flow)

Security teams receive invite links. After first-time setup, they log in via the same `/login` page — the system detects their role and routes them to the portal.

---

## REST API

All endpoints require `Authorization: Bearer <key>`. Generate or rotate your API key from **Settings → API Key**.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/reports` | List reports (excludes drafts; filter by `status`, `severity`) |
| POST | `/api/v1/reports` | Create draft report |
| GET | `/api/v1/reports/<uuid>` | Full report detail |
| POST | `/api/v1/reports/<uuid>/submit` | Submit a draft report |
| GET | `/api/v1/programs` | List program names |
| GET | `/api/v1/security-teams` | List security team invites (filter by `report_id`) |
| GET | `/api/v1/templates` | List report templates |
| POST | `/api/v1/templates` | Create report template |
| GET | `/api/v1/stats` | Dashboard statistics |

Rate limits: 100 req/hr for GET, 20 req/hr for POST. All responses include `X-Request-ID`.

**Examples:**

List reports:
```bash
curl -H "Authorization: Bearer <key>" https://yourdomain.com/api/v1/reports
```

Create a draft report:
```bash
curl -X POST https://yourdomain.com/api/v1/reports \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Reflected XSS in search parameter",
    "severity": "high",
    "description": "The `q` parameter on `/search` reflects unsanitized input into the DOM.",
    "steps_to_reproduce": "1. Navigate to /search?q=<script>alert(1)</script>\n2. Observe alert fires.",
    "impact_statement": "Allows arbitrary JavaScript execution in victim browsers.",
    "target_asset": "https://example.com/search",
    "program_name": "Example Corp",
    "tags": ["XSS", "Web App"]
  }'
```

Submit a draft report (moves status from `draft` → `submitted`):
```bash
curl -X POST https://yourdomain.com/api/v1/reports/<uuid>/submit \
  -H "Authorization: Bearer <key>"
```

Create a report template:
```bash
curl -X POST https://yourdomain.com/api/v1/templates \
  -H "Authorization: Bearer <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Stored XSS via Comment Field",
    "category": "web",
    "severity": "high",
    "cwe_id": 79,
    "cwe_name": "Improper Neutralization of Input During Web Page Generation",
    "title_template": "Stored XSS in [field] on [endpoint]",
    "description_template": "A stored cross-site scripting vulnerability exists in the [field] parameter.",
    "steps_template": "1. Navigate to [endpoint]\n2. Submit payload: <script>alert(document.cookie)</script>\n3. Observe execution on page load.",
    "remediation_template": "Encode all user-supplied output using context-appropriate escaping.",
    "tags": ["XSS", "Stored", "Web App"]
  }'
```

---

## Backup & Restore

**Backup**: Settings → Backup & Restore → Download Encrypted Backup (AES-256-GCM ZIP)

**Restore**: Upload ZIP → enter encryption key → confirm import

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Magic link not arriving | Check SMTP config, test via Settings → Send Test Email |
| Celery tasks not running | Ensure Redis is running and `REDIS_URL` is correct |
| `flask db upgrade` fails | Check `DATABASE_URL`, ensure PostgreSQL is running |
| hCaptcha bypass in dev | Set `HCAPTCHA_SECRET_KEY=0x0000000000000000000000000000000000000000` |
| PDF export broken | Install WeasyPrint system deps (`apt install libpango-1.0-0 libpangoft2-1.0-0`) |
| Delete report 500 error | Run `flask db upgrade` to create the `report_versions` table |

---

## Security Disclosure

Contact the operator via `OPERATOR_EMAIL`. Response target: 72 hours. Researchers credited in release notes unless anonymity is requested.

---

## License

GhostPortal is released under **AGPL-3.0**. Free to use, modify, and distribute — modifications must share source under the same license. Not for sale as a proprietary product.

See [LICENSE](LICENSE) for the full text.

---

## Support

GhostPortal is free and open source under AGPL-3.0. If it saves you time or you find it useful, a small donation is appreciated but never expected.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/robotstxt)

**PayPal**: https://paypal.me/robotstxt

---

## Credits

Built by **Spade** as part of **Project-Apocalypse**.

Third-party libraries used retain their original licenses. See `requirements.txt` and the `/licenses/` directory.
