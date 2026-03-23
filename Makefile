# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0
# Developer convenience Makefile

.PHONY: up down build logs shell migrate seed test lint audit backup \
        install dev-install clean format typecheck

# ── Docker Compose ─────────────────────────────────────────────────────────────

up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build --no-cache

logs:
	docker compose logs -f app worker beat

shell:
	docker compose exec app flask shell

# ── Database ───────────────────────────────────────────────────────────────────

migrate:
	docker compose exec app flask db upgrade

makemigrations:
	docker compose exec app flask db migrate -m "$(MSG)"

seed:
	docker compose exec app python scripts/seed_db.py

# ── Testing ────────────────────────────────────────────────────────────────────

test:
	docker compose exec app pytest tests/ -v --tb=short \
		--cov=app --cov-report=term-missing \
		--cov-fail-under=80

test-auth:
	docker compose exec app pytest tests/integration/test_auth_flow.py -v

test-security:
	docker compose exec app pytest tests/security/ -v

test-unit:
	docker compose exec app pytest tests/unit/ -v

# ── Code Quality ───────────────────────────────────────────────────────────────

lint:
	docker compose exec app ruff check app/ tests/

format:
	docker compose exec app ruff format app/ tests/

typecheck:
	docker compose exec app mypy app/ --ignore-missing-imports

# ── Security Audit ────────────────────────────────────────────────────────────

audit:
	docker compose exec app bash -c "\
		mkdir -p audit && \
		bandit -r app/ -ll -f json -o audit/bandit_report.json && \
		bandit -r app/ -ll && \
		pip-audit --format json -o audit/pip_audit.json && \
		pip-audit && \
		safety check --full-report > audit/safety_report.txt && \
		detect-secrets scan . --all-files > audit/secrets_baseline.json && \
		echo '=== Audit complete. Results in audit/ directory ==='"

bandit:
	docker compose exec app bandit -r app/ -ll

pip-audit:
	docker compose exec app pip-audit

secrets-scan:
	docker compose exec app detect-secrets scan . --all-files

# ── Operations ─────────────────────────────────────────────────────────────────

backup:
	docker compose exec app python scripts/backup_now.py

# ── Local Development (without Docker) ────────────────────────────────────────

install:
	pip install -r requirements.txt

dev-install:
	pip install -r requirements.txt
	pip install ruff mypy bandit pip-audit safety detect-secrets pytest pytest-cov pytest-flask freezegun responses

run:
	FLASK_ENV=development flask --app wsgi:app run --debug

worker-local:
	celery -A celery_worker.celery worker --concurrency=2 --loglevel=debug

beat-local:
	celery -A celery_worker.celery beat --loglevel=debug --schedule=/tmp/celerybeat-schedule

# ── Cleanup ────────────────────────────────────────────────────────────────────

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
	rm -rf htmlcov/ 2>/dev/null || true

# ── Help ───────────────────────────────────────────────────────────────────────

help:
	@echo "GhostPortal — Project-Apocalypse"
	@echo ""
	@echo "Docker targets:"
	@echo "  make up              Start all services"
	@echo "  make down            Stop all services"
	@echo "  make build           Rebuild Docker images"
	@echo "  make logs            Tail app/worker/beat logs"
	@echo "  make shell           Open Flask shell in app container"
	@echo ""
	@echo "Database targets:"
	@echo "  make migrate         Apply pending migrations"
	@echo "  make makemigrations  Create new migration (MSG=<description>)"
	@echo "  make seed            Seed initial data (CWE, templates)"
	@echo ""
	@echo "Test targets:"
	@echo "  make test            Full test suite with coverage"
	@echo "  make test-security   Security tests only"
	@echo "  make test-unit       Unit tests only"
	@echo ""
	@echo "Audit targets:"
	@echo "  make audit           Full security audit (bandit + pip-audit + safety)"
	@echo "  make bandit          SAST scan with bandit"
	@echo "  make pip-audit       CVE scan of dependencies"
	@echo ""
	@echo "Operations:"
	@echo "  make backup          Create encrypted backup archive"
