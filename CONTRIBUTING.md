# Contributing to GhostPortal

Thank you for your interest in contributing to GhostPortal (Project-Apocalypse).
This project is maintained by Spade and welcomes contributions under the AGPL-3.0 license.

## Ground Rules

- All contributions must be original work or compatible open-source (AGPL-3.0 compatible license)
- Security-related contributions are especially welcome
- Contributors agree their code will be licensed under AGPL-3.0
- No backdoors, telemetry, data collection, or phone-home features will be accepted
- No changes that weaken security defaults

## Reporting Security Vulnerabilities

**Do NOT open public GitHub issues for security vulnerabilities in GhostPortal itself.**

If you discover a security vulnerability in this platform, please practice the same responsible
disclosure that GhostPortal is designed to facilitate.

Contact the maintainer privately. We aim to respond within 72 hours. Researchers will be
credited in release notes unless anonymity is requested.

## What We Welcome

- Bug fixes
- Security hardening improvements
- New vulnerability report templates (add to `seeds/templates.json`)
- Additional AI provider integrations
- Documentation improvements
- Translation / i18n support
- New export formats
- Test coverage improvements

## What We Don't Accept

- Integration with proprietary paid services as hard dependencies
- Changes that weaken security defaults (e.g., disabling CSRF, weakening CSP)
- Backdoors, telemetry, or data collection features
- Removal of AGPL-3.0 license headers
- Password-based authentication (this platform is intentionally passwordless)

## Development Setup

```bash
# Clone and set up
git clone https://github.com/0xspade/ghostportal
cd project-apocalypse
cp .env.example .env
# Edit .env with your configuration

# Install dependencies
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run migrations
flask db upgrade

# Seed initial data
python scripts/seed_db.py

# Run tests
pytest tests/ -v
```

## Code Standards

- Follow the existing code style (enforced by `ruff`)
- All Python files must include the AGPL-3.0 license header
- All DB primary keys must be UUID type
- All externally exposed IDs must be UUID v4
- All secret comparisons must use `hmac.compare_digest` — never `==`
- All markdown fields must be sanitized with `bleach.clean()` before storage and render
- No raw SQL strings — SQLAlchemy ORM only
- All auth endpoints must use `constant_time_response()`
- Run `bandit -r app/ -ll` before submitting — fix all high/critical findings

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes following the code standards above
4. Add tests for new functionality
5. Run the full test suite: `pytest tests/ -v`
6. Run the security audit: `bandit -r app/ -ll && pip-audit`
7. Submit a pull request with a clear description of the change and its rationale

## License

By contributing to GhostPortal, you agree that your contributions will be licensed
under the GNU Affero General Public License v3.0 (AGPL-3.0).

See [LICENSE](LICENSE) for the full license text.
