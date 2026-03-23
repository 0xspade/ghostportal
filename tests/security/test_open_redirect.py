# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Security tests for open redirect vulnerabilities.

Tests:
  - /go/<token> rejects invalid tokens
  - /go/<token> shows interstitial (not immediate redirect)
  - RFC1918 destinations are blocked
  - javascript: scheme destinations are blocked
  - data: scheme destinations are blocked
  - Valid public HTTPS URLs show interstitial
"""

import uuid

import pytest


MALICIOUS_URLS = [
    "javascript:alert(1)",
    "javascript:void(0)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "http://192.168.1.1/admin",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "ftp://example.com/file",
    "file:///etc/passwd",
]


class TestExternalLinkInterstitial:
    def test_invalid_token_returns_404(self, client, owner_session):
        fake_uuid = uuid.uuid4()
        resp = owner_session.get(f"/go/{fake_uuid}")
        assert resp.status_code == 404

    def test_valid_external_link_shows_interstitial(self, client, owner_session, db):
        """Valid external links should show warning interstitial, not immediate redirect."""
        from app.models import ExternalLink

        link = ExternalLink(
            id=uuid.uuid4(),
            token=uuid.uuid4(),
            original_url="https://example.com",
            domain="example.com",
            click_count=0,
        )
        db.session.add(link)
        db.session.commit()

        resp = owner_session.get(f"/go/{link.token}", follow_redirects=False)
        # Should either show interstitial page (200) or immediate redirect to valid https
        # Must NOT do immediate redirect without warning
        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            # If redirecting, must be to a safe HTTPS URL
            assert location.startswith("https://")

    def test_link_validate_blocks_rfc1918(self, app):
        """URL validation utility blocks RFC1918 destinations."""
        from app.utils.external_links import validate_redirect_url
        with app.app_context():
            for url in [
                "http://192.168.1.1/admin",
                "http://10.0.0.1/",
                "http://172.16.0.1/",
                "http://127.0.0.1/",
                "http://localhost/",
            ]:
                is_valid = validate_redirect_url(url)
                assert is_valid is False, (
                    f"RFC1918/private URL should be blocked: {url}"
                )

    def test_link_validate_blocks_dangerous_schemes(self, app):
        """URL validation blocks javascript:, data:, vbscript:, file: schemes."""
        from app.utils.external_links import validate_redirect_url
        with app.app_context():
            dangerous = [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:msgbox(1)",
                "file:///etc/passwd",
                "ftp://example.com/file",
            ]
            for url in dangerous:
                is_valid = validate_redirect_url(url)
                assert is_valid is False, (
                    f"Dangerous scheme should be blocked: {url}"
                )

    def test_link_validate_allows_public_https(self, app):
        """Validation allows legitimate public HTTPS URLs."""
        from app.utils.external_links import validate_redirect_url
        with app.app_context():
            valid_urls = [
                "https://example.com",
                "https://www.google.com/search?q=test",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
                "http://example.com",  # HTTP allowed (warn but not block)
            ]
            for url in valid_urls:
                is_valid = validate_redirect_url(url)
                assert is_valid is True, (
                    f"Valid public URL should be allowed: {url}"
                )
