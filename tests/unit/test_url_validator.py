# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Unit tests for URL validation (SSRF prevention).

Tests:
  - RFC1918 private address blocking
  - Loopback address blocking
  - Cloud metadata endpoint blocking
  - Valid public URLs allowed
  - Scheme whitelist enforcement
"""

import pytest


class TestRFC1918Blocking:
    def test_blocks_10_network(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("10.0.0.1") is True
        assert is_rfc1918_or_reserved("10.255.255.255") is True
        assert is_rfc1918_or_reserved("10.1.2.3") is True

    def test_blocks_172_16_network(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("172.16.0.1") is True
        assert is_rfc1918_or_reserved("172.31.255.255") is True
        assert is_rfc1918_or_reserved("172.20.5.10") is True

    def test_allows_172_outside_range(self):
        from app.utils.security import is_rfc1918_or_reserved
        # 172.15.x.x and 172.32.x.x are NOT RFC1918
        assert is_rfc1918_or_reserved("172.15.0.1") is False
        assert is_rfc1918_or_reserved("172.32.0.1") is False

    def test_blocks_192_168_network(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("192.168.0.1") is True
        assert is_rfc1918_or_reserved("192.168.255.255") is True

    def test_blocks_loopback(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("127.0.0.1") is True
        assert is_rfc1918_or_reserved("127.255.255.255") is True
        assert is_rfc1918_or_reserved("::1") is True

    def test_blocks_link_local(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("169.254.0.1") is True
        assert is_rfc1918_or_reserved("169.254.169.254") is True  # AWS metadata

    def test_blocks_all_zeros(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("0.0.0.0") is True

    def test_allows_public_ips(self):
        from app.utils.security import is_rfc1918_or_reserved
        assert is_rfc1918_or_reserved("8.8.8.8") is False
        assert is_rfc1918_or_reserved("1.1.1.1") is False
        assert is_rfc1918_or_reserved("93.184.216.34") is False


class TestSafeFetch:
    def test_blocks_localhost_url(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises(SSRFError):
                safe_fetch("http://localhost/admin")

    def test_blocks_127_0_0_1(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises(SSRFError):
                safe_fetch("http://127.0.0.1/")

    def test_blocks_rfc1918(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises(SSRFError):
                safe_fetch("http://192.168.1.1/")

    def test_blocks_aws_metadata(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises(SSRFError):
                safe_fetch("http://169.254.169.254/latest/meta-data/")

    def test_blocks_javascript_scheme(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises((SSRFError, ValueError)):
                safe_fetch("javascript:alert(1)")

    def test_blocks_file_scheme(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises((SSRFError, ValueError)):
                safe_fetch("file:///etc/passwd")

    def test_blocks_ftp_scheme(self, app):
        from app.utils.safe_fetch import safe_fetch, SSRFError
        with app.app_context():
            with pytest.raises((SSRFError, ValueError)):
                safe_fetch("ftp://example.com/file")
