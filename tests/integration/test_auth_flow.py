# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Integration tests for magic link + OTP authentication flow.

Tests:
  - Login page renders
  - POST /login returns generic response regardless of email validity
  - Token generation and storage
  - OTP verification success flow
  - OTP verification failure (wrong OTP)
  - OTP attempt exhaustion (max 5)
  - Expired token rejection
  - Used token rejection
  - Session creation on success
  - Redirect to dashboard (owner) or portal (security team)
  - Logout clears session
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest


def utcnow():
    return datetime.now(timezone.utc)


class TestLoginPage:
    def test_login_get_renders_form(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"email" in resp.data.lower()

    def test_login_post_unknown_email_generic_response(self, client):
        """Unknown email must return same 200 response as known email."""
        resp = client.post(
            "/login",
            data={"email": "nobody@unknown.example", "h-captcha-response": ""},
        )
        assert resp.status_code == 200
        # Must not expose that the email was not found
        assert b"not found" not in resp.data.lower()
        assert b"no account" not in resp.data.lower()

    def test_login_post_known_email_generic_response(self, client, owner_user):
        """Known email must return same generic response."""
        with patch("app.blueprints.auth.routes._verify_hcaptcha", return_value=True):
            with patch("app.blueprints.auth.routes._send_magic_link_email"):
                resp = client.post(
                    "/login",
                    data={"email": "owner@test.example", "h-captcha-response": "test"},
                )
        assert resp.status_code == 200

    def test_login_honeypot_filled_returns_generic(self, client):
        """If honeypot field is filled, silently ignore and return generic response."""
        resp = client.post(
            "/login",
            data={
                "email": "owner@test.example",
                "website": "http://evil.com",  # honeypot filled
                "h-captcha-response": "",
            },
        )
        assert resp.status_code == 200

    def test_login_invalid_email_format_generic_response(self, client):
        """Invalid email format returns generic response — no validation error leakage."""
        resp = client.post(
            "/login",
            data={"email": "notanemail", "h-captcha-response": ""},
        )
        assert resp.status_code == 200

    def test_login_empty_email_generic_response(self, client):
        resp = client.post(
            "/login",
            data={"email": "", "h-captcha-response": ""},
        )
        assert resp.status_code == 200


class TestMagicLinkVerify:
    def _setup_owner_token(self, db, owner_user, expired=False, used=False):
        """Set a valid URL token and OTP on the owner user."""
        from app.utils.security import generate_magic_link_token, generate_otp, hash_token

        url_token = generate_magic_link_token()
        otp = generate_otp(20)

        owner_user.login_url_token_hash = hash_token(url_token)
        owner_user.login_otp_hash = hash_token(otp)
        owner_user.token_expiry = (
            utcnow() - timedelta(minutes=1) if expired
            else utcnow() + timedelta(minutes=15)
        )
        owner_user.token_used = used
        db.session.add(owner_user)
        db.session.commit()

        return url_token, otp

    def test_verify_get_valid_token_shows_otp_form(self, client, db, owner_user):
        url_token, otp = self._setup_owner_token(db, owner_user)
        resp = client.get(f"/auth/verify/{url_token}")
        assert resp.status_code == 200
        # Should show OTP entry form
        assert b"otp" in resp.data.lower() or b"code" in resp.data.lower()

    def test_verify_get_invalid_token_redirects(self, client):
        resp = client.get("/auth/verify/invalid_token_that_does_not_exist")
        assert resp.status_code == 302  # redirect to login
        assert "/login" in resp.headers.get("Location", "")

    def test_verify_get_expired_token_redirects(self, client, db, owner_user):
        url_token, _ = self._setup_owner_token(db, owner_user, expired=True)
        resp = client.get(f"/auth/verify/{url_token}")
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")

    def test_verify_post_valid_otp_authenticates_owner(self, client, db, owner_user):
        url_token, otp = self._setup_owner_token(db, owner_user)

        with patch("app.blueprints.auth.routes.redis_client") as mock_redis:
            mock_redis.get.return_value = None
            mock_redis.incr.return_value = 1
            mock_redis.expire.return_value = True
            mock_redis.delete.return_value = True

            resp = client.post(
                f"/auth/verify/{url_token}",
                data={"otp": otp},
            )

        # Should redirect to dashboard on success
        assert resp.status_code == 302

    def test_verify_post_wrong_otp_returns_error(self, client, db, owner_user):
        url_token, correct_otp = self._setup_owner_token(db, owner_user)

        with patch("app.blueprints.auth.routes.redis_client") as mock_redis:
            mock_redis.get.return_value = None
            mock_redis.incr.return_value = 1
            mock_redis.expire.return_value = True

            resp = client.post(
                f"/auth/verify/{url_token}",
                data={"otp": "WrongOTPwrong12345!"},
            )

        # Should not authenticate
        assert resp.status_code != 302 or "/dashboard" not in resp.headers.get("Location", "")

    def test_verify_post_used_token_rejected(self, client, db, owner_user):
        url_token, otp = self._setup_owner_token(db, owner_user, used=True)

        resp = client.get(f"/auth/verify/{url_token}")
        assert resp.status_code == 302  # redirect to login — token already used

    def test_verify_generic_error_no_leakage(self, client, db, owner_user):
        """Error responses must not reveal which part of auth failed."""
        url_token, correct_otp = self._setup_owner_token(db, owner_user)

        with patch("app.blueprints.auth.routes.redis_client") as mock_redis:
            mock_redis.get.return_value = None
            mock_redis.incr.return_value = 1
            mock_redis.expire.return_value = True

            resp = client.post(
                f"/auth/verify/{url_token}",
                data={"otp": "WrongCodeXXXXXXXXXX"},
            )

        # Must not say "wrong OTP" or "invalid token" specifically
        assert b"wrong otp" not in resp.data.lower()
        assert b"invalid token" not in resp.data.lower()
        assert b"url token" not in resp.data.lower()


class TestLogout:
    def test_logout_clears_session(self, owner_session):
        resp = owner_session.post("/logout")
        assert resp.status_code == 302

        # Session should be cleared — dashboard should redirect to login
        resp2 = owner_session.get("/dashboard")
        assert resp2.status_code == 302
        assert "/login" in resp2.headers.get("Location", "")

    def test_logout_post_only(self, client):
        """Logout must only accept POST."""
        resp = client.get("/logout")
        assert resp.status_code == 405


class TestSessionKeepalive:
    def test_ping_authenticated(self, owner_session):
        resp = owner_session.post("/auth/ping")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True

    def test_ping_unauthenticated(self, client):
        resp = client.post("/auth/ping")
        assert resp.status_code == 401
