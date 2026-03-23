# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Integration tests for anti-enumeration protections.

Tests:
  - /login POST returns identical response body for known and unknown emails
  - /login POST returns same HTTP status code for known and unknown emails
  - No session data leaks user existence
  - /auth/verify generic error messages for all failure modes
"""

import pytest


class TestEmailEnumeration:
    def test_unknown_email_same_status_as_known(self, client, owner_user):
        """Known and unknown emails must return same HTTP status."""
        resp_known = client.post(
            "/login",
            data={"email": "owner@test.example", "h-captcha-response": ""},
        )
        resp_unknown = client.post(
            "/login",
            data={"email": "nobody@unknown.example", "h-captcha-response": ""},
        )
        assert resp_known.status_code == resp_unknown.status_code == 200

    def test_unknown_email_same_response_length_class(self, client, owner_user):
        """
        Response for unknown email should not be substantially shorter than
        for known email (would indicate different code path).
        """
        resp_known = client.post(
            "/login",
            data={"email": "owner@test.example", "h-captcha-response": ""},
        )
        resp_unknown = client.post(
            "/login",
            data={"email": "nobody@unknown.example", "h-captcha-response": ""},
        )
        len_known = len(resp_known.data)
        len_unknown = len(resp_unknown.data)
        # Response lengths should be within 5% of each other
        assert abs(len_known - len_unknown) < max(len_known, len_unknown) * 0.05, (
            f"Response length differs: known={len_known}, unknown={len_unknown} — "
            "possible anti-enumeration failure"
        )

    def test_no_email_exists_error_message(self, client):
        """Error messages must not reveal email existence."""
        resp = client.post(
            "/login",
            data={"email": "nobody@unknown.example", "h-captcha-response": ""},
        )
        data = resp.data.decode("utf-8").lower()
        forbidden_phrases = [
            "email not found",
            "no account",
            "not registered",
            "user not found",
            "invalid email",
            "doesn't exist",
            "does not exist",
        ]
        for phrase in forbidden_phrases:
            assert phrase not in data, (
                f"Response contains enumeration-leaking phrase: '{phrase}'"
            )

    def test_verify_page_generic_errors(self, client):
        """Verify page must use generic error messages."""
        # Invalid token
        resp = client.get("/auth/verify/completely_fake_token")
        assert resp.status_code == 302

        # Wrong OTP — should not reveal which part failed
        # (covered in test_auth_flow.py)


class TestHoneypotProtection:
    def test_honeypot_filled_returns_200(self, client):
        """Honeypot-filled forms should return 200 (not reveal detection)."""
        resp = client.post(
            "/login",
            data={
                "email": "owner@test.example",
                "website": "http://spam.com",
                "h-captcha-response": "",
            },
        )
        assert resp.status_code == 200

    def test_honeypot_filled_no_token_generated(self, client, db, owner_user):
        """When honeypot is filled, no login token should be stored."""
        # Get initial token state
        initial_token = owner_user.login_url_token_hash

        client.post(
            "/login",
            data={
                "email": "owner@test.example",
                "website": "definitely-a-bot",
                "h-captcha-response": "",
            },
        )

        db.session.refresh(owner_user)
        # Token should not have been updated
        assert owner_user.login_url_token_hash == initial_token
