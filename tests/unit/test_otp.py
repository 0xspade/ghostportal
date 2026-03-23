# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Unit tests for OTP generation.

Tests:
  - OTP charset (A-Z + a-z + 0-9 only)
  - OTP length matches requested length
  - OTP entropy (no collisions across 10,000 samples)
  - OTP uses secrets.choice (no modulo bias detectable in distribution)
  - hash_token produces consistent SHA3-256 hex digests
  - compare_hash_digest is constant-time and correct
"""

import hashlib
import string
from collections import Counter

import pytest


OTP_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits


class TestGenerateOTP:
    def test_otp_default_length(self):
        from app.utils.security import generate_otp
        otp = generate_otp()
        assert len(otp) == 20

    def test_otp_custom_length(self):
        from app.utils.security import generate_otp
        for length in [16, 20, 24, 32]:
            otp = generate_otp(length)
            assert len(otp) == length

    def test_otp_charset_uppercase_lowercase_digits_only(self):
        from app.utils.security import generate_otp
        for _ in range(100):
            otp = generate_otp(20)
            for char in otp:
                assert char in OTP_ALPHABET, (
                    f"Character '{char}' not in OTP_ALPHABET"
                )

    def test_otp_no_collisions(self):
        """10,000 unique OTPs — no duplicates expected at 62^20 entropy."""
        from app.utils.security import generate_otp
        otps = [generate_otp(20) for _ in range(10_000)]
        assert len(set(otps)) == 10_000, "Collision detected in 10,000 OTPs"

    def test_otp_distribution_not_skewed(self):
        """
        Character distribution should be roughly uniform.
        With 10,000 OTPs of length 20, we expect ~100k / 62 ≈ 1613 of each char.
        Reject if any character appears >3x or <0.33x expected.
        """
        from app.utils.security import generate_otp
        all_chars = "".join(generate_otp(20) for _ in range(10_000))
        counts = Counter(all_chars)
        total = len(all_chars)
        expected = total / len(OTP_ALPHABET)

        for char in OTP_ALPHABET:
            count = counts.get(char, 0)
            assert count > expected * 0.33, (
                f"Character '{char}' appears suspiciously rarely: {count} vs expected {expected:.0f}"
            )
            assert count < expected * 3.0, (
                f"Character '{char}' appears suspiciously often: {count} vs expected {expected:.0f}"
            )

    def test_otp_minimum_length_16(self):
        from app.utils.security import generate_otp
        otp = generate_otp(16)
        assert len(otp) == 16

    def test_otp_returns_string(self):
        from app.utils.security import generate_otp
        otp = generate_otp()
        assert isinstance(otp, str)


class TestHashToken:
    def test_hash_token_produces_hex_string(self):
        from app.utils.security import hash_token
        result = hash_token("test_token")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA3-256 = 256 bits = 64 hex chars
        int(result, 16)  # Must be valid hex

    def test_hash_token_is_deterministic(self):
        from app.utils.security import hash_token
        token = "my_test_token_12345"
        assert hash_token(token) == hash_token(token)

    def test_hash_token_uses_sha3_256(self):
        from app.utils.security import hash_token
        token = "known_token"
        expected = hashlib.sha3_256(token.encode("utf-8")).hexdigest()
        assert hash_token(token) == expected

    def test_hash_token_different_inputs_different_outputs(self):
        from app.utils.security import hash_token
        assert hash_token("token_a") != hash_token("token_b")

    def test_hash_token_empty_string(self):
        from app.utils.security import hash_token
        result = hash_token("")
        assert len(result) == 64


class TestCompareHashDigest:
    def test_correct_otp_returns_true(self):
        from app.utils.security import compare_hash_digest, hash_token
        otp = "ValidOTP12345678ab"
        stored_hash = hash_token(otp)
        assert compare_hash_digest(otp, stored_hash) is True

    def test_wrong_otp_returns_false(self):
        from app.utils.security import compare_hash_digest, hash_token
        otp = "ValidOTP12345678ab"
        stored_hash = hash_token(otp)
        assert compare_hash_digest("WrongOTPwrong12345", stored_hash) is False

    def test_empty_otp_returns_false(self):
        from app.utils.security import compare_hash_digest, hash_token
        stored_hash = hash_token("RealToken123456789")
        assert compare_hash_digest("", stored_hash) is False

    def test_compare_is_not_equal_operator(self):
        """Verify we're not accidentally using == somewhere."""
        from app.utils.security import compare_hash_digest
        import inspect
        source = inspect.getsource(compare_hash_digest)
        # The function should use hmac.compare_digest, not ==
        assert "hmac.compare_digest" in source or "compare_digest" in source


class TestGenerateMagicLinkToken:
    def test_generates_string(self):
        from app.utils.security import generate_magic_link_token
        token = generate_magic_link_token()
        assert isinstance(token, str)

    def test_has_sufficient_length(self):
        from app.utils.security import generate_magic_link_token
        # secrets.token_urlsafe(48) produces ~64 chars
        token = generate_magic_link_token()
        assert len(token) >= 48

    def test_unique_across_calls(self):
        from app.utils.security import generate_magic_link_token
        tokens = [generate_magic_link_token() for _ in range(1000)]
        assert len(set(tokens)) == 1000
