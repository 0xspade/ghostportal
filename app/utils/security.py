# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Core security utilities.

- generate_otp(): cryptographically secure alphanumeric OTP
- hash_token(): SHA3-256 hex digest for token storage
- constant_time_response(): pad auth endpoint response times
- safe_token_compare(): constant-time comparison via hmac.compare_digest

NEVER store raw tokens. NEVER use == for secret comparison.
"""

import hashlib
import hmac
import ipaddress
import secrets
import string
import time
from typing import Optional

# OTP alphabet: A-Z + a-z + 0-9 = 62 characters
# 62^20 ≈ 7 × 10^35 possible codes — vastly more entropy than 6-digit OTP
OTP_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits

# Minimum response time for auth endpoints (milliseconds)
MIN_AUTH_RESPONSE_MS = 800


def generate_otp(length: int = 20) -> str:
    """
    Generate a cryptographically secure alphanumeric OTP.

    Uses secrets.choice() for each character — no modulo bias.
    Default length 20 gives 62^20 ≈ 7 × 10^35 possible codes.

    Args:
        length: OTP length. Must be between 16 and 32 (validated at call site).

    Returns:
        OTP string of the given length using A-Z, a-z, 0-9 charset.
    """
    if length < 16 or length > 32:
        raise ValueError(f"OTP length must be 16–32, got {length}")
    return "".join(secrets.choice(OTP_ALPHABET) for _ in range(length))


def hash_token(raw: str) -> str:
    """
    SHA3-256 hex digest of a raw token string.

    Used for all token storage — url_token, otp, invite token, session token.
    Raw tokens are NEVER stored in the database or logs.

    Args:
        raw: Raw token string (URL-safe base64, alphanumeric OTP, etc.)

    Returns:
        64-character hex string (SHA3-256 digest).
    """
    return hashlib.sha3_256(raw.encode("utf-8")).hexdigest()


def hash_email_for_log(email: str) -> str:
    """
    SHA-256 hex digest of a normalized email address.

    Used in AccessLog to avoid storing plaintext emails.

    Args:
        email: Email address string.

    Returns:
        64-character hex string.
    """
    normalized = email.strip().lower().encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def safe_token_compare(token_a: str, token_b: str) -> bool:
    """
    Constant-time comparison of two token strings via hmac.compare_digest.

    ALWAYS use this instead of == for any secret comparison.
    Both inputs are hashed before comparison to normalize length.

    Args:
        token_a: First token string.
        token_b: Second token string.

    Returns:
        True if tokens are equal, False otherwise.
    """
    # Hash both sides to ensure equal-length comparison
    digest_a = hashlib.sha3_256(token_a.encode("utf-8")).digest()
    digest_b = hashlib.sha3_256(token_b.encode("utf-8")).digest()
    return hmac.compare_digest(digest_a, digest_b)


def compare_hash_digest(submitted_raw: str, stored_hash: str) -> bool:
    """
    Constant-time comparison: SHA3-256(submitted_raw) vs stored_hash.

    Use this to verify a submitted token against its stored hash.

    Args:
        submitted_raw: The raw token submitted by the user.
        stored_hash: The SHA3-256 hex digest stored in the database.

    Returns:
        True if the raw token matches the stored hash.
    """
    computed_hash = hashlib.sha3_256(submitted_raw.encode("utf-8")).hexdigest()
    return hmac.compare_digest(
        computed_hash.encode("utf-8"),
        stored_hash.encode("utf-8"),
    )


def compare_api_key(submitted: str, stored_hash: str) -> bool:
    """
    Constant-time comparison for API key Bearer token validation.

    Args:
        submitted: Raw API key from Authorization header.
        stored_hash: SHA3-256 hash stored in SystemConfig.

    Returns:
        True if API key matches.
    """
    return compare_hash_digest(submitted, stored_hash)


def constant_time_response(start_time: float) -> None:
    """
    Pad the current execution time to at least MIN_AUTH_RESPONSE_MS milliseconds.

    Call this at the END of every auth endpoint handler to prevent
    timing-based email enumeration attacks.

    Args:
        start_time: Value from time.monotonic() at the start of the request.
    """
    elapsed_ms = (time.monotonic() - start_time) * 1000
    if elapsed_ms < MIN_AUTH_RESPONSE_MS:
        sleep_s = (MIN_AUTH_RESPONSE_MS - elapsed_ms) / 1000
        time.sleep(sleep_s)


def generate_magic_link_token() -> str:
    """
    Generate a raw magic link URL token.

    Returns:
        URL-safe base64 token (secrets.token_urlsafe(48)).
        This raw value goes in the clickable link URL — NEVER store it.
        Store SHA3-256(raw) in the database instead.
    """
    return secrets.token_urlsafe(48)


def generate_invite_token() -> str:
    """
    Generate a raw invite URL token.

    Same policy as magic link tokens: store the SHA3-256 hash, not the raw value.

    Returns:
        URL-safe base64 token (secrets.token_urlsafe(48)).
    """
    return secrets.token_urlsafe(48)


def generate_session_token() -> str:
    """
    Generate a raw session token.

    Returns:
        URL-safe base64 token (secrets.token_urlsafe(48)).
    """
    return secrets.token_urlsafe(48)


def generate_api_key() -> str:
    """
    Generate a read-only API key.

    Returns:
        URL-safe base64 token (secrets.token_urlsafe(48)).
    """
    return secrets.token_urlsafe(48)


def is_rfc1918_or_reserved(host: str) -> bool:
    """
    Check if a hostname resolves to an RFC1918 or otherwise reserved/private IP range.

    Used for SSRF protection — blocks requests to internal network addresses.

    Checks:
    - RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    - Loopback: 127.0.0.0/8, ::1
    - Link-local: 169.254.0.0/16, fe80::/10
    - IANA special: 0.0.0.0, 100.64.0.0/10 (CGNAT), 198.18.0.0/15
    - Multicast: 224.0.0.0/4
    - Cloud metadata: 169.254.169.254

    Args:
        host: IP address string or hostname (caller must resolve hostname to IP first).

    Returns:
        True if the host is in a reserved/private range (BLOCK), False if safe.
    """
    BLOCKED_NETWORKS = [
        # RFC1918 private ranges
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        # Loopback
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        # Link-local (AWS metadata service lives here)
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fe80::/10"),
        # IANA special-purpose
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
        ipaddress.ip_network("198.18.0.0/15"),   # Benchmarking
        ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
        # Multicast
        ipaddress.ip_network("224.0.0.0/4"),
        # Broadcast
        ipaddress.ip_network("255.255.255.255/32"),
    ]

    try:
        addr = ipaddress.ip_address(host)
        for network in BLOCKED_NETWORKS:
            if addr in network:
                return True
        return False
    except ValueError:
        # Not an IP address — caller should resolve first
        return False


def validate_otp_format(otp: str, expected_length: int = 20) -> bool:
    """
    Validate OTP format (alphanumeric, correct length).
    Client-side validation only — server still does constant-time hash comparison.

    Args:
        otp: OTP string to validate.
        expected_length: Expected OTP length.

    Returns:
        True if format is valid.
    """
    if len(otp) != expected_length:
        return False
    return all(c in OTP_ALPHABET for c in otp)


def verify_hcaptcha(response_token: str, secret_key: str) -> bool:
    """
    Verify hCaptcha response token with the hCaptcha API.

    Uses safe_fetch for SSRF protection (RFC1918 blocking, scheme whitelist, timeout).

    Args:
        response_token: The h-captcha-response from the form submission.
        secret_key: The hCaptcha secret key from config.

    Returns:
        True if verification succeeded.
    """
    from app.utils.safe_fetch import safe_fetch
    try:
        resp = safe_fetch(
            "https://hcaptcha.com/siteverify",
            method="POST",
            data={"secret": secret_key, "response": response_token},
            timeout=(5, 10),
        )
        return bool(resp.json().get("success"))
    except Exception:
        return False
