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
PayPal Payouts API client.

Handles:
- OAuth2 token acquisition
- Payout initiation via PayPal Payouts API v1
- Payout status polling
- Webhook signature verification

SECURITY:
- PayPal Client Secret NEVER logged, NEVER in HTTP responses
- All API calls go through this helper (never inline in routes)
- Webhook signature validated on EVERY webhook request
- Idempotency: check existing transaction_id before processing
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from app.utils.safe_fetch import safe_fetch

logger = logging.getLogger(__name__)

# PayPal API base URLs
PAYPAL_LIVE_BASE = "https://api-m.paypal.com"
PAYPAL_SANDBOX_BASE = "https://api-m.sandbox.paypal.com"

# Token cache (in-process — not shared across workers, but reduces API calls)
_token_cache: dict[str, Any] = {"token": None, "expires_at": 0}


def get_paypal_base_url(mode: str = "sandbox") -> str:
    """Get PayPal API base URL for the configured mode."""
    return PAYPAL_LIVE_BASE if mode == "live" else PAYPAL_SANDBOX_BASE


def get_access_token(client_id: str, client_secret: str, mode: str = "sandbox") -> str:
    """
    Get a PayPal OAuth2 access token.

    Tokens are cached in-process until 60 seconds before expiry.

    Args:
        client_id: PayPal application client ID.
        client_secret: PayPal application client secret. NEVER log this.
        mode: "live" or "sandbox".

    Returns:
        OAuth2 access token string.

    Raises:
        RuntimeError: If token acquisition fails.
    """
    global _token_cache

    # Return cached token if still valid
    if _token_cache["token"] and time.time() < _token_cache["expires_at"]:
        return _token_cache["token"]

    base_url = get_paypal_base_url(mode)
    url = f"{base_url}/v1/oauth2/token"

    try:
        response = safe_fetch(
            url,
            method="POST",
            auth=(client_id, client_secret),
            data={"grant_type": "client_credentials"},
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()

        token = data["access_token"]
        expires_in = data.get("expires_in", 32400)

        _token_cache = {
            "token": token,
            "expires_at": time.time() + expires_in - 60,
        }

        logger.info("PayPal access token acquired")
        return token

    except Exception as exc:
        # Never log the client_secret — only log safe info
        logger.error(f"PayPal OAuth2 token acquisition failed: {exc}")
        raise RuntimeError(f"PayPal authentication failed") from exc


def initiate_payout(
    client_id: str,
    client_secret: str,
    payment_id: str,
    recipient_email: str,
    amount: str,
    currency: str,
    display_id: str,
    report_title_safe: str,
    mode: str = "sandbox",
) -> dict:
    """
    Initiate a PayPal payout.

    Args:
        client_id: PayPal application client ID.
        client_secret: PayPal client secret. NEVER log this value.
        payment_id: BountyPayment UUID (used as sender_batch_id and sender_item_id).
        recipient_email: Recipient's PayPal email address.
        amount: Payment amount as string (e.g., "500.00").
        currency: ISO currency code (e.g., "USD").
        display_id: Report display ID for email subject (e.g., "GP-2025-0042").
        report_title_safe: Sanitized report title for the payout note.
        mode: "live" or "sandbox".

    Returns:
        Dict with batch_id, item_id, status.

    Raises:
        RuntimeError: If payout initiation fails.
    """
    token = get_access_token(client_id, client_secret, mode)
    base_url = get_paypal_base_url(mode)
    url = f"{base_url}/v1/payments/payouts"

    payload = {
        "sender_batch_header": {
            "sender_batch_id": str(payment_id),
            "email_subject": f"GhostPortal Bug Bounty Payment — {display_id}",
            "email_message": f"Payment for vulnerability report {display_id}",
        },
        "items": [
            {
                "recipient_type": "EMAIL",
                "amount": {
                    "value": str(amount),
                    "currency": currency.upper(),
                },
                "receiver": recipient_email,
                "sender_item_id": str(payment_id),
                "note": f"Bug bounty: {report_title_safe[:100]}",
            }
        ],
    }

    try:
        response = safe_fetch(
            url,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        response.raise_for_status()
        data = response.json()

        batch_header = data.get("batch_header", {})
        batch_id = batch_header.get("payout_batch_id", "")

        logger.info(f"PayPal payout initiated: batch_id={batch_id}")

        return {
            "batch_id": batch_id,
            "status": batch_header.get("batch_status", "PENDING"),
        }

    except Exception as exc:
        logger.error(f"PayPal payout initiation failed: {exc}")
        raise RuntimeError(f"PayPal payout failed") from exc


def get_payout_item_status(
    client_id: str,
    client_secret: str,
    payout_item_id: str,
    mode: str = "sandbox",
) -> dict:
    """
    Get the status of a PayPal payout item.

    Args:
        client_id: PayPal application client ID.
        client_secret: PayPal client secret.
        payout_item_id: PayPal payout item ID.
        mode: "live" or "sandbox".

    Returns:
        Dict with transaction_id, status, amount, currency.
    """
    token = get_access_token(client_id, client_secret, mode)
    base_url = get_paypal_base_url(mode)
    url = f"{base_url}/v1/payments/payouts-item/{payout_item_id}"

    try:
        response = safe_fetch(
            url,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        data = response.json()

        return {
            "status": data.get("transaction_status", "PENDING"),
            "transaction_id": data.get("transaction_id", ""),
            "payout_item_id": data.get("payout_item_id", ""),
        }

    except Exception as exc:
        logger.error(f"PayPal payout status check failed: {exc}")
        raise RuntimeError(f"PayPal status check failed") from exc


def verify_webhook_signature(
    transmission_id: str,
    timestamp: str,
    webhook_id: str,
    event_body: bytes,
    cert_url: str,
    actual_sig: str,
    auth_algo: str,
) -> bool:
    """
    Verify a PayPal webhook signature.

    The signature is computed as:
    CRC32(webhook_id) + "|" + transmission_id + "|" + timestamp + "|" + CRC32(event_body)

    Then verified against the signature in the header using the PayPal cert.

    Args:
        transmission_id: PayPal-Transmission-Id header value.
        timestamp: PayPal-Transmission-Time header value.
        webhook_id: Configured PAYPAL_WEBHOOK_ID.
        event_body: Raw request body bytes.
        cert_url: PayPal-Cert-Url header value.
        actual_sig: PayPal-Transmission-Sig header value.
        auth_algo: PayPal-Auth-Algo header value.

    Returns:
        True if signature is valid.
    """
    try:
        import binascii
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        import base64

        # Validate cert URL is from PayPal's domain
        from urllib.parse import urlparse
        cert_parsed = urlparse(cert_url)
        if not cert_parsed.hostname or not cert_parsed.hostname.endswith("paypal.com"):
            logger.warning(f"PayPal webhook: suspicious cert URL domain: {cert_parsed.hostname}")
            return False

        # Fetch the PayPal cert (via safe_fetch for SSRF protection)
        cert_response = safe_fetch(cert_url)
        cert_response.raise_for_status()
        cert_data = cert_response.content

        # Build the message to verify
        webhook_id_crc = binascii.crc32(webhook_id.encode()) & 0xFFFFFFFF
        body_crc = binascii.crc32(event_body) & 0xFFFFFFFF
        message = f"{transmission_id}|{timestamp}|{webhook_id}|{body_crc}"

        # Verify signature
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(cert_data)
        public_key = cert.public_key()

        sig_bytes = base64.b64decode(actual_sig)
        public_key.verify(
            sig_bytes,
            message.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        return True

    except Exception as exc:
        logger.warning(f"PayPal webhook signature verification failed: {exc}")
        return False
