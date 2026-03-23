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
Content Security Policy management.

- Per-route CSP directive dicts
- CSP violation report handler
- Nonce injection for inline scripts (where unavoidable)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import current_app, request

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CSP directive dicts (for programmatic use)
# ---------------------------------------------------------------------------

BASE_CSP: dict[str, str | list[str]] = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "font-src": ["'self'", "https://fonts.gstatic.com"],
    "img-src": ["'self'", "data:"],
    "connect-src": "'self'",
    "media-src": "'self'",
    "object-src": "'none'",
    "frame-src": "'none'",
    "frame-ancestors": "'none'",
    "form-action": "'self'",
    "base-uri": "'self'",
    "navigate-to": "'self'",
    "upgrade-insecure-requests": "",
    "block-all-mixed-content": "",
    "report-uri": "/csp-report",
    "report-to": "csp-endpoint",
}

AUTHENTICATED_CSP: dict[str, str | list[str]] = {
    **BASE_CSP,
    "img-src": ["'self'", "data:", "blob:"],
    "media-src": ["'self'", "blob:"],
    "worker-src": ["'self'", "blob:"],
    "navigate-to": ["'self'", "/go/"],
}

INTERSTITIAL_CSP: dict[str, str | list[str]] = {
    "default-src": "'self'",
    "script-src": "'none'",
    "style-src": ["'self'", "'unsafe-inline'"],
    "font-src": "'self'",
    "img-src": "'self'",
    "object-src": "'none'",
    "frame-src": "'none'",
    "frame-ancestors": "'none'",
    "form-action": "'none'",
    "base-uri": "'none'",
    "navigate-to": "*",
    "upgrade-insecure-requests": "",
}

OTP_PAGE_CSP: dict[str, str | list[str]] = {
    **BASE_CSP,
    "navigate-to": "'self'",
}

PUBLIC_PAGE_CSP: dict[str, str | list[str]] = BASE_CSP


# ---------------------------------------------------------------------------
# CSP string builder
# ---------------------------------------------------------------------------

def build_csp_string(directives: dict[str, str | list[str]]) -> str:
    """
    Convert a CSP directive dict to a header-ready string.

    Args:
        directives: Dict mapping directive names to values.
                    Values can be strings or lists of strings.

    Returns:
        CSP header string.
    """
    parts = []
    for directive, value in directives.items():
        if value == "":
            # Flag directive with no value (e.g., upgrade-insecure-requests)
            parts.append(directive)
        elif isinstance(value, list):
            parts.append(f"{directive} {' '.join(value)}")
        else:
            parts.append(f"{directive} {value}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# CSP violation report handler
# ---------------------------------------------------------------------------

def handle_csp_report(req) -> None:
    """
    Process a CSP violation report from the browser.

    Stores violation to application log.
    Future: store to DB for the settings violation log viewer.

    Args:
        req: Flask request object with CSP report JSON body.
    """
    try:
        data = req.get_json(silent=True, force=True)
        if not data:
            return

        report = data.get("csp-report", data)

        violation = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "blocked_uri": report.get("blocked-uri", ""),
            "violated_directive": report.get("violated-directive", ""),
            "effective_directive": report.get("effective-directive", ""),
            "document_uri": report.get("document-uri", ""),
            "disposition": report.get("disposition", ""),
            "source_file": report.get("source-file", ""),
            "line_number": report.get("line-number", ""),
            "original_policy": report.get("original-policy", "")[:200],  # truncate
            "ip": req.remote_addr,
        }

        logger.warning(
            "CSP violation reported",
            extra={"csp_violation": violation},
        )

        # Store to DB for settings viewer — best-effort, never block the response
        try:
            from app.models import CSPViolation
            from app.extensions import db
            db.session.add(CSPViolation(
                blocked_uri=violation["blocked_uri"][:500] if violation["blocked_uri"] else None,
                violated_directive=violation["violated_directive"][:200] if violation["violated_directive"] else None,
                effective_directive=violation["effective_directive"][:200] if violation["effective_directive"] else None,
                original_policy=violation["original_policy"],
                document_uri=violation["document_uri"][:500] if violation["document_uri"] else None,
                disposition=violation["disposition"][:20] if violation["disposition"] else None,
                source_file=violation["source_file"][:500] if violation["source_file"] else None,
                line_number=int(violation["line_number"]) if str(violation["line_number"]).isdigit() else None,
                ip_address=violation["ip"],
                user_agent=req.headers.get("User-Agent", "")[:500],
            ))
            db.session.commit()
        except Exception as db_exc:
            logger.error(f"Failed to store CSP violation to DB: {db_exc}")
            try:
                from app.extensions import db
                db.session.rollback()
            except Exception:
                pass

    except Exception as exc:
        logger.error(f"Failed to process CSP report: {exc}")
