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
HTTP security headers — defense-in-depth at the app layer.

Primary security headers (CSP, HSTS, etc.) are set by nginx in production.
These app-level headers serve as a fallback for development environments
and as defense-in-depth if nginx is misconfigured.

Manages:
  - Core security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Cache-Control / Pragma / Expires  (route-specific caching)
  - X-Request-ID                      (per-request log correlation)
"""

import uuid

from flask import Response, request


# Default CSP — restrictive baseline
_DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "base-uri 'self'; "
    "upgrade-insecure-requests; "
    "block-all-mixed-content"
)

# Zero-JS CSP for external link interstitial
_INTERSTITIAL_CSP = (
    "default-src 'self'; "
    "script-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)


def apply_security_headers(response: Response) -> Response:
    """
    Apply HTTP security headers to every response.
    Called from the after_request hook in app/__init__.py.
    """
    # Per-request correlation ID for log tracing
    response.headers.setdefault("X-Request-ID", str(uuid.uuid4()))

    # --- Core security headers (defense-in-depth, nginx also sets these) ---
    # CSP is intentionally NOT set here — HUD Admin uses inline scripts/fonts
    # that conflict with strict CSP. nginx sets CSP in production.
    response.headers.setdefault(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    response.headers.setdefault("X-XSS-Protection", "0")
    response.headers.setdefault("X-DNS-Prefetch-Control", "off")
    response.headers.setdefault("X-Download-Options", "noopen")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), accelerometer=(), "
        "gyroscope=(), magnetometer=(), payment=(), usb=(), interest-cohort=()"
    )

    # Cache control
    if _is_authenticated_route():
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    elif _is_static_asset():
        response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"

    return response


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_authenticated_route() -> bool:
    path = request.path
    authenticated_prefixes = (
        "/dashboard",
        "/reports",
        "/portal",
        "/templates",
        "/security-teams",
        "/settings",
        "/ai/",
        "/api/programs",
        "/attachments",
        "/auth/verify",
    )
    return any(path.startswith(p) for p in authenticated_prefixes)


def _is_static_asset() -> bool:
    return request.path.startswith("/static/")
