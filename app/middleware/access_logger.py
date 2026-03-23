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
Access logging middleware.

Writes an AccessLog entry for every authenticated request.
Also provides the log_access_event() helper for explicit event logging
from route handlers (login_success, login_failed, etc.).

Privacy:
- Email addresses stored as SHA-256 hashes only
- path field strips query strings (no sensitive params in logs)
- user_ref stored as string UUID (no FK — log survives account deletion)
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, session, request, g

logger = logging.getLogger(__name__)

# Paths that don't need AccessLog entries (static, health, CSP report)
LOG_EXCLUDED_PATHS = {
    "/health",
    "/static/",
    "/csp-report",
    "/favicon.ico",
}

# Paths that DO need explicit logging (auth events)
AUTH_PATHS = {"/login", "/auth/verify", "/logout", "/auth/ping"}

# Paths requiring authenticated session log
AUTHENTICATED_PREFIXES = (
    "/dashboard",
    "/reports",
    "/portal",
    "/templates",
    "/security-teams",
    "/settings",
    "/ai/",
    "/attachments",
    "/api/programs",
)


def register_access_logger(app: Flask) -> None:
    """
    Register access logger as an after_request hook.

    Args:
        app: Flask application instance.
    """
    @app.after_request
    def log_access(response):
        """Write AccessLog entry for authenticated requests."""
        path = request.path

        # Skip excluded paths
        if any(path.startswith(p) for p in LOG_EXCLUDED_PATHS):
            return response

        # Only log authenticated requests and auth events
        role = session.get("role") or session.get("portal_role")
        is_auth_event = path in AUTH_PATHS or path.startswith("/auth/")

        if not role and not is_auth_event:
            return response

        try:
            _write_access_log(response.status_code)
        except Exception as exc:
            # Access log failure must NEVER block the response
            logger.error(f"AccessLog write failed: {exc}", exc_info=False)

        return response


def _write_access_log(response_code: int, event_type: Optional[str] = None) -> None:
    """
    Write a single AccessLog entry.

    Args:
        response_code: HTTP response status code.
        event_type: Override event type (uses g.access_event_type if not set).
    """
    from app.models import AccessLog
    from app.extensions import db
    from app.utils.ua_parser import parse_user_agent
    from app.utils.geoip import lookup_country

    role = session.get("role") or session.get("portal_role")
    user_ref = (session.get("user_id") or session.get("portal_member_id")
                or session.get("member_id"))
    session_id = session.get("session_id") or session.get("portal_session_id")

    # Determine event type
    evt_type = event_type or getattr(g, "access_event_type", None)
    if not evt_type:
        evt_type = _infer_event_type(request.path, request.method, response_code)

    # Get real IP (behind reverse proxy)
    ip = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )

    ua_string = request.user_agent.string
    parsed_ua = parse_user_agent(ua_string)

    # GeoIP lookup (optional)
    country = lookup_country(ip)

    # Strip query string from path (avoid logging sensitive params)
    clean_path = request.path[:2000]

    try:
        log_entry = AccessLog(
            user_type=role or "owner",
            user_ref=str(user_ref) if user_ref else None,
            session_id=str(session_id) if session_id else None,
            ip_address=ip[:45],
            ip_country=country,
            user_agent=ua_string[:1000] if ua_string else None,
            ua_browser=parsed_ua.browser[:100],
            ua_os=parsed_ua.os[:100],
            ua_is_bot=parsed_ua.is_bot,
            method=request.method[:10],
            path=clean_path,
            response_code=response_code,
            event_type=evt_type,
            metadata_=getattr(g, "access_metadata", None),
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"AccessLog DB write failed: {exc}")


def log_access_event(
    user,
    event_type: str,
    response_code: int = 200,
    metadata: Optional[dict] = None,
) -> None:
    """
    Explicitly log an access event (called from route handlers).

    Use for auth events: login_success, login_failed, logout, etc.

    Args:
        user: User or SecurityTeamMember model object (or None for unknown).
        event_type: Event type string from AccessLog.event_type enum.
        response_code: HTTP response code to log.
        metadata: Optional dict of event-specific metadata.
    """
    from app.models import AccessLog
    from app.extensions import db
    from app.utils.ua_parser import parse_user_agent
    from app.utils.geoip import lookup_country

    ip = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )

    ua_string = request.user_agent.string
    parsed_ua = parse_user_agent(ua_string)
    country = lookup_country(ip)

    # Determine user type
    user_type = "owner"
    user_ref = None
    if user is not None:
        from app.models import SecurityTeamMember
        user_type = "security_team" if isinstance(user, SecurityTeamMember) else "owner"
        user_ref = str(user.id)

    try:
        log_entry = AccessLog(
            user_type=user_type,
            user_ref=user_ref,
            session_id=str(session.get("session_id") or session.get("portal_session_id") or "") or None,
            ip_address=ip[:45],
            ip_country=country,
            user_agent=ua_string[:1000] if ua_string else None,
            ua_browser=parsed_ua.browser[:100],
            ua_os=parsed_ua.os[:100],
            ua_is_bot=parsed_ua.is_bot,
            method=request.method[:10],
            path=request.path[:2000],
            response_code=response_code,
            event_type=event_type,
            metadata_=metadata,
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Explicit AccessLog write failed: {exc}")


def _infer_event_type(path: str, method: str, response_code: int) -> str:
    """
    Infer event type from request context.

    Args:
        path: Request path.
        method: HTTP method.
        response_code: Response status code.

    Returns:
        Event type string.
    """
    if "/login" in path:
        if response_code < 400:
            return "login_success"
        return "login_failed"
    elif "/logout" in path:
        return "logout"
    elif "/reports/" in path and "/export" in path:
        return "export_generated"
    elif "/reports/" in path and method == "GET":
        return "report_viewed"
    elif "/reports/" in path and method == "POST":
        return "report_edited"
    elif "/invite" in path:
        return "invite_sent"
    elif "/portal" in path:
        return "portal_accessed"
    elif "/attachments/" in path:
        return "file_downloaded"
    elif "/settings" in path:
        return "settings_changed"
    elif "/api/" in path:
        return "api_access"
    elif response_code == 429:
        return "rate_limit_hit"
    else:
        return "portal_accessed"
