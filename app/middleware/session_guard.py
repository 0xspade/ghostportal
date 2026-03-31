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
Session guard middleware.

Runs before every request to enforce:
1. Idle timeout — logs out users after IDLE_TIMEOUT_SECONDS of inactivity
2. Single session enforcement — revokes sessions displaced by new logins
3. Session revocation check — fast Redis check for revoked sessions

Returns JSON for AJAX requests, redirect for browser requests.
"""

import logging
from datetime import datetime, timezone, timedelta

from flask import Flask, session, redirect, url_for, request, jsonify, current_app

logger = logging.getLogger(__name__)

# Routes that don't require session guard checks
EXEMPT_PATHS = {
    "/login",
    "/auth/verify",
    "/portal/access-expired",  # public page, no session needed
    "/health",
    "/csp-report",
    "/static/",
    "/legal/",
    "/go/",
    "/webhooks/",
    "/api/v1/",
}

# Routes that are considered authenticated (require idle timeout check)
# Portal public entry/setup routes (/portal/<token>) are NOT listed here,
# so they are naturally skipped. Only authenticated portal routes are included.
AUTHENTICATED_PREFIXES = (
    "/dashboard",
    "/reports",
    "/templates",
    "/security-teams",
    "/settings",
    "/ai/",
    "/api/programs",
    "/attachments",
    "/portal/dashboard",
    "/portal/report/",
)


def register_session_guard(app: Flask) -> None:
    """
    Register session guard as a before_request hook.

    Args:
        app: Flask application instance.
    """
    @app.before_request
    def session_guard():
        """
        Check session validity before processing authenticated requests.

        Owner routes use session keys: role, session_id, last_active.
        Portal routes use namespaced keys: portal_role, portal_session_id, portal_last_active.
        This prevents owner login from displacing the security team session and vice versa.
        """
        path = request.path

        # Skip guard for non-authenticated paths
        if not _is_authenticated_path(path):
            return None

        # Skip for /auth/ping (it handles session update itself)
        if path == "/auth/ping":
            return None

        # Select the correct session namespace based on route
        is_portal = path.startswith("/portal/")
        if is_portal:
            role = session.get("portal_role")
            session_id = session.get("portal_session_id")
            last_active_key = "portal_last_active"
        else:
            role = session.get("role")
            session_id = session.get("session_id")
            last_active_key = "last_active"

        if not role:
            return _handle_no_session()

        # Check Redis for revoked sessions (fast path), with DB fallback for portal
        if session_id and _is_session_revoked(session_id, is_portal=is_portal):
            return _handle_displaced_session()

        # Check idle timeout using the correct last_active key
        result = _check_idle_timeout(last_active_key)
        if result is not None:
            return result

        # Update last_active for this namespace
        session[last_active_key] = datetime.now(timezone.utc).isoformat()
        session.modified = True

        return None


def _is_authenticated_path(path: str) -> bool:
    """Check if this path requires session guard."""
    # First check: is this an explicitly exempt path?
    for prefix in EXEMPT_PATHS:
        if path == prefix or path.startswith(prefix):
            return False
    # Second check: is this an authenticated route?
    for prefix in AUTHENTICATED_PREFIXES:
        if path.startswith(prefix):
            return True
    return False


def _is_session_revoked(session_id: str, is_portal: bool = False) -> bool:
    """Check Redis (fast path) with DB fallback for portal sessions."""
    try:
        from app.extensions import redis_client
        result = redis_client.get(f"revoked_session:{session_id}")
        return bool(result)
    except Exception as exc:
        logger.warning(f"Redis session revocation check failed: {exc} — trying DB fallback")
        if is_portal:
            try:
                from app.models import SecurityTeamSession
                from app.extensions import db
                import uuid as _uuid
                sid = _uuid.UUID(str(session_id))
                sess = db.session.get(SecurityTeamSession, sid)
                if sess is not None:
                    return bool(sess.is_revoked)
            except Exception as db_exc:
                logger.error(f"DB fallback for session revocation also failed: {db_exc}")
        # Fail open — log at ERROR level so an alert can be triggered on Redis outage
        logger.error(
            "Session revocation check failed for session_id=%s (both Redis and DB unavailable) "
            "— allowing request through. Investigate immediately.",
            session_id,
        )
        return False


_PORTAL_SESSION_KEYS = (
    "portal_role", "portal_member_id", "portal_member_email",
    "portal_session_id", "portal_last_active",
)
_OWNER_SESSION_KEYS = ("role", "user_id", "session_id", "last_active")


def _check_idle_timeout(last_active_key: str = "last_active") -> None | object:
    """
    Check if the session has exceeded the idle timeout.

    Args:
        last_active_key: Session key to read — 'last_active' for owner,
                         'portal_last_active' for portal.

    Returns:
        Response to return (redirect or JSON) if session is expired,
        None if session is still valid.
    """
    idle_timeout = int(current_app.config.get("IDLE_TIMEOUT_SECONDS", 300))

    # "Remember me" users get 2-week idle window regardless of global setting
    remember_key = "portal_remember_me" if last_active_key == "portal_last_active" else "remember_me"
    if session.get(remember_key):
        idle_timeout = 14 * 24 * 3600  # 14 days

    if idle_timeout <= 0:
        return None  # Idle timeout disabled

    last_active_str = session.get(last_active_key)
    if not last_active_str:
        return None  # No timestamp — let it pass (first request after login)

    try:
        last_active = datetime.fromisoformat(last_active_str)
        if last_active.tzinfo is None:
            last_active = last_active.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        elapsed = (now - last_active).total_seconds()

        if elapsed > idle_timeout:
            _log_idle_logout(elapsed, last_active_key)

            # Clear only the relevant namespace — preserve the other role's session
            if last_active_key == "portal_last_active":
                for k in _PORTAL_SESSION_KEYS:
                    session.pop(k, None)
                session.pop("portal_remember_me", None)
            else:
                for k in _OWNER_SESSION_KEYS:
                    session.pop(k, None)
                session.pop("remember_me", None)
            session.modified = True

            if _is_ajax_request():
                return jsonify({"error": "session_expired", "code": 401}), 401

            return redirect(url_for("auth.login", reason="idle"))

    except (ValueError, TypeError) as exc:
        logger.warning(f"Could not parse last_active timestamp: {exc}")
        # Don't block the request — just skip the check

    return None


def _handle_no_session():
    """Handle request with no active session."""
    if _is_ajax_request():
        return jsonify({"error": "not_authenticated", "code": 401}), 401
    return redirect(url_for("auth.login"))


def _handle_displaced_session():
    """Handle session that was revoked by a new login from another location."""
    from app.utils.auth_messages import MSG_SESSION_DISPLACED
    session.clear()

    if _is_ajax_request():
        return jsonify({"error": "session_displaced", "code": 401}), 401

    from flask import flash
    flash(MSG_SESSION_DISPLACED, "warning")
    return redirect(url_for("auth.login", reason="displaced"))


def _log_idle_logout(idle_seconds: float, last_active_key: str = "last_active") -> None:
    """Log idle logout event to AccessLog using the correct session namespace."""
    try:
        from app.models import AccessLog
        from app.extensions import db

        is_portal = last_active_key == "portal_last_active"
        if is_portal:
            user_type = session.get("portal_role", "security_team")
            user_ref = session.get("portal_member_id")
            session_id = session.get("portal_session_id")
        else:
            user_type = session.get("role", "owner")
            user_ref = session.get("user_id")
            session_id = session.get("session_id")

        log_entry = AccessLog(
            user_type=user_type,
            user_ref=user_ref,
            session_id=session_id,
            ip_address=request.remote_addr or "unknown",
            user_agent=request.user_agent.string,
            method=request.method,
            path=request.path,
            response_code=302,
            event_type="idle_logout",
            metadata_={"idle_seconds": int(idle_seconds)},
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as exc:
        logger.error(f"Failed to log idle logout: {exc}")


def _is_ajax_request() -> bool:
    """Check if request expects JSON response."""
    return (
        request.accept_mimetypes.accept_json
        and not request.accept_mimetypes.accept_html
    ) or request.headers.get("X-Requested-With") == "XMLHttpRequest"


def enforce_single_session(user_or_member, new_session_id) -> None:
    """
    Invalidate any previous active session for a user.

    Called from auth flow after successful login.
    Works for both User (owner) and SecurityTeamMember.

    Args:
        user_or_member: User or SecurityTeamMember model instance.
        new_session_id: UUID of the new session being created.
    """
    from flask import current_app
    from app.extensions import db, redis_client
    from app.models import SecurityTeamSession, AccessLog

    if not current_app.config.get("SINGLE_SESSION_ENFORCE", True):
        return

    old_session_id = getattr(user_or_member, "current_session_id", None)

    if old_session_id:
        # Mark old SecurityTeamSession as revoked (if applicable)
        old_session = SecurityTeamSession.query.filter_by(
            id=old_session_id, is_revoked=False
        ).first()
        if old_session:
            old_session.is_revoked = True
            db.session.add(old_session)

        # Revoke in Redis for immediate effect across workers
        lifetime = current_app.config.get("PERMANENT_SESSION_LIFETIME")
        if hasattr(lifetime, "total_seconds"):
            ttl = int(lifetime.total_seconds())
        else:
            ttl = int(lifetime) if lifetime else 86400

        try:
            redis_client.setex(
                f"revoked_session:{old_session_id}",
                ttl,
                "1",
            )
        except Exception as exc:
            logger.error(f"Redis session revocation failed: {exc}")

        # Log the displacement
        try:
            log_entry = AccessLog(
                user_type="owner" if hasattr(user_or_member, "login_url_token_hash") else "security_team",
                user_ref=str(user_or_member.id),
                session_id=str(old_session_id),
                ip_address=request.remote_addr or "unknown",
                user_agent=request.user_agent.string if request else "",
                method=request.method if request else "POST",
                path=request.path if request else "/auth/verify",
                response_code=302,
                event_type="session_displaced",
                metadata_={
                    "old_session": str(old_session_id),
                    "new_session": str(new_session_id),
                    "ip": request.remote_addr if request else None,
                },
            )
            db.session.add(log_entry)
        except Exception as exc:
            logger.error(f"Failed to log session displacement: {exc}")

    # Update the user's current session
    user_or_member.current_session_id = new_session_id
    db.session.add(user_or_member)
