# GhostPortal -- Project-Apocalypse -- Shared decorators
# AGPL-3.0 License
import uuid
from functools import wraps
from flask import session, redirect, url_for, abort


def owner_required(f):
    """Only owner sessions allowed."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "owner":
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def security_team_required(f):
    """Security team member sessions only — checks portal_role key."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("portal_role") != "security_team":
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def login_required(f):
    """Either role accepted."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("role") and not session.get("portal_role"):
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def parse_uuid(value):
    """Parse UUID string, raise 404 on failure."""
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        abort(404)
