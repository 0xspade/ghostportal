# GhostPortal -- Project-Apocalypse -- Settings Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import json
from datetime import datetime, timezone

from flask import (current_app, flash, jsonify, redirect, render_template,
                   request, url_for)

from app.blueprints.settings import settings_bp
from app.blueprints.decorators import owner_required
from app.extensions import db


def utcnow():
    return datetime.now(timezone.utc)


def get_system_config(key, default=None):
    """Get a SystemConfig value, falling back to default."""
    try:
        from app.models import SystemConfig
        row = SystemConfig.query.filter_by(key=key).first()
        if row:
            return json.loads(row.value)
    except Exception:
        pass
    return default


def set_system_config(key, value, value_type="str"):
    """Set a SystemConfig value."""
    from app.models import SystemConfig
    row = SystemConfig.query.filter_by(key=key).first()
    if row:
        row.value = json.dumps(value)
        row.value_type = value_type
        row.updated_at = utcnow()
    else:
        row = SystemConfig(key=key, value=json.dumps(value), value_type=value_type)
        db.session.add(row)
    db.session.commit()


@settings_bp.route("/settings")
@owner_required
def index():
    from app.models import SecurityTeamSession, AccessLog, CSPViolation
    # Active portal sessions
    active_sessions = (SecurityTeamSession.query
                       .filter_by(is_revoked=False)
                       .order_by(SecurityTeamSession.last_seen.desc())
                       .limit(20).all())
    # Recent login attempts
    recent_logins = (AccessLog.query
                     .filter(AccessLog.event_type.in_(['login_success', 'login_failed']))
                     .order_by(AccessLog.created_at.desc())
                     .limit(30).all())
    # CSP violations
    recent_csp = (CSPViolation.query
                  .order_by(CSPViolation.created_at.desc())
                  .limit(100).all()) if hasattr(CSPViolation, '__table__') else []

    config_vals = {
        'idle_timeout': get_system_config('idle_timeout_seconds', current_app.config.get('IDLE_TIMEOUT_SECONDS', 300)),
        'single_session': get_system_config('single_session_enforce', True),
        'resolved_expiry': get_system_config('resolved_access_expiry_days', 10),
        'invite_extension': get_system_config('invite_extension_days', 30),
        'followup_schedule': get_system_config('followup_schedule', [30, 60, 90]),
        'followup_skip': get_system_config('followup_skip_if_replied', True),
        'ai_provider': get_system_config('ai_default_provider', current_app.config.get('AI_DEFAULT_PROVIDER', 'anthropic')),
    }

    return render_template(
        "settings/index.html",
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        active_sessions=active_sessions,
        recent_logins=recent_logins,
        recent_csp=recent_csp,
        config_vals=config_vals,
    )


@settings_bp.route("/settings/idle-timeout", methods=["POST"])
@owner_required
def save_idle_timeout():
    try:
        val = int(request.form.get("idle_timeout_seconds", 300))
        if val < 0:
            val = 0
        if val > 3600:
            flash("Idle timeout must be 0–3600 seconds.", "error")
            return redirect(url_for("settings.index"))
        set_system_config("idle_timeout_seconds", val, "int")
        flash(f"Idle timeout set to {val}s.", "success")
    except (ValueError, TypeError):
        flash("Invalid value.", "error")
    return redirect(url_for("settings.index") + "#auth-section")


@settings_bp.route("/settings/single-session", methods=["POST"])
@owner_required
def save_single_session():
    val = request.form.get("single_session_enforce") == "on"
    set_system_config("single_session_enforce", val, "bool")
    flash(f"Single session enforcement {'enabled' if val else 'disabled'}.", "success")
    return redirect(url_for("settings.index") + "#auth-section")


@settings_bp.route("/settings/resolved-expiry", methods=["POST"])
@owner_required
def save_resolved_expiry():
    try:
        val = int(request.form.get("resolved_access_expiry_days", 10))
        if not 10 <= val <= 15:
            flash("Resolved access expiry must be 10–15 days.", "error")
            return redirect(url_for("settings.index") + "#followup-section")
        set_system_config("resolved_access_expiry_days", val, "int")
        flash(f"Resolved access expiry set to {val} days.", "success")
    except (ValueError, TypeError):
        flash("Invalid value.", "error")
    return redirect(url_for("settings.index") + "#followup-section")


@settings_bp.route("/settings/test-email", methods=["POST"])
@owner_required
def test_email():
    owner_email = current_app.config.get("OWNER_EMAIL", "")
    try:
        from app.tasks.notifications import _send_test_email
        _send_test_email({"recipient": owner_email})
        flash("Test email sent successfully. Check your inbox.", "success")
    except Exception as exc:
        current_app.logger.exception("Test email failed")
        flash(f"Email test failed: {exc}", "error")
    return redirect(url_for("settings.index") + "#smtp-section")


@settings_bp.route("/settings/test-discord", methods=["POST"])
@owner_required
def test_discord():
    try:
        from app.tasks.notifications import send_test_notification
        send_test_notification.delay("discord", None)
        flash("Discord test message queued.", "success")
    except Exception as exc:
        flash(f"Discord test failed: {exc}", "error")
    return redirect(url_for("settings.index") + "#notifications-section")


@settings_bp.route("/settings/test-telegram", methods=["POST"])
@owner_required
def test_telegram():
    try:
        from app.tasks.notifications import send_test_notification
        send_test_notification.delay("telegram", None)
        flash("Telegram test message queued.", "success")
    except Exception as exc:
        flash(f"Telegram test failed: {exc}", "error")
    return redirect(url_for("settings.index") + "#notifications-section")


@settings_bp.route("/settings/test-ai", methods=["POST"])
@owner_required
def test_ai():
    provider = request.form.get("provider") or current_app.config.get("AI_DEFAULT_PROVIDER", "anthropic")
    prompt = request.form.get("prompt") or "Say 'GhostPortal AI test successful' in one sentence."
    try:
        from app.ai.provider import get_provider
        prov = get_provider(provider)
        import asyncio
        result = asyncio.run(prov.generate(prompt, "You are a helpful assistant."))
        return jsonify({"ok": True, "text": result.text, "tokens": result.tokens_used})
    except Exception as exc:
        current_app.logger.exception("AI test failed")
        return jsonify({"ok": False, "error": str(exc)}), 500


@settings_bp.route("/settings/sessions/<session_uuid>/revoke", methods=["POST"])
@owner_required
def revoke_session(session_uuid):
    from app.models import SecurityTeamSession
    from app.blueprints.decorators import parse_uuid
    sid = parse_uuid(session_uuid)
    sess = SecurityTeamSession.query.get_or_404(sid)
    sess.is_revoked = True
    db.session.commit()
    # Also set Redis TTL
    try:
        from app.extensions import get_redis
        redis = get_redis()
        if redis:
            redis.setex(f"revoked_session:{session_uuid}", 86400, "1")
    except Exception:
        pass
    flash("Session revoked.", "success")
    return redirect(url_for("settings.index") + "#auth-section")


@settings_bp.route("/settings/followup", methods=["POST"])
@owner_required
def save_followup():
    days = []
    for d in ['30', '60', '90']:
        if request.form.get(f"followup_{d}"):
            days.append(int(d))
    skip = request.form.get("followup_skip_if_replied") == "on"
    prefix = (request.form.get("followup_custom_prefix") or "").strip()[:500]
    set_system_config("followup_schedule", days, "json")
    set_system_config("followup_skip_if_replied", skip, "bool")
    set_system_config("followup_custom_prefix", prefix, "str")
    flash("Follow-up settings saved.", "success")
    return redirect(url_for("settings.index") + "#followup-section")


@settings_bp.route("/settings/csp-log/clear", methods=["POST"])
@owner_required
def clear_csp_log():
    try:
        from app.models import CSPViolation
        CSPViolation.query.delete()
        db.session.commit()
        flash("CSP violation log cleared.", "success")
    except Exception as exc:
        flash(f"Error clearing log: {exc}", "error")
    return redirect(url_for("settings.index") + "#csp-section")


@settings_bp.route("/settings/access-log")
@owner_required
def access_log():
    from app.models import AccessLog
    page = max(1, int(request.args.get("page", 1) or 1))
    event_type = request.args.get("event_type", "")
    user_type = request.args.get("user_type", "")
    q = AccessLog.query.order_by(AccessLog.created_at.desc())
    if event_type:
        q = q.filter_by(event_type=event_type)
    if user_type:
        q = q.filter_by(user_type=user_type)
    pagination = q.paginate(page=page, per_page=50, error_out=False)
    return render_template(
        "settings/access_log.html",
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        logs=pagination.items,
        pagination=pagination,
        event_type=event_type,
        user_type=user_type,
    )
