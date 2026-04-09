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

# Full passwordless auth routes — magic link + OTP two-factor within one flow

import hashlib
import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import (
    current_app, flash, jsonify, redirect,
    render_template, request, session, url_for,
)
from sqlalchemy import update as sa_update

from app.blueprints.auth import auth_bp
from app.extensions import db, limiter, redis_client
from app.middleware.access_logger import log_access_event
from app.middleware.session_guard import enforce_single_session
from app.models import SecurityTeamInvite, SecurityTeamMember, User
from app.utils.auth_messages import (
    MSG_ACCOUNT_ISSUE,
    MSG_INVALID_LINK,
    MSG_LOGGED_OUT,
    MSG_RATE_LIMITED,
)
from app.utils.security import (
    compare_hash_digest,
    constant_time_response,
    generate_magic_link_token,
    generate_otp,
    hash_token,
    verify_hcaptcha,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc_iso(dt: datetime | None) -> str | None:
    """
    Return a UTC-aware ISO 8601 string (always includes +00:00 suffix).

    Handles naive datetimes (treats as UTC) and aware datetimes of any timezone.
    JavaScript's Date constructor correctly parses strings with explicit timezone,
    so this prevents local-time mis-interpretation in user browsers.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Return a UTC-aware datetime, treating naive datetimes as UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _verify_hcaptcha(token: str) -> bool:
    """Verify hCaptcha response token server-side. Returns True if valid or unconfigured in dev."""
    secret = current_app.config.get("HCAPTCHA_SECRET_KEY", "")
    if not secret:
        # No secret configured — allow in dev, reject in production
        return current_app.config.get("FLASK_ENV") != "production"
    return verify_hcaptcha(token, secret)


def _send_magic_link_email_sync(email: str, url_token: str, role: str) -> None:
    """Synchronous fallback email send (used when Celery is unavailable)."""
    try:
        from flask_mail import Message
        from app.extensions import mail

        base_url = current_app.config.get("BASE_URL", "").rstrip("/")
        platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
        expiry_min = int(current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15))
        verify_url = f"{base_url}/auth/verify/{url_token}"

        html_body = None
        try:
            html_body = render_template(
                "email/magic_link.html",
                platform_name=platform_name,
                verify_url=verify_url,
                expiry_minutes=expiry_min,
            )
        except Exception:
            pass

        msg = Message(
            subject=f"[{platform_name}] Your magic link — expires in {expiry_min} minutes",
            recipients=[email],
            html=html_body,
            body=(
                f"{platform_name} — Secure Login\n\n"
                f"Click the link below. It will show your 20-character login code.\n"
                f"Copy the code and paste it in the tab where you requested access.\n\n"
                f"{verify_url}\n\n"
                f"Expires in {expiry_min} minutes. Single-use only.\n"
                f"If you did not request this, ignore this email.\n"
            ),
        )
        mail.send(msg)
    except Exception as exc:
        current_app.logger.error("Synchronous magic link email failed: %s", exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def login():
    """Login page — GET renders form, POST initiates magic link flow."""
    if request.method == "GET":
        # Redirect already-authenticated users to their dashboard
        if session.get("role") == "owner":
            return redirect(url_for("dashboard.index"))
        if session.get("portal_role") == "security_team":
            return redirect(url_for("portal.dashboard"))
        return render_template(
            "auth/login.html",
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        )

    start = time.monotonic()

    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
    otp_length = int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20))
    expiry_minutes = int(current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15))

    def _render_waiting(em: str, exp_iso: str) -> tuple:
        masked = (em[0] + "***@" + em.split("@")[1]) if "@" in em else "***"
        return render_template(
            "auth/login_sent.html",
            platform_name=platform_name,
            email=em,
            masked_email=masked,
            expiry_iso=exp_iso,
            otp_length=otp_length,
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
        ), 200

    # --- Honeypot check (bots fill hidden fields) ---
    if request.form.get("website", ""):
        dummy_expiry = _to_utc_iso(utcnow() + timedelta(minutes=expiry_minutes))
        constant_time_response(start)
        return _render_waiting("", dummy_expiry)

    # --- hCaptcha verification BEFORE any DB query ---
    hcaptcha_token = request.form.get("h-captcha-response", "")
    if not _verify_hcaptcha(hcaptcha_token):
        constant_time_response(start)
        flash(MSG_RATE_LIMITED, "error")
        return render_template(
            "auth/login.html",
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
            platform_name=platform_name,
        ), 200

    email = request.form.get("email", "").strip().lower()
    dummy_expiry = _to_utc_iso(utcnow() + timedelta(minutes=expiry_minutes))

    if not email or "@" not in email or len(email) > 254:
        constant_time_response(start)
        return _render_waiting(email, dummy_expiry)

    # --- Dummy work to normalize timing regardless of email existence ---
    _ = hashlib.sha3_256(secrets.token_bytes(32)).hexdigest()

    owner = User.query.filter_by(email=email).first()
    member = SecurityTeamMember.query.filter_by(email=email).first()

    expiry_iso = dummy_expiry  # overwritten below if a real token is issued

    if owner or member:
        subject = owner if owner else member
        role = "owner" if owner else "security_team"

        # If a valid (non-used, non-expired) token already exists, do not
        # overwrite it — user has an email in flight. Show the waiting screen
        # so they can still enter the code from the link they already received.
        already_valid = (
            subject.login_url_token_hash
            and not subject.token_used
            and subject.token_expiry
            and _ensure_utc(subject.token_expiry) > utcnow()
        )
        if already_valid:
            expiry_iso = _to_utc_iso(subject.token_expiry)
            constant_time_response(start)
            return _render_waiting(email, expiry_iso)

        url_token = generate_magic_link_token()
        otp = generate_otp(otp_length)
        url_token_hash = hash_token(url_token)
        otp_hash = hash_token(otp)
        expiry = utcnow() + timedelta(minutes=expiry_minutes)
        expiry_iso = _to_utc_iso(expiry)

        try:
            subject.login_url_token_hash = url_token_hash
            subject.login_otp_hash = otp_hash
            subject.token_expiry = expiry
            subject.token_used = False
            db.session.add(subject)
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error("Token storage failed for login attempt: %s", exc)
            constant_time_response(start)
            return _render_waiting(email, dummy_expiry)

        # Store raw OTP in Redis so the magic link page can display it.
        # Key: otp_raw:{url_token_hash} — TTL matches token window + 30s buffer.
        # Raw value in Redis is acceptable: private network, short-lived, TTL-bounded.
        try:
            redis_client.setex(
                f"otp_raw:{url_token_hash}",
                expiry_minutes * 60 + 30,
                otp,
            )
        except Exception as exc:
            current_app.logger.error("Failed to cache raw OTP in Redis: %s", exc)
            # Non-fatal — magic link page will redirect to /login with generic error

        # Store "remember me" preference alongside the token (expires with it)
        if request.form.get("remember_me"):
            try:
                redis_client.setex(
                    f"login_remember:{url_token_hash}",
                    expiry_minutes * 60 + 30,
                    "1",
                )
            except Exception:
                pass

        # Send email — magic link only (OTP is shown on the verify page, not in email)
        try:
            from app.tasks.notifications import send_magic_link_email_task
            send_magic_link_email_task.delay(email, url_token, role)
        except Exception:
            _send_magic_link_email_sync(email, url_token, role)

    else:
        # Unknown email — log attempt hash for monitoring, never reveal to user
        current_app.logger.info(
            "Login attempt for unregistered email (sha256 prefix: %s)",
            hashlib.sha256(email.encode()).hexdigest()[:16],
        )

    constant_time_response(start)
    return _render_waiting(email, expiry_iso)


@auth_bp.route("/auth/verify/<raw_url_token>", methods=["GET"])
@limiter.limit("10 per 15 minutes")
def verify_magic_link(raw_url_token: str):
    """
    GET — Displays the 20-char OTP after user clicks the magic link in their email.
    The user copies this code and pastes it into the original login tab.
    The OTP is retrieved from Redis (stored at login time). This endpoint does NOT
    authenticate the user — authentication happens at POST /auth/verify-code.
    """
    url_token_hash = hash_token(raw_url_token)
    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
    otp_length = int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20))

    owner = User.query.filter_by(
        login_url_token_hash=url_token_hash,
        token_used=False,
    ).first()
    member = None
    if not owner:
        member = SecurityTeamMember.query.filter_by(
            login_url_token_hash=url_token_hash,
            token_used=False,
        ).first()

    subject = owner or member

    if not subject or not subject.token_expiry or _ensure_utc(subject.token_expiry) < utcnow():
        log_access_event(None, event_type="login_failed",
                         metadata={"reason": "invalid_or_expired_url_token"})
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    # Retrieve raw OTP from Redis
    raw_otp: str | None = None
    try:
        cached = redis_client.get(f"otp_raw:{url_token_hash}")
        if cached:
            raw_otp = cached.decode("utf-8") if isinstance(cached, bytes) else cached
    except Exception as exc:
        current_app.logger.error("Redis unavailable when retrieving raw OTP: %s", exc)

    if not raw_otp:
        # OTP expired from Redis (or Redis down) — user must request a new link
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    otp_display = "  ".join(raw_otp[i:i + 5] for i in range(0, len(raw_otp), 5))

    return render_template(
        "auth/verify_otp.html",
        platform_name=platform_name,
        raw_otp=raw_otp,
        otp_display=otp_display,
        otp_length=otp_length,
        expiry_iso=_to_utc_iso(subject.token_expiry),
    )


@auth_bp.route("/auth/verify-code", methods=["POST"])
@limiter.limit("5 per 15 minutes")
def verify_code():
    """
    POST — Validate the OTP the user copied from the magic link page.
    Accepts: email (hidden field) + otp (user input) + csrf_token.
    This is the endpoint that actually authenticates and creates a session.
    All security invariants maintained: constant-time, atomic token invalidation,
    attempt counter, single-session enforcement, anti-enumeration.
    """
    start = time.monotonic()

    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
    otp_length = int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20))
    expiry_minutes = int(current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15))

    # hCaptcha verification (if configured)
    hcaptcha_token = request.form.get("h-captcha-response", "")
    if not _verify_hcaptcha(hcaptcha_token):
        flash(MSG_RATE_LIMITED, "error")
        constant_time_response(start)
        # Re-render with the email pre-filled so user doesn't have to retype
        email_pre = request.form.get("email", "").strip().lower()
        masked = (email_pre[0] + "***@" + email_pre.split("@")[1]) if "@" in email_pre else "***"
        return render_template(
            "auth/login_sent.html",
            platform_name=platform_name,
            email=email_pre,
            masked_email=masked,
            expiry_iso=_to_utc_iso(utcnow() + timedelta(minutes=expiry_minutes)),
            otp_length=otp_length,
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
        ), 200

    email = request.form.get("email", "").strip().lower()
    submitted_otp = request.form.get("otp", "").strip().replace(" ", "")

    if not email or "@" not in email or len(email) > 254:
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    masked_email = email[0] + "***@" + email.split("@")[1]

    def _rerender_waiting(attempts_left=None):
        """Re-render the OTP entry form with error already flashed."""
        expiry_fallback = _to_utc_iso(utcnow() + timedelta(minutes=expiry_minutes))
        subj_expiry = subject.token_expiry if subject else None
        return render_template(
            "auth/login_sent.html",
            platform_name=platform_name,
            email=email,
            masked_email=masked_email,
            expiry_iso=_to_utc_iso(subj_expiry) if subj_expiry else expiry_fallback,
            otp_length=otp_length,
            attempts_remaining=attempts_left,
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
        ), 200

    owner = User.query.filter_by(email=email).first()
    member = None
    if not owner:
        member = SecurityTeamMember.query.filter_by(email=email).first()

    subject = owner or member

    # Dummy work keeps timing identical for unknown vs known emails
    _ = hashlib.sha3_256(submitted_otp.encode()).hexdigest()

    # No valid pending token — treat as invalid (generic message, same timing)
    if (
        not subject
        or not subject.login_url_token_hash
        or subject.token_used
        or not subject.token_expiry
        or _ensure_utc(subject.token_expiry) < utcnow()
    ):
        log_access_event(None, event_type="login_failed",
                         metadata={"reason": "no_valid_pending_token", "email_prefix": email[:3]})
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return _rerender_waiting()

    url_token_hash = subject.login_url_token_hash
    attempt_key = f"otp_attempts:{url_token_hash}"
    MAX_ATTEMPTS = 5

    try:
        attempts = int(redis_client.get(attempt_key) or 0)
    except Exception:
        current_app.logger.error(
            "verify_code: Redis unavailable for OTP attempt counter — failing secure"
        )
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    # Exhausted attempts — invalidate token and force full re-login
    if attempts >= MAX_ATTEMPTS:
        try:
            db.session.execute(
                sa_update(User)
                .where(User.login_url_token_hash == url_token_hash)
                .values(token_used=True)
            )
            db.session.execute(
                sa_update(SecurityTeamMember)
                .where(SecurityTeamMember.login_url_token_hash == url_token_hash)
                .values(token_used=True)
            )
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            current_app.logger.error("Token invalidation failed after exhausted attempts: %s", exc)

        log_access_event(subject, event_type="login_failed",
                         metadata={"reason": "otp_attempts_exhausted"})
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    # Constant-time OTP comparison
    otp_valid = compare_hash_digest(submitted_otp, subject.login_otp_hash or "")

    if not otp_valid:
        try:
            redis_client.incr(attempt_key)
            redis_client.expire(attempt_key, 900)  # expire with token window
        except Exception:
            pass

        remaining = MAX_ATTEMPTS - attempts - 1
        log_access_event(subject, event_type="login_failed",
                         metadata={"reason": "invalid_otp", "attempts_remaining": remaining})
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        # Show attempts_remaining only after the first failure
        return _rerender_waiting(attempts_left=remaining if attempts > 0 else None)

    # -----------------------------------------------------------------------
    # OTP valid — atomically mark token used, create session
    # -----------------------------------------------------------------------
    new_session_id = uuid.uuid4()
    now = utcnow()

    try:
        if owner:
            result = db.session.execute(
                sa_update(User)
                .where(User.id == owner.id, User.token_used == False)  # noqa: E712
                .values(
                    token_used=True,
                    last_login=now,
                    last_login_ip=request.remote_addr,
                    last_login_ua=request.user_agent.string,
                )
            )
        else:
            result = db.session.execute(
                sa_update(SecurityTeamMember)
                .where(
                    SecurityTeamMember.id == member.id,
                    SecurityTeamMember.token_used == False,  # noqa: E712
                )
                .values(
                    token_used=True,
                    last_login_at=now,
                    last_login_ip=request.remote_addr,
                    last_login_ua=request.user_agent.string,
                )
            )

        if result.rowcount == 0:
            db.session.rollback()
            log_access_event(subject, event_type="login_failed",
                             metadata={"reason": "token_race_condition"})
            flash(MSG_INVALID_LINK, "error")
            constant_time_response(start)
            return redirect(url_for("auth.login"))

        enforce_single_session(subject, new_session_id)
        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        current_app.logger.error("Session creation failed in verify_code: %s", exc)
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    # Clean up Redis keys
    try:
        redis_client.delete(attempt_key)
        redis_client.delete(f"otp_raw:{url_token_hash}")
    except Exception:
        pass

    # Check if "remember me" was requested during the original login POST
    try:
        _remember_me = bool(redis_client.get(f"login_remember:{url_token_hash}"))
        redis_client.delete(f"login_remember:{url_token_hash}")
    except Exception:
        _remember_me = False

    if owner:
        for k in ("role", "user_id", "session_id", "last_active", "remember_me"):
            session.pop(k, None)
        session["role"] = "owner"
        session["user_id"] = str(owner.id)
        session["session_id"] = str(new_session_id)
        session["last_active"] = now.isoformat()
        if _remember_me:
            session["remember_me"] = True
        session.permanent = True
        session.modified = True
        log_access_event(owner, event_type="login_success")
        constant_time_response(start)
        return redirect(url_for("dashboard.index"))
    else:
        all_invites = SecurityTeamInvite.query.filter_by(
            email=member.email, is_active=True
        ).all()
        if not all_invites:
            log_access_event(member, event_type="login_failed",
                             metadata={"reason": "no_active_invites"})
            flash(MSG_ACCOUNT_ISSUE, "error")
            constant_time_response(start)
            return redirect(url_for("auth.login"))

        for k in ("portal_role", "portal_member_id", "portal_member_email",
                  "portal_session_id", "portal_last_active", "portal_remember_me"):
            session.pop(k, None)
        session["portal_role"] = "security_team"
        session["portal_member_id"] = str(member.id)
        session["portal_member_email"] = member.email
        session["portal_session_id"] = str(new_session_id)
        session["portal_last_active"] = now.isoformat()
        if _remember_me:
            session["portal_remember_me"] = True
        session.permanent = True
        session.modified = True
        log_access_event(member, event_type="login_success")
        constant_time_response(start)
        return redirect(url_for("portal.dashboard"))


@auth_bp.route("/auth/ping", methods=["POST"])
def ping():
    """
    Session keepalive endpoint — called by idle_timer.js on user activity.
    Updates last_active for whichever role(s) are active in this browser session.
    """
    # CSRF validation — prevent cross-site session keepalive abuse
    from app.extensions import csrf as _csrf
    try:
        _csrf.protect()
    except Exception:
        return jsonify({"ok": False, "error": "csrf_invalid"}), 403

    owner_role = session.get("role")
    portal_role = session.get("portal_role")
    if not owner_role and not portal_role:
        return jsonify({"ok": False, "error": "not_authenticated"}), 401
    now = utcnow().isoformat()
    if owner_role:
        session["last_active"] = now
    if portal_role:
        session["portal_last_active"] = now
    session.modified = True
    return jsonify({"ok": True}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Log out owner — clears owner session keys only. Portal session unaffected."""
    try:
        log_access_event(None, event_type="logout")
    except Exception:
        pass
    for k in ("role", "user_id", "session_id", "last_active"):
        session.pop(k, None)
    session.modified = True
    flash(MSG_LOGGED_OUT, "info")
    return redirect(url_for("auth.login"))
