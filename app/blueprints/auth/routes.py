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


def _send_magic_link_email_sync(email: str, url_token: str, otp: str, role: str) -> None:
    """Synchronous fallback email send (used when Celery is unavailable)."""
    try:
        from flask_mail import Message
        from app.extensions import mail

        base_url = current_app.config.get("BASE_URL", "").rstrip("/")
        platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
        expiry_min = int(current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15))
        verify_url = f"{base_url}/auth/verify/{url_token}"
        otp_display = "  ".join(otp[i:i + 5] for i in range(0, len(otp), 5))

        msg = Message(
            subject=f"[{platform_name}] Your verification code — expires in {expiry_min} minutes",
            recipients=[email],
            html=render_template(
                "email/magic_link.html",
                platform_name=platform_name,
                verify_url=verify_url,
                otp_display=otp_display,
                expiry_minutes=expiry_min,
            ),
            body=(
                f"{platform_name} Verification\n\n"
                f"Click to open verification page:\n{verify_url}\n\n"
                f"Your verification code:\n{otp_display}\n\n"
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

    # --- Honeypot check (bots fill hidden fields) ---
    if request.form.get("website", ""):
        # Silent reject — look identical to success
        constant_time_response(start)
        return render_template(
            "auth/login_sent.html",
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        ), 200

    # --- hCaptcha verification BEFORE any DB query ---
    hcaptcha_token = request.form.get("h-captcha-response", "")
    if not _verify_hcaptcha(hcaptcha_token):
        constant_time_response(start)
        flash(MSG_RATE_LIMITED, "error")
        return render_template(
            "auth/login.html",
            hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        ), 200

    email = request.form.get("email", "").strip().lower()
    if not email or "@" not in email or len(email) > 254:
        constant_time_response(start)
        return render_template(
            "auth/login_sent.html",
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        ), 200

    # --- Dummy work to normalize timing regardless of email existence ---
    _ = hashlib.sha3_256(secrets.token_bytes(32)).hexdigest()

    owner = User.query.filter_by(email=email).first()
    member = SecurityTeamMember.query.filter_by(email=email).first()

    if owner or member:
        subject = owner if owner else member
        role = "owner" if owner else "security_team"
        otp_length = int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20))
        expiry_minutes = int(current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15))

        # If a valid (non-used, non-expired) token already exists, do not
        # overwrite it — the user has an email in flight. Silently return
        # "check your inbox" so re-submitting the form doesn't invalidate
        # the link that was already sent.
        already_valid = (
            subject.login_url_token_hash
            and not subject.token_used
            and subject.token_expiry
            and _ensure_utc(subject.token_expiry) > utcnow()
        )
        if already_valid:
            constant_time_response(start)
            return render_template(
                "auth/login_sent.html",
                platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
            ), 200

        url_token = generate_magic_link_token()
        otp = generate_otp(otp_length)
        url_token_hash = hash_token(url_token)
        otp_hash = hash_token(otp)
        expiry = utcnow() + timedelta(minutes=expiry_minutes)

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
            return render_template(
                "auth/login_sent.html",
                platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
            ), 200

        # Store "remember me" preference alongside the token (expires with it)
        if request.form.get("remember_me"):
            try:
                redis_client.setex(
                    f"login_remember:{url_token_hash}",
                    expiry_minutes * 60 + 30,  # +30s buffer
                    "1",
                )
            except Exception:
                pass

        # Send email — prefer async Celery task, fall back to sync
        try:
            from app.tasks.notifications import send_magic_link_email_task
            send_magic_link_email_task.delay(email, url_token, otp, role)
        except Exception:
            _send_magic_link_email_sync(email, url_token, otp, role)

    else:
        # Unknown email — log attempt hash for monitoring, never reveal to user
        current_app.logger.info(
            "Login attempt for unregistered email (sha256 prefix: %s)",
            hashlib.sha256(email.encode()).hexdigest()[:16],
        )

    constant_time_response(start)
    return render_template(
        "auth/login_sent.html",
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    ), 200


@auth_bp.route("/auth/verify/<raw_url_token>", methods=["GET", "POST"])
@limiter.limit("5 per 15 minutes", methods=["POST"])
def verify_magic_link(raw_url_token: str):
    """
    GET  — Render OTP entry page after user clicks magic link.
    POST — Validate submitted OTP + URL token, create session.

    Both secrets (url_token hash + OTP hash) must match.
    Never reveal which part failed.
    """
    url_token_hash = hash_token(raw_url_token)

    # Look up owner first, then security team member
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

    # Validate token: exists, not used, not expired
    # Note: if token_expiry is None (unset), treat as expired — never allow expiry-less tokens
    if not subject or not subject.token_expiry or _ensure_utc(subject.token_expiry) < utcnow():
        log_access_event(None, event_type="login_failed",
                         metadata={"reason": "invalid_or_expired_url_token"})
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    otp_length = int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20))
    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")

    if request.method == "GET":
        return render_template(
            "auth/verify_otp.html",
            expiry_iso=_to_utc_iso(subject.token_expiry),
            url_token=raw_url_token,
            otp_length=otp_length,
            platform_name=platform_name,
        )

    # -----------------------------------------------------------------------
    # POST: OTP submission
    # -----------------------------------------------------------------------
    start = time.monotonic()
    submitted_otp = request.form.get("otp", "").strip().replace(" ", "")

    attempt_key = f"otp_attempts:{url_token_hash}"
    MAX_ATTEMPTS = 5

    try:
        attempts = int(redis_client.get(attempt_key) or 0)
    except Exception:
        # Redis unavailable — fail secure: treat as exhausted rather than allowing
        # unlimited brute-force. The user can request a new magic link immediately.
        current_app.logger.error(
            "verify_magic_link: Redis unavailable for OTP attempt counter — "
            "rejecting submission to fail secure (session_id context: %s)",
            url_token_hash[:8],
        )
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    # Exhausted attempts — invalidate token and force re-login
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

    # Constant-time OTP comparison — compare_hash_digest hashes both sides
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
        return render_template(
            "auth/verify_otp.html",
            expiry_iso=_to_utc_iso(subject.token_expiry),
            url_token=raw_url_token,
            otp_length=otp_length,
            platform_name=platform_name,
            # Show remaining count only after first failure (index > 0 = second attempt onward)
            attempts_remaining=remaining if attempts > 0 else None,
        )

    # -----------------------------------------------------------------------
    # Authentication success — atomically mark token used, create session
    # -----------------------------------------------------------------------
    new_session_id = uuid.uuid4()
    now = utcnow()

    try:
        # Atomic token invalidation — WHERE token_used=False prevents race condition
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

        # If rowcount is 0, another request won the race — deny
        if result.rowcount == 0:
            db.session.rollback()
            log_access_event(subject, event_type="login_failed",
                             metadata={"reason": "token_race_condition"})
            flash(MSG_INVALID_LINK, "error")
            constant_time_response(start)
            return redirect(url_for("auth.login"))

        # Single-session enforcement: revoke previous session if exists
        enforce_single_session(subject, new_session_id)
        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        current_app.logger.error("Session creation failed during verify: %s", exc)
        flash(MSG_INVALID_LINK, "error")
        constant_time_response(start)
        return redirect(url_for("auth.login"))

    # Clean up OTP attempt counter
    try:
        redis_client.delete(attempt_key)
    except Exception:
        pass

    # Check if "remember me" was requested during the original login POST
    try:
        _remember_me = bool(redis_client.get(f"login_remember:{url_token_hash}"))
        redis_client.delete(f"login_remember:{url_token_hash}")
    except Exception:
        _remember_me = False

    # Clear only the relevant role's session keys — preserves the other role's
    # session so owner and security team can coexist in the same browser.
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
        # Verify at least one active invite exists for this member's email
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
