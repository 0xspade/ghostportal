# GhostPortal -- Project-Apocalypse -- Security Team Portal Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta

from flask import (abort, current_app, flash, jsonify,
                   redirect, render_template, request, session, url_for)

from app.blueprints.portal import portal_bp
from app.blueprints.decorators import security_team_required, parse_uuid
from app.extensions import db, limiter, csrf
from app.models import (SecurityTeamInvite, SecurityTeamMember,
                        SecurityTeamSession, InviteActivity, ReportReply,
                        ReportFieldEdit, BountyPayment, ReportAttachment,
                        AccessLog)
from app.utils.security import hash_token, compare_hash_digest, verify_hcaptcha
from app.utils.auth_messages import MSG_INVALID_LINK, MSG_ACCOUNT_ISSUE
from app.utils.markdown_renderer import sanitize_markdown, render_markdown
from app.middleware.session_guard import enforce_single_session
from app.middleware.access_logger import log_access_event


def utcnow():
    return datetime.now(timezone.utc)


def _get_current_member():
    """Return SecurityTeamMember for the current portal session or abort 401."""
    member_id = session.get("portal_member_id")
    if not member_id:
        abort(401)
    try:
        mid = uuid.UUID(member_id)
    except ValueError:
        abort(401)
    member = db.session.get(SecurityTeamMember, mid)
    if not member or not member.is_active:
        abort(403)
    return member


def _get_scoped_invite(invite_uuid_str, member):
    """Fetch invite, verify it belongs to member, enforce access rules."""
    iid = parse_uuid(invite_uuid_str)
    invite = SecurityTeamInvite.query.filter_by(
        id=iid, email=member.email, is_active=True
    ).first()
    if not invite:
        abort(403)
    if invite.expires_at and invite.expires_at < utcnow():
        return render_template("portal/access_expired.html"), 403
    if invite.is_locked:
        return render_template("portal/locked.html", reason=invite.lock_reason), 403
    return invite


# ── First-time Portal Entry (invite link click) ───────────────────────────────
@portal_bp.route("/portal/<raw_invite_token>")
@limiter.limit("20 per minute")
def portal_entry(raw_invite_token):
    token_hash = hash_token(raw_invite_token)
    invite = SecurityTeamInvite.query.filter_by(
        token_hash=token_hash, is_active=True
    ).first()

    if not invite or (invite.expires_at and invite.expires_at < utcnow()):
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    if invite.is_locked:
        return render_template("portal/locked.html", reason=invite.lock_reason)

    # Already registered? Send to login
    existing = SecurityTeamMember.query.filter_by(email=invite.email, is_active=True).first()
    if existing and invite.first_accessed_at:
        flash("Your account is already set up. Please log in with your email.", "info")
        return redirect(url_for("auth.login"))

    # Log first access
    if not invite.first_accessed_at:
        invite.first_accessed_at = utcnow()
        db.session.add(InviteActivity(
            invite_id=invite.id,
            action="link_clicked",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
        ))
        db.session.commit()

    return render_template(
        "portal/setup.html",
        invite=invite,
        raw_token=raw_invite_token,
        hcaptcha_site_key=current_app.config.get("HCAPTCHA_SITE_KEY", ""),
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        otp_length=int(current_app.config.get("MAGIC_LINK_OTP_LENGTH", 20)),
        operator_email=current_app.config.get("OPERATOR_EMAIL", ""),
    )


# ── Portal Setup (first-time registration) ────────────────────────────────────
@portal_bp.route("/portal/<raw_invite_token>/setup", methods=["POST"])
@limiter.limit("10 per hour")
def portal_setup(raw_invite_token):
    token_hash = hash_token(raw_invite_token)
    invite = SecurityTeamInvite.query.filter_by(
        token_hash=token_hash, is_active=True
    ).first()

    if not invite or (invite.expires_at and invite.expires_at < utcnow()):
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    # hCaptcha validation — required when configured OR when in production
    hcaptcha_response = request.form.get("h-captcha-response", "")
    secret_key = current_app.config.get("HCAPTCHA_SECRET_KEY", "")
    if secret_key:
        if not verify_hcaptcha(hcaptcha_response, secret_key):
            flash("Captcha verification failed. Please try again.", "error")
            return redirect(url_for("portal.portal_entry", raw_invite_token=raw_invite_token))
    elif current_app.config.get("FLASK_ENV") == "production":
        # In production without hCaptcha configured, block setup entirely
        current_app.logger.error(
            "portal_setup: HCAPTCHA_SECRET_KEY not set in production — blocking access"
        )
        flash("Portal setup is currently unavailable. Please contact the researcher.", "error")
        return redirect(url_for("auth.login"))

    # Honeypot check
    if request.form.get("website"):
        return redirect(url_for("auth.login"))

    company_name = (request.form.get("company_name") or "").strip()[:200]
    if not company_name:
        flash("Company name is required.", "error")
        return redirect(url_for("portal.portal_entry", raw_invite_token=raw_invite_token))

    # OTP validation — the invite OTP was sent in the invitation email
    submitted_otp = (request.form.get("otp") or "").strip().replace(" ", "")
    attempt_key = f"otp_attempts:{token_hash}"
    MAX_OTP_ATTEMPTS = 5
    try:
        from app.extensions import redis_client
        attempts = int(redis_client.get(attempt_key) or 0)
    except Exception as exc:
        # Redis unavailable — fail secure: reject rather than allow unlimited brute-force.
        current_app.logger.error(
            "portal_setup: Redis unavailable for OTP attempt counter: %s — "
            "rejecting submission to fail secure", exc
        )
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    if attempts >= MAX_OTP_ATTEMPTS:
        # Invalidate the invite token to force fresh invite
        invite.token_hash = None
        invite.otp_hash = None
        db.session.commit()
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("auth.login"))

    if not invite.otp_hash or not compare_hash_digest(submitted_otp, invite.otp_hash):
        try:
            from app.extensions import redis_client
            redis_client.incr(attempt_key)
            redis_client.expire(attempt_key, 15 * 60)
        except Exception as exc:
            current_app.logger.warning("portal_setup: could not increment OTP attempts: %s", exc)
        flash(MSG_INVALID_LINK, "error")
        return redirect(url_for("portal.portal_entry", raw_invite_token=raw_invite_token))

    # OTP valid — clear attempt counter
    try:
        from app.extensions import redis_client
        redis_client.delete(attempt_key)
    except Exception:
        pass

    member = SecurityTeamMember.query.filter_by(email=invite.email).first()
    new_session_id = uuid.uuid4()

    if not member:
        member = SecurityTeamMember(
            email=invite.email,
            invite_id=invite.id,
            company_name=company_name,
            current_session_id=new_session_id,
            last_login_at=utcnow(),
            last_login_ip=request.remote_addr,
            last_login_ua=request.user_agent.string,
        )
        db.session.add(member)
        db.session.flush()  # get member.id before creating session record
    else:
        enforce_single_session(member, new_session_id)
        member.last_login_at = utcnow()
        member.last_login_ip = request.remote_addr
        member.last_login_ua = request.user_agent.string
        member.current_session_id = new_session_id

    invite.company_name = company_name
    if not invite.first_accessed_at:
        invite.first_accessed_at = utcnow()

    # Create SecurityTeamSession record for revocation tracking
    portal_session = SecurityTeamSession(
        id=new_session_id,
        invite_id=invite.id,
        member_id=member.id,
        session_token_hash=hash_token(str(new_session_id)),
        expires_at=utcnow() + timedelta(hours=24),
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        last_seen=utcnow(),
        last_activity_ip=request.remote_addr,
    )
    db.session.add(portal_session)

    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="setup_complete",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"company_name": company_name},
    ))
    db.session.commit()

    # Clear only portal namespace keys — preserve owner session if present in same browser
    for k in ("portal_role", "portal_member_id", "portal_member_email",
              "portal_session_id", "portal_last_active"):
        session.pop(k, None)
    session["portal_role"] = "security_team"
    session["portal_member_id"] = str(member.id)
    session["portal_member_email"] = invite.email
    session["portal_session_id"] = str(new_session_id)
    session["portal_last_active"] = utcnow().isoformat()
    session.permanent = True
    session.modified = True

    log_access_event(member, "login_success", metadata={"method": "invite_setup"})
    return redirect(url_for("portal.dashboard"))


# ── Portal Dashboard (multi-report view) ─────────────────────────────────────
@portal_bp.route("/portal/dashboard")
@security_team_required
def dashboard():
    member = _get_current_member()
    now = utcnow()
    invites = (SecurityTeamInvite.query
               .filter_by(email=member.email, is_active=True)
               .filter(SecurityTeamInvite.expires_at > now)
               .order_by(SecurityTeamInvite.created_at.desc())
               .all())

    return render_template(
        "portal/dashboard.html",
        member=member,
        active_invites=invites,
        now=now,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


# ── Portal Report View ────────────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>")
@security_team_required
def view_report(invite_uuid):
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result  # rendered error template

    invite = result
    report = invite.report
    # Replies: include owner replies (invite_id=None) and security team replies for this invite
    replies = (ReportReply.query
               .filter(
                   ReportReply.report_id == report.id,
                   ReportReply.is_internal == False,
                   db.or_(
                       ReportReply.invite_id == invite.id,
                       ReportReply.author_type == "owner"
                   )
               )
               .order_by(ReportReply.created_at.asc())
               .all())
    pending_edits = (ReportFieldEdit.query
                     .filter_by(invite_id=invite.id, status="pending")
                     .all())
    all_field_edits = (ReportFieldEdit.query
                       .filter_by(invite_id=invite.id)
                       .order_by(ReportFieldEdit.created_at.desc())
                       .limit(10)
                       .all())
    attachments = ReportAttachment.query.filter_by(report_id=report.id).all()

    # Activity timeline — recent invite events
    activity = (InviteActivity.query
                .filter_by(invite_id=invite.id)
                .order_by(InviteActivity.performed_at.desc())
                .limit(30)
                .all())

    # Build unified discussion thread: replies + notable activity events interleaved
    _THREAD_EVENT_LABELS = {
        "status_changed": ("arrow-repeat", "Status updated"),
        "bounty_set": ("currency-dollar", "Bounty offered"),
        "bounty_sent": ("send", "Payment sent"),
        "bounty_edited": ("pencil-square", "Bounty updated"),
        "retest_requested": ("arrow-clockwise", "Retest requested"),
        "retest_confirmed": ("patch-check", "Retest confirmed by researcher"),
        "report_reopened": ("arrow-counterclockwise", "Report reopened"),
        "report_edited": ("pencil", "Report updated by researcher"),
        "field_edit_accepted": ("check-circle", "Field correction accepted"),
        "field_edit_rejected": ("x-circle", "Field correction rejected"),
        "field_edit_proposed": ("pencil-square", "Correction proposed"),
    }
    thread_items = []
    for r in replies:
        author_name = "Researcher" if r.author_type == "owner" else (
            r.invite.company_name if r.invite and r.invite.company_name else "Security Team"
        )
        thread_items.append({
            "item_type": "reply",
            "author_type": r.author_type,
            "author_name": author_name,
            "body_html": render_markdown(r.body),
            "created_at": r.created_at,
        })
    for evt in activity:
        if evt.action not in _THREAD_EVENT_LABELS:
            continue
        icon, label = _THREAD_EVENT_LABELS[evt.action]
        meta = evt.metadata_ or {}
        if evt.action == "status_changed" and meta.get("new_status"):
            label = "Status → " + meta["new_status"].replace("_", " ").upper()
        elif evt.action == "bounty_set" and meta.get("amount"):
            label = "Bounty offered: {} {}".format(meta["amount"], meta.get("currency", ""))
        elif evt.action == "bounty_sent" and meta.get("amount"):
            label = "Payment sent: {} {}".format(meta["amount"], meta.get("currency", ""))
        elif evt.action == "retest_confirmed" and meta.get("outcome"):
            label = "Retest: {}".format(meta["outcome"].replace("_", " ").title())
        elif evt.action == "bounty_edited" and meta.get("new_amount"):
            label = "Bounty updated: {} {} \u2192 {} {}".format(
                meta.get("old_amount", "?"), meta.get("old_currency", ""),
                meta["new_amount"], meta.get("new_currency", ""))
        elif evt.action == "field_edit_proposed" and meta.get("field_name"):
            label = "Correction proposed: {}".format(meta["field_name"].replace("_", " "))
        elif evt.action == "field_edit_accepted":
            field = meta.get("field") or meta.get("field_name", "")
            if field:
                label = "Correction accepted: {}".format(field.replace("_", " "))
        elif evt.action == "field_edit_rejected":
            field = meta.get("field") or meta.get("field_name", "")
            if field:
                label = "Correction rejected: {}".format(field.replace("_", " "))
        thread_items.append({
            "item_type": "event",
            "action": evt.action,
            "icon": icon,
            "label": label,
            "created_at": evt.performed_at or utcnow(),
        })
    thread_items.sort(key=lambda x: x["created_at"])

    rendered = {k: render_markdown(getattr(report, k) or "") for k in [
        "description", "steps_to_reproduce", "proof_of_concept",
        "impact_statement", "remediation", "technical_details",
    ]}

    # ── Build bounty payment config from app settings ──────────────────────
    cfg = current_app.config
    bounty_config = {}

    if cfg.get("OWNER_PAYPAL_EMAIL"):
        bounty_config["paypal"] = {"email": cfg["OWNER_PAYPAL_EMAIL"]}

    _crypto_slots = [
        ("BTC",       "OWNER_CRYPTO_BTC",       "Bitcoin (BTC)"),
        ("ETH",       "OWNER_CRYPTO_ETH",        "Ethereum (ETH)"),
        ("USDT_TRC20","OWNER_CRYPTO_USDT_TRC20", "USDT — TRC-20 / Tron"),
        ("USDT_ERC20","OWNER_CRYPTO_USDT_ERC20", "USDT — ERC-20 / Ethereum"),
        ("USDC_ERC20","OWNER_CRYPTO_USDC_ERC20", "USDC — ERC-20 / Ethereum"),
        ("XMR",       "OWNER_CRYPTO_XMR",        "Monero (XMR)"),
        ("BNB",       "OWNER_CRYPTO_BNB",        "BNB — BSC"),
        ("DOGE",      "OWNER_CRYPTO_DOGE",       "Dogecoin (DOGE)"),
        ("LTC",       "OWNER_CRYPTO_LTC",        "Litecoin (LTC)"),
    ]
    _crypto = {}
    for _key, _env, _label in _crypto_slots:
        _addr = cfg.get(_env, "")
        if _addr:
            _crypto[_key] = {"address": _addr, "label": _label}
    if _crypto:
        bounty_config["crypto"] = _crypto

    _bank = {
        "account_name":   cfg.get("OWNER_BANK_ACCOUNT_NAME", ""),
        "account_number": cfg.get("OWNER_BANK_ACCOUNT_NUMBER", ""),
        "iban":           cfg.get("OWNER_BANK_IBAN", ""),
        "swift":          cfg.get("OWNER_BANK_SWIFT", ""),
        "routing":        cfg.get("OWNER_BANK_ROUTING", ""),
        "bank_name":      cfg.get("OWNER_BANK_NAME", ""),
        "bank_address":   cfg.get("OWNER_BANK_ADDRESS", ""),
        "country":        cfg.get("OWNER_BANK_COUNTRY", ""),
    }
    if any(_bank.values()):
        bounty_config["bank_transfer"] = _bank

    # Most recent BountyPayment record for this invite
    payment = (BountyPayment.query
               .filter_by(invite_id=invite.id)
               .order_by(BountyPayment.initiated_at.desc())
               .first())

    # Has the researcher confirmed a retest fix? (enables "Bonus" option)
    retest_confirmed_exists = InviteActivity.query.filter_by(
        invite_id=invite.id, action="retest_confirmed"
    ).first() is not None

    # Resolved-access expiry info for closed-report banner
    resolved_expiry_days = int(current_app.config.get("RESOLVED_ACCESS_EXPIRY_DAYS", 15))
    resolved_expiry_at = None
    if invite.all_resolved_at:
        resolved_expiry_at = invite.all_resolved_at + timedelta(days=resolved_expiry_days)

    # Update last activity
    invite.last_activity_at = utcnow()
    db.session.commit()

    log_access_event(member, "portal_accessed",
                     metadata={"invite_id": str(invite.id), "report_id": str(report.id)})

    return render_template(
        "portal/report.html",
        member=member,
        invite=invite,
        report=report,
        replies=replies,
        thread_items=thread_items,
        pending_edits=pending_edits,
        pending_count=len(pending_edits),
        all_field_edits=all_field_edits,
        attachments=attachments,
        activity=activity,
        rendered=rendered,
        bounty_config=bounty_config,
        payment=payment,
        retest_confirmed_exists=retest_confirmed_exists,
        resolved_expiry_days=resolved_expiry_days,
        resolved_expiry_at=resolved_expiry_at,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


# ── Portal Reply ──────────────────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/reply", methods=["POST"])
@security_team_required
@limiter.limit("20 per hour")
def reply(invite_uuid):
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result

    body = sanitize_markdown(request.form.get("body") or "")

    # Handle reply attachments — save as ReportAttachment, append markdown refs to body
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")
    attachment_refs = []
    for f in request.files.getlist("reply_attachments"):
        if f and f.filename:
            try:
                from app.utils.mime_validator import validate_and_store_upload as _validate_upload
                file_bytes = f.read()
                res = _validate_upload(file_bytes, f.filename, str(invite.report_id), upload_folder)
                if res.is_valid:
                    att = ReportAttachment(
                        report_id=invite.report_id,
                        filename_original=f.filename[:500],
                        filename_stored=res.stored_filename,
                        mime_type=res.mime_type,
                        file_size=len(file_bytes),
                    )
                    db.session.add(att)
                    db.session.flush()
                    att_url = url_for("serve_attachment", attachment_uuid=str(att.id))
                    if res.mime_type and res.mime_type.startswith("image/"):
                        attachment_refs.append("![{}]({})".format(f.filename, att_url))
                    else:
                        attachment_refs.append("[{}]({})".format(f.filename, att_url))
                else:
                    flash("File rejected: {}".format(res.error), "warning")
            except Exception as exc:
                flash("File upload error: {}".format(exc), "warning")

    if attachment_refs:
        body = (body + "\n\n" + "\n".join(attachment_refs)).strip() if body.strip() else "\n".join(attachment_refs)

    if not body.strip():
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    r = ReportReply(
        report_id=invite.report_id,
        author_type="security_team",
        invite_id=invite.id,
        body=body,
        is_internal=False,
    )
    db.session.add(r)

    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="reply_posted",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"author": invite.company_name or "Security Team"},
    ))

    invite.last_activity_at = utcnow()
    db.session.commit()

    # Notify owner
    try:
        from app.tasks.notifications import notify_owner
        notify_owner.delay(
            event="reply_posted",
            invite_id=str(invite.id),
            report_id=str(invite.report_id),
        )
    except Exception as exc:
        current_app.logger.warning("notify_owner failed for reply_posted: %s", exc)

    flash("Reply posted.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Compose (unified: status + bounty + reply in one form) ─────────────
@portal_bp.route("/portal/report/<invite_uuid>/compose", methods=["POST"])
@security_team_required
@limiter.limit("20 per hour")
def compose(invite_uuid):
    """Single submit handler: optional status change + optional bounty + optional reply."""
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result
    report = invite.report

    action = (request.form.get("action") or "").strip()
    body = sanitize_markdown(request.form.get("body") or "")
    did_something = False
    errors = []

    _VALID_STATUSES = {"triaged", "duplicate", "informative", "resolved", "wont_fix"}
    _CLOSED_STATUSES = {"duplicate", "informative", "resolved", "wont_fix"}

    # ── Status change ──────────────────────────────────────────────────────────
    if action in _VALID_STATUSES:
        report.status = action
        report.updated_at = utcnow()
        # Start 15-day access countdown when report is closed
        if action in _CLOSED_STATUSES and invite.all_resolved_at is None:
            invite.all_resolved_at = utcnow()
            invite.resolved_expiry_notified_3d = False
            invite.resolved_expiry_notified_1d = False
        db.session.add(InviteActivity(
            invite_id=invite.id,
            action="status_changed",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"new_status": action},
        ))
        try:
            from app.tasks.notifications import notify_owner
            notify_owner.delay(event="status_changed", invite_id=str(invite.id),
                               report_id=str(report.id))
        except Exception as exc:
            current_app.logger.warning("notify_owner failed for status_changed: %s", exc)
        did_something = True

    # ── Reopen ─────────────────────────────────────────────────────────────────
    elif action == "reopen":
        if report.status not in _CLOSED_STATUSES:
            errors.append("This report is not closed and cannot be reopened.")
        else:
            report.status = "submitted"
            report.updated_at = utcnow()
            # Lift the 15-day access countdown
            invite.all_resolved_at = None
            invite.resolved_expiry_notified_3d = False
            invite.resolved_expiry_notified_1d = False
            db.session.add(InviteActivity(
                invite_id=invite.id,
                action="report_reopened",
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                metadata_={"reopened_by": invite.company_name or "Security Team"},
            ))
            try:
                from app.tasks.notifications import notify_owner
                notify_owner.delay(event="report_reopened", invite_id=str(invite.id),
                                   report_id=str(report.id))
            except Exception as exc:
                current_app.logger.warning("notify_owner failed for report_reopened: %s", exc)
            did_something = True

    # ── Request retest ─────────────────────────────────────────────────────────
    elif action == "request_retest":
        db.session.add(InviteActivity(
            invite_id=invite.id,
            action="retest_requested",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"requested_by": invite.company_name or "Security Team"},
        ))
        try:
            from app.tasks.notifications import notify_owner
            notify_owner.delay(event="retest_requested", invite_id=str(invite.id),
                               report_id=str(report.id))
        except Exception as exc:
            current_app.logger.warning("notify_owner failed for retest_requested: %s", exc)
        did_something = True

    # ── Edit bounty (bonus) ────────────────────────────────────────────────────
    elif action == "edit_bounty":
        existing_payment = BountyPayment.query.filter_by(
            report_id=invite.report_id, invite_id=invite.id
        ).order_by(BountyPayment.initiated_at.desc()).first()
        if not existing_payment:
            errors.append("No existing bounty to edit.")
        elif existing_payment.status != "pending":
            errors.append("Bounty cannot be edited after payment has been sent or confirmed.")
        else:
            try:
                new_amount = float(request.form.get("bounty_amount") or 0)
            except (ValueError, TypeError):
                new_amount = 0
            if new_amount <= 0:
                errors.append("Bounty amount must be greater than zero.")
            else:
                new_currency = (request.form.get("bounty_currency") or existing_payment.currency or "USD").strip()[:10]
                old_amount = existing_payment.amount
                old_currency = existing_payment.currency
                existing_payment.amount = new_amount
                existing_payment.currency = new_currency
                report.bounty_amount = new_amount
                report.bounty_currency = new_currency
                db.session.add(InviteActivity(
                    invite_id=invite.id,
                    action="bounty_edited",
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    metadata_={
                        "old_amount": str(old_amount),
                        "old_currency": old_currency,
                        "new_amount": str(new_amount),
                        "new_currency": new_currency,
                    },
                ))
                try:
                    from app.tasks.notifications import notify_owner
                    notify_owner.delay(event="bounty_edited", invite_id=str(invite.id),
                                       report_id=str(report.id))
                except Exception as exc:
                    current_app.logger.warning("notify_owner failed for bounty_edited: %s", exc)
                did_something = True

    # ── Set bounty ─────────────────────────────────────────────────────────────
    elif action == "set_bounty":
        try:
            amount = float(request.form.get("bounty_amount") or 0)
        except (ValueError, TypeError):
            amount = 0
        if amount <= 0:
            errors.append("Bounty amount must be greater than zero.")
        else:
            currency = (request.form.get("bounty_currency") or "USD").strip()[:10]
            method = (request.form.get("method") or "").strip()
            _VALID_METHODS = {"paypal", "crypto", "bank_transfer", "other"}
            if method not in _VALID_METHODS:
                errors.append("Please select a payment method.")
            else:
                cfg = current_app.config
                paypal_email = None
                crypto_address = None
                crypto_network = None
                if method == "paypal":
                    paypal_email = cfg.get("OWNER_PAYPAL_EMAIL", "") or None
                elif method == "crypto":
                    crypto_network = (request.form.get("crypto_network") or "").strip()
                    _crypto_env_map = {
                        "BTC": "OWNER_CRYPTO_BTC", "ETH": "OWNER_CRYPTO_ETH",
                        "USDT_TRC20": "OWNER_CRYPTO_USDT_TRC20", "USDT_ERC20": "OWNER_CRYPTO_USDT_ERC20",
                        "USDC_ERC20": "OWNER_CRYPTO_USDC_ERC20", "XMR": "OWNER_CRYPTO_XMR",
                        "BNB": "OWNER_CRYPTO_BNB", "DOGE": "OWNER_CRYPTO_DOGE", "LTC": "OWNER_CRYPTO_LTC",
                    }
                    crypto_address = cfg.get(_crypto_env_map.get(crypto_network, ""), "") or None
                    if not crypto_address:
                        errors.append("Selected crypto network is not configured.")

                if not errors:
                    report.bounty_amount = amount
                    report.bounty_currency = currency
                    bp_obj = BountyPayment(
                        report_id=invite.report_id,
                        invite_id=invite.id,
                        method=method,
                        amount=amount,
                        currency=currency,
                        paypal_recipient_email=paypal_email,
                        crypto_address=crypto_address,
                        crypto_network=crypto_network,
                        status="pending",
                    )
                    db.session.add(bp_obj)
                    db.session.add(InviteActivity(
                        invite_id=invite.id,
                        action="bounty_set",
                        ip_address=request.remote_addr,
                        user_agent=request.user_agent.string,
                        metadata_={"amount": str(amount), "currency": currency, "method": method},
                    ))
                    try:
                        from app.tasks.notifications import notify_owner
                        notify_owner.delay(event="bounty_set", invite_id=str(invite.id),
                                           report_id=str(report.id))
                    except Exception as exc:
                        current_app.logger.warning("notify_owner failed for bounty_set: %s", exc)
                    did_something = True

    # ── Set bonus (additional bounty after retest confirmed) ───────────────────
    elif action == "set_bonus":
        confirmed_evt = InviteActivity.query.filter_by(
            invite_id=invite.id, action="retest_confirmed"
        ).first()
        if not confirmed_evt:
            errors.append("Bonus is only available after the researcher confirms a retest.")
        else:
            try:
                bonus_amount = float(request.form.get("bounty_amount") or 0)
            except (ValueError, TypeError):
                bonus_amount = 0
            if bonus_amount <= 0:
                errors.append("Bonus amount must be greater than zero.")
            else:
                bonus_currency = (request.form.get("bounty_currency") or "USD").strip()[:10]
                bonus_method = (request.form.get("method") or "").strip()
                _VALID_METHODS = {"paypal", "crypto", "bank_transfer", "other"}
                if bonus_method not in _VALID_METHODS:
                    errors.append("Please select a payment method for the bonus.")
                else:
                    cfg = current_app.config
                    paypal_email = None
                    crypto_address = None
                    crypto_network = None
                    if bonus_method == "paypal":
                        paypal_email = cfg.get("OWNER_PAYPAL_EMAIL", "") or None
                    elif bonus_method == "crypto":
                        crypto_network = (request.form.get("crypto_network") or "").strip()
                        _crypto_env_map = {
                            "BTC": "OWNER_CRYPTO_BTC", "ETH": "OWNER_CRYPTO_ETH",
                            "USDT_TRC20": "OWNER_CRYPTO_USDT_TRC20",
                            "USDT_ERC20": "OWNER_CRYPTO_USDT_ERC20",
                            "USDC_ERC20": "OWNER_CRYPTO_USDC_ERC20",
                            "XMR": "OWNER_CRYPTO_XMR", "BNB": "OWNER_CRYPTO_BNB",
                            "DOGE": "OWNER_CRYPTO_DOGE", "LTC": "OWNER_CRYPTO_LTC",
                        }
                        crypto_address = cfg.get(_crypto_env_map.get(crypto_network, ""), "") or None
                        if not crypto_address:
                            errors.append("Selected crypto network is not configured.")
                    if not errors:
                        bp_bonus = BountyPayment(
                            report_id=invite.report_id,
                            invite_id=invite.id,
                            method=bonus_method,
                            amount=bonus_amount,
                            currency=bonus_currency,
                            paypal_recipient_email=paypal_email,
                            crypto_address=crypto_address,
                            crypto_network=crypto_network,
                            status="pending",
                            is_bonus=True,
                        )
                        db.session.add(bp_bonus)
                        db.session.add(InviteActivity(
                            invite_id=invite.id,
                            action="bonus_set",
                            ip_address=request.remote_addr,
                            user_agent=request.user_agent.string,
                            metadata_={"amount": str(bonus_amount), "currency": bonus_currency,
                                       "method": bonus_method},
                        ))
                        try:
                            from app.tasks.notifications import notify_owner
                            notify_owner.delay(event="bonus_set", invite_id=str(invite.id),
                                               report_id=str(report.id))
                        except Exception as exc:
                            current_app.logger.warning("notify_owner failed for set_bonus: %s", exc)
                        did_something = True

    # ── Reply ──────────────────────────────────────────────────────────────────
    # Handle file attachments
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")
    attachment_refs = []
    for f in request.files.getlist("reply_attachments"):
        if f and f.filename:
            try:
                from app.utils.mime_validator import validate_and_store_upload as _validate_upload
                file_bytes = f.read()
                res = _validate_upload(file_bytes, f.filename, str(invite.report_id), upload_folder)
                if res.is_valid:
                    att = ReportAttachment(
                        report_id=invite.report_id,
                        filename_original=f.filename[:500],
                        filename_stored=res.stored_filename,
                        mime_type=res.mime_type,
                        file_size=len(file_bytes),
                    )
                    db.session.add(att)
                    db.session.flush()
                    att_url = url_for("serve_attachment", attachment_uuid=str(att.id))
                    if res.mime_type and res.mime_type.startswith("image/"):
                        attachment_refs.append("![{}]({})".format(f.filename, att_url))
                    else:
                        attachment_refs.append("[{}]({})".format(f.filename, att_url))
                else:
                    flash("File rejected: {}".format(res.error), "warning")
            except Exception as exc:
                current_app.logger.warning("File upload error in compose: %s", exc)
                flash("File upload error: {}".format(exc), "warning")

    if attachment_refs:
        body = (body + "\n\n" + "\n".join(attachment_refs)).strip() if body.strip() else "\n".join(attachment_refs)

    if body.strip():
        r = ReportReply(
            report_id=invite.report_id,
            author_type="security_team",
            invite_id=invite.id,
            body=body,
            is_internal=False,
        )
        db.session.add(r)
        db.session.add(InviteActivity(
            invite_id=invite.id,
            action="reply_posted",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"author": invite.company_name or "Security Team"},
        ))
        try:
            from app.tasks.notifications import notify_owner
            notify_owner.delay(event="reply_posted", invite_id=str(invite.id),
                               report_id=str(invite.report_id))
        except Exception as exc:
            current_app.logger.warning("notify_owner failed for reply_posted: %s", exc)
        did_something = True

    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    if not did_something:
        flash("Nothing to submit — select an action or write a message.", "warning")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    invite.last_activity_at = utcnow()
    db.session.commit()
    flash("Submitted.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Status Change ──────────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/status", methods=["POST"])
@security_team_required
def change_status(invite_uuid):
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result

    new_status = request.form.get("status", "").strip()
    # Status is optional — if blank, skip without error
    if not new_status:
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))
    valid_statuses = {"triaged", "duplicate", "informative", "resolved", "wont_fix"}
    if new_status not in valid_statuses:
        flash("Invalid status.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    explanation = (request.form.get("explanation") or "").strip()
    if len(explanation) < 50:
        flash("Explanation must be at least 50 characters.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    report = invite.report
    report.status = new_status
    report.updated_at = utcnow()

    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="status_changed",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"new_status": new_status, "explanation": explanation[:500]},
    ))

    invite.last_activity_at = utcnow()
    db.session.commit()

    try:
        from app.tasks.notifications import notify_owner
        notify_owner.delay(event="status_changed", invite_id=str(invite.id),
                           report_id=str(report.id))
    except Exception as exc:
        current_app.logger.warning("notify_owner failed for status_changed: %s", exc)

    flash(f"Status updated to {new_status.replace('_', ' ').title()}.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Bounty ─────────────────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/bounty", methods=["POST"])
@security_team_required
def set_bounty(invite_uuid):
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result

    try:
        amount = float(request.form.get("bounty_amount") or 0)
    except (ValueError, TypeError):
        flash("Invalid amount.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    if amount <= 0:
        flash("Amount must be greater than zero.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    currency = (request.form.get("bounty_currency") or "USD").strip()[:10]
    method = (request.form.get("method") or "").strip()
    valid_methods = {"paypal", "crypto", "bank_transfer", "other"}
    if method not in valid_methods:
        flash("Please select a payment method.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    cfg = current_app.config
    paypal_email = None
    crypto_address = None
    crypto_network = None

    if method == "paypal":
        paypal_email = cfg.get("OWNER_PAYPAL_EMAIL", "") or None
    elif method == "crypto":
        crypto_network = (request.form.get("crypto_network") or "").strip()
        _crypto_env_map = {
            "BTC": "OWNER_CRYPTO_BTC", "ETH": "OWNER_CRYPTO_ETH",
            "USDT_TRC20": "OWNER_CRYPTO_USDT_TRC20", "USDT_ERC20": "OWNER_CRYPTO_USDT_ERC20",
            "USDC_ERC20": "OWNER_CRYPTO_USDC_ERC20", "XMR": "OWNER_CRYPTO_XMR",
            "BNB": "OWNER_CRYPTO_BNB", "DOGE": "OWNER_CRYPTO_DOGE", "LTC": "OWNER_CRYPTO_LTC",
        }
        crypto_address = cfg.get(_crypto_env_map.get(crypto_network, ""), "") or None
        if not crypto_address:
            flash("Selected crypto network is not configured.", "error")
            return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    report = invite.report
    report.bounty_amount = amount
    report.bounty_currency = currency

    payment = BountyPayment(
        report_id=invite.report_id,
        invite_id=invite.id,
        method=method,
        amount=amount,
        currency=currency,
        paypal_recipient_email=paypal_email,
        crypto_address=crypto_address,
        crypto_network=crypto_network,
        status="pending",
    )
    db.session.add(payment)
    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="bounty_set",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"amount": str(amount), "currency": currency, "method": method},
    ))
    invite.last_activity_at = utcnow()
    db.session.commit()

    try:
        from app.tasks.notifications import notify_owner
        notify_owner.delay(event="bounty_set", invite_id=str(invite.id),
                           report_id=str(report.id))
    except Exception as exc:
        current_app.logger.warning("notify_owner failed for bounty_set: %s", exc)

    flash(f"Bounty of {amount} {currency} set via {method.replace('_', ' ').title()}.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Bounty — Mark Sent ──────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/bounty/sent", methods=["POST"])
@security_team_required
def mark_bounty_sent(invite_uuid):
    """Security team marks they have sent the bounty (pending → processing)."""
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result

    payment = (BountyPayment.query
               .filter_by(invite_id=invite.id, status="pending")
               .order_by(BountyPayment.initiated_at.desc())
               .first())
    if not payment:
        flash("No pending bounty payment found.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    tx_reference = (request.form.get("tx_reference") or "").strip()[:500]
    payment.status = "processing"
    if tx_reference:
        payment.reference = tx_reference

    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="bounty_sent",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"method": payment.method,
                   "amount": str(payment.amount), "currency": payment.currency,
                   "tx_reference": tx_reference},
    ))
    invite.last_activity_at = utcnow()
    db.session.commit()

    try:
        from app.tasks.notifications import notify_owner
        notify_owner.delay(event="bounty_set", invite_id=str(invite.id),
                           report_id=str(invite.report_id))
    except Exception as exc:
        current_app.logger.warning("notify_owner failed for mark_bounty_sent: %s", exc)

    flash("Payment marked as sent. Awaiting researcher confirmation.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Field Edit Proposal ────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/field-edit", methods=["POST"])
@security_team_required
def submit_field_edit(invite_uuid):
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return result
    invite = result

    # Max 3 pending proposals
    pending_count = ReportFieldEdit.query.filter_by(
        invite_id=invite.id, status="pending").count()
    if pending_count >= 3:
        flash("Maximum 3 pending field edit proposals allowed.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    field_name = request.form.get("field_name", "").strip()
    # target_asset is intentionally excluded — not in the DB enum (field_edit_field)
    valid_fields = {"title", "severity", "cvss_vector", "cvss_score", "cwe_id", "cwe_name"}
    if field_name not in valid_fields:
        flash("Invalid field.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    proposed_value = (request.form.get("proposed_value") or "").strip()
    if not proposed_value:
        flash("Proposed value cannot be empty.", "error")
        return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))

    reason = (request.form.get("reason") or "").strip()

    report = invite.report
    old_value = json.dumps(getattr(report, field_name, None))

    db.session.add(ReportFieldEdit(
        report_id=invite.report_id,
        invite_id=invite.id,
        field_name=field_name,
        old_value=old_value,
        proposed_value=json.dumps(proposed_value),
        reason=reason,
    ))
    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="field_edit_proposed",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        metadata_={"field_name": field_name},
    ))
    invite.last_activity_at = utcnow()
    db.session.commit()

    try:
        from app.tasks.notifications import notify_owner
        notify_owner.delay(event="field_edit_proposed", invite_id=str(invite.id),
                           report_id=str(invite.report_id))
    except Exception as exc:
        current_app.logger.warning("notify_owner failed for field_edit_proposed: %s", exc)

    flash("Field correction proposal submitted for researcher review.", "success")
    return redirect(url_for("portal.view_report", invite_uuid=invite_uuid))


# ── Portal Logout ─────────────────────────────────────────────────────────────
@portal_bp.route("/portal/logout", methods=["POST"])
def portal_logout():
    """Log out security team member — clears portal session keys only."""
    try:
        member_id = session.get("portal_member_id")
        if member_id:
            mid = uuid.UUID(member_id)
            member = db.session.get(SecurityTeamMember, mid)
            if member:
                log_access_event(member, "logout")
    except Exception as exc:
        current_app.logger.warning("portal_logout: failed to log access event: %s", exc)
    for k in ("portal_role", "portal_member_id", "portal_member_email",
              "portal_session_id", "portal_last_active"):
        session.pop(k, None)
    session.modified = True
    from app.utils.auth_messages import MSG_LOGGED_OUT
    flash(MSG_LOGGED_OUT, "info")
    return redirect(url_for("auth.login"))


# ── Portal Session Refresh ────────────────────────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/refresh")
@security_team_required
def refresh_session(invite_uuid):
    session["portal_last_active"] = utcnow().isoformat()
    session.modified = True
    return jsonify({"ok": True})


# ── Poll for New Replies (real-time updates) ──────────────────────────────────
@portal_bp.route("/portal/report/<invite_uuid>/poll")
@security_team_required
def poll_updates(invite_uuid):
    """Return new thread items (replies + events) since a given ISO timestamp."""
    member = _get_current_member()
    result = _get_scoped_invite(invite_uuid, member)
    if not isinstance(result, SecurityTeamInvite):
        return jsonify({"error": "forbidden"}), 403
    invite = result
    report = invite.report

    since_str = request.args.get("since", "")
    since = None
    if since_str:
        try:
            since = datetime.fromisoformat(since_str)
            if since.tzinfo is None:
                since = since.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    items = []
    q = ReportReply.query.filter(
        ReportReply.report_id == report.id,
        ReportReply.is_internal == False,
        db.or_(ReportReply.invite_id == invite.id, ReportReply.author_type == "owner"),
    )
    if since:
        q = q.filter(ReportReply.created_at > since)
    for r in q.order_by(ReportReply.created_at.asc()).all():
        author_name = "Researcher" if r.author_type == "owner" else (
            r.invite.company_name if r.invite and r.invite.company_name else "Security Team"
        )
        items.append({
            "item_type": "reply",
            "author_type": r.author_type,
            "author_name": author_name,
            "body_html": render_markdown(r.body),
            "created_at": r.created_at.isoformat(),
        })

    _EVT_ACTIONS = {
        "status_changed", "bounty_set", "bounty_sent", "bounty_edited",
        "field_edit_accepted", "field_edit_rejected", "report_edited",
        "reply_posted", "field_edit_proposed", "retest_requested", "retest_confirmed",
        "report_reopened",
    }
    _EVT_LABELS = {
        "status_changed": ("arrow-repeat", "Status updated"),
        "bounty_set": ("currency-dollar", "Bounty offered"),
        "bounty_sent": ("send", "Payment sent"),
        "bounty_edited": ("pencil-square", "Bounty updated"),
        "report_edited": ("pencil", "Report updated by researcher"),
        "field_edit_accepted": ("check-circle", "Field correction accepted"),
        "field_edit_rejected": ("x-circle", "Field correction rejected"),
        "reply_posted": ("chat-dots", "Reply posted"),
        "field_edit_proposed": ("pencil-square", "Correction proposed"),
        "retest_requested": ("arrow-clockwise", "Retest requested"),
        "retest_confirmed": ("patch-check", "Retest confirmed"),
        "report_reopened": ("arrow-counterclockwise", "Report reopened"),
    }
    eq = InviteActivity.query.filter(
        InviteActivity.invite_id == invite.id,
        InviteActivity.action.in_(_EVT_ACTIONS),
    )
    if since:
        eq = eq.filter(InviteActivity.performed_at > since)
    for evt in eq.order_by(InviteActivity.performed_at.asc()).all():
        icon, label = _EVT_LABELS.get(evt.action, ("circle", evt.action))
        meta = evt.metadata_ or {}
        if evt.action == "status_changed" and meta.get("new_status"):
            label = "Status \u2192 " + meta["new_status"].replace("_", " ").upper()
        elif evt.action == "bounty_set" and meta.get("amount"):
            label = "Bounty offered: {} {}".format(meta["amount"], meta.get("currency", ""))
        elif evt.action == "bounty_sent" and meta.get("amount"):
            label = "Payment sent: {} {}".format(meta["amount"], meta.get("currency", ""))
        elif evt.action == "retest_confirmed" and meta.get("outcome"):
            label = "Retest: {}".format(meta["outcome"].replace("_", " ").title())
        elif evt.action == "reply_posted" and meta.get("author"):
            label = "Reply by {}".format(meta["author"])
        elif evt.action == "field_edit_proposed" and meta.get("field_name"):
            label = "Correction proposed: {}".format(meta["field_name"].replace("_", " "))
        elif evt.action == "field_edit_accepted":
            field = meta.get("field") or meta.get("field_name", "")
            if field:
                label = "Correction accepted: {}".format(field.replace("_", " "))
        elif evt.action == "field_edit_rejected":
            field = meta.get("field") or meta.get("field_name", "")
            if field:
                label = "Correction rejected: {}".format(field.replace("_", " "))
        # reply_posted is a timeline-only event — it already appears as a full reply bubble
        # in the discussion thread, so JS should not add it there again.
        items.append({
            "item_type": "event",
            "action": evt.action,
            "icon": icon,
            "label": label,
            "created_at": (evt.performed_at or utcnow()).isoformat(),
            "timeline_only": evt.action in ("reply_posted",),
        })

    items.sort(key=lambda x: x["created_at"])
    return jsonify({"items": items, "now": utcnow().isoformat()})


# ── Access Expired ─────────────────────────────────────────────────────────────
@portal_bp.route("/portal/access-expired")
def access_expired():
    return render_template("portal/access_expired.html",
                           platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"))
