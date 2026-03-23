# GhostPortal resolved/terminal access expiry
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from datetime import datetime, timezone, timedelta
from app.extensions import celery

logger = logging.getLogger(__name__)

# Statuses that trigger the access-expiry countdown
_TERMINAL_STATUSES = {"resolved", "informative", "duplicate", "wont_fix"}


@celery.task
def check_resolved_access_expiry():
    """
    Daily task: expire security team access when a report is in a terminal status
    and has had no activity for RESOLVED_ACCESS_EXPIRY_DAYS (default 10).
    Sends 3-day and 1-day email warnings before expiry.
    Deactivates the invite; deactivates the member if they have no other active invites.
    """
    from app.models import SecurityTeamInvite, SecurityTeamMember, ReportReply, InviteActivity
    from app.extensions import db
    from flask import current_app

    expiry_days = int(current_app.config.get("RESOLVED_ACCESS_EXPIRY_DAYS", 10))
    now = datetime.now(timezone.utc)

    active_invites = SecurityTeamInvite.query.filter_by(is_active=True).all()
    for invite in active_invites:
        report = invite.report
        if not report:
            continue

        # ── Step 1: Mark all_resolved_at when terminal status first detected ──
        if report.status in _TERMINAL_STATUSES and invite.all_resolved_at is None:
            invite.all_resolved_at = now
            db.session.add(invite)
            db.session.flush()
            continue  # re-process on next daily run

        # ── Step 2: Reset if status was reverted to non-terminal ──
        if report.status not in _TERMINAL_STATUSES and invite.all_resolved_at is not None:
            invite.all_resolved_at = None
            invite.resolved_expiry_notified_3d = False
            invite.resolved_expiry_notified_1d = False
            db.session.add(invite)
            continue

        if invite.all_resolved_at is None:
            continue

        expiry_date = invite.all_resolved_at + timedelta(days=expiry_days)
        days_remaining = (expiry_date - now).days

        # ── Step 3: Send 3-day warning ──
        if days_remaining <= 3 and not invite.resolved_expiry_notified_3d:
            _send_expiry_warning(invite, report, days_remaining, expiry_date)
            invite.resolved_expiry_notified_3d = True
            db.session.add(invite)

        # ── Step 4: Send 1-day warning ──
        elif days_remaining <= 1 and not invite.resolved_expiry_notified_1d:
            _send_expiry_warning(invite, report, days_remaining, expiry_date)
            invite.resolved_expiry_notified_1d = True
            db.session.add(invite)

        # ── Step 5: Expire access ──
        if now >= expiry_date:
            invite.is_active = False
            db.session.add(invite)
            logger.info(
                f"Expired access for invite {invite.id} "
                f"(report {report.display_id}, status={report.status})"
            )
            # Deactivate member if they have no other active invites
            _maybe_deactivate_member(invite.email, db)

    db.session.commit()


def _maybe_deactivate_member(email, db):
    """Deactivate SecurityTeamMember if they have no remaining active invites."""
    from app.models import SecurityTeamMember, SecurityTeamInvite
    remaining = SecurityTeamInvite.query.filter_by(
        email=email, is_active=True
    ).count()
    if remaining == 0:
        member = SecurityTeamMember.query.filter_by(email=email, is_active=True).first()
        if member:
            member.is_active = False
            db.session.add(member)
            logger.info(f"Deactivated member {email} — no remaining active invites")


def _send_expiry_warning(invite, report, days_remaining, expiry_date):
    """Send expiry warning email + owner notification."""
    from flask import current_app
    try:
        from flask_mail import Message
        from app.extensions import mail
        platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
        base_url = current_app.config.get("BASE_URL", "").rstrip("/")
        owner_email = current_app.config.get("OWNER_EMAIL", "")

        days_word = "1 day" if days_remaining <= 1 else f"{days_remaining} days"
        expiry_str = expiry_date.strftime("%Y-%m-%d")

        # Email to security team member
        body = (
            f"{platform_name} — Access Expiry Notice\n\n"
            f"Your access to the vulnerability report portal will expire in {days_word} "
            f"({expiry_str}).\n\n"
            f"Report: {report.display_id} — {report.title}\n"
            f"Program: {report.program_name or 'N/A'}\n"
            f"Status: {report.status.replace('_', ' ').upper()}\n\n"
            f"After expiry, you will no longer be able to access this report on the portal.\n"
            f"If you have any outstanding responses, please submit them before {expiry_str}.\n\n"
            f"If you believe this is an error, contact: "
            f"{current_app.config.get('OPERATOR_EMAIL', owner_email)}\n"
        )
        msg = Message(
            subject=f"[{platform_name}] Portal Access Expiring in {days_word} — {report.display_id}",
            recipients=[invite.email],
            body=body,
        )
        mail.send(msg)
        logger.info(f"Expiry warning ({days_word}) sent to {invite.email[:3]}***")

        # Notify owner
        if owner_email:
            owner_body = (
                f"{platform_name} — Access Expiry Warning Sent\n\n"
                f"A {days_word} expiry warning was sent to the security team for:\n"
                f"Report: {report.display_id} — {report.title}\n"
                f"Company: {invite.company_name or invite.email}\n"
                f"Expires: {expiry_str}\n"
            )
            owner_msg = Message(
                subject=f"[{platform_name}] Expiry Warning Sent — {report.display_id}",
                recipients=[owner_email],
                body=owner_body,
            )
            mail.send(owner_msg)
    except Exception as exc:
        logger.error(f"Failed to send expiry warning for invite {invite.id}: {exc}")
