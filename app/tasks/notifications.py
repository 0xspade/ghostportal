# GhostPortal notifications task
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from app.extensions import celery, mail

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=3, default_retry_delay=60)
def send_magic_link_email_task(self, email, url_token, otp, role):
    try:
        from flask_mail import Message
        from flask import current_app, render_template
        platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
        base_url = current_app.config.get("BASE_URL", "")
        expiry_min = current_app.config.get("MAGIC_LINK_EXPIRY_MINUTES", 15)
        verify_url = f"{base_url}/auth/verify/{url_token}"
        otp_display = "  ".join(otp[i:i+5] for i in range(0, len(otp), 5))

        plain_body = (
            f"{platform_name} Verification\n\n"
            f"Click to open verification page:\n{verify_url}\n\n"
            f"Your verification code:\n{otp_display}\n\n"
            f"Expires in {expiry_min} minutes. Single-use only.\n"
        )

        html_body = None
        try:
            html_body = render_template(
                "email/magic_link.html",
                platform_name=platform_name,
                verify_url=verify_url,
                otp_display=otp_display,
                expiry_min=expiry_min,
            )
        except Exception as tmpl_exc:
            logger.warning(f"Magic link HTML template failed, falling back to plain: {tmpl_exc}")

        msg = Message(
            subject=f"[{platform_name}] Your verification code — expires in {expiry_min} minutes",
            recipients=[email],
            body=plain_body,
            html=html_body,
        )
        mail.send(msg)
        logger.info(f"Magic link email sent to {email[:3]}***")
    except Exception as exc:
        logger.error(f"Failed to send magic link email: {exc}")
        try:
            self.retry(exc=exc)
        except Exception:
            pass

@celery.task(bind=True, max_retries=3)
def retry_failed(self):
    from app.models import Notification
    from app.extensions import db
    from datetime import datetime, timezone
    pending = Notification.query.filter_by(status="failed").limit(50).all()
    for notif in pending:
        try:
            notif.status = "retrying"
            notif.attempts += 1
            notif.last_attempt_at = datetime.now(timezone.utc)
            db.session.add(notif)
        except Exception as exc:
            logger.error(f"Retry notification {notif.id} failed: {exc}")
    db.session.commit()

@celery.task
def send_expiry_warnings():
    from app.models import SecurityTeamInvite
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    warn_7d = now + timedelta(days=7)
    warn_1d = now + timedelta(days=1)
    expiring_7d = SecurityTeamInvite.query.filter(
        SecurityTeamInvite.expires_at <= warn_7d,
        SecurityTeamInvite.expires_at > now,
        SecurityTeamInvite.is_active == True,
    ).all()
    for invite in expiring_7d:
        logger.info(f"Invite expiring soon: {invite.id}")

@celery.task
def send_severity_escalation_alerts():
    from app.models import Report, SecurityTeamInvite
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=14)
    critical_reports = Report.query.filter(
        Report.severity.in_(["critical","high"]),
        Report.status.in_(["submitted","triaged"]),
        Report.created_at < cutoff,
    ).all()
    for report in critical_reports:
        logger.warning(f"Severity escalation alert: {report.display_id}")


@celery.task(bind=True, max_retries=3, default_retry_delay=300)
def notify_owner(self, event=None, invite_id=None, report_id=None, **kwargs):
    """Send owner notification via all configured channels for a given event."""
    import uuid as _uuid
    from app.models import SecurityTeamInvite, Report
    try:
        invite = SecurityTeamInvite.query.get(_uuid.UUID(invite_id)) if invite_id else None
        report = Report.query.get(_uuid.UUID(report_id)) if report_id else None
        if not invite or not report:
            logger.warning(f"notify_owner: missing invite or report for event={event}")
            return
        _send_owner_notification(event, invite, report)
    except Exception as exc:
        logger.error(f"notify_owner failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)


@celery.task(bind=True, max_retries=3, default_retry_delay=120)
def send_invite_email(self, invite_id_str, raw_token="", raw_otp=""):
    """Send invite email to security team member."""
    from app.models import SecurityTeamInvite, Report
    import uuid as _uuid
    try:
        invite_id = _uuid.UUID(invite_id_str)
        invite = SecurityTeamInvite.query.get(invite_id)
        if not invite:
            logger.warning(f"send_invite_email: invite {invite_id_str} not found")
            return
        report = Report.query.get(invite.report_id)
        if not report:
            logger.warning(f"send_invite_email: report not found for invite {invite_id_str}")
            return
        logger.info(f"Sending invite email to {invite.email} for report {report.display_id}")
        _send_invite_email_impl(invite, report, raw_token, raw_otp)
    except Exception as exc:
        logger.error(f"send_invite_email failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)


@celery.task(bind=True, max_retries=3, default_retry_delay=300)
def notify_security_team(self, event=None, report_id=None, **kwargs):
    """Notify all active security team members for a report (e.g. owner replied)."""
    import uuid as _uuid
    from datetime import datetime, timezone
    from app.models import SecurityTeamInvite, Report
    try:
        if not report_id:
            return
        report = Report.query.get(_uuid.UUID(report_id))
        if not report:
            return
        now = datetime.now(timezone.utc)
        invites = SecurityTeamInvite.query.filter_by(
            report_id=report.id, is_active=True, is_locked=False
        ).filter(SecurityTeamInvite.expires_at > now).all()
        for invite in invites:
            _notify_member_of_owner_reply(event, invite, report)
    except Exception as exc:
        logger.error(f"notify_security_team failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)


def _notify_member_of_owner_reply(event, invite, report):
    """Send a plain-text email to a security team member notifying of owner reply."""
    from flask import current_app
    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
    base_url = current_app.config.get("BASE_URL", "").rstrip("/")
    portal_url = f"{base_url}/portal/dashboard"
    try:
        from flask_mail import Message
        from app.extensions import mail
        msg = Message(
            subject=f"[{platform_name}] New researcher reply — {report.display_id}",
            recipients=[invite.email],
            body=(
                f"{platform_name}\n\n"
                f"The researcher has posted a new reply on report {report.display_id}.\n\n"
                f"Report: {report.title}\n"
                f"Program: {report.program_name or 'N/A'}\n"
                f"Severity: {(report.severity or 'unknown').upper()}\n\n"
                f"Visit your portal to view the reply:\n{portal_url}\n\n"
                f"This is an automated notification from {platform_name}."
            ),
        )
        mail.send(msg)
        logger.info(f"Security team reply notification sent to {invite.email[:3]}***")
    except Exception as exc:
        logger.error(f"_notify_member_of_owner_reply failed for invite {invite.id}: {exc}")


@celery.task
def send_test_notification(channel, config_json):
    """Send a test notification on the specified channel."""
    import json
    config = json.loads(config_json) if isinstance(config_json, str) else config_json
    if channel == "email":
        _send_test_email(config)
    elif channel == "discord":
        _send_test_discord(config)
    elif channel == "telegram":
        _send_test_telegram(config)
    else:
        logger.warning(f"Unknown test notification channel: {channel}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _send_owner_notification(event, invite, report):
    """Dispatch owner notifications via configured channels (email + Discord + Telegram)."""
    from flask import current_app

    platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
    owner_email = current_app.config.get("OWNER_EMAIL", "")
    base_url = current_app.config.get("BASE_URL", "").rstrip("/")

    _EVENT_LABELS = {
        "reply_posted":   "New Reply from Security Team",
        "status_changed": "Report Status Changed",
        "bounty_set":     "Bounty Amount Set",
        "bonus_set":      "Bonus Offered",
        "link_clicked":   "Invite Link Clicked",
        "setup_complete": "Security Team Portal Setup Complete",
    }
    label = _EVENT_LABELS.get(event, event.replace("_", " ").title())
    company = (invite.company_name or invite.email) if invite else "Unknown"
    severity = (report.severity or "unknown").upper()
    report_url = f"{base_url}/reports/{report.id}"

    # Special subject/body for bounty events
    if event == "bounty_set":
        bounty_amt = getattr(report, "bounty_amount", None)
        bounty_cur = getattr(report, "bounty_currency", "USD") or "USD"
        amt_str = f"{bounty_amt} {bounty_cur}" if bounty_amt else "amount TBD"
        subject = f"[{platform_name}] BOUNTY SET — {amt_str} on {report.display_id}"
        body = (
            f"{'=' * 55}\n"
            f"  {platform_name} — BOUNTY AWARDED\n"
            f"{'=' * 55}\n\n"
            f"  Report   : {report.display_id} — {report.title}\n"
            f"  Company  : {company}\n"
            f"  Severity : {severity}\n"
            f"  Bounty   : {amt_str}\n"
            f"  Status   : {report.status}\n"
            f"  View     : {report_url}\n\n"
            f"{'=' * 55}\n"
        )
    elif event == "bonus_set":
        # Get amount from the most recent pending bonus payment for this invite
        from app.models import BountyPayment as _BP
        _bonus_p = (_BP.query
                    .filter_by(report_id=report.id, is_bonus=True, status="pending")
                    .order_by(_BP.initiated_at.desc()).first())
        amt_str = (f"{_bonus_p.amount} {_bonus_p.currency}" if _bonus_p else "amount TBD")
        subject = f"[{platform_name}] BONUS OFFERED — {amt_str} on {report.display_id}"
        body = (
            f"{'*' * 55}\n"
            f"  {platform_name} — BONUS OFFERED\n"
            f"{'*' * 55}\n\n"
            f"  {company} has offered a bonus reward after a confirmed retest.\n\n"
            f"  Report   : {report.display_id} — {report.title}\n"
            f"  Company  : {company}\n"
            f"  Severity : {severity}\n"
            f"  Bonus    : {amt_str}\n"
            f"  View     : {report_url}\n\n"
            f"  Confirm receipt in the Bounty section of the report.\n"
            f"{'*' * 55}\n"
        )
    else:
        subject = f"[{platform_name}] {label} — {report.display_id}"
        body = (
            f"{platform_name} — {label}\n\n"
            f"Report   : {report.display_id} — {report.title}\n"
            f"Company  : {company}\n"
            f"Severity : {severity}\n"
            f"Status   : {report.status}\n"
            f"View     : {report_url}\n"
        )

    # E-mail to owner
    if owner_email:
        try:
            from flask_mail import Message
            from app.extensions import mail
            msg = Message(subject=subject, recipients=[owner_email], body=body)
            mail.send(msg)
            logger.info(f"Owner email sent for event={event} report={report.display_id}")
        except Exception as exc:
            logger.error(f"Owner email failed for event={event}: {exc}", exc_info=True)

    # Discord webhook
    discord_url = current_app.config.get("DISCORD_WEBHOOK_URL", "")
    if discord_url:
        _SEVERITY_COLORS = {
            "critical": 0xFF0000, "high": 0xFF6600,
            "medium": 0xFFAA00, "low": 0x00AAFF, "informational": 0x888888,
        }
        color = _SEVERITY_COLORS.get(report.severity or "", 0x00FF88)
        if event == "bounty_set":
            # Gold color for bounty notifications
            color = 0xFFD700
            bounty_amt = getattr(report, "bounty_amount", None)
            bounty_cur = getattr(report, "bounty_currency", "USD") or "USD"
            amt_str = f"{bounty_amt} {bounty_cur}" if bounty_amt else "TBD"
            embed_fields = [
                {"name": "Company",  "value": company,    "inline": True},
                {"name": "Bounty",   "value": amt_str,    "inline": True},
                {"name": "Severity", "value": severity,   "inline": True},
                {"name": "Report",   "value": report.title, "inline": False},
            ]
            embed_title = f"BOUNTY AWARDED — {report.display_id}"
        elif event == "bonus_set":
            # Distinct teal/cyan color to differentiate from regular bounty gold
            color = 0x00D4FF
            from app.models import BountyPayment as _BP2
            _bonus_p2 = (_BP2.query
                         .filter_by(report_id=report.id, is_bonus=True, status="pending")
                         .order_by(_BP2.initiated_at.desc()).first())
            amt_str = (f"{_bonus_p2.amount} {_bonus_p2.currency}" if _bonus_p2 else "TBD")
            embed_fields = [
                {"name": "Company",  "value": company,      "inline": True},
                {"name": "Bonus",    "value": amt_str,      "inline": True},
                {"name": "Severity", "value": severity,     "inline": True},
                {"name": "Report",   "value": report.title, "inline": False},
            ]
            embed_title = f"BONUS OFFERED — {report.display_id}"
        else:
            embed_fields = [
                {"name": "Company",  "value": company,         "inline": True},
                {"name": "Severity", "value": severity,        "inline": True},
                {"name": "Status",   "value": report.status,   "inline": True},
                {"name": "Report",   "value": report.title,    "inline": False},
            ]
            embed_title = f"{label} — {report.display_id}"
        embed = {
            "title": embed_title,
            "color": color,
            "fields": embed_fields,
            "url": report_url,
        }
        try:
            from app.utils.safe_fetch import safe_fetch
            safe_fetch(discord_url, method="POST", json={"embeds": [embed]}, timeout=(5, 10))
            logger.info(f"Discord notification sent for event={event}")
        except Exception as exc:
            logger.error(f"Discord notification failed for event={event}: {exc}", exc_info=True)

    # Telegram bot
    tg_token = current_app.config.get("TELEGRAM_BOT_TOKEN", "")
    tg_chat = current_app.config.get("TELEGRAM_CHAT_ID", "")
    if tg_token and tg_chat:
        if event == "bounty_set":
            bounty_amt = getattr(report, "bounty_amount", None)
            bounty_cur = getattr(report, "bounty_currency", "USD") or "USD"
            amt_str = f"{bounty_amt} {bounty_cur}" if bounty_amt else "TBD"
            tg_text = (
                f"<b>BOUNTY AWARDED</b>\n"
                f"Report: <code>{report.display_id}</code> — {report.title}\n"
                f"Company: {company}\n"
                f"Bounty: <b>{amt_str}</b>\n"
                f"Severity: {severity}\n"
                f'<a href="{report_url}">View Report</a>'
            )
        elif event == "bonus_set":
            from app.models import BountyPayment as _BP3
            _bonus_p3 = (_BP3.query
                         .filter_by(report_id=report.id, is_bonus=True, status="pending")
                         .order_by(_BP3.initiated_at.desc()).first())
            amt_str = (f"{_bonus_p3.amount} {_bonus_p3.currency}" if _bonus_p3 else "TBD")
            tg_text = (
                f"<b>BONUS OFFERED</b>\n"
                f"Report: <code>{report.display_id}</code> — {report.title}\n"
                f"Company: {company}\n"
                f"Bonus: <b>{amt_str}</b>\n"
                f"Severity: {severity}\n"
                f'<a href="{report_url}">View Report</a>'
            )
        else:
            tg_text = (
                f"<b>{label}</b>\n"
                f"Report: <code>{report.display_id}</code> — {report.title}\n"
                f"Company: {company}\n"
                f"Severity: {severity} | Status: {report.status}\n"
                f'<a href="{report_url}">View Report</a>'
            )
        try:
            from app.utils.safe_fetch import safe_fetch
            safe_fetch(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                method="POST",
                json={"chat_id": tg_chat, "text": tg_text, "parse_mode": "HTML",
                      "disable_web_page_preview": True},
                timeout=(5, 10),
            )
            logger.info(f"Telegram notification sent for event={event}")
        except Exception as exc:
            logger.error(f"Telegram notification failed for event={event}: {exc}", exc_info=True)


def _send_invite_email_impl(invite, report, raw_token="", raw_otp=""):
    """Send the actual invite email via Flask-Mail."""
    from flask import current_app
    from flask_mail import Message
    from app.extensions import mail
    try:
        platform_name = current_app.config.get("PLATFORM_NAME", "GhostPortal")
        base_url = current_app.config.get("BASE_URL", "").rstrip("/")
        severity = (report.severity or "unknown").upper()
        portal_url = f"{base_url}/portal/{raw_token}" if raw_token else ""

        subject = (
            f"[{platform_name}] Security Vulnerability Report — "
            f"{report.program_name or 'Unknown'} | Severity: {severity}"
        )
        body_lines = [
            f"{platform_name} — Vulnerability Disclosure",
            "=" * 50,
            "",
            "You are receiving this because a security researcher has identified a potential",
            "vulnerability and wishes to disclose it responsibly.",
            "",
            f"  Report ID : {report.display_id}",
            f"  Program   : {report.program_name or 'Unknown'}",
            f"  Severity  : {severity}",
        ]
        if report.cwe_id:
            body_lines.append(f"  CWE       : CWE-{report.cwe_id}{(' — ' + report.cwe_name) if report.cwe_name else ''}")
        if report.cvss_score:
            body_lines.append(f"  CVSS 4.0  : {report.cvss_score:.1f}")
        if report.target_asset:
            body_lines.append(f"  Asset     : {report.target_asset}")
        body_lines += [
            "",
            "ACCESS THE REPORT",
            "-" * 30,
        ]
        if portal_url:
            body_lines += [
                f"  Portal URL: {portal_url}",
                "",
                "  Click the link above to access the full vulnerability report,",
                "  submit your response, and set a bounty if applicable.",
                f"  This link expires in {current_app.config.get('INVITE_EXPIRY_DAYS', 90)} days.",
            ]
        else:
            body_lines.append("  [Portal URL unavailable — contact the researcher]")

        # Always include OTP if provided — required to complete portal setup
        if raw_otp:
            otp_display = "  ".join(raw_otp[i:i+5] for i in range(0, len(raw_otp), 5))
            body_lines += [
                "",
                "VERIFICATION CODE (required on first access)",
                "-" * 44,
                "",
                f"  {otp_display}",
                "",
                "  Enter this code on the portal setup page after clicking the link above.",
                "  This code is single-use and expires with the link.",
                "  Do not share this code.",
            ]

        body_lines += [
            "",
            "=" * 50,
            "If you did not expect this report, ignore this email.",
            f"Contact: {current_app.config.get('OPERATOR_EMAIL', current_app.config.get('OWNER_EMAIL', ''))}",
        ]
        body = "\n".join(body_lines)
        msg = Message(subject=subject, recipients=[invite.email], body=body)
        mail.send(msg)
        logger.info(f"Invite email sent to {invite.email}")
    except Exception as exc:
        logger.error(f"Failed to send invite email: {exc}", exc_info=True)
        raise


def _send_test_email(config):
    from flask_mail import Message
    from app.extensions import mail
    try:
        msg = Message(
            subject="[GhostPortal] Test Email",
            recipients=[config.get("recipient", "")],
            body="This is a test email from GhostPortal.",
        )
        mail.send(msg)
        logger.info("Test email sent successfully")
    except Exception as exc:
        logger.error(f"Test email failed: {exc}", exc_info=True)
        raise


def _send_test_discord(config):
    from app.utils.safe_fetch import safe_fetch
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return
    try:
        safe_fetch(webhook_url, method="POST",
                   json={"content": "GhostPortal test notification"}, timeout=(5, 10))
        logger.info("Test Discord notification sent")
    except Exception as exc:
        logger.error(f"Test Discord failed: {exc}", exc_info=True)
        raise


def _send_test_telegram(config):
    from app.utils.safe_fetch import safe_fetch
    token = config.get("bot_token", "")
    chat_id = config.get("chat_id", "")
    if not token or not chat_id:
        return
    try:
        safe_fetch(
            f"https://api.telegram.org/bot{token}/sendMessage",
            method="POST",
            json={"chat_id": chat_id, "text": "GhostPortal test notification"},
            timeout=(5, 10),
        )
        logger.info("Test Telegram notification sent")
    except Exception as exc:
        logger.error(f"Test Telegram failed: {exc}", exc_info=True)
        raise
