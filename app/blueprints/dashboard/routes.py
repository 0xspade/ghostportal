# GhostPortal -- Project-Apocalypse -- Dashboard Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

from datetime import datetime, timezone, timedelta
from flask import current_app, redirect, render_template, session, url_for
from sqlalchemy import func

from app.blueprints.dashboard import dashboard_bp
from app.blueprints.decorators import owner_required
from app.extensions import db
from app.models import Report, SecurityTeamInvite


def utcnow():
    return datetime.now(timezone.utc)


def _ensure_utc(dt):
    """Return UTC-aware datetime, treating naive datetimes as UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dashboard_bp.route("/")
def root():
    if session.get("role") == "owner":
        return redirect(url_for("dashboard.index"))
    if session.get("role") == "security_team":
        return redirect(url_for("portal.dashboard"))
    return redirect(url_for("auth.login"))


@dashboard_bp.route("/dashboard")
@owner_required
def index():
    now = utcnow()
    seven_days = now + timedelta(days=7)

    # ── Stats Cards ───────────────────────────────────────────────────────────
    total_reports = Report.query.count()
    open_reports = Report.query.filter(
        Report.status.in_(["submitted", "triaged"])
    ).count()
    resolved_reports = Report.query.filter_by(status="resolved").count()

    bounty_row = db.session.query(func.sum(Report.bounty_amount)).filter(
        Report.bounty_paid_at.isnot(None)
    ).scalar()
    total_bounty = "${:,.2f}".format(float(bounty_row or 0))

    active_invites_qs = (
        SecurityTeamInvite.query
        .filter_by(is_active=True, is_locked=False)
        .filter(SecurityTeamInvite.expires_at > now)
        .all()
    )
    active_invite_count = len(active_invites_qs)
    expiring_soon = sum(
        1 for i in active_invites_qs
        if _ensure_utc(i.expires_at) < seven_days
    )

    avg_response = None
    try:
        replied = [
            i for i in active_invites_qs
            if i.last_activity_at and i.created_at
        ]
        if replied:
            deltas = [
                (
                    _ensure_utc(i.last_activity_at) - _ensure_utc(i.created_at)
                ).total_seconds() / 86400
                for i in replied
            ]
            avg_response = round(sum(deltas) / len(deltas), 1) if deltas else None
    except Exception:
        pass

    stats = {
        "total_reports": total_reports,
        "open_reports": open_reports,
        "resolved_reports": resolved_reports,
        "total_bounty": total_bounty,
        "active_invites": active_invite_count,
        "expiring_soon": expiring_soon,
        "avg_response_days": avg_response,
    }

    # ── Chart Data ────────────────────────────────────────────────────────────

    def _submissions_weekly():
        """Last 12 weeks, one data point per week."""
        labels, data = [], []
        for weeks_ago in range(11, -1, -1):
            start = now - timedelta(weeks=weeks_ago + 1)
            end = now - timedelta(weeks=weeks_ago)
            count = Report.query.filter(
                Report.created_at >= start,
                Report.created_at < end,
            ).count()
            labels.append(start.strftime("%d %b"))
            data.append(count)
        return {"labels": labels, "data": data}

    def _submissions_monthly():
        """Last 12 months, one data point per month."""
        labels, data = [], []
        for months_ago in range(11, -1, -1):
            m = now.month - months_ago
            y = now.year
            while m <= 0:
                m += 12
                y -= 1
            start = datetime(y, m, 1, tzinfo=timezone.utc)
            end = datetime(y + 1, 1, 1, tzinfo=timezone.utc) if m == 12 \
                else datetime(y, m + 1, 1, tzinfo=timezone.utc)
            count = Report.query.filter(
                Report.created_at >= start,
                Report.created_at < end,
            ).count()
            labels.append(start.strftime("%b %Y"))
            data.append(count)
        return {"labels": labels, "data": data}

    def _submissions_yearly():
        """Last 5 years, one data point per year."""
        labels, data = [], []
        for years_ago in range(4, -1, -1):
            y = now.year - years_ago
            start = datetime(y, 1, 1, tzinfo=timezone.utc)
            end = datetime(y + 1, 1, 1, tzinfo=timezone.utc)
            count = Report.query.filter(
                Report.created_at >= start,
                Report.created_at < end,
            ).count()
            labels.append(str(y))
            data.append(count)
        return {"labels": labels, "data": data}

    by_status = {
        st: Report.query.filter_by(status=st).count()
        for st in ("draft", "submitted", "triaged", "duplicate",
                   "informative", "resolved", "wont_fix")
    }

    by_severity = {
        sev: Report.query.filter_by(severity=sev).count()
        for sev in ("critical", "high", "medium", "low", "informational")
    }

    # CVSS score histogram — 10 buckets [0,1) … [9,10]
    cvss_labels = [f"{i}-{i+1}" for i in range(10)]
    cvss_data = []
    for i in range(10):
        low, high = float(i), float(i + 1)
        q = Report.query.filter(Report.cvss_score >= low)
        q = q.filter(Report.cvss_score <= high) if i == 9 \
            else q.filter(Report.cvss_score < high)
        cvss_data.append(q.count())

    # Top 10 CWEs by frequency
    cwe_rows = (
        db.session.query(
            Report.cwe_id,
            Report.cwe_name,
            func.count(Report.id).label("cnt")
        )
        .filter(Report.cwe_id.isnot(None))
        .group_by(Report.cwe_id, Report.cwe_name)
        .order_by(func.count(Report.id).desc())
        .limit(10)
        .all()
    )
    top_cwe_labels = [
        (f"CWE-{r.cwe_id}: {r.cwe_name or ''}")[:40]
        for r in cwe_rows
    ]
    top_cwe_data = [r.cnt for r in cwe_rows]

    # Bounty paid per month (last 12 months)
    bounty_labels, bounty_data = [], []
    for months_ago in range(11, -1, -1):
        m = now.month - months_ago
        y = now.year
        while m <= 0:
            m += 12
            y -= 1
        start = datetime(y, m, 1, tzinfo=timezone.utc)
        end = datetime(y + 1, 1, 1, tzinfo=timezone.utc) if m == 12 \
            else datetime(y, m + 1, 1, tzinfo=timezone.utc)
        amount = db.session.query(func.sum(Report.bounty_amount)).filter(
            Report.bounty_paid_at >= start,
            Report.bounty_paid_at < end,
        ).scalar()
        bounty_labels.append(start.strftime("%b %Y"))
        bounty_data.append(float(amount or 0))

    chart_data = {
        "submissions": {
            "weekly": _submissions_weekly(),
            "monthly": _submissions_monthly(),
            "yearly": _submissions_yearly(),
        },
        "by_status": by_status,
        "by_severity": by_severity,
        "cvss_distribution": {"labels": cvss_labels, "data": cvss_data},
        "top_cwe": {"labels": top_cwe_labels, "data": top_cwe_data},
        "bounty_by_month": {"labels": bounty_labels, "data": bounty_data},
    }

    # ── Follow-Up Radar ───────────────────────────────────────────────────────
    followup_data = []
    for invite in active_invites_qs[:20]:
        created = _ensure_utc(invite.created_at)
        last_act = _ensure_utc(invite.last_activity_at)
        days_since_sent = (now - created).days if created else None
        last_activity_days = (now - last_act).days if last_act else None

        if last_activity_days is None or last_activity_days > 30:
            health = "red"
        elif last_activity_days > 14:
            health = "amber"
        else:
            health = "green"

        report = invite.report
        followup_data.append({
            "company_name": invite.company_name,
            "report_id": str(report.id) if report else None,
            "display_id": report.display_id if report else "—",
            "severity": report.severity if report else "—",
            "days_since_sent": days_since_sent,
            "followup_30_sent_at": invite.followup_30_sent_at,
            "followup_60_sent_at": invite.followup_60_sent_at,
            "followup_90_sent_at": invite.followup_90_sent_at,
            "last_activity_at": last_act,
            "health": health,
        })

    return render_template(
        "dashboard/index.html",
        stats=stats,
        chart_data=chart_data,
        followup_data=followup_data,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )
