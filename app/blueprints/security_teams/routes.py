# GhostPortal -- Project-Apocalypse -- Security Teams Management Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

from datetime import datetime, timezone, timedelta
from flask import (abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)

from app.blueprints.security_teams import security_teams_bp
from app.blueprints.decorators import owner_required, parse_uuid
from app.extensions import db
from app.models import SecurityTeamInvite, SecurityTeamMember, InviteActivity, SecurityTeamSession, ReportReply


def utcnow():
    return datetime.now(timezone.utc)


@security_teams_bp.route("/security-teams")
@owner_required
def list_teams():
    now = utcnow()
    invites = (SecurityTeamInvite.query
               .order_by(SecurityTeamInvite.created_at.desc())
               .all())

    # Annotate health
    for invite in invites:
        days_since = None
        if invite.last_activity_at:
            days_since = (now - invite.last_activity_at).days
        if days_since is None or days_since > 30 or (
                invite.expires_at and (invite.expires_at - now).days < 7):
            invite._health = "red"
        elif days_since > 14:
            invite._health = "amber"
        else:
            invite._health = "green"

    return render_template(
        "security_teams/list.html",
        invites=invites,
        now=now,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


@security_teams_bp.route("/security-teams/<invite_uuid>/lock", methods=["POST"])
@owner_required
def lock(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)
    invite.is_locked = True
    invite.lock_reason = (request.form.get("reason") or "").strip()[:500]
    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="account_locked",
        ip_address=request.remote_addr,
        metadata_={"reason": invite.lock_reason},
    ))
    db.session.commit()
    flash("Account locked.", "success")
    return redirect(url_for("security_teams.list_teams"))


@security_teams_bp.route("/security-teams/<invite_uuid>/unlock", methods=["POST"])
@owner_required
def unlock(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)
    invite.is_locked = False
    invite.lock_reason = None
    db.session.add(InviteActivity(
        invite_id=invite.id,
        action="account_unlocked",
        ip_address=request.remote_addr,
    ))
    db.session.commit()
    flash("Account unlocked.", "success")
    return redirect(url_for("security_teams.list_teams"))


@security_teams_bp.route("/security-teams/<invite_uuid>/extend", methods=["POST"])
@owner_required
def extend(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)
    ext_days = int(current_app.config.get("INVITE_EXTENSION_DAYS", 30))
    base = invite.expires_at if invite.expires_at and invite.expires_at > utcnow() else utcnow()
    invite.expires_at = base + timedelta(days=ext_days)
    invite.extended_count += 1
    db.session.commit()
    flash(f"Invite extended by {ext_days} days.", "success")
    return redirect(url_for("security_teams.list_teams"))


@security_teams_bp.route("/security-teams/<invite_uuid>/edit", methods=["POST"])
@owner_required
def edit(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)
    new_company = (request.form.get("company_name") or "").strip()[:200]
    new_email = (request.form.get("email") or "").strip().lower()
    if new_company:
        invite.company_name = new_company
    if new_email and "@" in new_email:
        invite.email = new_email
    db.session.commit()
    flash("Invite updated.", "success")
    return redirect(url_for("security_teams.list_teams"))


@security_teams_bp.route("/security-teams/<invite_uuid>/delete", methods=["POST"])
@owner_required
def delete(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)

    # Redact replies (FK is SET NULL on invite delete, so do this first)
    ReportReply.query.filter_by(invite_id=iid).update(
        {"body": "[REDACTED — Account Deleted]"}, synchronize_session=False
    )

    # Revoke all portal sessions for this invite
    SecurityTeamSession.query.filter_by(invite_id=iid).delete(synchronize_session=False)

    # Delete the invite record (InviteActivity cascades via DB FK)
    db.session.delete(invite)
    db.session.commit()

    flash("Invite deleted.", "success")
    return redirect(url_for("security_teams.list_teams"))


@security_teams_bp.route("/security-teams/<invite_uuid>/activity")
@owner_required
def activity_log(invite_uuid):
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.get_or_404(iid)
    activities = (InviteActivity.query
                  .filter_by(invite_id=iid)
                  .order_by(InviteActivity.performed_at.desc())
                  .all())
    return jsonify([{
        "action": a.action,
        "performed_at": a.performed_at.isoformat() if a.performed_at else None,
        "ip_address": a.ip_address,
        "metadata": a.metadata_ or {},
    } for a in activities])
