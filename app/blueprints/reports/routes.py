# GhostPortal -- Project-Apocalypse -- Reports Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import json
import secrets
import uuid
from datetime import datetime, timezone, timedelta

from flask import (abort, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for, make_response)

from app.blueprints.reports import reports_bp
from app.blueprints.decorators import owner_required, parse_uuid
from app.extensions import db, limiter, csrf
from app.models import (Report, ReportAttachment, ReportVersion, SecurityTeamInvite,
                        SecurityTeamMember, InviteActivity, ReportReply,
                        ReportFieldEdit, ExternalLink, FollowUpSchedule,
                        Notification, ProgramName, ReportTemplate, BountyPayment,
                        SecurityTeamSession)
from app.utils.security import generate_otp, hash_token
from app.utils.display_id import generate_display_id
from app.utils.markdown_renderer import sanitize_markdown, render_markdown
from app.utils.duplicate_check import check_for_duplicates as check_duplicate
from app.utils.program_names import save_program_name as upsert_program_name
from app.utils.export import export_report_json, export_report_markdown
from app.utils.mime_validator import validate_and_store_upload as validate_and_save, secure_delete_file as secure_delete
from app.utils.secrets_scanner import scan_for_secrets
from app.middleware.access_logger import log_access_event


def utcnow():
    return datetime.now(timezone.utc)


def _safe_float(val):
    try:
        return float(val) if val else None
    except (ValueError, TypeError):
        return None


def _safe_int(val):
    try:
        return int(val) if val else None
    except (ValueError, TypeError):
        return None


def _sanitize_report_fields(form):
    """Sanitize and extract all report fields from form data."""
    return {
        "title": (form.get("title") or "").strip()[:500],
        "description": sanitize_markdown(form.get("description") or ""),
        "steps_to_reproduce": sanitize_markdown(form.get("steps_to_reproduce") or ""),
        "proof_of_concept": sanitize_markdown(form.get("proof_of_concept") or ""),
        "impact_statement": sanitize_markdown(form.get("impact_statement") or ""),
        "remediation": sanitize_markdown(form.get("remediation") or ""),
        "technical_details": sanitize_markdown(form.get("technical_details") or ""),
        "target_asset": (form.get("target_asset") or "").strip()[:500],
        "program_name": (form.get("program_name") or "").strip()[:300],
        "cvss_vector": (form.get("cvss_vector") or "").strip()[:500],
        "cvss_score": _safe_float(form.get("cvss_score")),
        "cwe_id": _safe_int(form.get("cwe_id")),
        "cwe_name": (form.get("cwe_name") or "").strip()[:300],
        "severity": form.get("severity") or None,
        "tags": _safe_json_list(form.get("tags")),
        "bounty_amount": _safe_float(form.get("bounty_amount")),
        "bounty_currency": (form.get("bounty_currency") or "USD").strip()[:10],
        "template_id": form.get("template_id") or None,
    }


def _safe_json_list(val):
    try:
        parsed = json.loads(val or "[]")
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


# ── Report List ──────────────────────────────────────────────────────────────
@reports_bp.route("/reports")
@owner_required
def list_reports():
    severity_filter = request.args.getlist("severity")
    status_filter = request.args.getlist("status")
    search = (request.args.get("q") or "").strip()
    page = max(1, int(request.args.get("page", 1) or 1))

    query = Report.query.order_by(Report.created_at.desc())
    if severity_filter:
        query = query.filter(Report.severity.in_(severity_filter))
    if status_filter:
        query = query.filter(Report.status.in_(status_filter))
    if search:
        query = query.filter(
            db.or_(
                Report.title.ilike(f"%{search}%"),
                Report.description.ilike(f"%{search}%"),
                Report.display_id.ilike(f"%{search}%"),
            )
        )

    pagination = query.paginate(page=page, per_page=25, error_out=False)
    return render_template(
        "reports/list.html",
        pagination=pagination,
        reports=pagination.items,
        search=search,
        severity_filter=severity_filter,
        status_filter=status_filter,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


# ── New Report ───────────────────────────────────────────────────────────────
@reports_bp.route("/reports/new", methods=["GET", "POST"])
@owner_required
def new_report():
    templates = ReportTemplate.query.order_by(ReportTemplate.name).all()

    # Build list of configured AI providers
    ai_providers = []
    _ai_map = {
        "anthropic": ("Anthropic Claude", "ANTHROPIC_API_KEY"),
        "openai": ("OpenAI", "OPENAI_API_KEY"),
        "gemini": ("Google Gemini", "GEMINI_API_KEY"),
        "ollama": ("Ollama (Local)", None),
    }
    for key, (label, env_key) in _ai_map.items():
        if env_key is None or current_app.config.get(env_key):
            ai_providers.append({"id": key, "label": label})

    if request.method == "GET":
        template_id = request.args.get("template")
        prefill = {}
        if template_id:
            try:
                tmpl = ReportTemplate.query.get(uuid.UUID(template_id))
                if tmpl:
                    prefill = {
                        "title": tmpl.title_template or "",
                        "description": tmpl.description_template or "",
                        "steps_to_reproduce": tmpl.steps_template or "",
                        "proof_of_concept": tmpl.poc_template or "",
                        "remediation": tmpl.remediation_template or "",
                        "cwe_id": tmpl.cwe_id,
                        "cwe_name": tmpl.cwe_name or "",
                        "severity": tmpl.severity or "",
                        "cvss_vector": tmpl.cvss_vector or "",
                        "tags": tmpl.tags or [],
                    }
            except (ValueError, Exception):
                pass
        return render_template(
            "reports/new.html",
            templates=templates,
            prefill=prefill,
            ai_providers=ai_providers,
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        )

    # POST
    fields = _sanitize_report_fields(request.form)
    if not fields["title"]:
        flash("Report title is required.", "error")
        return render_template("reports/new.html", templates=templates, prefill=fields,
                               ai_providers=ai_providers,
                               platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"))

    # Secrets scan
    secrets_found = scan_for_secrets({
        "description": fields.get("description") or "",
        "proof_of_concept": fields.get("proof_of_concept") or "",
        "technical_details": fields.get("technical_details") or "",
    })

    # Duplicate detection
    duplicates = check_duplicate(
        fields["title"], fields.get("cwe_id"), fields.get("target_asset"))

    action = request.form.get("action", "submit")
    report_id = uuid.uuid4()
    report = Report(
        id=report_id,
        display_id=generate_display_id(report_id),
        title=fields["title"],
        description=fields["description"],
        steps_to_reproduce=fields["steps_to_reproduce"],
        proof_of_concept=fields["proof_of_concept"],
        impact_statement=fields["impact_statement"],
        remediation=fields["remediation"],
        technical_details=fields["technical_details"],
        target_asset=fields["target_asset"],
        program_name=fields["program_name"],
        cvss_score=fields["cvss_score"],
        cvss_vector=fields["cvss_vector"],
        cwe_id=fields["cwe_id"],
        cwe_name=fields["cwe_name"],
        severity=fields["severity"],
        tags=fields["tags"],
        bounty_amount=fields["bounty_amount"],
        bounty_currency=fields["bounty_currency"],
        status="submitted" if action == "submit" else "draft",
        submitted_at=utcnow() if action == "submit" else None,
    )
    db.session.add(report)

    # Handle attachments
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")
    for f in request.files.getlist("attachments"):
        if f and f.filename:
            try:
                file_bytes = f.read()
                result = validate_and_save(file_bytes, f.filename, str(report_id), upload_folder)
                if not result.is_valid:
                    flash(f"File rejected: {result.error}", "warning")
                    continue
                att = ReportAttachment(
                    report_id=report_id,
                    filename_original=f.filename[:500],
                    filename_stored=result.stored_filename,
                    mime_type=result.mime_type,
                    file_size=len(file_bytes),
                )
                db.session.add(att)
            except Exception as exc:
                flash(f"File rejected: {exc}", "warning")

    db.session.commit()

    # Process invite recipients when submitting (not drafting)
    if action == "submit":
        _rec_emails = request.form.getlist("recipient_emails[]")
        _rec_labels = request.form.getlist("recipient_labels[]")
        _valid_invites = []
        for _i, _em in enumerate(_rec_emails):
            _em = (_em or "").strip().lower()
            if _em and "@" in _em:
                _lbl = (_rec_labels[_i] if _i < len(_rec_labels) else "").strip()
                _valid_invites.append((_em, _lbl))
        if _valid_invites:
            _expiry_days = int(current_app.config.get("INVITE_EXPIRY_DAYS", 90))
            _expiry_dt = utcnow() + timedelta(days=_expiry_days)
            _fs_raw = current_app.config.get("FOLLOWUP_SCHEDULE", "30,60,90")
            _fdays = [int(d.strip()) for d in (
                _fs_raw if isinstance(_fs_raw, str) else ",".join(str(d) for d in _fs_raw)
            ).split(",") if d.strip().isdigit()]
            _pending_tasks = []
            for _em, _lbl in _valid_invites:
                _raw_tok = secrets.token_urlsafe(48)
                _raw_otp = generate_otp(20)
                _invite = SecurityTeamInvite(
                    report_id=report_id, email=_em, label=_lbl,
                    token_hash=hash_token(_raw_tok), otp_hash=hash_token(_raw_otp),
                    expires_at=_expiry_dt,
                )
                db.session.add(_invite)
                db.session.flush()
                for _day in _fdays:
                    db.session.add(FollowUpSchedule(
                        invite_id=_invite.id, scheduled_days=str(_day),
                        scheduled_at=utcnow() + timedelta(days=_day),
                    ))
                db.session.add(InviteActivity(
                    invite_id=_invite.id, action="invite_sent",
                    ip_address=request.remote_addr, user_agent=request.user_agent.string,
                    metadata_={"report_id": str(report_id), "display_id": report.display_id},
                ))
                _pending_tasks.append((str(_invite.id), _raw_tok, _raw_otp))
            db.session.commit()
            from app.tasks.notifications import send_invite_email as _sie
            for _iid, _rt, _ro in _pending_tasks:
                try:
                    _sie.delay(_iid, _rt, _ro)
                except Exception:
                    current_app.logger.exception("Failed to queue invite email %s", _iid)
            flash(f"Invites sent to {len(_pending_tasks)} recipient(s).", "success")

    # Save program name (best-effort)
    if fields["program_name"]:
        try:
            upsert_program_name(fields["program_name"])
            db.session.commit()
        except Exception:
            pass

    if secrets_found and not request.form.get("secrets_dismissed"):
        flash(
            f"Warning: {len(secrets_found)} potential secret(s) detected in report fields. "
            "Review before sending to security team.", "warning"
        )

    log_access_event(None, "report_created", metadata={"report_id": str(report_id)})
    flash("Report saved successfully.", "success")
    return redirect(url_for("reports.view_report", report_uuid=str(report_id)))


# ── View Report ──────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>")
@owner_required
def view_report(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    invites = (SecurityTeamInvite.query
               .filter_by(report_id=rid)
               .order_by(SecurityTeamInvite.created_at.desc())
               .all())
    replies = (ReportReply.query
               .filter_by(report_id=rid)
               .order_by(ReportReply.created_at.asc())
               .all())
    pending_edits = ReportFieldEdit.query.filter_by(report_id=rid, status="pending").all()
    attachments = ReportAttachment.query.filter_by(report_id=rid).all()

    rendered = {k: render_markdown(getattr(report, k) or "") for k in [
        "description", "steps_to_reproduce", "proof_of_concept",
        "impact_statement", "remediation", "technical_details",
    ]}

    # Invite health
    now = utcnow()
    for invite in invites:
        days_since = None
        if invite.last_activity_at:
            days_since = (now - invite.last_activity_at).days
        if days_since is None:
            invite._health = "red"
        elif days_since <= 14:
            invite._health = "green"
        elif days_since <= 30:
            invite._health = "amber"
        else:
            invite._health = "red"

    payments = BountyPayment.query.filter_by(report_id=rid).order_by(
        BountyPayment.initiated_at.desc()).all()

    # Build unified discussion thread (replies + notable activity events from all invites)
    invite_ids = [inv.id for inv in invites]
    _THREAD_ACTIONS = {
        "status_changed", "bounty_set", "bounty_sent", "bounty_edited",
        "field_edit_accepted", "field_edit_rejected", "report_edited",
        "retest_requested", "retest_confirmed", "report_reopened",
    }
    _THREAD_LABELS = {
        "status_changed": ("arrow-repeat", "Status updated"),
        "bounty_set": ("currency-dollar", "Bounty offered"),
        "bounty_sent": ("send", "Payment sent"),
        "bounty_edited": ("pencil-square", "Bounty edited"),
        "field_edit_accepted": ("check-circle", "Field correction accepted"),
        "field_edit_rejected": ("x-circle", "Field correction rejected"),
        "report_edited": ("pencil", "Report updated by owner"),
        "retest_requested": ("arrow-clockwise", "Retest requested"),
        "retest_confirmed": ("patch-check", "Retest confirmed"),
        "report_reopened": ("arrow-counterclockwise", "Report reopened by security team"),
    }
    # Broader set for activity sidebar (includes events that shouldn't duplicate in thread)
    _SIDEBAR_ACTIONS = _THREAD_ACTIONS | {
        "reply_posted", "invite_sent", "link_clicked", "setup_complete",
        "account_locked", "account_unlocked", "field_edit_proposed",
        "bounty_confirmed", "bonus_confirmed",
    }
    all_activity = []
    if invite_ids:
        all_activity = (InviteActivity.query
                        .filter(InviteActivity.invite_id.in_(invite_ids))
                        .filter(InviteActivity.action.in_(_SIDEBAR_ACTIONS))
                        .order_by(InviteActivity.performed_at.desc())
                        .all())

    thread_items = []
    for r in replies:
        if r.is_internal:
            continue
        invite_name = r.invite.company_name if r.invite and r.invite.company_name else "Security Team"
        thread_items.append({
            "item_type": "reply",
            "author_type": r.author_type,
            "author_name": "Researcher" if r.author_type == "owner" else invite_name,
            "body_html": render_markdown(r.body),
            "created_at": r.created_at,
        })
    for evt in all_activity:
        if evt.action not in _THREAD_ACTIONS:
            continue  # sidebar-only events, skip to avoid duplicates in thread
        icon, label = _THREAD_LABELS.get(evt.action, ("circle", evt.action))
        meta = evt.metadata_ or {}
        company = None
        if evt.invite_id:
            inv_obj = SecurityTeamInvite.query.get(evt.invite_id)
            company = inv_obj.company_name if inv_obj else None
        if evt.action == "status_changed" and meta.get("new_status"):
            label = "Status \u2192 {}{}".format(
                meta["new_status"].replace("_", " ").upper(),
                " (by {})".format(company) if company else ""
            )
        elif evt.action == "bounty_set" and meta.get("amount"):
            label = "Bounty offered: {} {}{}".format(
                meta["amount"], meta.get("currency", ""),
                " by {}".format(company) if company else ""
            )
        elif evt.action == "bounty_edited" and meta.get("new_amount"):
            label = "Bounty updated: {} {} \u2192 {} {}{}".format(
                meta.get("old_amount", "?"), meta.get("old_currency", ""),
                meta["new_amount"], meta.get("new_currency", ""),
                " by {}".format(company) if company else ""
            )
        elif evt.action == "retest_requested":
            label = "Retest requested{}".format(
                " by {}".format(company) if company else ""
            )
        elif evt.action == "retest_confirmed":
            outcome = meta.get("outcome", "")
            label = "Retest confirmed{}{}".format(
                ": {}".format(outcome.replace("_", " ").title()) if outcome else "",
                " by researcher" if not company else ""
            )
        elif evt.action == "bounty_sent" and meta.get("amount"):
            label = "Payment sent: {} {}{}".format(
                meta["amount"], meta.get("currency", ""),
                " by {}".format(company) if company else ""
            )
        elif company and evt.action == "field_edit_accepted":
            label = "Field correction accepted (proposed by {})".format(company)
        thread_items.append({
            "item_type": "event",
            "action": evt.action,
            "icon": icon,
            "label": label,
            "created_at": evt.performed_at or now,
        })
    thread_items.sort(key=lambda x: x["created_at"])

    # Find invites with pending retest (requested but not yet confirmed)
    retest_pending_invites = []
    if invite_ids:
        for inv in invites:
            has_req = InviteActivity.query.filter_by(
                invite_id=inv.id, action="retest_requested"
            ).order_by(InviteActivity.performed_at.desc()).first()
            has_conf = InviteActivity.query.filter_by(
                invite_id=inv.id, action="retest_confirmed"
            ).order_by(InviteActivity.performed_at.desc()).first()
            # Pending if last retest_requested is newer than last retest_confirmed
            if has_req:
                if not has_conf or has_req.performed_at > has_conf.performed_at:
                    retest_pending_invites.append(inv)

    log_access_event(None, "report_viewed",
                     metadata={"report_id": str(rid), "display_id": report.display_id})
    return render_template(
        "reports/detail.html",
        report=report,
        invites=invites,
        replies=replies,
        thread_items=thread_items,
        all_activity=all_activity,
        pending_edits=pending_edits,
        attachments=attachments,
        rendered=rendered,
        payments=payments,
        retest_pending_invites=retest_pending_invites,
        now=now,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


# ── Edit Report ──────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/edit", methods=["GET", "POST"])
@owner_required
def edit_report(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)

    if request.method == "GET":
        templates = ReportTemplate.query.order_by(ReportTemplate.name).all()
        ai_providers = []
        _ai_map = {
            "anthropic": ("Anthropic Claude", "ANTHROPIC_API_KEY"),
            "openai": ("OpenAI", "OPENAI_API_KEY"),
            "gemini": ("Google Gemini", "GEMINI_API_KEY"),
            "ollama": ("Ollama (Local)", None),
        }
        for key, (label, env_key) in _ai_map.items():
            if env_key is None or current_app.config.get(env_key):
                ai_providers.append({"id": key, "label": label})
        prefill = {
            "title": report.title or "",
            "description": report.description or "",
            "steps_to_reproduce": report.steps_to_reproduce or "",
            "proof_of_concept": report.proof_of_concept or "",
            "impact_statement": report.impact_statement or "",
            "remediation": report.remediation or "",
            "technical_details": report.technical_details or "",
            "target_asset": report.target_asset or "",
            "program_name": report.program_name or "",
            "cvss_vector": report.cvss_vector or "",
            "cvss_score": report.cvss_score,
            "cwe_id": report.cwe_id,
            "cwe_name": report.cwe_name or "",
            "severity": report.severity or "",
            "tags": report.tags or [],
            "bounty_amount": report.bounty_amount,
            "bounty_currency": report.bounty_currency or "USD",
        }
        return render_template(
            "reports/new.html",
            templates=templates,
            prefill=prefill,
            ai_providers=ai_providers,
            is_edit=True,
            edit_report_uuid=str(report.id),
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        )

    # POST
    if report.is_locked:
        flash("Report is locked and cannot be edited.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))
    fields = _sanitize_report_fields(request.form)
    # Capture old values before update for change logging
    _tracked_fields = [
        "title", "severity", "cvss_score", "cvss_vector", "cwe_id", "cwe_name",
        "target_asset", "program_name", "description", "steps_to_reproduce",
        "proof_of_concept", "impact_statement", "remediation", "technical_details",
    ]
    _old_vals = {k: getattr(report, k, None) for k in _tracked_fields}

    # Determine which fields will change before applying them
    _will_change = [k for k in _tracked_fields
                    if str(_old_vals.get(k) or "") != str(fields.get(k) or "")]

    # Snapshot the current state before applying changes (#17 ReportVersion)
    if _will_change:
        db.session.add(ReportVersion(
            report_id=rid,
            snapshot={k: str(_old_vals[k]) if _old_vals[k] is not None else None
                      for k in _tracked_fields},
            changed_fields=_will_change,
        ))

    for k, v in fields.items():
        if hasattr(report, k) and v is not None:
            setattr(report, k, v)
    report.updated_at = utcnow()

    # Handle new attachment uploads on edit
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")
    for f in request.files.getlist("attachments"):
        if f and f.filename:
            try:
                file_bytes = f.read()
                result = validate_and_save(file_bytes, f.filename, str(rid), upload_folder)
                if not result.is_valid:
                    flash(f"File rejected: {result.error}", "warning")
                    continue
                att = ReportAttachment(
                    report_id=rid,
                    filename_original=f.filename[:500],
                    filename_stored=result.stored_filename,
                    mime_type=result.mime_type,
                    file_size=len(file_bytes),
                )
                db.session.add(att)
            except Exception as exc:
                flash(f"File upload error: {exc}", "warning")

    db.session.commit()

    # Log changes in discussion thread + invite activity
    _short_fields = {"title", "severity", "cvss_score", "cvss_vector", "cwe_id",
                     "cwe_name", "target_asset", "program_name"}
    _changed = _will_change  # already computed above
    if _changed:
        _lines = ["**Report updated by owner**\n"]
        for _k in _changed:
            if _k in _short_fields:
                _lines.append(
                    f"- **{_k}**: `{str(_old_vals.get(_k) or '(empty)')[:80]}` "
                    f"→ `{str(fields.get(_k) or '(empty)')[:80]}`"
                )
            else:
                _lines.append(f"- **{_k}**: (content updated)")
        db.session.add(ReportReply(
            report_id=rid, author_type="owner",
            body=sanitize_markdown("\n".join(_lines)), is_internal=False,
        ))
        for _inv in SecurityTeamInvite.query.filter_by(report_id=rid, is_active=True).all():
            db.session.add(InviteActivity(
                invite_id=_inv.id, action="report_edited",
                metadata_={"changed_fields": _changed},
            ))
        db.session.commit()

    flash("Report updated.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Reply ────────────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/reply", methods=["POST"])
@owner_required
def reply(report_uuid):
    rid = parse_uuid(report_uuid)
    Report.query.get_or_404(rid)
    body = sanitize_markdown(request.form.get("body") or "")
    is_internal = request.form.get("is_internal") == "1"

    # Handle reply attachments
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")
    attachment_refs = []
    for f in request.files.getlist("reply_attachments"):
        if f and f.filename:
            try:
                file_bytes = f.read()
                result = validate_and_save(file_bytes, f.filename, str(rid), upload_folder)
                if result.is_valid:
                    att = ReportAttachment(
                        report_id=rid,
                        filename_original=f.filename[:500],
                        filename_stored=result.stored_filename,
                        mime_type=result.mime_type,
                        file_size=len(file_bytes),
                    )
                    db.session.add(att)
                    db.session.flush()
                    att_url = url_for("serve_attachment", attachment_uuid=str(att.id))
                    if result.mime_type and result.mime_type.startswith("image/"):
                        attachment_refs.append("![{}]({})".format(f.filename, att_url))
                    else:
                        attachment_refs.append("[{}]({})".format(f.filename, att_url))
                else:
                    flash("File rejected: {}".format(result.error), "warning")
            except Exception as exc:
                flash("File upload error: {}".format(exc), "warning")

    if attachment_refs:
        body = (body + "\n\n" + "\n".join(attachment_refs)).strip() if body.strip() else "\n".join(attachment_refs)

    if not body.strip():
        flash("Reply cannot be empty.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    r = ReportReply(report_id=rid, author_type="owner", body=body, is_internal=is_internal)
    db.session.add(r)

    # Log InviteActivity for all active invites (visible in owner activity sidebar)
    if not is_internal:
        for _inv in SecurityTeamInvite.query.filter_by(report_id=rid, is_active=True).all():
            db.session.add(InviteActivity(
                invite_id=_inv.id, action="reply_posted",
                ip_address=request.remote_addr,
                metadata_={"author": "Researcher"},
            ))

    db.session.commit()

    # Notify active security team members (only for public replies, not internal notes)
    if not is_internal:
        try:
            from app.tasks.notifications import notify_security_team
            notify_security_team.delay(event="owner_reply", report_id=str(rid))
        except Exception:
            pass

    flash("Reply posted.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Quick Action (status change + optional bounty set, owner-side) ────────────
@reports_bp.route("/reports/<report_uuid>/quick-action", methods=["POST"])
@owner_required
def quick_action(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    action = (request.form.get("action") or "").strip()

    _VALID_STATUSES = {"draft", "submitted", "triaged", "duplicate", "informative", "resolved", "wont_fix", "not_applicable"}
    _CLOSED_STATUSES = {"duplicate", "informative", "resolved", "wont_fix", "not_applicable"}

    if action in _VALID_STATUSES:
        old_status = report.status
        report.status = action
        # Log a ReportVersion snapshot
        db.session.add(ReportVersion(
            report_id=rid,
            snapshot={"status": old_status},
            changed_fields=["status"],
        ))
        # Handle all_resolved_at for all invites on this report
        for _inv in SecurityTeamInvite.query.filter_by(report_id=rid).all():
            if action in _CLOSED_STATUSES:
                # Start 15-day countdown if not already running
                if _inv.all_resolved_at is None:
                    _inv.all_resolved_at = utcnow()
                    _inv.resolved_expiry_notified_3d = False
                    _inv.resolved_expiry_notified_1d = False
            else:
                # Status moved back to non-closed — lift the countdown
                _inv.all_resolved_at = None
                _inv.resolved_expiry_notified_3d = False
                _inv.resolved_expiry_notified_1d = False
            db.session.add(InviteActivity(
                invite_id=_inv.id,
                action="status_changed",
                ip_address=request.remote_addr,
                metadata_={"old_status": old_status, "new_status": action, "changed_by": "owner"},
            ))
        db.session.commit()
        flash("Status updated.", "success")

    elif action == "set_bounty":
        try:
            amount = float(request.form.get("bounty_amount") or 0)
        except (ValueError, TypeError):
            amount = 0.0
        currency = (request.form.get("bounty_currency") or "USD").strip()[:10]
        method = (request.form.get("bounty_method") or "other").strip()
        tx_ref = (request.form.get("bounty_reference") or "").strip()[:500]
        if amount <= 0:
            flash("Bounty amount must be greater than 0.", "error")
            return redirect(url_for("reports.view_report", report_uuid=report_uuid))
        bp = BountyPayment(
            report_id=rid,
            method=method,
            amount=amount,
            currency=currency,
            reference=tx_ref,
            status="completed",
            initiated_at=utcnow(),
            completed_at=utcnow(),
        )
        db.session.add(bp)
        # Also update the report-level bounty field for display in meta bar
        report.bounty_amount = amount
        report.bounty_currency = currency
        report.bounty_paid_at = utcnow()
        for _inv in SecurityTeamInvite.query.filter_by(report_id=rid).all():
            db.session.add(InviteActivity(
                invite_id=_inv.id,
                action="bounty_set",
                ip_address=request.remote_addr,
                metadata_={"amount": str(amount), "currency": currency, "method": method},
            ))
        db.session.commit()
        flash("Bounty recorded.", "success")
    else:
        flash("Unknown action.", "error")

    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Send Invite ──────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/invite/send", methods=["POST"])
@owner_required
@limiter.limit("5 per day")
def send_invite(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    expiry_days = int(current_app.config.get("INVITE_EXPIRY_DAYS", 90))
    expiry_dt = utcnow() + timedelta(days=expiry_days)
    _fs_raw = current_app.config.get("FOLLOWUP_SCHEDULE", "30,60,90")
    if isinstance(_fs_raw, str):
        followup_schedule = [int(d.strip()) for d in _fs_raw.split(",") if d.strip().isdigit()]
    else:
        followup_schedule = [int(d) for d in _fs_raw]

    emails_raw = request.form.getlist("email[]") or [request.form.get("email", "")]
    labels_raw = request.form.getlist("label[]") or [""]
    # Collect Celery task args; dispatch only AFTER successful commit
    pending_email_tasks = []

    for idx, email in enumerate(emails_raw):
        email = (email or "").strip().lower()
        if not email or "@" not in email:
            continue
        label = (labels_raw[idx] if idx < len(labels_raw) else "").strip()

        raw_token = secrets.token_urlsafe(48)
        raw_otp = generate_otp(20)
        token_hash = hash_token(raw_token)
        otp_hash = hash_token(raw_otp)

        invite = SecurityTeamInvite(
            report_id=rid,
            email=email,
            label=label,
            token_hash=token_hash,
            otp_hash=otp_hash,
            expires_at=expiry_dt,
        )
        db.session.add(invite)
        db.session.flush()

        for day in followup_schedule:
            db.session.add(FollowUpSchedule(
                invite_id=invite.id,
                scheduled_days=str(day),
                scheduled_at=utcnow() + timedelta(days=day),
            ))

        db.session.add(InviteActivity(
            invite_id=invite.id,
            action="invite_sent",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"report_id": str(rid), "display_id": report.display_id},
        ))

        db.session.add(Notification(
            report_id=rid, invite_id=invite.id,
            channel="email", event="invite_sent", recipient=email,
        ))

        pending_email_tasks.append((str(invite.id), raw_token, raw_otp))

    if not pending_email_tasks:
        flash("No valid email addresses provided.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    if report.status == "draft":
        report.status = "submitted"
        report.submitted_at = utcnow()

    db.session.commit()

    # Dispatch email tasks only after DB commit — invite records now exist
    from app.tasks.notifications import send_invite_email
    for invite_id_str, raw_token, raw_otp in pending_email_tasks:
        try:
            send_invite_email.delay(invite_id_str, raw_token, raw_otp)
        except Exception:
            current_app.logger.exception("Failed to queue invite email for invite %s", invite_id_str)

    flash(f"Invite sent to {len(pending_email_tasks)} recipient(s).", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Extend Invite ─────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/invite/<invite_uuid>/extend", methods=["POST"])
@owner_required
def extend_invite(report_uuid, invite_uuid):
    rid = parse_uuid(report_uuid)
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.filter_by(id=iid, report_id=rid).first_or_404()
    ext_days = int(current_app.config.get("INVITE_EXTENSION_DAYS", 30))
    base = invite.expires_at if invite.expires_at and invite.expires_at > utcnow() else utcnow()
    invite.expires_at = base + timedelta(days=ext_days)
    invite.extended_count += 1
    db.session.commit()
    flash(f"Invite extended by {ext_days} days.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Lock Invite ───────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/invite/<invite_uuid>/lock", methods=["POST"])
@owner_required
def lock_invite(report_uuid, invite_uuid):
    rid = parse_uuid(report_uuid)
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.filter_by(id=iid, report_id=rid).first_or_404()
    invite.is_locked = True
    invite.lock_reason = (request.form.get("lock_reason") or "").strip()[:500]
    db.session.commit()
    flash("Invite locked.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Unlock Invite ─────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/invite/<invite_uuid>/unlock", methods=["POST"])
@owner_required
def unlock_invite(report_uuid, invite_uuid):
    rid = parse_uuid(report_uuid)
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.filter_by(id=iid, report_id=rid).first_or_404()
    invite.is_locked = False
    invite.lock_reason = None
    db.session.commit()
    flash("Invite unlocked.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Delete Invite ─────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/invite/<invite_uuid>/delete", methods=["POST"])
@owner_required
def delete_invite(report_uuid, invite_uuid):
    rid = parse_uuid(report_uuid)
    iid = parse_uuid(invite_uuid)
    invite = SecurityTeamInvite.query.filter_by(id=iid, report_id=rid).first_or_404()

    # Redact replies before deletion (FK is SET NULL on invite delete)
    ReportReply.query.filter_by(invite_id=iid).update(
        {"body": "[REDACTED — Account Deleted]"}, synchronize_session=False
    )
    # Revoke portal sessions
    SecurityTeamSession.query.filter_by(invite_id=iid).delete(synchronize_session=False)
    # Delete invite (InviteActivity, FollowUpSchedule, Notification cascade)
    db.session.delete(invite)
    db.session.commit()

    flash("Invite deleted and replies redacted.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Field Edit Accept/Reject ──────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/field-edit/<edit_uuid>/accept", methods=["POST"])
@owner_required
def accept_field_edit(report_uuid, edit_uuid):
    rid = parse_uuid(report_uuid)
    eid = parse_uuid(edit_uuid)
    report = Report.query.get_or_404(rid)
    edit = ReportFieldEdit.query.filter_by(
        id=eid, report_id=rid, status="pending").first_or_404()

    try:
        new_value = json.loads(edit.proposed_value)
    except (json.JSONDecodeError, TypeError):
        new_value = edit.proposed_value

    field_map = {
        "title": ("title", lambda v: str(v)[:500]),
        "severity": ("severity", str),
        "cvss_score": ("cvss_score", float),
        "cvss_vector": ("cvss_vector", lambda v: str(v)[:500]),
        "cwe_id": ("cwe_id", int),
        "cwe_name": ("cwe_name", lambda v: str(v)[:300]),
        "target_asset": ("target_asset", lambda v: str(v)[:500]),
    }
    if edit.field_name in field_map:
        attr, cast = field_map[edit.field_name]
        try:
            setattr(report, attr, cast(new_value))
        except (ValueError, TypeError):
            flash("Could not apply proposed value.", "error")
            return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    edit.status = "accepted"
    edit.reviewed_at = utcnow()
    db.session.add(InviteActivity(
        invite_id=edit.invite_id,
        action="field_edit_accepted",
        metadata_={"field": edit.field_name, "new_value": str(new_value)[:200]},
    ))
    db.session.commit()
    flash(f"Field edit for '{edit.field_name}' accepted.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


@reports_bp.route("/reports/<report_uuid>/field-edit/<edit_uuid>/reject", methods=["POST"])
@owner_required
def reject_field_edit(report_uuid, edit_uuid):
    rid = parse_uuid(report_uuid)
    eid = parse_uuid(edit_uuid)
    edit = ReportFieldEdit.query.filter_by(
        id=eid, report_id=rid, status="pending").first_or_404()
    edit.status = "rejected"
    edit.reviewed_at = utcnow()
    db.session.commit()
    flash("Field edit proposal rejected.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Bounty Confirm Receipt ────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/bounty/confirm", methods=["POST"])
@owner_required
def confirm_bounty_receipt(report_uuid):
    """Owner confirms they received the bounty payment from security team."""
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    if not report.bounty_amount:
        flash("No bounty amount set on this report.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))
    report.bounty_paid_at = utcnow()
    # Mark most recent pending/processing BountyPayment as completed
    pending_payment = (BountyPayment.query
                       .filter(BountyPayment.report_id == rid,
                               BountyPayment.status.in_(["pending", "processing"]))
                       .order_by(BountyPayment.initiated_at.desc())
                       .first())
    if pending_payment:
        pending_payment.status = "completed"
        pending_payment.completed_at = utcnow()

    # Log InviteActivity so the confirmation appears in the timeline
    _amount_str = str(report.bounty_amount) if report.bounty_amount else "0"
    _currency = report.bounty_currency or "USD"
    for _inv in SecurityTeamInvite.query.filter_by(report_id=rid, is_active=True).all():
        db.session.add(InviteActivity(
            invite_id=_inv.id,
            action="bounty_confirmed",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"amount": _amount_str, "currency": _currency},
        ))
    db.session.commit()

    # Notify security team that the researcher confirmed receipt (#15)
    try:
        from app.tasks.notifications import notify_security_team
        notify_security_team.delay(event="bounty_confirmed", report_id=str(rid))
    except Exception as exc:
        import logging as _logging
        _logging.getLogger(__name__).warning(
            "notify_security_team failed for bounty_confirmed: %s", exc
        )

    flash("Bounty receipt confirmed.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Bonus Confirm Receipt ─────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/bounty/bonus/<payment_uuid>/confirm", methods=["POST"])
@owner_required
def confirm_bonus_receipt(report_uuid, payment_uuid):
    """Owner confirms receipt of a specific bonus payment."""
    rid = parse_uuid(report_uuid)
    pid = parse_uuid(payment_uuid)
    report = Report.query.get_or_404(rid)
    payment = BountyPayment.query.get_or_404(pid)
    if payment.report_id != rid:
        flash("Invalid payment reference.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))
    if not payment.is_bonus:
        flash("Use the main bounty confirm button for regular bounty payments.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))
    payment.status = "completed"
    payment.completed_at = utcnow()

    # Log InviteActivity so the confirmation appears in the timeline
    _log_invite_ids = []
    if payment.invite_id:
        _log_invite_ids.append(payment.invite_id)
    else:
        _log_invite_ids = [i.id for i in SecurityTeamInvite.query.filter_by(report_id=rid, is_active=True).all()]
    for _iid in _log_invite_ids:
        db.session.add(InviteActivity(
            invite_id=_iid,
            action="bonus_confirmed",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            metadata_={"amount": str(payment.amount), "currency": payment.currency or "USD"},
        ))
    db.session.commit()
    flash("Bonus receipt confirmed.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Confirm Retest (owner confirms fix is good or bypassable) ─────────────────
@reports_bp.route("/reports/<report_uuid>/retest/confirm", methods=["POST"])
@owner_required
def confirm_retest(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    outcome = (request.form.get("outcome") or "").strip()
    if outcome not in ("fixed", "bypassable"):
        flash("Invalid outcome. Choose 'fixed' or 'bypassable'.", "error")
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    invite_uuid_str = (request.form.get("invite_uuid") or "").strip()
    if invite_uuid_str:
        try:
            iid = parse_uuid(invite_uuid_str)
            target_invite = SecurityTeamInvite.query.filter_by(id=iid, report_id=rid).first()
        except Exception:
            target_invite = None
    else:
        target_invite = None

    invites_to_log = [target_invite] if target_invite else SecurityTeamInvite.query.filter_by(report_id=rid).all()
    for inv in invites_to_log:
        db.session.add(InviteActivity(
            invite_id=inv.id,
            action="retest_confirmed",
            ip_address=request.remote_addr,
            metadata_={"outcome": outcome, "confirmed_by": "owner"},
        ))
    db.session.commit()

    try:
        from app.tasks.notifications import notify_security_team
        notify_security_team.delay(event="retest_confirmed", report_id=str(rid),
                                   outcome=outcome)
    except Exception as exc:
        current_app.logger.warning("notify_security_team failed for retest_confirmed: %s", exc)

    label = "fixed — fix verified" if outcome == "fixed" else "bypassable — still vulnerable"
    flash("Retest confirmed: {}.".format(label), "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Poll for New Discussion Items (real-time updates) ─────────────────────────
@reports_bp.route("/reports/<report_uuid>/poll")
@owner_required
def poll_updates(report_uuid):
    rid = parse_uuid(report_uuid)
    Report.query.get_or_404(rid)

    since_str = request.args.get("since", "")
    since = None
    if since_str:
        try:
            from datetime import timezone as _tz
            since = datetime.fromisoformat(since_str)
            if since.tzinfo is None:
                since = since.replace(tzinfo=_tz.utc)
        except ValueError:
            pass

    items = []
    q = ReportReply.query.filter_by(report_id=rid, is_internal=False)
    if since:
        q = q.filter(ReportReply.created_at > since)
    for r in q.order_by(ReportReply.created_at.asc()).all():
        invite_name = r.invite.company_name if r.invite and r.invite.company_name else "Security Team"
        items.append({
            "item_type": "reply",
            "author_type": r.author_type,
            "author_name": "Researcher" if r.author_type == "owner" else invite_name,
            "body_html": render_markdown(r.body),
            "created_at": r.created_at.isoformat(),
        })

    _EVT_ACTIONS = {
        "status_changed", "bounty_set", "bounty_sent", "bounty_edited",
        "field_edit_accepted", "field_edit_rejected", "report_edited",
        "retest_requested", "retest_confirmed", "report_reopened",
        "bounty_confirmed", "bonus_confirmed",
    }
    _EVT_LABELS = {
        "status_changed": ("arrow-repeat", "Status updated"),
        "bounty_set": ("currency-dollar", "Bounty offered"),
        "bounty_sent": ("send", "Payment sent"),
        "bounty_edited": ("pencil-square", "Bounty updated"),
        "field_edit_accepted": ("check-circle", "Field correction accepted"),
        "field_edit_rejected": ("x-circle", "Field correction rejected"),
        "report_edited": ("pencil", "Report updated by owner"),
        "retest_requested": ("arrow-clockwise", "Retest requested"),
        "retest_confirmed": ("patch-check", "Retest confirmed"),
        "report_reopened": ("arrow-counterclockwise", "Report reopened"),
        "bounty_confirmed": ("check-circle-fill", "Bounty receipt confirmed"),
        "bonus_confirmed": ("check-circle-fill", "Bonus receipt confirmed"),
    }
    invite_ids = [i.id for i in SecurityTeamInvite.query.filter_by(report_id=rid).all()]
    if invite_ids:
        eq = InviteActivity.query.filter(
            InviteActivity.invite_id.in_(invite_ids),
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
                if meta.get("bonus"):
                    label = "Bonus offered: {} {}".format(meta["amount"], meta.get("currency", ""))
                else:
                    label = "Bounty offered: {} {}".format(meta["amount"], meta.get("currency", ""))
            elif evt.action == "bounty_sent" and meta.get("amount"):
                label = "Payment sent: {} {}".format(meta["amount"], meta.get("currency", ""))
            elif evt.action == "bounty_edited" and meta.get("new_amount"):
                label = "Bounty updated: {} \u2192 {} {}".format(
                    meta.get("old_amount", "?"), meta["new_amount"], meta.get("new_currency", ""))
            elif evt.action == "retest_confirmed" and meta.get("outcome"):
                label = "Retest: {}".format(meta["outcome"].replace("_", " ").title())
            elif evt.action == "bounty_confirmed" and meta.get("amount"):
                label = "Bounty confirmed: {} {}".format(meta["amount"], meta.get("currency", ""))
            elif evt.action == "bonus_confirmed" and meta.get("amount"):
                label = "Bonus confirmed: {} {}".format(meta["amount"], meta.get("currency", ""))
            items.append({
                "item_type": "event",
                "action": evt.action,
                "icon": icon,
                "label": label,
                "created_at": (evt.performed_at or utcnow()).isoformat(),
            })

    items.sort(key=lambda x: x["created_at"])

    # Compute retest_pending so client can react in real-time
    retest_pending = False
    if invite_ids:
        for _inv in SecurityTeamInvite.query.filter(
            SecurityTeamInvite.id.in_(invite_ids)
        ).all():
            _req = InviteActivity.query.filter_by(
                invite_id=_inv.id, action="retest_requested"
            ).order_by(InviteActivity.performed_at.desc()).first()
            _conf = InviteActivity.query.filter_by(
                invite_id=_inv.id, action="retest_confirmed"
            ).order_by(InviteActivity.performed_at.desc()).first()
            if _req and (not _conf or _req.performed_at > _conf.performed_at):
                retest_pending = True
                break

    return jsonify({"items": items, "now": utcnow().isoformat(), "retest_pending": retest_pending})


# ── Lock/Unlock Report ────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/lock", methods=["POST"])
@owner_required
def lock_report(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    report.is_locked = True
    db.session.commit()
    flash("Report locked.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


@reports_bp.route("/reports/<report_uuid>/unlock", methods=["POST"])
@owner_required
def unlock_report(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    report.is_locked = False
    db.session.commit()
    flash("Report unlocked.", "success")
    return redirect(url_for("reports.view_report", report_uuid=report_uuid))


# ── Delete Report ─────────────────────────────────────────────────────────────
_CONCLUDED_STATUSES = {"resolved", "informative", "wont_fix", "duplicate"}


def _report_delete_eligible(report):
    """Return (eligible: bool, reason: str) for deletion eligibility."""
    now = utcnow()
    if report.created_at and (now - report.created_at).days >= 90:
        return True, "Report is older than 90 days."
    if report.status in _CONCLUDED_STATUSES:
        last_activity = report.updated_at or report.created_at
        last_reply = (ReportReply.query.filter_by(report_id=report.id)
                      .order_by(ReportReply.created_at.desc()).first())
        if last_reply and last_reply.created_at > last_activity:
            last_activity = last_reply.created_at
        for inv in SecurityTeamInvite.query.filter_by(report_id=report.id).all():
            last_act = (InviteActivity.query.filter_by(invite_id=inv.id)
                        .order_by(InviteActivity.performed_at.desc()).first())
            if last_act and last_act.performed_at and last_act.performed_at > last_activity:
                last_activity = last_act.performed_at
        if last_activity and (now - last_activity).days >= 15:
            return True, f"Concluded ({report.status}) with no activity for 15+ days."
    return False, None


@reports_bp.route("/reports/<report_uuid>/delete", methods=["POST"])
@owner_required
def delete_report(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    eligible, _ = _report_delete_eligible(report)
    if not eligible:
        flash(
            "Report cannot be deleted yet. Reports can be deleted after 90 days, "
            "or when concluded (resolved/duplicate/informative/won't fix) with no "
            "activity for 15+ days.", "error"
        )
        return redirect(url_for("reports.view_report", report_uuid=report_uuid))

    display = report.display_id
    upload_folder = current_app.config.get("UPLOAD_FOLDER", "./uploads")

    # Secure-delete attachment files + records
    import os
    for att in ReportAttachment.query.filter_by(report_id=rid).all():
        try:
            fpath = os.path.join(upload_folder, str(rid), att.filename_stored)
            if os.path.exists(fpath):
                secure_delete(fpath)
        except Exception:
            pass
        db.session.delete(att)

    # Revoke sessions + delete invites (cascades activity/schedule/notification)
    for inv in SecurityTeamInvite.query.filter_by(report_id=rid).all():
        SecurityTeamSession.query.filter_by(invite_id=inv.id).delete(synchronize_session=False)
        db.session.delete(inv)

    ReportReply.query.filter_by(report_id=rid).delete(synchronize_session=False)
    ReportFieldEdit.query.filter_by(report_id=rid).delete(synchronize_session=False)
    db.session.delete(report)
    db.session.commit()

    log_access_event(None, "report_deleted", metadata={"display_id": display})
    flash(f"Report {display} has been deleted.", "success")
    return redirect(url_for("reports.list_reports"))


# ── Exports ───────────────────────────────────────────────────────────────────
@reports_bp.route("/reports/<report_uuid>/export/json")
@owner_required
def export_json(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    data = export_report_json(report)
    response = make_response(json.dumps(data, indent=2, default=str))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=report-{rid}-{int(utcnow().timestamp())}.json")
    log_access_event(None, "export_generated", metadata={"report_id": str(rid), "format": "json"})
    return response


@reports_bp.route("/reports/<report_uuid>/export/markdown")
@owner_required
def export_markdown(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    content = export_report_markdown(report)
    response = make_response(content)
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=report-{rid}-{int(utcnow().timestamp())}.md")
    log_access_event(None, "export_generated", metadata={"report_id": str(rid), "format": "markdown"})
    return response


@reports_bp.route("/reports/<report_uuid>/export/pdf")
@owner_required
def export_pdf(report_uuid):
    rid = parse_uuid(report_uuid)
    report = Report.query.get_or_404(rid)
    rendered = {k: render_markdown(getattr(report, k) or "") for k in [
        "description", "steps_to_reproduce", "proof_of_concept",
        "impact_statement", "remediation", "technical_details",
    ]}
    html_content = render_template("reports/export_pdf.html", report=report, rendered=rendered)
    try:
        from weasyprint import HTML
        pdf_bytes = HTML(string=html_content).write_pdf()
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = (
            f"attachment; filename=report-{rid}-{int(utcnow().timestamp())}.pdf")
        log_access_event(None, "export_generated", metadata={"report_id": str(rid), "format": "pdf"})
        return response
    except ImportError:
        flash("WeasyPrint not installed. Serving HTML export.", "warning")
        response = make_response(html_content)
        response.headers["Content-Type"] = "text/html"
        return response


# ── Backup / Restore ──────────────────────────────────────────────────────────
@reports_bp.route("/reports/backup", methods=["POST"])
@owner_required
def backup():
    from app.utils.export import create_encrypted_backup
    try:
        key = current_app.config.get("BACKUP_ENCRYPTION_KEY", "")
        zip_bytes, filename = create_encrypted_backup(key)
        response = make_response(zip_bytes)
        response.headers["Content-Type"] = "application/zip"
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        log_access_event(None, "backup_created")
        return response
    except Exception as exc:
        current_app.logger.exception("Backup failed")
        flash(f"Backup failed: {exc}", "error")
        return redirect(url_for("dashboard.index"))


@reports_bp.route("/reports/restore", methods=["POST"])
@owner_required
def restore():
    flash("Upload a backup ZIP file and enter your encryption key to restore.", "info")
    return redirect(url_for("settings.index"))


# ── External Link Interstitial ─────────────────────────────────────────────────
@reports_bp.route("/go/<link_uuid>")
@limiter.limit("30 per minute")
def go_external(link_uuid):
    try:
        token = uuid.UUID(link_uuid)
    except ValueError:
        abort(404)
    link = ExternalLink.query.filter_by(token=token).first_or_404()

    from urllib.parse import urlparse
    import ipaddress
    import socket as _socket

    parsed = urlparse(link.original_url)
    if parsed.scheme not in ("http", "https"):
        abort(403)

    try:
        ip_str = _socket.gethostbyname(parsed.hostname or "")
        addr = ipaddress.ip_address(ip_str)
        private_nets = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7",
        ]
        for net in private_nets:
            if addr in ipaddress.ip_network(net, strict=False):
                abort(403)
    except Exception:
        pass

    link.click_count = (link.click_count or 0) + 1
    db.session.commit()
    return render_template(
        "go_interstitial.html",
        link=link,
        domain=link.domain,
        destination=link.original_url,
    )
