# GhostPortal -- Project-Apocalypse -- Report Templates Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import json
from flask import (abort, current_app, flash, jsonify, make_response,
                   redirect, render_template, request, url_for)

from app.blueprints.templates_bp import templates_bp
from app.blueprints.decorators import owner_required, parse_uuid
from app.extensions import db
from app.models import ReportTemplate


@templates_bp.route("/templates")
@owner_required
def list_templates():
    templates = ReportTemplate.query.order_by(ReportTemplate.name).all()
    return render_template(
        "templates_bp/list.html",
        templates=templates,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


@templates_bp.route("/templates/new", methods=["GET", "POST"])
@owner_required
def new_template():
    if request.method == "GET":
        return render_template(
            "templates_bp/form.html",
            template=None,
            platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        )
    t = ReportTemplate(
        name=(request.form.get("name") or "").strip()[:200],
        category=(request.form.get("category") or "custom").strip()[:50],
        title_template=(request.form.get("title_template") or "").strip()[:500],
        description_template=request.form.get("description_template") or "",
        steps_template=request.form.get("steps_template") or "",
        poc_template=request.form.get("poc_template") or "",
        remediation_template=request.form.get("remediation_template") or "",
        cwe_id=int(request.form.get("cwe_id") or 0) or None,
        cwe_name=(request.form.get("cwe_name") or "").strip()[:300],
        severity=request.form.get("severity") or None,
        cvss_vector=(request.form.get("cvss_vector") or "").strip()[:500],
        tags=_safe_json(request.form.get("tags")),
        is_builtin=False,
    )
    if not t.name:
        flash("Template name is required.", "error")
        return render_template("templates_bp/form.html", template=None,
                               platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"))
    db.session.add(t)
    db.session.commit()
    flash("Template created.", "success")
    return redirect(url_for("templates.list_templates"))


@templates_bp.route("/templates/<template_uuid>")
@owner_required
def view_template(template_uuid):
    tid = parse_uuid(template_uuid)
    t = ReportTemplate.query.get_or_404(tid)
    return render_template(
        "templates_bp/form.html",
        template=t,
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
    )


@templates_bp.route("/templates/<template_uuid>/edit", methods=["POST"])
@owner_required
def edit_template(template_uuid):
    tid = parse_uuid(template_uuid)
    t = ReportTemplate.query.get_or_404(tid)
    t.name = (request.form.get("name") or t.name).strip()[:200]
    t.category = (request.form.get("category") or t.category).strip()[:50]
    t.title_template = (request.form.get("title_template") or "").strip()[:500]
    t.description_template = request.form.get("description_template") or ""
    t.steps_template = request.form.get("steps_template") or ""
    t.poc_template = request.form.get("poc_template") or ""
    t.remediation_template = request.form.get("remediation_template") or ""
    t.cwe_id = int(request.form.get("cwe_id") or 0) or None
    t.cwe_name = (request.form.get("cwe_name") or "").strip()[:300]
    t.severity = request.form.get("severity") or None
    t.cvss_vector = (request.form.get("cvss_vector") or "").strip()[:500]
    t.tags = _safe_json(request.form.get("tags"))
    db.session.commit()
    flash("Template updated.", "success")
    return redirect(url_for("templates.list_templates"))


@templates_bp.route("/templates/<template_uuid>/delete", methods=["POST"])
@owner_required
def delete_template(template_uuid):
    tid = parse_uuid(template_uuid)
    t = ReportTemplate.query.get_or_404(tid)
    if t.is_builtin:
        flash("Built-in templates cannot be deleted.", "error")
        return redirect(url_for("templates.list_templates"))
    db.session.delete(t)
    db.session.commit()
    flash("Template deleted.", "success")
    return redirect(url_for("templates.list_templates"))


@templates_bp.route("/templates/<template_uuid>/export")
@owner_required
def export_template(template_uuid):
    tid = parse_uuid(template_uuid)
    t = ReportTemplate.query.get_or_404(tid)
    data = {
        "name": t.name, "category": t.category,
        "title_template": t.title_template,
        "description_template": t.description_template,
        "steps_template": t.steps_template,
        "poc_template": t.poc_template,
        "remediation_template": t.remediation_template,
        "cwe_id": t.cwe_id, "cwe_name": t.cwe_name,
        "severity": t.severity, "cvss_vector": t.cvss_vector, "tags": t.tags,
    }
    resp = make_response(json.dumps(data, indent=2))
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f"attachment; filename=template-{tid}.json"
    return resp


def _safe_json(val):
    try:
        parsed = json.loads(val or "[]")
        return parsed if isinstance(parsed, list) else []
    except (json.JSONDecodeError, TypeError):
        return []
