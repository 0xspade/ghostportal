# GhostPortal -- Project-Apocalypse -- Read-Only API Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import hmac
import uuid
from datetime import datetime, timezone

from flask import current_app, jsonify, make_response, request

from app.blueprints.api import api_bp
from app.extensions import db, limiter
from app.utils.security import hash_token


def utcnow():
    return datetime.now(timezone.utc)


def api_key_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        submitted = auth[7:].strip()
        stored = current_app.config.get("API_KEY", "")
        if not stored:
            return jsonify({"error": "API not configured"}), 503
        # Constant-time comparison
        if not hmac.compare_digest(
            hash_token(submitted).encode(),
            hash_token(stored).encode()
        ):
            return jsonify({"error": "unauthorized"}), 401
        response = f(*args, **kwargs)
        return response

    return decorated


def _add_request_id(response):
    response.headers["X-Request-ID"] = str(uuid.uuid4())
    return response


# ── Report List ──────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/reports")
@api_key_required
@limiter.limit("100 per hour")
def list_reports():
    from app.models import Report
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = min(100, int(request.args.get("per_page", 50) or 50))
    reports = (Report.query
               .filter(Report.status != "draft")
               .order_by(Report.created_at.desc())
               .paginate(page=page, per_page=per_page, error_out=False))
    data = [{
        "id": str(r.id),
        "display_id": r.display_id,
        "title": r.title,
        "severity": r.severity,
        "status": r.status,
        "cvss_score": r.cvss_score,
        "cwe_id": r.cwe_id,
        "program_name": r.program_name,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
    } for r in reports.items]
    resp = make_response(jsonify({
        "reports": data,
        "total": reports.total,
        "page": page,
        "per_page": per_page,
        "pages": reports.pages,
    }))
    return _add_request_id(resp)


# ── Report Detail ─────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/reports/<report_uuid>")
@api_key_required
@limiter.limit("100 per hour")
def get_report(report_uuid):
    from app.models import Report
    try:
        rid = uuid.UUID(report_uuid)
    except ValueError:
        return jsonify({"error": "invalid uuid"}), 400
    report = Report.query.get_or_404(rid)
    if report.status == "draft":
        return jsonify({"error": "not found"}), 404
    data = {
        "id": str(report.id),
        "display_id": report.display_id,
        "title": report.title,
        "description": report.description,
        "severity": report.severity,
        "status": report.status,
        "cvss_score": report.cvss_score,
        "cvss_vector": report.cvss_vector,
        "cwe_id": report.cwe_id,
        "cwe_name": report.cwe_name,
        "target_asset": report.target_asset,
        "program_name": report.program_name,
        "tags": report.tags or [],
        "bounty_amount": str(report.bounty_amount) if report.bounty_amount else None,
        "bounty_currency": report.bounty_currency,
        "created_at": report.created_at.isoformat() if report.created_at else None,
        "submitted_at": report.submitted_at.isoformat() if report.submitted_at else None,
        "updated_at": report.updated_at.isoformat() if report.updated_at else None,
    }
    return _add_request_id(make_response(jsonify(data)))


# ── Create Draft Report ───────────────────────────────────────────────────────
@api_bp.route("/api/v1/reports", methods=["POST"])
@api_key_required
@limiter.limit("20 per hour")
def create_report():
    from app.models import Report
    from app.utils.display_id import generate_display_id
    from app.utils.markdown_renderer import sanitize_markdown
    data = request.get_json(force=True, silent=True) or {}
    title = str(data.get("title") or "").strip()[:500]
    if not title:
        return jsonify({"error": "title required"}), 400
    rid = uuid.uuid4()
    report = Report(
        id=rid,
        display_id=generate_display_id(rid),
        title=title,
        description=sanitize_markdown(data.get("description") or ""),
        severity=data.get("severity"),
        target_asset=str(data.get("target_asset") or "")[:500],
        program_name=str(data.get("program_name") or "")[:300],
        status="draft",
    )
    db.session.add(report)
    db.session.commit()
    return _add_request_id(make_response(
        jsonify({"id": str(rid), "display_id": report.display_id}), 201
    ))


# ── Stats ─────────────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/stats")
@api_key_required
@limiter.limit("100 per hour")
def stats():
    from app.models import Report, SecurityTeamInvite
    from sqlalchemy import func
    severity_counts = {}
    for sev in ("critical", "high", "medium", "low", "informational"):
        severity_counts[sev] = Report.query.filter_by(severity=sev).count()
    status_counts = {}
    for st in ("draft", "submitted", "triaged", "duplicate",
               "informative", "resolved", "wont_fix"):
        status_counts[st] = Report.query.filter_by(status=st).count()
    bounty_total = db.session.query(
        func.sum(Report.bounty_amount)
    ).filter(Report.bounty_paid_at.isnot(None)).scalar()
    data = {
        "total_reports": Report.query.count(),
        "open_reports": Report.query.filter(
            Report.status.in_(["submitted", "triaged"])).count(),
        "resolved_reports": Report.query.filter_by(status="resolved").count(),
        "active_invites": SecurityTeamInvite.query.filter_by(is_active=True).count(),
        "total_bounty_paid": float(bounty_total or 0),
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "generated_at": utcnow().isoformat(),
    }
    return _add_request_id(make_response(jsonify(data)))
