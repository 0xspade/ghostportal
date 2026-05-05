# GhostPortal -- Project-Apocalypse -- API Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

import hmac
import json
import uuid
from datetime import datetime, timezone

from flask import current_app, jsonify, make_response, request

from app.blueprints.api import api_bp
from app.extensions import db, limiter
from app.utils.security import hash_token


def utcnow():
    return datetime.now(timezone.utc)


def _get_stored_api_key_hash():
    """Return the stored API key hash from SystemConfig, or None if not set."""
    try:
        from app.models import SystemConfig
        row = SystemConfig.query.filter_by(key="api_key_hash").first()
        if row:
            return json.loads(row.value)
    except Exception:
        pass
    return None


def api_key_required(f):
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "unauthorized"}), 401
        submitted = auth[7:].strip()
        if not submitted:
            return jsonify({"error": "unauthorized"}), 401

        submitted_hash = hash_token(submitted)

        # Check SystemConfig-stored key first (runtime-generated)
        stored_hash = _get_stored_api_key_hash()
        if stored_hash:
            if not hmac.compare_digest(submitted_hash.encode(), stored_hash.encode()):
                _log_api_access(401)
                return jsonify({"error": "unauthorized"}), 401
            _log_api_access(200)
            return f(*args, **kwargs)

        # Fall back to env-var API_KEY
        stored_env = current_app.config.get("API_KEY", "")
        if not stored_env:
            return jsonify({"error": "API not configured"}), 503
        if not hmac.compare_digest(submitted_hash.encode(), hash_token(stored_env).encode()):
            _log_api_access(401)
            return jsonify({"error": "unauthorized"}), 401

        _log_api_access(200)
        return f(*args, **kwargs)

    return decorated


def _log_api_access(status_code: int) -> None:
    """Log API access to AccessLog (best-effort, never blocks response)."""
    try:
        from app.models import AccessLog
        from app.utils.ua_parser import parse_user_agent
        ip = (
            request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or "unknown"
        )
        ua_string = request.user_agent.string or ""
        parsed = parse_user_agent(ua_string)
        entry = AccessLog(
            user_type="owner",
            user_ref=None,
            session_id=None,
            ip_address=ip[:45],
            ip_country=None,
            user_agent=ua_string[:1000],
            ua_browser=parsed.browser[:100],
            ua_os=parsed.os[:100],
            ua_is_bot=parsed.is_bot,
            method=request.method[:10],
            path=request.path[:2000],
            response_code=status_code,
            event_type="api_access",
            metadata_={"endpoint": request.path, "method": request.method},
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        try:
            db.session.rollback()
        except Exception:
            pass


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
    status_filter = request.args.get("status")
    severity_filter = request.args.get("severity")
    q = Report.query
    if status_filter:
        q = q.filter(Report.status == status_filter)
    else:
        q = q.filter(Report.status != "draft")
    if severity_filter:
        q = q.filter(Report.severity == severity_filter)
    reports = q.order_by(Report.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    data = [{
        "id": str(r.id),
        "display_id": r.display_id,
        "title": r.title,
        "severity": r.severity,
        "status": r.status,
        "cvss_score": float(r.cvss_score) if r.cvss_score is not None else None,
        "cwe_id": r.cwe_id,
        "program_name": r.program_name,
        "target_asset": r.target_asset,
        "tags": r.tags or [],
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    } for r in reports.items]
    return _add_request_id(make_response(jsonify({
        "reports": data,
        "total": reports.total,
        "page": page,
        "per_page": per_page,
        "pages": reports.pages,
    })))


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
        "steps_to_reproduce": report.steps_to_reproduce,
        "proof_of_concept": report.proof_of_concept,
        "impact_statement": report.impact_statement,
        "remediation": report.remediation,
        "technical_details": report.technical_details,
        "severity": report.severity,
        "status": report.status,
        "cvss_score": float(report.cvss_score) if report.cvss_score is not None else None,
        "cvss_vector": report.cvss_vector,
        "cwe_id": report.cwe_id,
        "cwe_name": report.cwe_name,
        "target_asset": report.target_asset,
        "program_name": report.program_name,
        "tags": report.tags or [],
        "bounty_amount": str(report.bounty_amount) if report.bounty_amount else None,
        "bounty_currency": report.bounty_currency,
        "bounty_paid_at": report.bounty_paid_at.isoformat() if report.bounty_paid_at else None,
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
    severity = data.get("severity", "medium")
    if severity not in ("critical", "high", "medium", "low", "informational"):
        severity = "medium"
    rid = uuid.uuid4()
    report = Report(
        id=rid,
        display_id=generate_display_id(rid),
        title=title,
        description=sanitize_markdown(data.get("description") or ""),
        steps_to_reproduce=sanitize_markdown(data.get("steps_to_reproduce") or ""),
        proof_of_concept=sanitize_markdown(data.get("proof_of_concept") or ""),
        impact_statement=sanitize_markdown(data.get("impact_statement") or ""),
        remediation=sanitize_markdown(data.get("remediation") or ""),
        severity=severity,
        target_asset=str(data.get("target_asset") or "")[:500],
        program_name=str(data.get("program_name") or "")[:300],
        tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
        status="draft",
    )
    db.session.add(report)
    db.session.commit()
    return _add_request_id(make_response(
        jsonify({"id": str(rid), "display_id": report.display_id, "status": "draft"}), 201
    ))


# ── Submit Report ─────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/reports/<report_uuid>/submit", methods=["POST"])
@api_key_required
@limiter.limit("20 per hour")
def submit_report(report_uuid):
    from app.models import Report
    try:
        rid = uuid.UUID(report_uuid)
    except ValueError:
        return jsonify({"error": "invalid uuid"}), 400
    report = Report.query.get(rid)
    if not report:
        return jsonify({"error": "not found"}), 404
    if report.status != "draft":
        return jsonify({"error": "only draft reports can be submitted", "current_status": report.status}), 409
    report.status = "submitted"
    report.submitted_at = utcnow()
    db.session.commit()
    return _add_request_id(make_response(jsonify({
        "id": str(report.id),
        "display_id": report.display_id,
        "status": report.status,
        "submitted_at": report.submitted_at.isoformat(),
    })))


# ── Program List ──────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/programs")
@api_key_required
@limiter.limit("100 per hour")
def list_programs():
    from app.models import ProgramName
    programs = ProgramName.query.order_by(ProgramName.use_count.desc()).all()
    data = [{
        "id": str(p.id),
        "name": p.name,
        "use_count": p.use_count,
        "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None,
    } for p in programs]
    return _add_request_id(make_response(jsonify({"programs": data, "total": len(data)})))


# ── Security Teams ────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/security-teams")
@api_key_required
@limiter.limit("100 per hour")
def list_security_teams():
    from app.models import SecurityTeamInvite, Report
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = min(100, int(request.args.get("per_page", 50) or 50))
    report_uuid = request.args.get("report_id")
    q = SecurityTeamInvite.query
    if report_uuid:
        try:
            rid = uuid.UUID(report_uuid)
            q = q.filter(SecurityTeamInvite.report_id == rid)
        except ValueError:
            return jsonify({"error": "invalid report_id uuid"}), 400
    invites = q.order_by(SecurityTeamInvite.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    data = [{
        "id": str(i.id),
        "report_id": str(i.report_id),
        "company_name": i.company_name,
        "is_active": i.is_active,
        "is_locked": i.is_locked,
        "expires_at": i.expires_at.isoformat() if i.expires_at else None,
        "first_accessed_at": i.first_accessed_at.isoformat() if i.first_accessed_at else None,
        "last_activity_at": i.last_activity_at.isoformat() if i.last_activity_at else None,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    } for i in invites.items]
    return _add_request_id(make_response(jsonify({
        "security_teams": data,
        "total": invites.total,
        "page": page,
        "per_page": per_page,
        "pages": invites.pages,
    })))


# ── Template List ──────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/templates")
@api_key_required
@limiter.limit("100 per hour")
def list_templates():
    from app.models import ReportTemplate
    templates = ReportTemplate.query.order_by(ReportTemplate.name).all()
    data = [{
        "id": str(t.id),
        "name": t.name,
        "category": t.category,
        "cwe_id": t.cwe_id,
        "cwe_name": t.cwe_name,
        "severity": t.severity,
        "tags": t.tags or [],
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in templates]
    return _add_request_id(make_response(jsonify({"templates": data, "total": len(data)})))


# ── Create Template ────────────────────────────────────────────────────────────
@api_bp.route("/api/v1/templates", methods=["POST"])
@api_key_required
@limiter.limit("20 per hour")
def create_template():
    from app.models import ReportTemplate
    from app.utils.markdown_renderer import sanitize_markdown
    data = request.get_json(force=True, silent=True) or {}
    name = str(data.get("name") or "").strip()[:200]
    if not name:
        return jsonify({"error": "name required"}), 400
    category = data.get("category", "custom")
    valid_categories = ("web", "api", "mobile", "web3", "network", "physical",
                        "social_engineering", "custom")
    if category not in valid_categories:
        category = "custom"
    severity = data.get("severity", "medium")
    if severity not in ("critical", "high", "medium", "low", "informational"):
        severity = "medium"
    tid = uuid.uuid4()
    template = ReportTemplate(
        id=tid,
        name=name,
        category=category,
        title_template=str(data.get("title_template") or "")[:500],
        description_template=sanitize_markdown(data.get("description_template") or ""),
        steps_template=sanitize_markdown(data.get("steps_template") or ""),
        poc_template=sanitize_markdown(data.get("poc_template") or ""),
        remediation_template=sanitize_markdown(data.get("remediation_template") or ""),
        cwe_id=int(data["cwe_id"]) if data.get("cwe_id") else None,
        cwe_name=str(data.get("cwe_name") or "")[:200] or None,
        severity=severity,
        tags=data.get("tags") if isinstance(data.get("tags"), list) else [],
    )
    db.session.add(template)
    db.session.commit()
    return _add_request_id(make_response(
        jsonify({"id": str(tid), "name": template.name, "category": template.category}), 201
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
