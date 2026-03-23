# GhostPortal legal routes
from flask import render_template, current_app
from app.blueprints.legal import legal_bp

def _ctx():
    return dict(
        platform_name=current_app.config.get("PLATFORM_NAME","GhostPortal"),
        operator_name=current_app.config.get("OPERATOR_NAME",""),
        operator_email=current_app.config.get("OPERATOR_EMAIL",""),
        operator_country=current_app.config.get("OPERATOR_COUNTRY","Philippines"),
        platform_url=current_app.config.get("PLATFORM_URL",""),
        policy_version=current_app.config.get("POLICY_VERSION","1.0"),
        policy_last_updated=current_app.config.get("POLICY_LAST_UPDATED","2026-01-01"),
    )

@legal_bp.route("/legal/terms")
def terms():
    return render_template("legal/terms.html", **_ctx())

@legal_bp.route("/legal/privacy")
def privacy():
    return render_template("legal/privacy.html", **_ctx())

@legal_bp.route("/legal/disclosure-policy")
def disclosure_policy():
    return render_template("legal/disclosure_policy.html", **_ctx())
