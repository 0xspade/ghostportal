# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
GhostPortal Flask application factory.
All configuration validation happens here — fail fast on bad config.
"""

import logging
import os
import uuid
from datetime import timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, request, g
from dotenv import load_dotenv

from app.extensions import (
    db,
    migrate,
    csrf,
    mail,
    limiter,
    init_redis,
    init_celery,
)
import app.extensions as _ext

load_dotenv()

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def configure_logging(app: Flask) -> None:
    """Configure structured JSON logging to file + console."""
    log_dir = os.path.join(app.root_path, "..", "logs")
    os.makedirs(log_dir, exist_ok=True)

    formatter = logging.Formatter(
        '{"time": "%(asctime)s", "level": "%(levelname)s", '
        '"name": "%(name)s", "message": "%(message)s"}'
    )

    # File handler — rotating, max 10MB, keep 5 backups
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.WARNING if not app.debug else logging.DEBUG)

    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(logging.INFO)

    # Suppress noisy loggers in production
    if not app.debug:
        logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Config validation — fail fast on bad config
# ---------------------------------------------------------------------------

def validate_config(app: Flask) -> None:
    """
    Validate critical configuration values at startup.
    Raises RuntimeError if any required config is missing or invalid.
    """
    errors = []

    # Secret key must be at least 64 hex chars (256-bit)
    secret_key = app.config.get("SECRET_KEY", "")
    if not secret_key or len(secret_key) < 64:
        errors.append("SECRET_KEY must be >= 64 characters (use secrets.token_hex(64))")

    if not app.config.get("OWNER_EMAIL"):
        errors.append("OWNER_EMAIL is required")

    # RESOLVED_ACCESS_EXPIRY_DAYS must be 10–15
    expiry = int(app.config.get("RESOLVED_ACCESS_EXPIRY_DAYS", 10))
    if not 10 <= expiry <= 15:
        errors.append(f"RESOLVED_ACCESS_EXPIRY_DAYS must be 10–15 (got: {expiry})")

    # MAGIC_LINK_OTP_LENGTH must be 16–32
    otp_len = int(app.config.get("MAGIC_LINK_OTP_LENGTH", 20))
    if not 16 <= otp_len <= 32:
        errors.append(f"MAGIC_LINK_OTP_LENGTH must be 16–32 (got: {otp_len})")

    # Production-only requirements
    if app.config.get("FLASK_ENV") == "production":
        for key in ["HCAPTCHA_SECRET_KEY", "BACKUP_ENCRYPTION_KEY"]:
            if not app.config.get(key):
                errors.append(f"{key} is required in production")

        if not app.config.get("SESSION_COOKIE_SECURE", True):
            errors.append("SESSION_COOKIE_SECURE must be True in production")

        if app.config.get("SECRET_KEY", "").startswith("CHANGE_ME"):
            errors.append("SECRET_KEY must be changed from the example placeholder")

    if errors:
        raise RuntimeError(
            "GhostPortal startup failed:\n"
            + "\n".join(f"  x {e}" for e in errors)
        )


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(config_overrides: dict | None = None) -> Flask:
    """
    Flask application factory.

    Args:
        config_overrides: Optional dict of config values to override (for testing).

    Returns:
        Configured Flask application.
    """
    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # Load configuration from environment
    # -----------------------------------------------------------------------
    _load_config(app)

    # Apply any test overrides
    if config_overrides:
        app.config.update(config_overrides)

    # -----------------------------------------------------------------------
    # Configure logging
    # -----------------------------------------------------------------------
    configure_logging(app)

    # -----------------------------------------------------------------------
    # Initialize extensions
    # -----------------------------------------------------------------------
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    mail.init_app(app)

    # Flask-Limiter — use Redis if available, fall back to memory for local dev
    redis_url = app.config.get("REDIS_URL", "redis://localhost:6379/0")
    _redis_available = False
    try:
        import redis as _redis_probe
        _probe = _redis_probe.from_url(redis_url, socket_connect_timeout=1)
        _probe.ping()
        _redis_available = True
    except Exception:
        pass

    if _redis_available:
        app.config["RATELIMIT_STORAGE_URI"] = redis_url
    else:
        app.config["RATELIMIT_STORAGE_URI"] = "memory://"
        app.logger.warning("Redis unavailable — rate limiter using in-memory storage")
    limiter.init_app(app)

    # Security headers are set by nginx in production.
    # App-managed headers (CSP, Cache-Control, X-Request-ID, Report-To, NEL)
    # are applied via the after_request hook in apply_security_headers().

    # Redis client (best-effort)
    try:
        _ext.redis_client = init_redis(app)
        _ext.redis_client.ping()  # confirm connection
    except Exception:
        _ext.redis_client = None
        app.logger.warning("Redis unavailable — session/OTP features will use DB fallbacks")
    app.redis_client = _ext.redis_client  # type: ignore[attr-defined]

    # Celery
    celery = init_celery(app)
    app.celery = celery  # type: ignore[attr-defined]

    # -----------------------------------------------------------------------
    # Register middlewares
    # -----------------------------------------------------------------------
    from app.middleware.session_guard import register_session_guard
    from app.middleware.access_logger import register_access_logger
    register_session_guard(app)
    register_access_logger(app)

    # -----------------------------------------------------------------------
    # Register blueprints
    # -----------------------------------------------------------------------
    _register_blueprints(app)

    # Add email_templates/ as a Jinja2 search path under the "email/" prefix.
    # Done after blueprint registration so Flask's DispatchingJinjaLoader is
    # already initialised — we wrap it rather than replace it.
    import jinja2 as _jinja2
    _email_loader = _jinja2.PrefixLoader(
        {"email": _jinja2.FileSystemLoader(
            os.path.join(app.root_path, "email_templates")
        )},
        delimiter="/",
    )
    app.jinja_env.loader = _jinja2.ChoiceLoader([
        app.jinja_env.loader,
        _email_loader,
    ])

    # -----------------------------------------------------------------------
    # Register Jinja2 markdown filters
    # -----------------------------------------------------------------------
    from app.utils.markdown_renderer import register_markdown_filters
    register_markdown_filters(app)

    # -----------------------------------------------------------------------
    # Register custom Jinja2 tests
    # -----------------------------------------------------------------------
    import re as _re
    app.jinja_env.tests['match'] = lambda value, pattern: bool(
        _re.match(pattern, value) if value else False
    )

    # -----------------------------------------------------------------------
    # Register error handlers
    # -----------------------------------------------------------------------
    _register_error_handlers(app)

    # -----------------------------------------------------------------------
    # Security headers on every response
    # -----------------------------------------------------------------------
    _register_after_request_hooks(app)

    # -----------------------------------------------------------------------
    # Health check endpoint (no auth, used by Docker)
    # -----------------------------------------------------------------------
    @app.route("/health")
    def health():
        try:
            db.session.execute(db.text("SELECT 1"))
            db_status = "ok"
        except Exception as exc:
            app.logger.error(f"Health DB check failed: {exc}")
            return jsonify({"status": "error", "detail": "DB unavailable"}), 503
        redis_status = "ok"
        if _ext.redis_client:
            try:
                _ext.redis_client.ping()
            except Exception:
                redis_status = "unavailable"
        else:
            redis_status = "unavailable"
        return jsonify({"status": "ok", "db": db_status, "redis": redis_status}), 200

    # CSP violation reporting endpoint
    @app.route("/csp-report", methods=["POST"])
    @csrf.exempt
    @limiter.limit("100 per minute")
    def csp_report():
        from app.utils.csp import handle_csp_report
        handle_csp_report(request)
        return "", 204

    # Markdown preview endpoint — owner-session required, rate-limited
    @app.route("/api/preview-markdown", methods=["POST"])
    @limiter.limit("60 per minute")
    def preview_markdown():
        from flask import session as _session
        from app.utils.markdown_renderer import render_markdown
        if _session.get("role") != "owner" and _session.get("portal_role") != "security_team":
            return jsonify({"error": "Unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        text = (body.get("text") or "")[:50000]
        return jsonify({"html": render_markdown(text)})

    # External link registration (open redirect prevention)
    @app.route("/api/external-link", methods=["POST"])
    @limiter.limit("120 per minute")
    def register_external_link():
        from flask import session as _session
        from app.utils.external_links import get_or_create_external_link
        from app.extensions import db as _db
        if _session.get("role") != "owner" and _session.get("portal_role") != "security_team":
            return jsonify({"error": "Unauthorized"}), 401
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        link = get_or_create_external_link(url)
        if link is None:
            return jsonify({"error": "URL not allowed"}), 400
        _db.session.commit()
        return jsonify({"token": str(link.token)})

    # Attachment serve route — always through Flask with auth check
    @app.route("/attachments/<attachment_uuid>")
    def serve_attachment(attachment_uuid):
        import os
        from flask import session as _session, send_file, abort as _abort
        from app.models import ReportAttachment, SecurityTeamInvite
        owner_role = _session.get("role")
        portal_role = _session.get("portal_role")
        if not owner_role and not portal_role:
            _abort(401)
        try:
            att_id = uuid.UUID(attachment_uuid)
        except ValueError:
            _abort(404)
        att = ReportAttachment.query.get_or_404(att_id)
        if owner_role == "owner":
            pass  # Owner can access all attachments
        elif portal_role == "security_team":
            # Member can only access attachments for reports they're invited to
            from app.models import SecurityTeamMember
            try:
                mid = uuid.UUID(_session.get("portal_member_id", ""))
            except ValueError:
                _abort(403)
            member = SecurityTeamMember.query.get(mid)
            if not member:
                _abort(403)
            invite = SecurityTeamInvite.query.filter_by(
                report_id=att.report_id, email=member.email, is_active=True
            ).first()
            if not invite:
                _abort(403)
        else:
            _abort(403)
        upload_folder = app.config.get("UPLOAD_FOLDER", "./uploads")
        # Path traversal protection: strip directory separators from stored filename
        safe_filename = os.path.basename(att.filename_stored)
        file_path = os.path.join(upload_folder, "verified",
                                 str(att.report_id), safe_filename)
        # Ensure resolved path stays within upload_folder
        real_base = os.path.realpath(os.path.join(upload_folder, "verified"))
        real_path = os.path.realpath(file_path)
        if not real_path.startswith(real_base + os.sep) and real_path != real_base:
            _abort(403)
        if not os.path.exists(real_path):
            _abort(404)
        response = send_file(
            real_path,
            mimetype=att.mime_type,
            as_attachment=True,
            download_name=att.filename_original,
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Sanitize filename to prevent header injection (strip quotes, newlines)
        safe_dl_name = att.filename_original.replace('"', '').replace('\r', '').replace('\n', '')
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{safe_dl_name}"'
        )
        return response

    # External link interstitial (open redirect prevention)
    @app.route("/go/<link_token>")
    @limiter.limit("30 per minute")
    def go_interstitial(link_token):
        from app.models import ExternalLink
        from app.utils.external_links import validate_redirect_url
        try:
            token_uuid = uuid.UUID(link_token)
        except ValueError:
            return render_template("errors/404.html"), 404
        link = ExternalLink.query.filter_by(token=token_uuid).first_or_404()
        is_safe, err = validate_redirect_url(link.original_url)
        if not is_safe:
            app.logger.warning(f"Blocked redirect to: {link.original_url} — {err}")
            return render_template("errors/403.html"), 403
        link.click_count = (link.click_count or 0) + 1
        db.session.commit()
        platform_name = app.config.get("PLATFORM_NAME", "GhostPortal")
        return render_template(
            "go_interstitial.html",
            link=link,
            domain=link.domain,
            redirect_url=link.original_url,
            platform_name=platform_name,
        )

    # Template detail API — for template pre-fill in new report form
    @app.route("/api/templates/<template_uuid>")
    def get_template_api(template_uuid):
        from flask import session as _session
        from app.models import ReportTemplate
        if _session.get("role") != "owner":
            return jsonify({"error": "Unauthorized"}), 401
        try:
            tid = uuid.UUID(template_uuid)
        except ValueError:
            return jsonify({"error": "Invalid ID"}), 400
        tmpl = ReportTemplate.query.get_or_404(tid)
        return jsonify({
            "id": str(tmpl.id),
            "name": tmpl.name,
            "title_template": tmpl.title_template or "",
            "description_template": tmpl.description_template or "",
            "steps_template": tmpl.steps_template or "",
            "poc_template": tmpl.poc_template or "",
            "remediation_template": tmpl.remediation_template or "",
            "cwe_id": tmpl.cwe_id,
            "cwe_name": tmpl.cwe_name or "",
            "severity": tmpl.severity or "",
            "cvss_vector": tmpl.cvss_vector or "",
            "tags": tmpl.tags or [],
        })

    # -----------------------------------------------------------------------
    # Validate config — fail fast
    # -----------------------------------------------------------------------
    validate_config(app)

    # -----------------------------------------------------------------------
    # Ensure upload directories exist at startup
    # -----------------------------------------------------------------------
    import os as _os
    upload_base = app.config.get("UPLOAD_FOLDER", "./uploads")
    for _subdir in ("verified", "quarantine"):
        _os.makedirs(_os.path.join(upload_base, _subdir), exist_ok=True)

    app.logger.info("GhostPortal started successfully")
    return app


# ---------------------------------------------------------------------------
# Configuration loader
# ---------------------------------------------------------------------------

def _load_config(app: Flask) -> None:
    """Load all configuration from environment variables."""
    env = os.getenv

    app.config.update(
        # Flask core
        SECRET_KEY=env("SECRET_KEY", "insecure-dev-key-change-me-in-production"),
        FLASK_ENV=env("FLASK_ENV", "development"),
        DEBUG=env("FLASK_ENV", "development") == "development",
        TESTING=False,

        # Session
        SESSION_COOKIE_NAME="gp_session",
        SESSION_COOKIE_SECURE=env("SESSION_COOKIE_SECURE", "false").lower() == "true",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(
            seconds=int(env("PERMANENT_SESSION_LIFETIME", "86400"))
        ),

        # Database
        SQLALCHEMY_DATABASE_URI=env(
            "DATABASE_URL", "sqlite:///ghostportal_dev.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={
            "pool_pre_ping": True,
            "pool_recycle": 300,
        },

        # SMTP
        MAIL_SERVER=env("MAIL_SERVER", "localhost"),
        MAIL_PORT=int(env("MAIL_PORT", "587")),
        MAIL_USE_TLS=env("MAIL_USE_TLS", "true").lower() == "true",
        MAIL_USERNAME=env("MAIL_USERNAME", ""),
        MAIL_PASSWORD=env("MAIL_PASSWORD", ""),
        MAIL_DEFAULT_SENDER=env("MAIL_DEFAULT_SENDER", "ghostportal@localhost"),

        # hCaptcha
        HCAPTCHA_SITE_KEY=env("HCAPTCHA_SITE_KEY", ""),
        HCAPTCHA_SECRET_KEY=env("HCAPTCHA_SECRET_KEY", ""),

        # Owner
        OWNER_EMAIL=env("OWNER_EMAIL", ""),

        # Notifications
        DISCORD_WEBHOOK_URL=env("DISCORD_WEBHOOK_URL", ""),
        TELEGRAM_BOT_TOKEN=env("TELEGRAM_BOT_TOKEN", ""),
        TELEGRAM_CHAT_ID=env("TELEGRAM_CHAT_ID", ""),

        # Invite & follow-up
        INVITE_EXPIRY_DAYS=int(env("INVITE_EXPIRY_DAYS", "90")),
        INVITE_EXTENSION_DAYS=int(env("INVITE_EXTENSION_DAYS", "30")),
        FOLLOWUP_SCHEDULE=env("FOLLOWUP_SCHEDULE", "30,60,90"),
        BASE_URL=env("BASE_URL", "http://localhost:5000"),

        # File uploads — resolve relative paths from project root, not app package
        UPLOAD_FOLDER=os.path.abspath(
            os.path.join(os.path.dirname(os.path.dirname(__file__)),
                         env("UPLOAD_FOLDER", "./uploads"))
        ),
        MAX_CONTENT_LENGTH=int(env("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024))),
        ALLOWED_EXTENSIONS=set(
            env("ALLOWED_EXTENSIONS", "png,jpg,jpeg,gif,mp4,mov,webm,pdf,txt,log").split(",")
        ),

        # Backup
        BACKUP_ENCRYPTION_KEY=env("BACKUP_ENCRYPTION_KEY", ""),

        # Redis / Celery
        REDIS_URL=env("REDIS_URL", "redis://localhost:6379/0"),

        # Rate limiting (RATELIMIT_STORAGE_URI is set later after Redis availability check)
        RATELIMIT_DEFAULT=env("RATELIMIT_DEFAULT", "100 per hour"),
        RATELIMIT_STORAGE_URI="memory://",

        # AI — Ollama only (self-hosted); disabled by default
        AI_ENABLED=env("AI_ENABLED", "false").lower() in ("true", "1", "yes"),
        AI_DEFAULT_PROVIDER="ollama",
        OLLAMA_BASE_URL=env("OLLAMA_BASE_URL", "http://localhost:11434"),
        OLLAMA_MODEL=env("OLLAMA_MODEL", "llama3.1"),

        # API
        API_KEY=env("API_KEY", ""),

        # Session policy
        IDLE_TIMEOUT_SECONDS=int(env("IDLE_TIMEOUT_SECONDS", "300")),
        SINGLE_SESSION_ENFORCE=env("SINGLE_SESSION_ENFORCE", "true").lower() == "true",

        # Magic link OTP
        MAGIC_LINK_OTP_LENGTH=int(env("MAGIC_LINK_OTP_LENGTH", "20")),
        MAGIC_LINK_EXPIRY_MINUTES=int(env("MAGIC_LINK_EXPIRY_MINUTES", "15")),

        # Security team access expiry
        RESOLVED_ACCESS_EXPIRY_DAYS=int(env("RESOLVED_ACCESS_EXPIRY_DAYS", "10")),

        # Platform identity
        PLATFORM_NAME=env("PLATFORM_NAME", "GhostPortal"),
        OPERATOR_NAME=env("OPERATOR_NAME", ""),
        OPERATOR_EMAIL=env("OPERATOR_EMAIL", ""),
        OPERATOR_COUNTRY=env("OPERATOR_COUNTRY", "Philippines"),
        PLATFORM_URL=env("PLATFORM_URL", "https://yourdomain.com"),

        # Legal
        POLICY_VERSION=env("POLICY_VERSION", "1.0"),
        POLICY_LAST_UPDATED=env("POLICY_LAST_UPDATED", "2026-01-01"),

        # GeoIP
        GEOIP_ENABLED=env("GEOIP_ENABLED", "false").lower() == "true",
        GEOIP_DB_PATH=env("GEOIP_DB_PATH", "./GeoLite2-Country.mmdb"),

        # Owner Payment Details — displayed to security teams when they set a bounty
        # Leave blank to hide that payment method from the security team's options
        OWNER_PAYPAL_EMAIL=env("PAYPAL_EMAIL", ""),
        PAYPAL_ME_URL=env("PAYPAL_ME_URL", ""),
        # Crypto wallet addresses (leave blank to hide that coin/network)
        OWNER_CRYPTO_BTC=env("OWNER_CRYPTO_BTC", ""),
        OWNER_CRYPTO_ETH=env("OWNER_CRYPTO_ETH", ""),
        OWNER_CRYPTO_USDT_TRC20=env("OWNER_CRYPTO_USDT_TRC20", ""),
        OWNER_CRYPTO_USDT_ERC20=env("OWNER_CRYPTO_USDT_ERC20", ""),
        OWNER_CRYPTO_USDC_ERC20=env("OWNER_CRYPTO_USDC_ERC20", ""),
        OWNER_CRYPTO_XMR=env("OWNER_CRYPTO_XMR", ""),
        OWNER_CRYPTO_BNB=env("OWNER_CRYPTO_BNB", ""),
        OWNER_CRYPTO_DOGE=env("OWNER_CRYPTO_DOGE", ""),
        OWNER_CRYPTO_LTC=env("OWNER_CRYPTO_LTC", ""),
        # Bank transfer / international wire (leave all blank to hide bank option)
        OWNER_BANK_ACCOUNT_NAME=env("OWNER_BANK_ACCOUNT_NAME", ""),
        OWNER_BANK_ACCOUNT_NUMBER=env("OWNER_BANK_ACCOUNT_NUMBER", ""),
        OWNER_BANK_IBAN=env("OWNER_BANK_IBAN", ""),
        OWNER_BANK_SWIFT=env("OWNER_BANK_SWIFT", ""),
        OWNER_BANK_ROUTING=env("OWNER_BANK_ROUTING", ""),
        OWNER_BANK_NAME=env("OWNER_BANK_NAME", ""),
        OWNER_BANK_ADDRESS=env("OWNER_BANK_ADDRESS", ""),
        OWNER_BANK_COUNTRY=env("OWNER_BANK_COUNTRY", ""),

        # TOTP
        TOTP_ENABLED=env("TOTP_ENABLED", "false").lower() == "true",

        # IP allowlist
        OWNER_IP_ALLOWLIST=env("OWNER_IP_ALLOWLIST", ""),

        # WTF
        WTF_CSRF_TIME_LIMIT=3600,
    )

    # Ensure upload directories exist
    upload_folder = app.config["UPLOAD_FOLDER"]
    for subdir in ["quarantine", "verified"]:
        os.makedirs(os.path.join(upload_folder, subdir), exist_ok=True)


# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------

def _register_blueprints(app: Flask) -> None:
    """Register all application blueprints."""
    from app.blueprints.auth import auth_bp
    from app.blueprints.dashboard import dashboard_bp
    from app.blueprints.reports import reports_bp
    from app.blueprints.portal import portal_bp
    from app.blueprints.templates_bp import templates_bp
    from app.blueprints.security_teams import security_teams_bp
    from app.blueprints.bounty import bounty_bp
    from app.blueprints.programs import programs_bp
    from app.blueprints.program_list import program_list_bp
    from app.blueprints.webhooks import webhooks_bp
    from app.blueprints.ai_bp import ai_bp
    from app.blueprints.legal import legal_bp
    from app.blueprints.api import api_bp
    from app.blueprints.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(portal_bp)
    app.register_blueprint(templates_bp)
    app.register_blueprint(security_teams_bp)
    app.register_blueprint(bounty_bp)
    app.register_blueprint(programs_bp)
    app.register_blueprint(program_list_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(legal_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(settings_bp)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

def _register_error_handlers(app: Flask) -> None:
    """Register custom error handlers — no stacktraces in responses."""

    @app.errorhandler(400)
    def bad_request(e):
        if _wants_json():
            return jsonify({"error": "Bad Request", "message": "Your request could not be processed."}), 400
        return render_template("errors/400.html"), 400

    @app.errorhandler(403)
    def forbidden(e):
        if _wants_json():
            return jsonify({"error": "Forbidden", "message": "You do not have permission to access this resource."}), 403
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({"error": "Not Found", "message": "The resource does not exist or has been moved."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        if _wants_json():
            return jsonify({"error": "Method Not Allowed", "message": "This action is not permitted on this endpoint."}), 405
        return render_template("errors/405.html"), 405

    @app.errorhandler(429)
    def rate_limited(e):
        if _wants_json():
            return jsonify({"error": "Too Many Requests", "message": "Too many requests. Please wait."}), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(e):
        request_id = getattr(g, "request_id", str(uuid.uuid4()))
        app.logger.error(
            f"Internal error: {e}",
            extra={"request_id": request_id},
            exc_info=True,
        )
        if _wants_json():
            return jsonify({
                "error": "Internal Server Error",
                "message": "An unexpected error occurred. The incident has been logged.",
                "request_id": request_id,
            }), 500
        return render_template("errors/500.html", request_id=request_id), 500

    @app.errorhandler(503)
    def service_unavailable(e):
        if _wants_json():
            return jsonify({"error": "Service Unavailable", "message": "GhostPortal is temporarily unavailable."}), 503
        return render_template("errors/503.html"), 503


def _wants_json() -> bool:
    """Check if the client prefers JSON response."""
    return (
        request.accept_mimetypes.accept_json
        and not request.accept_mimetypes.accept_html
    )


# ---------------------------------------------------------------------------
# After-request hooks
# ---------------------------------------------------------------------------

def _register_after_request_hooks(app: Flask) -> None:
    """Register hooks that run after every request."""
    from app.utils.security_headers import apply_security_headers

    @app.before_request
    def assign_request_id():
        g.request_id = str(uuid.uuid4())

    @app.after_request
    def add_security_headers(response):
        response = apply_security_headers(response)
        # X-Request-ID is set by apply_security_headers; override with the
        # request-scoped ID assigned in before_request so it matches logs.
        response.headers["X-Request-ID"] = getattr(g, "request_id", response.headers.get("X-Request-ID", ""))
        # Remove server fingerprinting headers
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        return response
