# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
pytest configuration and shared fixtures for GhostPortal tests.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest

# Force test environment before any app imports
os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("TESTING", "true")
os.environ.setdefault("SECRET_KEY", "a" * 64)
os.environ.setdefault("OWNER_EMAIL", "owner@test.example")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("WTF_CSRF_ENABLED", "false")
os.environ.setdefault("HCAPTCHA_SECRET_KEY", "")
os.environ.setdefault("MAGIC_LINK_OTP_LENGTH", "20")
os.environ.setdefault("MAGIC_LINK_EXPIRY_MINUTES", "15")
os.environ.setdefault("RESOLVED_ACCESS_EXPIRY_DAYS", "10")
os.environ.setdefault("BACKUP_ENCRYPTION_KEY", "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXQ=")
os.environ.setdefault("BASE_URL", "http://localhost:5000")
os.environ.setdefault("IDLE_TIMEOUT_SECONDS", "0")  # Disable for tests
os.environ.setdefault("SINGLE_SESSION_ENFORCE", "false")


@pytest.fixture(scope="session")
def app():
    """Create Flask app for testing."""
    from app import create_app
    flask_app = create_app()
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "HCAPTCHA_SECRET_KEY": "",
        "IDLE_TIMEOUT_SECONDS": 0,
        "SINGLE_SESSION_ENFORCE": False,
    })
    return flask_app


@pytest.fixture(scope="session")
def db(app):
    """Create database tables for testing."""
    from app.extensions import db as _db
    with app.app_context():
        _db.create_all()
        yield _db
        _db.drop_all()


@pytest.fixture(autouse=True)
def db_session(db, app):
    """Wrap each test in a transaction that gets rolled back."""
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        db.session.bind = connection
        yield db.session
        db.session.remove()
        transaction.rollback()
        connection.close()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def owner_user(db, app):
    """Create and return an owner User record."""
    from app.models import User
    user = User(
        id=uuid.uuid4(),
        email="owner@test.example",
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def owner_session(client, owner_user):
    """Return authenticated client session for owner."""
    with client.session_transaction() as sess:
        sess["role"] = "owner"
        sess["user_id"] = str(owner_user.id)
        sess["session_id"] = str(uuid.uuid4())
        sess["last_active"] = datetime.now(timezone.utc).isoformat()
    return client


@pytest.fixture
def security_team_member(db, app):
    """Create a SecurityTeamMember record."""
    from app.models import SecurityTeamMember
    member = SecurityTeamMember(
        id=uuid.uuid4(),
        email="security@company.example",
        company_name="Test Security Corp",
        registered_at=datetime.now(timezone.utc),
        is_active=True,
    )
    db.session.add(member)
    db.session.commit()
    return member


@pytest.fixture
def active_invite(db, app, owner_user, security_team_member):
    """Create an active SecurityTeamInvite."""
    from app.models import Report, SecurityTeamInvite
    from datetime import timedelta

    report = Report(
        id=uuid.uuid4(),
        title="Test XSS Vulnerability",
        severity="high",
        status="submitted",
    )
    db.session.add(report)

    invite = SecurityTeamInvite(
        id=uuid.uuid4(),
        report_id=report.id,
        email=security_team_member.email,
        company_name="Test Security Corp",
        token_hash="testhash",
        is_active=True,
        is_locked=False,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    db.session.add(invite)
    db.session.commit()
    return invite, report


OWNER_EMAIL = "owner@test.example"
