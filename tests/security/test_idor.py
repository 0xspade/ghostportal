# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Security tests for IDOR (Insecure Direct Object Reference) vulnerabilities.

Tests:
  - Security team member A cannot access member B's report
  - Owner cannot be impersonated by security team session
  - Portal routes verify invite ownership
  - Cross-invite data isolation
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest


class TestPortalIDOR:
    def test_member_a_cannot_access_member_b_invite(self, client, db, app):
        """Security team member A with valid session must not access member B's invite."""
        from app.models import (
            Report, SecurityTeamInvite, SecurityTeamMember,
        )

        # Create two members
        member_a = SecurityTeamMember(
            id=uuid.uuid4(),
            email="member_a@company-a.example",
            company_name="Company A",
            registered_at=datetime.now(timezone.utc),
            is_active=True,
        )
        member_b = SecurityTeamMember(
            id=uuid.uuid4(),
            email="member_b@company-b.example",
            company_name="Company B",
            registered_at=datetime.now(timezone.utc),
            is_active=True,
        )
        db.session.add_all([member_a, member_b])

        # Create report and invite for member B
        report = Report(
            id=uuid.uuid4(),
            title="Member B's Report",
            severity="high",
            status="submitted",
        )
        db.session.add(report)

        invite_b = SecurityTeamInvite(
            id=uuid.uuid4(),
            report_id=report.id,
            email=member_b.email,
            company_name="Company B",
            token_hash="hash_b",
            is_active=True,
            is_locked=False,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db.session.add(invite_b)
        db.session.commit()

        # Log in as member A
        with client.session_transaction() as sess:
            sess["role"] = "security_team"
            sess["member_id"] = str(member_a.id)
            sess["member_email"] = member_a.email
            sess["session_id"] = str(uuid.uuid4())
            sess["last_active"] = datetime.now(timezone.utc).isoformat()

        # Try to access member B's invite
        resp = client.get(f"/portal/report/{invite_b.id}")
        assert resp.status_code in [403, 302], (
            f"Member A accessed Member B's report (status: {resp.status_code})"
        )
        # Must not contain Member B's report title
        assert b"Member B's Report" not in resp.data

    def test_unauthenticated_cannot_access_portal_report(self, client, db, active_invite):
        """Unauthenticated requests to portal must be redirected."""
        invite, report = active_invite
        resp = client.get(f"/portal/report/{invite.id}")
        assert resp.status_code in [302, 401]
        if resp.status_code == 302:
            assert "/login" in resp.headers.get("Location", "")

    def test_owner_session_cannot_access_portal_route(self, client, owner_session, db, active_invite):
        """Owner session should not be able to use portal routes (different namespaces)."""
        invite, report = active_invite
        # The portal route requires security_team role, not owner
        resp = owner_session.get(f"/portal/report/{invite.id}")
        # Should get forbidden or redirect (not 200 with portal content)
        assert resp.status_code in [302, 403, 404]


class TestReportIDOR:
    def test_owner_can_access_own_reports(self, client, owner_session, db):
        """Owner can access their own reports."""
        from app.models import Report
        report = Report(
            id=uuid.uuid4(),
            title="Owner's Report",
            severity="medium",
            status="draft",
        )
        db.session.add(report)
        db.session.commit()

        resp = owner_session.get(f"/reports/{report.id}")
        # Should be 200 or redirect to report detail
        assert resp.status_code in [200, 302]

    def test_unauthenticated_cannot_access_reports(self, client, db):
        """Unauthenticated users cannot view reports."""
        from app.models import Report
        report = Report(
            id=uuid.uuid4(),
            title="Secret Report",
            severity="critical",
            status="submitted",
        )
        db.session.add(report)
        db.session.commit()

        resp = client.get(f"/reports/{report.id}")
        assert resp.status_code in [302, 401]
        if resp.status_code == 302:
            assert "/login" in resp.headers.get("Location", "")

    def test_nonexistent_report_returns_404(self, client, owner_session):
        """Nonexistent report UUID returns 404, not an error revealing internal state."""
        fake_id = uuid.uuid4()
        resp = owner_session.get(f"/reports/{fake_id}")
        assert resp.status_code == 404
