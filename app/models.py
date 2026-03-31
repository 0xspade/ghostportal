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
All SQLAlchemy models — UUID primary keys throughout.
PostgreSQL UUID type used for all PKs and FKs.
SQLite fallback uses String(36) for dev compatibility.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    JSON,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, validates
from sqlalchemy.types import TypeDecorator, CHAR
import sqlalchemy as sa

from app.extensions import db


# ---------------------------------------------------------------------------
# UUID Column helper — PostgreSQL native UUID, SQLite String fallback
# ---------------------------------------------------------------------------

class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type, otherwise uses CHAR(36), storing as
    stringified hex values.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return str(value) if not isinstance(value, uuid.UUID) else value
        else:
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(str(value)))
            return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(str(value))
        return value


def utcnow() -> datetime:
    """Return current UTC datetime (timezone-aware)."""
    return datetime.now(timezone.utc)


def new_uuid() -> uuid.UUID:
    """Generate a new UUID v4."""
    return uuid.uuid4()


# ---------------------------------------------------------------------------
# Immutable audit log guard — prevents UPDATE/DELETE on InviteActivity
# ---------------------------------------------------------------------------

def _prevent_mutation(mapper, connection, target):
    raise RuntimeError(
        f"InviteActivity records are immutable. "
        f"Attempted to modify record {target.id}."
    )


# ---------------------------------------------------------------------------
# User (Owner)
# ---------------------------------------------------------------------------

class User(db.Model):
    """
    Owner account — single researcher. Passwordless only.
    Magic link + OTP two-factor within one flow.
    """
    __tablename__ = "users"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    email = Column(String(254), nullable=False, unique=True, index=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    last_login_ua = Column(Text, nullable=True)
    current_session_id = Column(GUID(), nullable=True)

    # Magic link + OTP (both must match — two-factor within one flow)
    login_url_token_hash = Column(String(64), nullable=True, unique=True)
    login_otp_hash = Column(String(64), nullable=True)
    token_expiry = Column(DateTime(timezone=True), nullable=True)
    token_used = Column(Boolean, default=False, nullable=False)

    # TOTP second factor (opt-in)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    totp_secret_encrypted = Column(Text, nullable=True)  # AES-256-GCM encrypted

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<User {self.email}>"


# ---------------------------------------------------------------------------
# SecurityTeamMember
# ---------------------------------------------------------------------------

class SecurityTeamMember(db.Model):
    """
    Registered security team member. Created on first portal setup.
    Can subsequently log in via /login (same page as owner).
    """
    __tablename__ = "security_team_members"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    email = Column(String(254), nullable=False, unique=True, index=True)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="SET NULL"), nullable=True)
    company_name = Column(String(200), nullable=True)
    registered_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    last_login_ua = Column(Text, nullable=True)
    current_session_id = Column(GUID(), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Magic link + OTP
    login_url_token_hash = Column(String(64), nullable=True, unique=True)
    login_otp_hash = Column(String(64), nullable=True)
    token_expiry = Column(DateTime(timezone=True), nullable=True)
    token_used = Column(Boolean, default=False, nullable=False)

    # Relationships
    first_invite = relationship(
        "SecurityTeamInvite",
        foreign_keys=[invite_id],
        back_populates="registering_member",
    )
    sessions = relationship(
        "SecurityTeamSession",
        foreign_keys="SecurityTeamSession.member_id",
        back_populates="member",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SecurityTeamMember {self.email}>"


# ---------------------------------------------------------------------------
# ReportTemplate
# ---------------------------------------------------------------------------

class ReportTemplate(db.Model):
    """Built-in and custom vulnerability report templates."""
    __tablename__ = "report_templates"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    name = Column(String(200), nullable=False)
    category = Column(
        Enum(
            "web", "api", "mobile", "web3", "network",
            "physical", "social_engineering", "custom",
            name="template_category",
        ),
        nullable=False,
        default="custom",
    )
    title_template = Column(Text, nullable=True)
    description_template = Column(Text, nullable=True)
    steps_template = Column(Text, nullable=True)
    poc_template = Column(Text, nullable=True)
    remediation_template = Column(Text, nullable=True)
    cwe_id = Column(Integer, nullable=True)
    cwe_name = Column(String(200), nullable=True)
    severity = Column(
        Enum("critical", "high", "medium", "low", "informational", name="severity_enum"),
        nullable=True,
    )
    cvss_vector = Column(String(500), nullable=True)
    cvss_score = Column(db.Numeric(4, 1), nullable=True)
    tags = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    reports = relationship("Report", back_populates="template")

    def __repr__(self) -> str:
        return f"<ReportTemplate {self.name}>"


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report(db.Model):
    """Core vulnerability report. All IDs are UUIDs."""
    __tablename__ = "reports"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    display_id = Column(String(20), nullable=True, unique=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    steps_to_reproduce = Column(Text, nullable=True)
    cvss_score = Column(Numeric(4, 1), nullable=True)
    cvss_vector = Column(String(500), nullable=True)
    cwe_id = Column(Integer, nullable=True)
    cwe_name = Column(String(200), nullable=True)
    severity = Column(
        Enum("critical", "high", "medium", "low", "informational", name="report_severity_enum"),
        nullable=False,
        default="medium",
    )
    status = Column(
        Enum(
            "draft", "submitted", "triaged", "duplicate",
            "informative", "resolved", "wont_fix", "not_applicable",
            name="report_status_enum",
        ),
        nullable=False,
        default="draft",
    )
    remediation = Column(Text, nullable=True)
    technical_details = Column(Text, nullable=True)
    impact_statement = Column(Text, nullable=True)
    proof_of_concept = Column(Text, nullable=True)
    target_asset = Column(String(500), nullable=True)
    program_name = Column(String(300), nullable=True)
    tags = Column(JSON, default=list, nullable=False)
    template_id = Column(GUID(), ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True)
    bounty_amount = Column(Numeric(18, 8), nullable=True)
    bounty_currency = Column(String(10), nullable=True)
    bounty_paid_at = Column(DateTime(timezone=True), nullable=True)
    ai_generated = Column(Boolean, default=False, nullable=False)
    ai_provider = Column(String(50), nullable=True)
    is_locked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    submitted_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    template = relationship("ReportTemplate", back_populates="reports")
    attachments = relationship(
        "ReportAttachment",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    invites = relationship(
        "SecurityTeamInvite",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    replies = relationship(
        "ReportReply",
        back_populates="report",
        cascade="all, delete-orphan",
        order_by="ReportReply.created_at",
    )
    field_edits = relationship(
        "ReportFieldEdit",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    bounty_payments = relationship(
        "BountyPayment",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    ai_jobs = relationship(
        "AIGenerationJob",
        back_populates="report",
        cascade="all, delete-orphan",
    )
    external_links = relationship(
        "ExternalLink",
        back_populates="report",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Report {self.display_id or str(self.id)[:8]}>"


# ---------------------------------------------------------------------------
# ReportAttachment
# ---------------------------------------------------------------------------

class ReportAttachment(db.Model):
    """File attachments for reports. UUID-renamed filenames."""
    __tablename__ = "report_attachments"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    filename_original = Column(String(500), nullable=False)
    filename_stored = Column(String(100), nullable=False)  # UUID.ext
    mime_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)
    uploaded_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    report = relationship("Report", back_populates="attachments")

    def __repr__(self) -> str:
        return f"<ReportAttachment {self.filename_original}>"


# ---------------------------------------------------------------------------
# ReportVersion — snapshot on every significant owner edit
# ---------------------------------------------------------------------------

class ReportVersion(db.Model):
    """Immutable snapshot of a report's fields before each owner edit."""
    __tablename__ = "report_versions"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    # Snapshot stored as JSON-encoded dict of all tracked fields
    snapshot = Column(JSON, nullable=False)
    # Which fields changed in the edit that triggered this snapshot
    changed_fields = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    report = relationship("Report", backref="versions")

    def __repr__(self) -> str:
        return f"<ReportVersion {self.report_id} @ {self.created_at}>"


# ---------------------------------------------------------------------------
# SecurityTeamInvite
# ---------------------------------------------------------------------------

class SecurityTeamInvite(db.Model):
    """Per-report invite for a security team member. Each email gets its own invite."""
    __tablename__ = "security_team_invites"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(254), nullable=False, index=True)
    company_name = Column(String(200), nullable=True)
    label = Column(String(100), nullable=True)  # e.g., "PSIRT", "Vendor Security"

    # Token storage — raw tokens NEVER stored, only SHA3-256 hashes
    token_hash = Column(String(64), nullable=True, unique=True)
    otp_hash = Column(String(64), nullable=True)
    token_created_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    extended_count = Column(Integer, default=0, nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)
    lock_reason = Column(Text, nullable=True)

    first_accessed_at = Column(DateTime(timezone=True), nullable=True)
    last_activity_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Follow-up tracking
    followup_30_sent_at = Column(DateTime(timezone=True), nullable=True)
    followup_60_sent_at = Column(DateTime(timezone=True), nullable=True)
    followup_90_sent_at = Column(DateTime(timezone=True), nullable=True)

    # Resolved-access expiry
    all_resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_expiry_notified_3d = Column(Boolean, default=False, nullable=False)
    resolved_expiry_notified_1d = Column(Boolean, default=False, nullable=False)

    # Relationships
    report = relationship("Report", back_populates="invites")
    registering_member = relationship(
        "SecurityTeamMember",
        foreign_keys="SecurityTeamMember.invite_id",
        back_populates="first_invite",
    )
    sessions = relationship(
        "SecurityTeamSession",
        back_populates="invite",
        cascade="all, delete-orphan",
    )
    activity_log = relationship(
        "InviteActivity",
        back_populates="invite",
        passive_deletes=True,
        order_by="InviteActivity.performed_at",
    )
    replies = relationship(
        "ReportReply",
        back_populates="invite",
    )
    field_edits = relationship(
        "ReportFieldEdit",
        back_populates="invite",
        cascade="all, delete-orphan",
    )
    bounty_payments = relationship(
        "BountyPayment",
        back_populates="invite",
        cascade="all, delete-orphan",
    )
    followup_schedules = relationship(
        "FollowUpSchedule",
        back_populates="invite",
        cascade="all, delete-orphan",
    )
    notifications = relationship(
        "Notification",
        back_populates="invite",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SecurityTeamInvite {self.email} for report {self.report_id}>"


# ---------------------------------------------------------------------------
# SecurityTeamSession
# ---------------------------------------------------------------------------

class SecurityTeamSession(db.Model):
    """Portal session for security team members."""
    __tablename__ = "security_team_sessions"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="CASCADE"), nullable=False)
    member_id = Column(GUID(), ForeignKey("security_team_members.id", ondelete="CASCADE"), nullable=False)
    session_token_hash = Column(String(64), nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_activity_ip = Column(String(45), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    is_revoked = Column(Boolean, default=False, nullable=False)

    # Relationships
    invite = relationship("SecurityTeamInvite", back_populates="sessions")
    member = relationship(
        "SecurityTeamMember",
        foreign_keys=[member_id],
        back_populates="sessions",
    )

    def __repr__(self) -> str:
        return f"<SecurityTeamSession member={self.member_id}>"


# ---------------------------------------------------------------------------
# AccessLog (immutable)
# ---------------------------------------------------------------------------

class AccessLog(db.Model):
    """
    Immutable access log for all authenticated requests.
    Email stored as SHA-256 hash — never plaintext.
    """
    __tablename__ = "access_logs"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    user_type = Column(
        Enum("owner", "security_team", name="access_user_type"),
        nullable=False,
    )
    user_ref = Column(String(36), nullable=True)       # UUID string, no FK (log survives deletion)
    session_id = Column(String(36), nullable=True)     # UUID string, no FK
    ip_address = Column(String(45), nullable=False)
    ip_country = Column(String(2), nullable=True)
    user_agent = Column(Text, nullable=True)
    ua_browser = Column(String(100), nullable=True)
    ua_os = Column(String(100), nullable=True)
    ua_is_bot = Column(Boolean, default=False, nullable=False)
    method = Column(String(10), nullable=False)
    path = Column(String(2000), nullable=False)
    response_code = Column(Integer, nullable=True)
    event_type = Column(String(50), nullable=False, index=True)
    metadata_ = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<AccessLog {self.event_type} {self.ip_address}>"


# ---------------------------------------------------------------------------
# InviteActivity (immutable audit log)
# ---------------------------------------------------------------------------

class InviteActivity(db.Model):
    """
    Immutable audit log for security team actions.
    Guarded at ORM level — no UPDATE or DELETE allowed.
    """
    __tablename__ = "invite_activities"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(
        Enum(
            "invite_sent",
            "link_clicked", "setup_complete", "reply_posted", "bounty_set", "bounty_sent",
            "bounty_edited", "status_changed", "session_refreshed", "account_locked",
            "account_unlocked", "followup_30_sent", "followup_60_sent", "followup_90_sent",
            "followup_skipped", "field_edit_proposed", "field_edit_accepted",
            "field_edit_rejected", "report_edited", "retest_requested", "retest_confirmed",
            "report_reopened", "bounty_confirmed", "bonus_confirmed",
            name="invite_activity_action",
        ),
        nullable=False,
        index=True,
    )
    performed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    metadata_ = Column("metadata", JSON, nullable=True)

    # Relationships
    invite = relationship("SecurityTeamInvite", back_populates="activity_log")

    def __repr__(self) -> str:
        return f"<InviteActivity {self.action} invite={self.invite_id}>"


# Attach immutability guard after class definition
event.listen(InviteActivity, "before_update", _prevent_mutation)
event.listen(InviteActivity, "before_delete", _prevent_mutation)


# ---------------------------------------------------------------------------
# ReportReply
# ---------------------------------------------------------------------------

class ReportReply(db.Model):
    """Reply/comment on a report. Supports owner-only internal notes."""
    __tablename__ = "report_replies"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    author_type = Column(
        Enum("owner", "security_team", name="reply_author_type"),
        nullable=False,
    )
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="SET NULL"), nullable=True)
    body = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    report = relationship("Report", back_populates="replies")
    invite = relationship("SecurityTeamInvite", back_populates="replies")

    def __repr__(self) -> str:
        return f"<ReportReply {self.author_type} on report={self.report_id}>"


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

class Notification(db.Model):
    """Tracks all notification send attempts with retry logic."""
    __tablename__ = "notifications"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="SET NULL"), nullable=True)
    channel = Column(
        Enum("email", "discord", "telegram", name="notification_channel"),
        nullable=False,
    )
    event = Column(String(100), nullable=False)
    recipient = Column(String(500), nullable=False)
    status = Column(
        Enum("pending", "sent", "failed", "retrying", name="notification_status"),
        nullable=False,
        default="pending",
    )
    attempts = Column(Integer, default=0, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    invite = relationship("SecurityTeamInvite", back_populates="notifications")

    def __repr__(self) -> str:
        return f"<Notification {self.channel} {self.event} {self.status}>"


# ---------------------------------------------------------------------------
# ExternalLink (open redirect prevention)
# ---------------------------------------------------------------------------

class ExternalLink(db.Model):
    """All outbound URLs routed through /go/<token> interstitial."""
    __tablename__ = "external_links"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    token = Column(GUID(), unique=True, nullable=False, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=True)
    original_url = Column(Text, nullable=False)
    domain = Column(String(253), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    click_count = Column(Integer, default=0, nullable=False)

    # Relationships
    report = relationship("Report", back_populates="external_links")

    def __repr__(self) -> str:
        return f"<ExternalLink {self.domain}>"


# ---------------------------------------------------------------------------
# AIGenerationJob
# ---------------------------------------------------------------------------

class AIGenerationJob(db.Model):
    """Tracks async AI report generation requests."""
    __tablename__ = "ai_generation_jobs"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)
    provider = Column(
        Enum("anthropic", "openai", "gemini", "ollama", name="ai_provider_enum"),
        nullable=False,
    )
    model = Column(String(100), nullable=False)
    prompt_type = Column(
        Enum(
            "full_report", "section", "improve", "explain_cvss",
            "suggest_remediation", "suggest_cwe",
            name="ai_prompt_type",
        ),
        nullable=False,
    )
    status = Column(
        Enum("pending", "running", "completed", "failed", name="ai_job_status"),
        nullable=False,
        default="pending",
    )
    input_context = Column(JSON, nullable=True)
    output_text = Column(Text, nullable=True)
    tokens_used = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    report = relationship("Report", back_populates="ai_jobs")

    def __repr__(self) -> str:
        return f"<AIGenerationJob {self.provider} {self.status}>"


# ---------------------------------------------------------------------------
# FollowUpSchedule
# ---------------------------------------------------------------------------

class FollowUpSchedule(db.Model):
    """Scheduled follow-up notifications per invite (30/60/90 day)."""
    __tablename__ = "followup_schedules"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="CASCADE"), nullable=False, index=True)
    scheduled_days = Column(
        Enum("30", "60", "90", name="followup_days"),
        nullable=False,
    )
    scheduled_at = Column(DateTime(timezone=True), nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(
        Enum("pending", "sent", "skipped", name="followup_status"),
        nullable=False,
        default="pending",
    )
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    invite = relationship("SecurityTeamInvite", back_populates="followup_schedules")

    def __repr__(self) -> str:
        return f"<FollowUpSchedule day={self.scheduled_days} {self.status}>"


# ---------------------------------------------------------------------------
# ProgramName
# ---------------------------------------------------------------------------

class ProgramName(db.Model):
    """Auto-saved program names for owner autocomplete and program directory."""
    __tablename__ = "program_names"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    name = Column(String(300), nullable=False)
    name_normalized = Column(String(300), nullable=False, unique=True, index=True)
    email = Column(String(254), nullable=True)  # Security contact email for this program
    last_used_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    use_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<ProgramName {self.name}>"


# ---------------------------------------------------------------------------
# ReportFieldEdit
# ---------------------------------------------------------------------------

class ReportFieldEdit(db.Model):
    """Security team proposed field corrections — never auto-applied."""
    __tablename__ = "report_field_edits"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="CASCADE"), nullable=False)
    field_name = Column(
        Enum(
            "title", "severity", "cvss_vector", "cvss_score", "cwe_id", "cwe_name",
            name="field_edit_field",
        ),
        nullable=False,
    )
    old_value = Column(Text, nullable=True)       # JSON-encoded original value
    proposed_value = Column(Text, nullable=False)  # JSON-encoded proposed value
    reason = Column(Text, nullable=False)          # Mandatory explanation (min 30 chars)
    status = Column(
        Enum("pending", "accepted", "rejected", name="field_edit_status"),
        nullable=False,
        default="pending",
    )
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    # Relationships
    report = relationship("Report", back_populates="field_edits")
    invite = relationship("SecurityTeamInvite", back_populates="field_edits")

    @validates("reason")
    def validate_reason(self, key: str, value: str) -> str:
        if value and len(value.strip()) < 30:
            raise ValueError("Field edit reason must be at least 30 characters.")
        return value

    def __repr__(self) -> str:
        return f"<ReportFieldEdit {self.field_name} {self.status}>"


# ---------------------------------------------------------------------------
# BountyPayment
# ---------------------------------------------------------------------------

class BountyPayment(db.Model):
    """Tracks all bounty payment attempts and completions."""
    __tablename__ = "bounty_payments"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    report_id = Column(GUID(), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    invite_id = Column(GUID(), ForeignKey("security_team_invites.id", ondelete="SET NULL"), nullable=True)
    method = Column(
        Enum("paypal", "crypto", "bank_transfer", "other", name="payment_method"),
        nullable=False,
    )
    amount = Column(Numeric(18, 8), nullable=False)
    currency = Column(String(10), nullable=False)

    # PayPal fields
    paypal_payout_batch_id = Column(String(200), nullable=True)
    paypal_item_id = Column(String(200), nullable=True)
    paypal_recipient_email = Column(String(254), nullable=True)
    paypal_transaction_id = Column(String(200), nullable=True, unique=True)

    # Crypto fields
    crypto_address = Column(String(200), nullable=True)
    crypto_network = Column(String(50), nullable=True)
    crypto_tx_hash = Column(String(200), nullable=True)
    crypto_confirmations = Column(Integer, nullable=True)

    # Bonus flag (True when this payment is an additional reward after retest)
    is_bonus = Column(Boolean, nullable=False, default=False, server_default="false")

    # Common fields
    status = Column(
        Enum("pending", "processing", "completed", "failed", "refunded", name="payment_status"),
        nullable=False,
        default="pending",
    )
    reference = Column(Text, nullable=True)
    initiated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    # Relationships
    report = relationship("Report", back_populates="bounty_payments")
    invite = relationship("SecurityTeamInvite", back_populates="bounty_payments")

    def __repr__(self) -> str:
        return f"<BountyPayment {self.method} {self.amount} {self.currency} {self.status}>"


# ---------------------------------------------------------------------------
# SystemConfig
# ---------------------------------------------------------------------------

class SystemConfig(db.Model):
    """Runtime-editable settings. Cached in Redis for performance."""
    __tablename__ = "system_configs"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    key = Column(String(100), nullable=False, unique=True, index=True)
    value = Column(Text, nullable=False)          # JSON-encoded
    value_type = Column(
        Enum("int", "bool", "str", "json", name="config_value_type"),
        nullable=False,
        default="str",
    )
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    updated_by = Column(String(50), default="owner", nullable=False)

    def __repr__(self) -> str:
        return f"<SystemConfig {self.key}={self.value}>"


# ---------------------------------------------------------------------------
# CSPViolation
# ---------------------------------------------------------------------------

class CSPViolation(db.Model):
    """Stores Content Security Policy violation reports."""
    __tablename__ = "csp_violations"

    id = Column(GUID(), primary_key=True, default=new_uuid)
    blocked_uri = Column(Text, nullable=True)
    violated_directive = Column(String(200), nullable=True)
    effective_directive = Column(String(200), nullable=True)
    original_policy = Column(Text, nullable=True)
    document_uri = Column(Text, nullable=True)
    disposition = Column(String(20), nullable=True)   # "enforce" | "report"
    source_file = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    column_number = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<CSPViolation {self.violated_directive} {self.blocked_uri}>"
