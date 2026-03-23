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
Report export and backup utilities.

Formats:
- PDF: WeasyPrint with HUD Admin print-safe CSS
- Markdown: Raw .md with YAML front matter
- JSON: Full report object + replies + invite metadata
- ZIP: Full encrypted backup (AES-256-GCM)

Security:
- Export filenames: report-<uuid>-<timestamp>.<ext> — never include title
- Backup: AES-256-GCM encryption, key from BACKUP_ENCRYPTION_KEY
- Temp files: securely deleted after serving
"""

import io
import json
import logging
import os
import secrets
import struct
import tempfile
import uuid
import zipfile
from base64 import b64decode, b64encode
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Export filename generation (never include report title)
# ---------------------------------------------------------------------------

def make_export_filename(report_uuid: uuid.UUID, extension: str) -> str:
    """
    Generate a secure export filename.

    Format: report-<uuid>-<unix_timestamp>.<ext>
    Never includes the report title (information disclosure risk).

    Args:
        report_uuid: Report UUID.
        extension: File extension without dot.

    Returns:
        Safe export filename.
    """
    timestamp = int(datetime.now(timezone.utc).timestamp())
    return f"report-{report_uuid}-{timestamp}.{extension}"


def make_backup_filename() -> str:
    """
    Generate a secure backup archive filename.

    Returns:
        Backup filename with timestamp (no sequential numbers).
    """
    timestamp = int(datetime.now(timezone.utc).timestamp())
    rand = secrets.token_hex(4)
    return f"ghostportal-backup-{timestamp}-{rand}.zip"


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def export_report_json(report, include_invite_emails: bool = False) -> str:
    """
    Export a report as JSON.

    Args:
        report: Report model object.
        include_invite_emails: If True, include security team emails (default False).

    Returns:
        JSON string.
    """
    data: dict[str, Any] = {
        "export_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "report": {
            "id": str(report.id),
            "display_id": report.display_id,
            "title": report.title,
            "severity": report.severity,
            "status": report.status,
            "cvss_score": float(report.cvss_score) if report.cvss_score else None,
            "cvss_vector": report.cvss_vector,
            "cwe_id": report.cwe_id,
            "cwe_name": report.cwe_name,
            "target_asset": report.target_asset,
            "program_name": report.program_name,
            "tags": report.tags or [],
            "description": report.description,
            "steps_to_reproduce": report.steps_to_reproduce,
            "proof_of_concept": report.proof_of_concept,
            "impact_statement": report.impact_statement,
            "remediation": report.remediation,
            "technical_details": report.technical_details,
            "bounty_amount": float(report.bounty_amount) if report.bounty_amount else None,
            "bounty_currency": report.bounty_currency,
            "ai_generated": report.ai_generated,
            "ai_provider": report.ai_provider,
            "created_at": report.created_at.isoformat() if report.created_at else None,
            "updated_at": report.updated_at.isoformat() if report.updated_at else None,
            "submitted_at": report.submitted_at.isoformat() if report.submitted_at else None,
        },
        "attachments": [
            {
                "id": str(att.id),
                "filename_original": att.filename_original,
                "mime_type": att.mime_type,
                "file_size": att.file_size,
                "uploaded_at": att.uploaded_at.isoformat() if att.uploaded_at else None,
            }
            for att in (report.attachments or [])
        ],
        "replies": [
            {
                "id": str(reply.id),
                "author_type": reply.author_type,
                "body": reply.body,
                "is_internal": reply.is_internal,
                "created_at": reply.created_at.isoformat() if reply.created_at else None,
            }
            for reply in (report.replies or [])
            if not reply.is_internal  # Never export internal notes
        ],
    }

    # Invite metadata (emails redacted by default)
    invites_data = []
    for invite in (report.invites or []):
        invite_dict: dict[str, Any] = {
            "id": str(invite.id),
            "company_name": invite.company_name,
            "is_active": invite.is_active,
            "created_at": invite.created_at.isoformat() if invite.created_at else None,
        }
        if include_invite_emails:
            invite_dict["email"] = invite.email
        else:
            invite_dict["email"] = "[REDACTED]"
        invites_data.append(invite_dict)

    data["invites"] = invites_data

    return json.dumps(data, indent=2, default=str)


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------

def export_report_markdown(report) -> str:
    """
    Export a report as Markdown with YAML front matter.

    Args:
        report: Report model object.

    Returns:
        Markdown string with YAML front matter block.
    """
    lines = [
        "---",
        f"id: {report.id}",
        f"display_id: {report.display_id or ''}",
        f"title: {report.title!r}",
        f"severity: {report.severity}",
        f"status: {report.status}",
        f"cvss_score: {report.cvss_score or ''}",
        f"cvss_vector: {report.cvss_vector or ''}",
        f"cwe_id: {report.cwe_id or ''}",
        f"cwe_name: {report.cwe_name or ''}",
        f"target_asset: {report.target_asset or ''}",
        f"program_name: {report.program_name or ''}",
        f"tags: {report.tags or []}",
        f"created_at: {report.created_at.isoformat() if report.created_at else ''}",
        f"submitted_at: {report.submitted_at.isoformat() if report.submitted_at else ''}",
        "---",
        "",
        f"# {report.title}",
        "",
        f"**Severity**: {(report.severity or '').upper()}  ",
        f"**Status**: {report.status}  ",
        f"**CVSS 4.0**: {report.cvss_score or 'N/A'}  ",
        f"**CWE**: {report.cwe_id or 'N/A'} — {report.cwe_name or ''}  ",
        f"**Target**: {report.target_asset or 'N/A'}  ",
        "",
    ]

    if report.description:
        lines += ["## Description", "", report.description, ""]

    if report.steps_to_reproduce:
        lines += ["## Steps to Reproduce", "", report.steps_to_reproduce, ""]

    if report.proof_of_concept:
        lines += ["## Proof of Concept", "", report.proof_of_concept, ""]

    if report.impact_statement:
        lines += ["## Impact", "", report.impact_statement, ""]

    if report.remediation:
        lines += ["## Remediation", "", report.remediation, ""]

    if report.technical_details:
        lines += ["## Technical Details", "", report.technical_details, ""]

    lines += [
        "",
        "---",
        f"*Exported from GhostPortal — CONFIDENTIAL*",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PDF export (WeasyPrint)
# ---------------------------------------------------------------------------

def export_report_pdf(report, app=None) -> bytes:
    """
    Export a report as a PDF using WeasyPrint.

    Args:
        report: Report model object.
        app: Flask application (for template rendering context).

    Returns:
        PDF bytes.
    """
    try:
        from weasyprint import HTML, CSS
        from flask import render_template

        html_content = render_template(
            "reports/export_pdf.html",
            report=report,
        )

        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes

    except ImportError:
        logger.error("WeasyPrint not installed — PDF export unavailable")
        raise RuntimeError("PDF export requires WeasyPrint: pip install weasyprint")
    except Exception as exc:
        logger.error(f"PDF export failed for report {report.id}: {exc}", exc_info=True)
        raise


# ---------------------------------------------------------------------------
# Encrypted ZIP backup
# ---------------------------------------------------------------------------

def create_encrypted_backup(encryption_key_b64: str, upload_folder: str) -> bytes:
    """
    Create an AES-256-GCM encrypted ZIP backup of all reports and attachments.

    Args:
        encryption_key_b64: Base64-encoded 32-byte AES key.
        upload_folder: Path to the uploads directory.

    Returns:
        Encrypted ZIP bytes.
    """
    from app.models import Report

    try:
        # Decode encryption key
        key = b64decode(encryption_key_b64)
        if len(key) != 32:
            raise ValueError(f"Encryption key must be 32 bytes, got {len(key)}")
    except Exception as exc:
        raise ValueError(f"Invalid encryption key: {exc}") from exc

    # Create ZIP in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Write schema version
        zf.writestr("schema_version.txt", "1.0\n")
        zf.writestr("export_info.json", json.dumps({
            "version": "1.0",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "platform": "GhostPortal",
        }))

        # Export all reports as JSON
        reports = Report.query.all()
        for report in reports:
            report_json = export_report_json(report, include_invite_emails=True)
            zf.writestr(f"reports/{report.id}.json", report_json)

        # Include attachment files
        verified_folder = os.path.join(upload_folder, "verified")
        if os.path.exists(verified_folder):
            for report_uuid_dir in os.listdir(verified_folder):
                report_dir = os.path.join(verified_folder, report_uuid_dir)
                if os.path.isdir(report_dir):
                    for filename in os.listdir(report_dir):
                        file_path = os.path.join(report_dir, filename)
                        if os.path.isfile(file_path):
                            zf.write(
                                file_path,
                                f"uploads/{report_uuid_dir}/{filename}",
                            )

    zip_data = zip_buffer.getvalue()

    # Encrypt with AES-256-GCM
    encrypted = _aes_gcm_encrypt(key, zip_data)
    return encrypted


def decrypt_backup(encrypted_data: bytes, encryption_key_b64: str) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted backup.

    Args:
        encrypted_data: Encrypted backup bytes.
        encryption_key_b64: Base64-encoded 32-byte AES key.

    Returns:
        Decrypted ZIP bytes.
    """
    try:
        key = b64decode(encryption_key_b64)
        if len(key) != 32:
            raise ValueError(f"Encryption key must be 32 bytes, got {len(key)}")
    except Exception as exc:
        raise ValueError(f"Invalid encryption key: {exc}") from exc

    return _aes_gcm_decrypt(key, encrypted_data)


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt bytes with AES-256-GCM.

    Format: [nonce (12 bytes)][ciphertext][tag (16 bytes)]

    Args:
        key: 32-byte AES key.
        plaintext: Data to encrypt.

    Returns:
        Encrypted bytes with nonce prepended.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def _aes_gcm_decrypt(key: bytes, encrypted: bytes) -> bytes:
    """
    Decrypt AES-256-GCM encrypted bytes.

    Args:
        key: 32-byte AES key.
        encrypted: Encrypted bytes (nonce + ciphertext + tag).

    Returns:
        Decrypted plaintext bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(encrypted) < 12 + 16:
        raise ValueError("Encrypted data too short")

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
