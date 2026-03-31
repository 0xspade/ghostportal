# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

"""
Program List — directory of bug bounty programs and their security contact emails.
Supports add, edit, delete, import (JSON), and export (JSON).
"""

import json
import re
import uuid as _uuid

from flask import (
    current_app, flash, jsonify, redirect,
    render_template, request, url_for,
)

from app.blueprints.decorators import owner_required, parse_uuid
from app.blueprints.program_list import program_list_bp
from app.extensions import db
from app.models import ProgramName

# RFC 5322-ish simple email pattern — server-side validation
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Limits for import to prevent abuse
_IMPORT_MAX_ENTRIES = 500
_IMPORT_MAX_FIELD_LEN = 300


def _validate_email(value: str) -> bool:
    return bool(value) and bool(_EMAIL_RE.match(value)) and len(value) <= 254


def _normalize(name: str) -> str:
    return name.strip().lower()


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list")
@owner_required
def index():
    """List all programs with their security contact emails."""
    programs = (
        ProgramName.query
        .order_by(ProgramName.name.asc())
        .all()
    )
    return render_template(
        "program_list/index.html",
        platform_name=current_app.config.get("PLATFORM_NAME", "GhostPortal"),
        programs=programs,
    )


# ---------------------------------------------------------------------------
# Add
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list/add", methods=["POST"])
@owner_required
def add():
    """Add a new program entry."""
    name = request.form.get("name", "").strip()[:300]
    email = request.form.get("email", "").strip().lower()

    if not name:
        flash("Program name is required.", "error")
        return redirect(url_for("program_list.index"))

    if email and not _validate_email(email):
        flash("Invalid email address.", "error")
        return redirect(url_for("program_list.index"))

    normalized = _normalize(name)
    existing = ProgramName.query.filter_by(name_normalized=normalized).first()
    if existing:
        flash(f"Program '{name}' already exists.", "warning")
        return redirect(url_for("program_list.index"))

    entry = ProgramName(
        name=name,
        name_normalized=normalized,
        email=email if email else None,
        use_count=0,
    )
    db.session.add(entry)
    db.session.commit()
    flash(f"Program '{name}' added.", "success")
    return redirect(url_for("program_list.index"))


# ---------------------------------------------------------------------------
# Edit
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list/<program_uuid>/edit", methods=["POST"])
@owner_required
def edit(program_uuid: str):
    """Edit an existing program entry (name and/or email)."""
    pid = parse_uuid(program_uuid)
    entry = ProgramName.query.get_or_404(pid)

    name = request.form.get("name", "").strip()[:300]
    email = request.form.get("email", "").strip().lower()

    if not name:
        flash("Program name is required.", "error")
        return redirect(url_for("program_list.index"))

    if email and not _validate_email(email):
        flash("Invalid email address.", "error")
        return redirect(url_for("program_list.index"))

    normalized = _normalize(name)
    # Check for duplicate name (excluding self)
    conflict = ProgramName.query.filter(
        ProgramName.name_normalized == normalized,
        ProgramName.id != entry.id,
    ).first()
    if conflict:
        flash(f"Another program named '{name}' already exists.", "warning")
        return redirect(url_for("program_list.index"))

    entry.name = name
    entry.name_normalized = normalized
    entry.email = email if email else None
    db.session.commit()
    flash(f"Program '{name}' updated.", "success")
    return redirect(url_for("program_list.index"))


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list/<program_uuid>/delete", methods=["POST"])
@owner_required
def delete(program_uuid: str):
    """Delete a program entry."""
    pid = parse_uuid(program_uuid)
    entry = ProgramName.query.get_or_404(pid)
    name = entry.name
    db.session.delete(entry)
    db.session.commit()
    flash(f"Program '{name}' deleted.", "success")
    return redirect(url_for("program_list.index"))


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list/export")
@owner_required
def export():
    """
    Export all programs as JSON.
    Only exports name and email — no internal IDs or metadata.
    """
    programs = ProgramName.query.order_by(ProgramName.name.asc()).all()
    payload = {
        "programs": [
            {
                "program_name": p.name,
                "program_email": p.email or "",
            }
            for p in programs
        ]
    }
    response = current_app.make_response(
        json.dumps(payload, ensure_ascii=False, indent=2)
    )
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=program_list_export.json"
    # Prevent caching of the export file
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

@program_list_bp.route("/programs/list/import", methods=["POST"])
@owner_required
def import_programs():
    """
    Import programs from a JSON file upload or pasted JSON body.

    Expected JSON schema:
        {"programs": [{"program_name": "...", "program_email": "..."}, ...]}

    Security:
    - File size limited to 1 MB
    - Schema strictly validated before any DB writes
    - Email format validated per RFC 5322 subset
    - Max 500 entries per import
    - All strings trimmed and length-capped
    - Duplicates (by normalized name) are skipped, not overwritten
    - CSRF protected (inherited from @owner_required + form POST)
    """
    # Accept either file upload or raw textarea JSON
    raw = None
    uploaded_file = request.files.get("json_file")
    if uploaded_file and uploaded_file.filename:
        if not uploaded_file.filename.lower().endswith(".json"):
            flash("Only .json files are accepted for import.", "error")
            return redirect(url_for("program_list.index"))
        content = uploaded_file.read(1024 * 1024 + 1)  # read up to 1 MB + 1 byte
        if len(content) > 1024 * 1024:
            flash("Import file too large (max 1 MB).", "error")
            return redirect(url_for("program_list.index"))
        try:
            raw = content.decode("utf-8")
        except UnicodeDecodeError:
            flash("Import file must be UTF-8 encoded.", "error")
            return redirect(url_for("program_list.index"))
    else:
        raw = request.form.get("json_text", "").strip()

    if not raw:
        flash("No JSON data provided.", "error")
        return redirect(url_for("program_list.index"))

    # Parse JSON
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        flash(f"Invalid JSON: {exc}", "error")
        return redirect(url_for("program_list.index"))

    # Schema validation
    if not isinstance(data, dict) or "programs" not in data:
        flash("Invalid format: expected {\"programs\": [...]}.", "error")
        return redirect(url_for("program_list.index"))

    entries = data["programs"]
    if not isinstance(entries, list):
        flash("Invalid format: 'programs' must be a list.", "error")
        return redirect(url_for("program_list.index"))

    if len(entries) > _IMPORT_MAX_ENTRIES:
        flash(f"Too many entries (max {_IMPORT_MAX_ENTRIES} per import).", "error")
        return redirect(url_for("program_list.index"))

    added = 0
    updated = 0
    skipped = 0
    errors = []

    for i, item in enumerate(entries):
        if not isinstance(item, dict):
            errors.append(f"Entry {i+1}: not an object, skipped.")
            skipped += 1
            continue

        name = str(item.get("program_name") or "").strip()[:_IMPORT_MAX_FIELD_LEN]
        email = str(item.get("program_email") or "").strip().lower()[:254]

        if not name:
            errors.append(f"Entry {i+1}: missing program_name, skipped.")
            skipped += 1
            continue

        if email and not _validate_email(email):
            errors.append(f"Entry {i+1}: invalid email '{email}', email cleared.")
            email = ""

        normalized = _normalize(name)
        existing = ProgramName.query.filter_by(name_normalized=normalized).first()
        if existing:
            # Update email if it was blank and we have one now
            if not existing.email and email:
                existing.email = email
                updated += 1
            else:
                skipped += 1
            continue

        entry = ProgramName(
            name=name,
            name_normalized=normalized,
            email=email if email else None,
            use_count=0,
        )
        db.session.add(entry)
        added += 1

    db.session.commit()

    parts = []
    if added:
        parts.append(f"{added} added")
    if updated:
        parts.append(f"{updated} email(s) updated")
    if skipped:
        parts.append(f"{skipped} skipped (already exist)")
    msg = "Import complete: " + (", ".join(parts) or "nothing to do") + "."
    if errors:
        msg += f" Warnings: {'; '.join(errors[:5])}"
        if len(errors) > 5:
            msg += f" ... and {len(errors) - 5} more."
    flash(msg, "success" if not errors else "warning")
    return redirect(url_for("program_list.index"))
