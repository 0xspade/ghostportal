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
Program name deduplication and autocomplete.

Auto-saves program names on report submission.
Deduplication: strip + lowercase normalization.
Original case preserved for display.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def normalize_program_name(name: str) -> str:
    """
    Normalize a program name for deduplication.

    Args:
        name: Raw program name string.

    Returns:
        Normalized (stripped, lowercased) string.
    """
    return name.strip().lower()


def save_program_name(name: str) -> None:
    """
    Save or update a program name (upsert by normalized name).

    Called asynchronously after report submission.
    Creates new record or updates use_count + last_used_at.

    Args:
        name: Program/target name from the report form.
    """
    from app.extensions import db
    from app.models import ProgramName

    if not name or not name.strip():
        return

    name_norm = normalize_program_name(name)

    try:
        existing = ProgramName.query.filter_by(name_normalized=name_norm).first()

        if existing:
            existing.use_count += 1
            existing.last_used_at = datetime.now(timezone.utc)
        else:
            entry = ProgramName(
                name=name.strip(),
                name_normalized=name_norm,
            )
            db.session.add(entry)

        db.session.commit()
        logger.debug(f"Program name saved/updated: {name!r}")

    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to save program name '{name}': {exc}")


def search_program_names(query: str, limit: int = 20) -> list[dict]:
    """
    Search program names for autocomplete.

    Ordered by use_count DESC, then last_used_at DESC.

    Args:
        query: Search query string (1+ characters).
        limit: Maximum number of results.

    Returns:
        List of dicts with id, name, use_count, last_used.
    """
    from app.models import ProgramName

    if not query:
        return []

    norm_query = normalize_program_name(query)

    results = (
        ProgramName.query
        .filter(ProgramName.name_normalized.contains(norm_query))
        .order_by(ProgramName.use_count.desc(), ProgramName.last_used_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": str(r.id),
            "name": r.name,
            "email": r.email or "",
            "use_count": r.use_count,
            "last_used": r.last_used_at.isoformat() if r.last_used_at else None,
        }
        for r in results
    ]


def get_all_program_names(limit: int = 200) -> list[dict]:
    """
    Get all program names, ordered by most recently used.

    Args:
        limit: Maximum number of results.

    Returns:
        List of dicts with id, name, use_count, last_used, created_at.
    """
    from app.models import ProgramName

    results = (
        ProgramName.query
        .order_by(ProgramName.last_used_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": str(r.id),
            "name": r.name,
            "name_normalized": r.name_normalized,
            "use_count": r.use_count,
            "last_used": r.last_used_at.isoformat() if r.last_used_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in results
    ]


def rename_program_name(program_id: str, new_name: str) -> bool:
    """
    Rename a program name entry.

    Args:
        program_id: UUID of the ProgramName record.
        new_name: New display name.

    Returns:
        True if successful.
    """
    from app.extensions import db
    from app.models import ProgramName
    import uuid

    try:
        entry = ProgramName.query.get(uuid.UUID(program_id))
        if not entry:
            return False

        new_norm = normalize_program_name(new_name)

        # Check for collision with another entry
        existing = ProgramName.query.filter_by(name_normalized=new_norm).first()
        if existing and str(existing.id) != program_id:
            # Merge: add counts to the existing entry, delete this one
            _epoch = datetime.min.replace(tzinfo=timezone.utc)
            existing.use_count += entry.use_count
            if (entry.last_used_at or _epoch) > (existing.last_used_at or _epoch):
                existing.last_used_at = entry.last_used_at
            db.session.delete(entry)
        else:
            entry.name = new_name.strip()
            entry.name_normalized = new_norm

        db.session.commit()
        return True

    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to rename program name {program_id}: {exc}")
        return False


def delete_program_name(program_id: str) -> bool:
    """
    Delete a program name entry.

    Args:
        program_id: UUID of the ProgramName record.

    Returns:
        True if successful.
    """
    from app.extensions import db
    from app.models import ProgramName
    import uuid

    try:
        entry = ProgramName.query.get(uuid.UUID(program_id))
        if not entry:
            return False
        db.session.delete(entry)
        db.session.commit()
        return True
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to delete program name {program_id}: {exc}")
        return False
