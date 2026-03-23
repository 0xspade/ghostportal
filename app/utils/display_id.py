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
Human-readable display ID generation.

Format: GP-YYYY-XXXX
- GP: platform prefix
- YYYY: year the report was created
- XXXX: 4-digit zero-padded numeric value derived from UUID hash

Important:
- Display IDs are ONLY shown in UI — NEVER used in URLs or API responses
- The underlying UUID is always used for routing and DB queries
- Display IDs are deterministic from the UUID + year (reproducible)
- Not sequential — derived from UUID hash to prevent enumeration

Example: GP-2025-0042
"""

import hashlib
import uuid
from datetime import datetime, timezone


def generate_display_id(report_uuid: uuid.UUID, created_at: datetime | None = None) -> str:
    """
    Generate a human-readable display ID from a report UUID.

    Formula: "GP-" + year + "-" + zero_padded_4(sha3_256(uuid_bytes)[:2] mod 9999 + 1)

    Args:
        report_uuid: The report's UUID v4.
        created_at: Report creation timestamp. Defaults to current UTC time.

    Returns:
        Display ID string in format "GP-YYYY-XXXX".
    """
    if created_at is None:
        created_at = datetime.now(timezone.utc)

    year = created_at.year

    # Derive a 4-digit number from the UUID hash
    # Use first 4 hex chars of SHA3-256 → convert to int → mod 9999 + 1
    # Range: 0001–9999 (never 0000)
    uuid_bytes = str(report_uuid).encode("utf-8")
    digest = hashlib.sha3_256(uuid_bytes).hexdigest()
    numeric = int(digest[:4], 16) % 9999 + 1

    return f"GP-{year}-{numeric:04d}"


def parse_display_id(display_id: str) -> dict | None:
    """
    Parse a display ID string into its components.

    Args:
        display_id: Display ID string like "GP-2025-0042".

    Returns:
        Dict with "prefix", "year", "sequence" keys, or None if invalid format.
    """
    parts = display_id.split("-")
    if len(parts) != 3:
        return None

    prefix, year_str, seq_str = parts

    if prefix != "GP":
        return None

    try:
        year = int(year_str)
        sequence = int(seq_str)
        if not (2020 <= year <= 2099):
            return None
        if not (1 <= sequence <= 9999):
            return None
        return {"prefix": prefix, "year": year, "sequence": sequence}
    except ValueError:
        return None


def is_valid_display_id(display_id: str) -> bool:
    """Check if a string is a valid display ID format."""
    return parse_display_id(display_id) is not None
