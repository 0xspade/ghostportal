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
Duplicate report detection.

Two detection methods:
1. Fuzzy title matching (difflib SequenceMatcher, threshold 0.75)
2. Exact CWE ID match against existing reports with same target asset

Results are NON-BLOCKING — owner sees a warning and can dismiss it.
"""

import logging
from difflib import SequenceMatcher
from typing import NamedTuple
from uuid import UUID

logger = logging.getLogger(__name__)

# Fuzzy match threshold: 0.75 = 75% similarity required to flag as potential duplicate
FUZZY_THRESHOLD = 0.75


class DuplicateMatch(NamedTuple):
    """A potential duplicate report match."""
    report_id: UUID
    display_id: str
    title: str
    similarity: float
    match_type: str  # "fuzzy_title" or "cwe_asset"


def check_for_duplicates(
    new_title: str,
    new_cwe_id: int | None,
    new_target_asset: str | None,
    exclude_report_id: UUID | None = None,
) -> list[DuplicateMatch]:
    """
    Check a new/edited report for potential duplicates.

    Args:
        new_title: Title of the new report.
        new_cwe_id: CWE ID of the new report (may be None).
        new_target_asset: Target asset of the new report (may be None).
        exclude_report_id: UUID to exclude from results (for edits of existing reports).

    Returns:
        List of DuplicateMatch objects (may be empty).
    """
    from app.models import Report

    matches: list[DuplicateMatch] = []

    # Build base query excluding draft status and the current report
    base_query = Report.query.filter(
        Report.status != "draft"
    )
    if exclude_report_id:
        base_query = base_query.filter(Report.id != exclude_report_id)

    existing_reports = base_query.all()

    seen_ids: set[UUID] = set()

    # Method 1: Fuzzy title matching
    if new_title:
        for report in existing_reports:
            if report.id in seen_ids:
                continue

            similarity = SequenceMatcher(
                None,
                new_title.lower().strip(),
                (report.title or "").lower().strip(),
            ).ratio()

            if similarity >= FUZZY_THRESHOLD:
                matches.append(
                    DuplicateMatch(
                        report_id=report.id,
                        display_id=report.display_id or str(report.id)[:8],
                        title=report.title,
                        similarity=round(similarity, 2),
                        match_type="fuzzy_title",
                    )
                )
                seen_ids.add(report.id)

    # Method 2: Exact CWE ID + same target asset
    if new_cwe_id and new_target_asset:
        cwe_matches = Report.query.filter(
            Report.cwe_id == new_cwe_id,
            Report.target_asset == new_target_asset,
            Report.status != "draft",
        )
        if exclude_report_id:
            cwe_matches = cwe_matches.filter(Report.id != exclude_report_id)

        for report in cwe_matches.all():
            if report.id not in seen_ids:
                matches.append(
                    DuplicateMatch(
                        report_id=report.id,
                        display_id=report.display_id or str(report.id)[:8],
                        title=report.title,
                        similarity=1.0,
                        match_type="cwe_asset",
                    )
                )
                seen_ids.add(report.id)

    # Sort by similarity descending, then by match type
    matches.sort(key=lambda m: (-m.similarity, m.match_type))

    if matches:
        logger.info(
            f"Duplicate check found {len(matches)} potential matches for: {new_title!r}"
        )

    return matches


def format_duplicate_warning(matches: list[DuplicateMatch]) -> list[dict]:
    """
    Format duplicate matches for JSON API response or template rendering.

    Args:
        matches: List of DuplicateMatch objects from check_for_duplicates().

    Returns:
        List of dicts suitable for JSON serialization or template use.
    """
    return [
        {
            "report_id": str(m.report_id),
            "display_id": m.display_id,
            "title": m.title,
            "similarity_pct": int(m.similarity * 100),
            "match_type": m.match_type,
            "match_type_label": (
                "Similar title" if m.match_type == "fuzzy_title"
                else "Same CWE + target asset"
            ),
        }
        for m in matches
    ]
