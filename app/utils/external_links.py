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
External link interception and open-redirect prevention.

All external URLs in reports, replies, and emails are routed through
the /go/<link_uuid> warning interstitial.

Flow:
1. At render time: detect http(s) links in markdown-rendered HTML
2. Each unique URL → ExternalLink record with UUID token (idempotent)
3. Rendered as: <a href="/go/<link_uuid>" rel="noopener noreferrer" target="_blank">
4. /go/<link_uuid> route: validates URL → shows 5-second interstitial → redirects
"""

import logging
import re
import uuid
from urllib.parse import urlparse

from app.utils.safe_fetch import validate_url_for_storage

logger = logging.getLogger(__name__)

# Regex to match HTTP/HTTPS URLs in HTML
URL_PATTERN = re.compile(
    r'href=["\']((https?://)[^"\'<>\s]+)["\']',
    re.IGNORECASE,
)


def get_or_create_external_link(url: str, report_id=None) -> "ExternalLink | None":
    """
    Get existing or create new ExternalLink record for a URL.

    Idempotent: same URL + report returns same ExternalLink token.
    Validates URL before creating the record.

    Args:
        url: The external URL to register.
        report_id: UUID of the associated report (optional).

    Returns:
        ExternalLink object, or None if URL is invalid.
    """
    from app.extensions import db
    from app.models import ExternalLink

    # Validate URL before storing
    is_valid, error = validate_url_for_storage(url)
    if not is_valid:
        logger.warning(f"Rejected external URL: {url} — {error}")
        return None

    # Extract domain for display
    try:
        domain = urlparse(url).hostname or "unknown"
    except Exception:
        domain = "unknown"

    # Check for existing link (idempotent per URL + report)
    existing = ExternalLink.query.filter_by(
        original_url=url,
        report_id=report_id,
    ).first()

    if existing:
        return existing

    # Create new ExternalLink
    link = ExternalLink(
        token=uuid.uuid4(),
        report_id=report_id,
        original_url=url,
        domain=domain,
    )
    db.session.add(link)
    db.session.flush()  # Get ID without committing

    return link


def process_html_links(html: str, report_id=None) -> str:
    """
    Replace all external href URLs in rendered HTML with /go/<token> links.

    Args:
        html: Rendered HTML with external links.
        report_id: Associated report UUID (for ExternalLink records).

    Returns:
        HTML with external links replaced by /go/<token> interstitial URLs.
    """
    def replace_link(match: re.Match) -> str:
        original_url = match.group(1)
        link = get_or_create_external_link(original_url, report_id)
        if link is None:
            # Invalid URL — remove the href entirely (render as text)
            return 'href="#" data-blocked="true"'
        return f'href="/go/{link.token}" data-external="true" data-domain="{link.domain}"'

    return URL_PATTERN.sub(replace_link, html)


def validate_redirect_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL before redirecting to it from /go/<token>.

    Additional validation beyond what's done at storage time:
    - Recheck scheme whitelist
    - Recheck for dangerous URL patterns

    Args:
        url: URL from ExternalLink.original_url.

    Returns:
        Tuple of (is_safe, error_message).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Blocked URL scheme: {scheme}"

    # Block dangerous patterns
    lower_url = url.lower()
    dangerous_patterns = [
        "javascript:", "data:", "vbscript:", "file:",
        "\x00", "%00",  # Null byte injection
    ]
    for pattern in dangerous_patterns:
        if pattern in lower_url:
            return False, f"Dangerous URL pattern detected"

    return True, ""
