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
Markdown rendering pipeline with bleach sanitization.

TWO-PASS SANITIZATION:
1. bleach.clean() BEFORE storage (strip dangerous HTML/attributes)
2. bleach.clean() AFTER markdown rendering (prevent XSS in rendered output)

NEVER render unsanitized content. NEVER skip either bleach pass.

Usage:
    from app.utils.markdown_renderer import sanitize_markdown, render_markdown

    # Before storing to DB:
    safe_input = sanitize_markdown(user_input)

    # Before rendering to HTML:
    html = render_markdown(safe_input)
"""

import logging
import re
from typing import Any

import bleach
import markdown
from markdown.extensions import fenced_code, tables, nl2br, toc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed HTML tags and attributes for sanitization
# ---------------------------------------------------------------------------

# Safe HTML tags for report content (no script, no event handlers)
ALLOWED_TAGS = [
    # Structure
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "br", "hr",
    "div", "span", "section", "article",
    # Text formatting
    "strong", "b", "em", "i", "u", "s", "del", "ins", "mark",
    "sub", "sup", "small", "code", "pre", "kbd", "var", "samp",
    # Lists
    "ul", "ol", "li", "dl", "dt", "dd",
    # Links (href validated separately)
    "a",
    # Images (src validated separately — no data: URIs)
    "img",
    # Tables
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
    # Blockquotes
    "blockquote",
    # Misc
    "details", "summary",
]

# Allowed attributes per tag
ALLOWED_ATTRIBUTES: dict[str, list[str]] = {
    "a": ["href", "title", "rel", "target"],
    "img": ["src", "alt", "title", "width", "height"],
    "th": ["scope", "colspan", "rowspan", "align"],
    "td": ["colspan", "rowspan", "align"],
    "code": ["class"],      # for syntax highlighting class names
    "pre": ["class"],
    "div": ["class", "id"],
    "span": ["class"],
    "h1": ["id"], "h2": ["id"], "h3": ["id"],
    "h4": ["id"], "h5": ["id"], "h6": ["id"],
}

# Allowed URL schemes in href/src attributes
# "" (empty string) allows relative URLs like /attachments/<uuid> so that
# markdown image references render correctly after bleach sanitization.
ALLOWED_PROTOCOLS = ["http", "https", "mailto", ""]

# Markdown extensions to enable
MARKDOWN_EXTENSIONS = [
    "fenced_code",    # ```code blocks```
    "tables",          # GFM-style tables
    "nl2br",           # Newlines → <br>
    "toc",             # Table of contents
    "extra",           # Various extras (abbr, footnotes, etc.)
    "sane_lists",      # Better list handling
    "smarty",          # Smart quotes
    "attr_list",       # Attribute lists
]

MARKDOWN_EXTENSION_CONFIGS: dict[str, Any] = {
    "toc": {
        "permalink": True,
        "baselevel": 2,      # Don't allow h1 (reserved for report title)
    },
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def sanitize_markdown(raw_input: str | None) -> str:
    """
    Sanitize raw user input BEFORE storing to the database.

    Strips dangerous HTML tags, event handlers, and unsafe attributes.
    Does NOT render markdown — that happens separately at display time.

    Args:
        raw_input: Raw text/markdown from user form input.

    Returns:
        Sanitized text safe for storage. Returns "" for None input.
    """
    if not raw_input:
        return ""

    text = str(raw_input)

    # First pass: strip any raw HTML using bleach
    cleaned = bleach.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,           # Strip disallowed tags (don't escape them)
        strip_comments=True,  # Remove HTML comments
    )

    return cleaned


def render_markdown(sanitized_text: str | None) -> str:
    """
    Render sanitized markdown to HTML.

    IMPORTANT: Input must have already been sanitized via sanitize_markdown().
    This function applies a SECOND bleach pass after rendering to catch any
    edge cases where the markdown renderer may produce unsafe output.

    Args:
        sanitized_text: Pre-sanitized markdown text.

    Returns:
        Safe HTML string ready for rendering in templates.
    """
    if not sanitized_text:
        return ""

    try:
        # Render markdown to HTML
        html = markdown.markdown(
            sanitized_text,
            extensions=MARKDOWN_EXTENSIONS,
            extension_configs=MARKDOWN_EXTENSION_CONFIGS,
            output_format="html",
        )

        # Second pass: sanitize rendered HTML (defense in depth)
        safe_html = bleach.clean(
            html,
            tags=ALLOWED_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            protocols=ALLOWED_PROTOCOLS,
            strip=True,
            strip_comments=True,
        )

        # Post-process links: add rel="noopener noreferrer" and target="_blank"
        # to all external links (additional XSS protection)
        safe_html = _process_links(safe_html)

        return safe_html

    except Exception as exc:
        logger.error(f"Markdown rendering failed: {exc}", exc_info=True)
        # Fail safe: return bleach-stripped plain text
        return bleach.clean(sanitized_text or "", tags=[], strip=True)


def sanitize_and_render(raw_input: str | None) -> str:
    """
    Convenience function: sanitize then render in one call.

    Use this for display-time rendering when you need to go from raw input
    to HTML in one step (e.g., in Jinja2 filters).

    Args:
        raw_input: Raw markdown input.

    Returns:
        Safe rendered HTML.
    """
    return render_markdown(sanitize_markdown(raw_input))


def strip_markdown(text: str | None) -> str:
    """
    Strip all markdown formatting and return plain text.

    Useful for generating email plain-text versions or excerpts.

    Args:
        text: Markdown text.

    Returns:
        Plain text with all markdown syntax removed.
    """
    if not text:
        return ""

    # Render then strip all HTML tags
    html = render_markdown(sanitize_markdown(text))
    plain = bleach.clean(html, tags=[], strip=True)

    # Clean up excess whitespace
    plain = re.sub(r"\n{3,}", "\n\n", plain)
    return plain.strip()


# ---------------------------------------------------------------------------
# Link post-processor
# ---------------------------------------------------------------------------

def _process_links(html: str) -> str:
    """
    Add security attributes to external links in rendered HTML.

    Adds rel="noopener noreferrer" and target="_blank" to all <a> tags
    with external hrefs.

    Args:
        html: Rendered HTML string.

    Returns:
        HTML with processed link attributes.
    """
    def replace_link(match: re.Match) -> str:
        tag = match.group(0)
        href_match = re.search(r'href=["\']([^"\']*)["\']', tag)
        if href_match:
            href = href_match.group(1)
            # External links get security attributes
            if href.startswith(("http://", "https://")):
                if "rel=" not in tag:
                    tag = tag.replace(">", ' rel="noopener noreferrer">', 1)
                if "target=" not in tag:
                    tag = tag.replace(">", ' target="_blank">', 1)
        return tag

    return re.sub(r'<a\s[^>]*>', replace_link, html)


# ---------------------------------------------------------------------------
# Jinja2 filter registration helper
# ---------------------------------------------------------------------------

def register_markdown_filters(app) -> None:
    """
    Register markdown rendering as Jinja2 template filters.

    Call from app factory after app creation.

    Adds:
        {{ report.description | markdown }} → rendered HTML
        {{ report.description | markdown_strip }} → plain text
    """
    from markupsafe import Markup

    @app.template_filter("markdown")
    def markdown_filter(text: str) -> Markup:
        """Render markdown to safe HTML."""
        return Markup(render_markdown(sanitize_markdown(text)))

    @app.template_filter("markdown_strip")
    def markdown_strip_filter(text: str) -> str:
        """Strip markdown to plain text."""
        return strip_markdown(text)

    @app.template_filter("sanitize")
    def sanitize_filter(text: str) -> str:
        """Sanitize HTML/markdown input."""
        return sanitize_markdown(text)
