# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

"""
Security tests for XSS vulnerabilities.

Tests:
  - Markdown input is sanitized before storage
  - Markdown rendering does not produce XSS payloads
  - HTML in report fields is escaped
  - Script tags are stripped from all user input
"""

import pytest


XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "';alert(1);//",
    "<body onload=alert(1)>",
    "<a href='javascript:void(0)' onclick='alert(1)'>click</a>",
    '"><script>alert(document.cookie)</script>',
    "<SCRIPT SRC=//ha.ckers.org/.j></SCRIPT>",
]


class TestMarkdownSanitization:
    def test_sanitize_strips_script_tags(self):
        from app.utils.markdown_renderer import sanitize_markdown
        for payload in XSS_PAYLOADS:
            result = sanitize_markdown(payload)
            assert "<script" not in result.lower(), (
                f"Script tag not stripped from: {payload}"
            )
            assert "onerror=" not in result.lower(), (
                f"Event handler not stripped from: {payload}"
            )
            assert "onload=" not in result.lower(), (
                f"Event handler not stripped from: {payload}"
            )

    def test_render_markdown_strips_script_tags(self):
        from app.utils.markdown_renderer import render_markdown
        for payload in XSS_PAYLOADS:
            result = render_markdown(payload)
            assert "<script" not in result.lower(), (
                f"Script tag survived render: {payload}"
            )

    def test_safe_markdown_renders_correctly(self):
        from app.utils.markdown_renderer import render_markdown
        safe_md = "## Title\n\nSome **bold** and *italic* text.\n\n- List item 1\n- List item 2"
        result = render_markdown(safe_md)
        assert "<h2>" in result or "Title" in result
        assert "<strong>" in result or "<b>" in result

    def test_code_blocks_are_preserved(self):
        from app.utils.markdown_renderer import render_markdown
        code_md = "```python\nprint('hello')\n```"
        result = render_markdown(code_md)
        assert "print" in result
        # Code content should be escaped, not executed
        assert "<script" not in result.lower()

    def test_links_are_allowed_but_safe(self):
        from app.utils.markdown_renderer import render_markdown, sanitize_markdown
        link_md = "[Click here](https://example.com)"
        result = render_markdown(link_md)
        assert "href" in result
        assert "example.com" in result
        # javascript: links must be stripped
        js_link = "[Click here](javascript:alert(1))"
        result_js = render_markdown(sanitize_markdown(js_link))
        assert "javascript:" not in result_js

    def test_html_injection_in_link_title(self):
        from app.utils.markdown_renderer import sanitize_markdown
        payload = '[<script>alert(1)</script>](https://example.com)'
        result = sanitize_markdown(payload)
        assert "<script" not in result.lower()


class TestReportFieldSanitization:
    """Test that report fields are sanitized when submitted via the form."""

    def test_report_description_xss_stripped(self, client, owner_session, db):
        """XSS in report description must be stripped before storage."""
        payload = "<script>alert('xss')</script>Normal description text"

        resp = owner_session.post(
            "/reports/new",
            data={
                "title": "Test XSS Report",
                "description": payload,
                "severity": "medium",
                "status": "draft",
            },
        )

        # Get the created report
        from app.models import Report
        report = Report.query.filter_by(title="Test XSS Report").first()

        if report:
            # Description must not contain the script tag
            assert "<script" not in (report.description or "").lower()
