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
User-Agent string parsing for access logging and bot detection.

Returns parsed browser name + version, OS name + version, and bot flag.
Uses ua-parser Python library (ua-parser/uap-python).

Known scanner signatures for bot detection:
- Nikto, SQLMap, Nessus, Masscan, Burp Suite, OWASP ZAP, etc.
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Known security scanner / bot User-Agent signatures
KNOWN_SCANNER_SIGNATURES = [
    r"nikto",
    r"sqlmap",
    r"nessus",
    r"masscan",
    r"burpsuite",
    r"burp suite",
    r"owaspzap",
    r"owasp zap",
    r"dirbuster",
    r"gobuster",
    r"nuclei",
    r"nmap",
    r"metasploit",
    r"w3af",
    r"acunetix",
    r"havij",
    r"openvas",
    r"wpscan",
    r"zgrab",
    r"python-requests",
    r"libwww-perl",
    r"curl\/[0-9]",
    r"wget\/[0-9]",
    r"go-http-client",
    r"java\/[0-9]",
    r"scrapy",
    r"httpx",  # Only flag as bot in auth context; this is also used legitimately
    r"shodan",
    r"censys",
]

SCANNER_PATTERN = re.compile(
    "|".join(KNOWN_SCANNER_SIGNATURES),
    re.IGNORECASE,
)


@dataclass
class ParsedUA:
    """Parsed User-Agent result."""
    browser: str     # e.g., "Firefox 124"
    os: str          # e.g., "Windows 11"
    is_bot: bool     # True if detected as bot/scanner
    scanner_sig: Optional[str] = None  # Matched scanner signature if is_bot


def parse_user_agent(ua_string: str | None) -> ParsedUA:
    """
    Parse a User-Agent string into browser, OS, and bot status.

    Args:
        ua_string: Raw User-Agent header value.

    Returns:
        ParsedUA dataclass with browser, os, and is_bot fields.
    """
    if not ua_string:
        return ParsedUA(browser="Unknown", os="Unknown", is_bot=False)

    # Check for scanner signatures first (fast path)
    scanner_match = SCANNER_PATTERN.search(ua_string)
    is_bot = scanner_match is not None
    scanner_sig = scanner_match.group(0).lower() if scanner_match else None

    # Try ua-parser library
    try:
        from ua_parser import user_agent_parser

        result = user_agent_parser.Parse(ua_string)

        # Browser
        browser_family = result["user_agent"]["family"] or "Unknown"
        browser_major = result["user_agent"].get("major") or ""
        browser = f"{browser_family} {browser_major}".strip()

        # OS
        os_family = result["os"]["family"] or "Unknown"
        os_major = result["os"].get("major") or ""
        os_str = f"{os_family} {os_major}".strip()

        # Also check if ua-parser detected it as a bot/spider
        device_family = result.get("device", {}).get("family", "")
        if device_family in ("Spider", "Bot") or "bot" in browser_family.lower():
            is_bot = True

        return ParsedUA(
            browser=browser,
            os=os_str,
            is_bot=is_bot,
            scanner_sig=scanner_sig,
        )

    except ImportError:
        logger.warning("ua-parser not installed — using simplified UA parsing")
        return _simple_ua_parse(ua_string, is_bot, scanner_sig)
    except Exception as exc:
        logger.debug(f"UA parsing failed: {exc}")
        return _simple_ua_parse(ua_string, is_bot, scanner_sig)


def _simple_ua_parse(
    ua_string: str,
    is_bot: bool,
    scanner_sig: Optional[str],
) -> ParsedUA:
    """
    Simplified UA parsing fallback when ua-parser is unavailable.

    Args:
        ua_string: Raw UA string.
        is_bot: Pre-detected bot flag.
        scanner_sig: Matched scanner signature.

    Returns:
        ParsedUA with basic detection.
    """
    browser = "Unknown"
    os_str = "Unknown"

    ua_lower = ua_string.lower()

    # Browser detection
    if "firefox/" in ua_lower:
        m = re.search(r"firefox/(\d+)", ua_lower)
        browser = f"Firefox {m.group(1)}" if m else "Firefox"
    elif "chrome/" in ua_lower and "chromium" not in ua_lower:
        m = re.search(r"chrome/(\d+)", ua_lower)
        browser = f"Chrome {m.group(1)}" if m else "Chrome"
    elif "safari/" in ua_lower and "chrome" not in ua_lower:
        m = re.search(r"version/(\d+)", ua_lower)
        browser = f"Safari {m.group(1)}" if m else "Safari"
    elif "edg/" in ua_lower:
        m = re.search(r"edg/(\d+)", ua_lower)
        browser = f"Edge {m.group(1)}" if m else "Edge"
    elif "curl" in ua_lower:
        browser = ua_string[:50]
        is_bot = True

    # OS detection
    if "windows nt 10.0" in ua_lower:
        os_str = "Windows 10/11"
    elif "windows nt" in ua_lower:
        os_str = "Windows"
    elif "mac os x" in ua_lower:
        m = re.search(r"mac os x (\d+[._]\d+)", ua_lower)
        os_str = f"macOS {m.group(1).replace('_', '.')}" if m else "macOS"
    elif "linux" in ua_lower:
        os_str = "Linux"
    elif "android" in ua_lower:
        m = re.search(r"android (\d+)", ua_lower)
        os_str = f"Android {m.group(1)}" if m else "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_str = "iOS"

    return ParsedUA(
        browser=browser,
        os=os_str,
        is_bot=is_bot,
        scanner_sig=scanner_sig,
    )


def is_suspicious_request(ua_string: str | None) -> bool:
    """
    Check if a request appears to be from an automated scanner or suspicious tool.

    Args:
        ua_string: User-Agent header value.

    Returns:
        True if request appears suspicious.
    """
    if not ua_string:
        return True  # Missing UA is suspicious on non-API routes

    parsed = parse_user_agent(ua_string)
    return parsed.is_bot
