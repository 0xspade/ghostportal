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
SSRF-safe HTTP utility.

ALL server-side HTTP requests MUST use safe_fetch() instead of requests.get()
directly. This prevents Server-Side Request Forgery (SSRF) by:

1. Resolving the hostname to an IP before making the request
2. Blocking RFC1918, loopback, link-local, IANA special-purpose ranges
3. Blocking cloud metadata endpoints (169.254.169.254, etc.)
4. Enforcing strict timeouts
5. Disabling automatic redirects (each redirect destination validated independently)
6. Whitelisting allowed URL schemes (https/http only)

Usage:
    from app.utils.safe_fetch import safe_fetch

    response = safe_fetch("https://api.example.com/data")
    response = safe_fetch("https://api.example.com/data", method="POST", json={"key": "val"})
"""

import ipaddress
import logging
import socket
from typing import Any
from urllib.parse import urlparse

import requests
from requests import Response

from app.utils.security import is_rfc1918_or_reserved

logger = logging.getLogger(__name__)

# Allowed URL schemes for outbound requests
ALLOWED_SCHEMES = {"http", "https"}

# Cloud metadata service IP addresses to explicitly block
CLOUD_METADATA_IPS = {
    "169.254.169.254",    # AWS/GCP/Azure instance metadata
    "fd00:ec2::254",      # AWS IPv6 metadata
    "100.100.100.200",    # Alibaba Cloud metadata
    "192.0.0.192",        # Oracle Cloud metadata
}

# Default timeouts: (connect_timeout, read_timeout) in seconds
DEFAULT_TIMEOUT = (5, 30)


class SSRFError(ValueError):
    """Raised when a URL is blocked due to SSRF protection."""
    pass


def safe_fetch(
    url: str,
    method: str = "GET",
    timeout: tuple[int, int] = DEFAULT_TIMEOUT,
    allow_redirects: bool = False,
    **kwargs: Any,
) -> Response:
    """
    Make an HTTP request with SSRF protection.

    Validates the URL before making the request:
    - Scheme must be http or https
    - Hostname must resolve to a public IP (no RFC1918, loopback, link-local)
    - Cloud metadata endpoints are explicitly blocked

    Args:
        url: Target URL.
        method: HTTP method (GET, POST, PUT, etc.).
        timeout: Tuple of (connect_timeout, read_timeout) in seconds.
        allow_redirects: If True, each redirect destination is also validated.
        **kwargs: Additional arguments passed to requests.request().

    Returns:
        requests.Response object.

    Raises:
        SSRFError: If the URL is blocked.
        requests.RequestException: If the request fails.
    """
    # Validate URL before making any request
    _validate_url(url)

    # Make the request without automatic redirects
    response = requests.request(
        method=method.upper(),
        url=url,
        timeout=timeout,
        allow_redirects=False,
        **kwargs,
    )

    # Handle redirects manually (validate each destination)
    if allow_redirects:
        max_redirects = 5
        redirects = 0
        while response.is_redirect and redirects < max_redirects:
            redirect_url = response.headers.get("Location", "")
            if not redirect_url:
                break
            # Resolve relative redirects
            if redirect_url.startswith("/"):
                parsed = urlparse(url)
                redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
            _validate_url(redirect_url)
            response = requests.request(
                method="GET",
                url=redirect_url,
                timeout=timeout,
                allow_redirects=False,
                **kwargs,
            )
            redirects += 1

    return response


def _validate_url(url: str) -> None:
    """
    Validate a URL for SSRF safety.

    Args:
        url: URL to validate.

    Raises:
        SSRFError: If the URL is not safe.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"Invalid URL: {exc}") from exc

    # Check scheme
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"URL scheme '{scheme}' is not allowed. "
            f"Only {ALLOWED_SCHEMES} are permitted."
        )

    # Get hostname
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL has no hostname")

    # Explicitly block cloud metadata hostnames before DNS resolution
    if hostname in CLOUD_METADATA_IPS:
        raise SSRFError(f"Blocked: cloud metadata endpoint {hostname}")

    # Resolve hostname to IP address
    try:
        # getaddrinfo returns a list of (family, type, proto, canonname, sockaddr) tuples
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addr_infos:
            raise SSRFError(f"Could not resolve hostname: {hostname}")

        # Check EVERY resolved IP address (hostname may have multiple)
        for addr_info in addr_infos:
            ip_str = addr_info[4][0]  # sockaddr[0] is the IP

            # Block cloud metadata IPs
            if ip_str in CLOUD_METADATA_IPS:
                raise SSRFError(f"Blocked: resolves to cloud metadata endpoint {ip_str}")

            # Block RFC1918, loopback, link-local, reserved ranges
            if is_rfc1918_or_reserved(ip_str):
                raise SSRFError(
                    f"Blocked: hostname '{hostname}' resolves to private/reserved IP {ip_str}"
                )

    except SSRFError:
        raise
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve hostname '{hostname}': {exc}") from exc
    except Exception as exc:
        raise SSRFError(f"Error validating URL '{url}': {exc}") from exc

    logger.debug(f"SSRF check passed for URL: {scheme}://{hostname}/...")


def validate_url_for_storage(url: str, base_url: str = "") -> tuple[bool, str]:
    """
    Validate a URL before storing it as an ExternalLink.

    Args:
        url: URL to validate.
        base_url: The platform's own BASE_URL (to prevent self-redirect loops).

    Returns:
        Tuple of (is_valid, error_message). error_message is "" if valid.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"URL scheme '{scheme}' is not allowed (only http/https)"

    # Check for dangerous schemes embedded in the URL
    dangerous_schemes = {"javascript", "data", "vbscript", "ftp", "file"}
    if scheme in dangerous_schemes:
        return False, f"Dangerous URL scheme: {scheme}"

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    # Prevent self-redirect loops
    if base_url:
        base_parsed = urlparse(base_url)
        if hostname == base_parsed.hostname:
            return False, "Cannot link to the GhostPortal instance itself"

    # Check for RFC1918 / reserved IP addresses
    try:
        ip_addr = ipaddress.ip_address(hostname)
        if is_rfc1918_or_reserved(str(ip_addr)):
            return False, f"URL points to a private/reserved IP address: {hostname}"
    except ValueError:
        # Not an IP address — hostname format is fine for storage
        pass

    return True, ""
