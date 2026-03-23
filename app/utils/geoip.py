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
Optional GeoIP lookup using MaxMind GeoLite2 local database.

No API calls — uses local .mmdb file for offline lookups.
Returns ISO 3166-1 alpha-2 country codes (e.g., "PH", "US", "DE").

Configuration:
    GEOIP_ENABLED=true
    GEOIP_DB_PATH=./GeoLite2-Country.mmdb

Download the free GeoLite2-Country database from:
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

import logging
from functools import lru_cache
from typing import Optional

logger = logging.getLogger(__name__)

# Singleton reader — initialized on first use
_reader = None
_geoip_enabled = False


def init_geoip(app) -> None:
    """
    Initialize the GeoIP reader from app config.

    Call from app factory after config is loaded.

    Args:
        app: Flask application instance.
    """
    global _reader, _geoip_enabled

    if not app.config.get("GEOIP_ENABLED", False):
        _geoip_enabled = False
        logger.info("GeoIP lookup disabled (GEOIP_ENABLED=false)")
        return

    db_path = app.config.get("GEOIP_DB_PATH", "./GeoLite2-Country.mmdb")

    try:
        import maxminddb
        _reader = maxminddb.open_database(db_path)
        _geoip_enabled = True
        logger.info(f"GeoIP initialized from: {db_path}")
    except ImportError:
        logger.warning("maxminddb not installed — GeoIP lookup unavailable")
        _geoip_enabled = False
    except FileNotFoundError:
        logger.warning(f"GeoLite2 database not found at: {db_path}")
        logger.warning("Download from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        _geoip_enabled = False
    except Exception as exc:
        logger.error(f"GeoIP initialization failed: {exc}")
        _geoip_enabled = False


def lookup_country(ip_address: str) -> Optional[str]:
    """
    Look up the ISO country code for an IP address.

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        ISO 3166-1 alpha-2 country code (e.g., "PH"), or None if unavailable.
    """
    global _reader, _geoip_enabled

    if not _geoip_enabled or _reader is None:
        return None

    # Skip private/local IPs
    if _is_private_ip(ip_address):
        return None

    try:
        record = _reader.get(ip_address)
        if record and "country" in record:
            return record["country"].get("iso_code")
        return None
    except Exception as exc:
        logger.debug(f"GeoIP lookup failed for {ip_address}: {exc}")
        return None


def _is_private_ip(ip: str) -> bool:
    """Quick check for private/local IPs that don't need GeoIP lookup."""
    private_prefixes = ("127.", "10.", "192.168.", "172.16.", "172.17.",
                        "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                        "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                        "172.28.", "172.29.", "172.30.", "172.31.", "::1", "fc", "fd")
    return any(ip.startswith(p) for p in private_prefixes)
