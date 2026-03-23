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
Secret pattern detection for report submission.

Scans report markdown fields for patterns that look like API keys, tokens,
private keys, or connection strings. Results are WARNINGS only — owner
must make the redaction decision. Never auto-redact.

Patterns detected:
- AWS Access Key IDs (AKIA...)
- OpenAI API keys (sk-...)
- Anthropic API keys (sk-ant-...)
- Generic API keys
- PEM private keys
- Database connection strings (postgres://, mongodb://, mysql://)
- JWT tokens
- GitHub personal access tokens
- Slack tokens
- Generic bearer tokens
"""

import re
import logging
from dataclasses import dataclass
from typing import NamedTuple

logger = logging.getLogger(__name__)


@dataclass
class SecretMatch:
    """A detected potential secret in report content."""
    field_name: str
    pattern_name: str
    description: str
    # Truncated match for display (never log/store full value)
    snippet: str


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}", re.IGNORECASE),
     "AWS Access Key ID"),

    ("aws_secret_key", re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"),
     "Possible AWS Secret Access Key"),

    ("openai_api_key", re.compile(r"sk-[a-zA-Z0-9]{48}", re.IGNORECASE),
     "OpenAI API Key"),

    ("anthropic_api_key", re.compile(r"sk-ant-[a-zA-Z0-9\-_]{48,}", re.IGNORECASE),
     "Anthropic API Key"),

    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}", re.IGNORECASE),
     "GitHub Personal Access Token"),

    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}", re.IGNORECASE),
     "Slack Token"),

    ("pem_private_key", re.compile(r"-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE KEY-----"),
     "PEM Private Key"),

    ("postgres_url", re.compile(r"postgres(?:ql)?://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+", re.IGNORECASE),
     "PostgreSQL Connection String"),

    ("mysql_url", re.compile(r"mysql://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+", re.IGNORECASE),
     "MySQL Connection String"),

    ("mongodb_url", re.compile(r"mongodb(?:\+srv)?://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+", re.IGNORECASE),
     "MongoDB Connection String"),

    ("redis_url_with_auth", re.compile(r"redis://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+", re.IGNORECASE),
     "Redis Connection String with Password"),

    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "JSON Web Token (JWT)"),

    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE),
     "Google API Key"),

    ("stripe_key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}", re.IGNORECASE),
     "Stripe Secret Key"),

    ("twilio_account_sid", re.compile(r"AC[a-z0-9]{32}", re.IGNORECASE),
     "Twilio Account SID"),

    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", re.IGNORECASE),
     "SendGrid API Key"),

    ("generic_bearer", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}", re.IGNORECASE),
     "Bearer Token in Content"),

    ("ssh_private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
     "OpenSSH Private Key"),
]


def scan_for_secrets(fields: dict[str, str]) -> list[SecretMatch]:
    """
    Scan report fields for potential secrets.

    Args:
        fields: Dict mapping field names to their content strings.
                e.g., {"description": "...", "proof_of_concept": "..."}

    Returns:
        List of SecretMatch objects for detected potential secrets.
        May be empty if no secrets detected.
    """
    matches: list[SecretMatch] = []

    for field_name, content in fields.items():
        if not content:
            continue

        for pattern_name, pattern, description in SECRET_PATTERNS:
            found = pattern.search(content)
            if found:
                # Create a safe snippet (first 20 chars of match, masked)
                raw_match = found.group(0)
                snippet = _mask_secret(raw_match)

                matches.append(SecretMatch(
                    field_name=field_name,
                    pattern_name=pattern_name,
                    description=description,
                    snippet=snippet,
                ))

                logger.warning(
                    f"Potential secret detected in field '{field_name}': {pattern_name}",
                    # Never log the actual value
                )

                # One match per pattern per field is enough for warning
                break

    return matches


def _mask_secret(value: str) -> str:
    """
    Create a safe display snippet from a potential secret.

    Shows first 6 chars + "..." + last 4 chars (total ≤ 15 chars shown).
    Never reveals the full secret value.

    Args:
        value: Detected secret string.

    Returns:
        Masked representation for display.
    """
    if len(value) <= 10:
        return "*" * len(value)

    prefix = value[:6]
    suffix = value[-4:]
    masked_middle = "..." + ("*" * min(8, len(value) - 10))
    return f"{prefix}{masked_middle}{suffix}"


def format_secret_warnings(matches: list[SecretMatch]) -> list[dict]:
    """
    Format SecretMatch objects for JSON API response or template rendering.

    Args:
        matches: List of SecretMatch objects.

    Returns:
        List of dicts with field, description, and snippet.
    """
    return [
        {
            "field": m.field_name,
            "field_label": _field_label(m.field_name),
            "description": m.description,
            "snippet": m.snippet,
        }
        for m in matches
    ]


def _field_label(field_name: str) -> str:
    """Convert a field_name to a human-readable label."""
    labels = {
        "description": "Description",
        "steps_to_reproduce": "Steps to Reproduce",
        "proof_of_concept": "Proof of Concept",
        "impact_statement": "Impact Statement",
        "remediation": "Remediation",
        "technical_details": "Technical Details",
    }
    return labels.get(field_name, field_name.replace("_", " ").title())
