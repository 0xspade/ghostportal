#!/usr/bin/env python3
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
Manual backup script for GhostPortal.

Creates an AES-256-GCM encrypted ZIP backup of all reports and attachments.
Backup is saved to the current directory.

Usage:
    python scripts/backup_now.py [--output /path/to/backup.zip]

Or via Docker:
    docker compose exec app python scripts/backup_now.py

Or via Makefile:
    make backup

The backup file is named:
    ghostportal-backup-<ISO-timestamp>.zip

Encrypted with BACKUP_ENCRYPTION_KEY from .env (AES-256-GCM).
"""

import argparse
import os
import sys
from datetime import datetime, timezone

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser(description="GhostPortal manual backup")
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Output path for backup ZIP (default: current directory)",
    )
    args = parser.parse_args()

    from app import create_app
    from app.utils.export import create_encrypted_backup

    app = create_app()

    with app.app_context():
        print("GhostPortal — Manual Backup")
        print("=" * 50)

        encryption_key = app.config.get("BACKUP_ENCRYPTION_KEY", "")
        if not encryption_key:
            print("ERROR: BACKUP_ENCRYPTION_KEY is not configured in .env")
            print("       Set a base64-encoded 32-byte AES key to enable backup encryption.")
            sys.exit(1)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"ghostportal-backup-{timestamp}.zip"

        if args.output:
            output_path = args.output
        else:
            output_path = os.path.join(os.getcwd(), filename)

        print(f"Creating backup: {output_path}")
        print("This may take a moment for large datasets...")

        try:
            zip_bytes = create_encrypted_backup(encryption_key)

            with open(output_path, "wb") as f:
                f.write(zip_bytes)

            size_mb = len(zip_bytes) / (1024 * 1024)
            print(f"[OK]   Backup created: {output_path}")
            print(f"       Size: {size_mb:.2f} MB")
            print(f"       Encrypted with AES-256-GCM")
            print("")
            print("Store this backup securely. The decryption key is in your .env file.")

        except Exception as exc:
            print(f"ERROR: Backup failed — {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
