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
Database seeder for GhostPortal.

Seeds:
  1. Owner User record (from OWNER_EMAIL env var)
  2. Built-in report templates (from seeds/templates.json)
  3. CWE data is available via seeds/cwe_full.json for reference
     (CWE lookups use JSON at runtime, not seeded to DB)

Usage:
    python scripts/seed_db.py

Or via Docker:
    docker compose exec app python scripts/seed_db.py

Or via Makefile:
    make seed
"""

import json
import os
import re
import sys
import uuid

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def seed():
    from app import create_app
    from app.extensions import db
    from app.models import User, ReportTemplate, ProgramName

    app = create_app()

    with app.app_context():
        print("GhostPortal — Database Seeder")
        print("=" * 50)

        # ── 1. Owner User ──────────────────────────────────────────────────────
        owner_email = app.config.get("OWNER_EMAIL", "").strip().lower()
        if not owner_email:
            print("ERROR: OWNER_EMAIL is not configured in .env")
            sys.exit(1)

        existing_owner = User.query.filter_by(email=owner_email).first()
        if existing_owner:
            print(f"[SKIP] Owner already exists: {owner_email}")
        else:
            owner = User(
                id=uuid.uuid4(),
                email=owner_email,
            )
            db.session.add(owner)
            db.session.commit()
            print(f"[OK]   Created owner: {owner_email}")

        # ── 2. Report Templates ────────────────────────────────────────────────
        templates_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "seeds",
            "templates.json",
        )

        if not os.path.exists(templates_path):
            print(f"[WARN] templates.json not found at {templates_path} — skipping")
        else:
            with open(templates_path, encoding="utf-8") as f:
                templates_data = json.load(f)

            seeded_count = 0
            skipped_count = 0

            for tpl in templates_data:
                name = tpl.get("name", "").strip()
                if not name:
                    continue

                existing = ReportTemplate.query.filter_by(name=name).first()
                if existing:
                    skipped_count += 1
                    continue

                template = ReportTemplate(
                    id=uuid.uuid4(),
                    name=name,
                    category=tpl.get("category", "custom"),
                    title_template=tpl.get("title_template", ""),
                    description_template=tpl.get("description_template", ""),
                    steps_template=tpl.get("steps_template", ""),
                    poc_template=tpl.get("poc_template", ""),
                    remediation_template=tpl.get("remediation_template", ""),
                    cwe_id=tpl.get("cwe_id"),
                    cwe_name=tpl.get("cwe_name", ""),
                    severity=tpl.get("severity", "medium"),
                    tags=tpl.get("tags", []),
                )
                db.session.add(template)
                seeded_count += 1

            db.session.commit()
            print(f"[OK]   Templates: {seeded_count} seeded, {skipped_count} already existed")

        # ── 3. Program List ────────────────────────────────────────────────────
        program_list_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "program_list.json",
        )

        if not os.path.exists(program_list_path):
            print(f"[WARN] program_list.json not found at {program_list_path} — skipping")
        else:
            with open(program_list_path, encoding="utf-8") as f:
                program_data = json.load(f)

            programs = program_data.get("programs", [])
            _email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
            prog_seeded = 0
            prog_skipped = 0

            for entry in programs:
                name = str(entry.get("program_name") or "").strip()
                raw_email = str(entry.get("program_email") or "").strip()
                email = raw_email if raw_email and _email_re.match(raw_email) else None
                if not name:
                    continue

                name_normalized = name.lower().strip()
                existing = ProgramName.query.filter_by(name_normalized=name_normalized).first()
                if existing:
                    # Update email if the existing entry has none
                    if email and not existing.email:
                        existing.email = email
                        db.session.add(existing)
                    prog_skipped += 1
                    continue

                prog = ProgramName(
                    id=uuid.uuid4(),
                    name=name,
                    name_normalized=name_normalized,
                    email=email,
                    use_count=0,
                )
                db.session.add(prog)
                prog_seeded += 1

            db.session.commit()
            print(f"[OK]   Programs: {prog_seeded} seeded, {prog_skipped} already existed")

        print("=" * 50)
        print("Seeding complete.")
        print("")
        print("Next steps:")
        print("  1. Configure your .env file (SMTP, AI provider, etc.)")
        print("  2. Start the application: make up")
        print(f"  3. Request a magic link login at your BASE_URL/login")
        print(f"     Email: {owner_email}")


if __name__ == "__main__":
    seed()
