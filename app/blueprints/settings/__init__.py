# GhostPortal — Project-Apocalypse — Settings Blueprint
# Copyright (C) 2026 Spade — AGPL-3.0 License

from flask import Blueprint

settings_bp = Blueprint("settings", __name__)

from app.blueprints.settings import routes  # noqa: F401, E402
