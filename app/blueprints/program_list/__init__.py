# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade — AGPL-3.0 License

from flask import Blueprint

program_list_bp = Blueprint("program_list", __name__)

from app.blueprints.program_list import routes  # noqa: E402, F401
