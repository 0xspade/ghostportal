# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License

from flask import Blueprint

auth_bp = Blueprint("auth", __name__, url_prefix="")

from app.blueprints.auth import routes  # noqa: E402, F401
