# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="")
from app.blueprints.dashboard import routes  # noqa
