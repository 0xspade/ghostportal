# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
security_teams_bp = Blueprint("security_teams", __name__, url_prefix="")
from app.blueprints.security_teams import routes  # noqa
