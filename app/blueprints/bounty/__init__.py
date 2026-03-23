# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
bounty_bp = Blueprint("bounty", __name__, url_prefix="")
from app.blueprints.bounty import routes  # noqa
