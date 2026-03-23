# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
api_bp = Blueprint("api", __name__, url_prefix="")
from app.blueprints.api import routes  # noqa
