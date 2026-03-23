# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
legal_bp = Blueprint("legal", __name__, url_prefix="")
from app.blueprints.legal import routes  # noqa
