# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
reports_bp = Blueprint("reports", __name__, url_prefix="")
from app.blueprints.reports import routes  # noqa
