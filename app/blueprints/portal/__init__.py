# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
portal_bp = Blueprint("portal", __name__, url_prefix="")
from app.blueprints.portal import routes  # noqa
