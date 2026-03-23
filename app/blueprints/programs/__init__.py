# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
programs_bp = Blueprint("programs", __name__, url_prefix="")
from app.blueprints.programs import routes  # noqa
