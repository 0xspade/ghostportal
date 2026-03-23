# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
ai_bp = Blueprint("ai_bp", __name__, url_prefix="")
from app.blueprints.ai_bp import routes  # noqa
