# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
templates_bp = Blueprint("templates", __name__, url_prefix="")
from app.blueprints.templates_bp import routes  # noqa
