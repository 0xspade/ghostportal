# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
# AGPL-3.0 License
from flask import Blueprint
webhooks_bp = Blueprint("webhooks", __name__, url_prefix="")
from app.blueprints.webhooks import routes  # noqa
