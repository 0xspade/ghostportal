# GhostPortal — Project-Apocalypse
# Copyright (C) 2026 Spade
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Celery worker entry point for GhostPortal.

Start the worker with:
    celery -A celery_worker.celery worker --concurrency=4 --loglevel=info

Or via Docker Compose (see docker-compose.yml):
    docker compose up worker
"""

import os

from app import create_app
from app.extensions import init_celery

flask_app = create_app()
celery = init_celery(flask_app)

# Import all task modules so Celery auto-discovers them
import app.tasks.notifications   # noqa: F401, E402
import app.tasks.followup        # noqa: F401, E402
import app.tasks.resolved_expiry # noqa: F401, E402
import app.tasks.ai_generation   # noqa: F401, E402
import app.tasks.cleanup         # noqa: F401, E402
import app.tasks.bounty          # noqa: F401, E402
