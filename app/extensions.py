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

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from celery import Celery
import redis as redis_lib

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
mail = Mail()

import os as _os

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],
    # Storage URI is overridden in create_app() after Redis availability check.
    # Uses RATELIMIT_STORAGE_URI from app config (set before limiter.init_app).
    storage_uri="memory://",
)

celery = Celery(__name__)
redis_client = None


def init_redis(app):
    global redis_client
    redis_url = app.config.get("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis_lib.from_url(redis_url, decode_responses=True)
    return redis_client


def get_redis():
    return redis_client


def init_celery(app):
    """Configure Celery with Flask app context."""
    celery.conf.update(
        broker_url=app.config.get("REDIS_URL", "redis://localhost:6379/0"),
        result_backend=app.config.get("REDIS_URL", "redis://localhost:6379/0"),
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
    )

    class ContextTask(celery.Task):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    # Celery 5.x deprecated `celery.Task = X` via __setattr__.
    # Bypass it by writing directly to the instance __dict__ — same effect,
    # no deprecation warning, no functional difference.
    celery.__dict__["Task"] = ContextTask
    return celery
