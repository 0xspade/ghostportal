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
Celery Beat scheduler entry point for GhostPortal.

Defines the full periodic task schedule. Beat dispatches tasks; workers execute them.

Start Beat with:
    celery -A celery_worker.celery beat --loglevel=info --schedule=/tmp/celerybeat-schedule

Or via Docker Compose:
    docker compose up beat

Schedule overview:
    03:00 UTC — Purge expired magic link tokens + OTP Redis keys
    04:00 UTC — Purge old AI generation jobs (>7 days)
    06:00 UTC — Purge expired portal sessions (every 6 hours)
    07:00 UTC — Severity escalation alerts (idle Critical/High reports)
    08:00 UTC — Dispatch due follow-up notifications (30/60/90-day)
    09:00 UTC — Invite expiry warnings (7-day and 1-day)
    10:00 UTC — Resolved access expiry check (auto-revoke after all resolved)
    :00      — Retry failed notifications (every hour)
    Sun 02:00 UTC — Prune old AccessLog entries beyond retention window
"""

import os

from celery.schedules import crontab

from app import create_app
from app.extensions import init_celery

flask_app = create_app()
celery = init_celery(flask_app)

# Import all task modules so Beat can reference them
import app.tasks.notifications   # noqa: F401, E402
import app.tasks.followup        # noqa: F401, E402
import app.tasks.resolved_expiry # noqa: F401, E402
import app.tasks.ai_generation   # noqa: F401, E402
import app.tasks.cleanup         # noqa: F401, E402
import app.tasks.bounty          # noqa: F401, E402

celery.conf.beat_schedule = {
    # ── Cleanup Jobs ──────────────────────────────────────────────────────────

    # Purge expired magic link tokens + OTP Redis keys — daily 03:00 UTC
    "cleanup-expired-tokens": {
        "task": "app.tasks.cleanup.purge_expired_tokens",
        "schedule": crontab(hour=3, minute=0),
        "options": {"expires": 3600},
    },

    # Purge completed/failed AI jobs older than 7 days — daily 04:00 UTC
    "cleanup-ai-jobs": {
        "task": "app.tasks.cleanup.purge_old_ai_jobs",
        "schedule": crontab(hour=4, minute=0),
        "options": {"expires": 3600},
    },

    # Purge expired portal sessions — every 6 hours
    "cleanup-portal-sessions": {
        "task": "app.tasks.cleanup.purge_expired_portal_sessions",
        "schedule": crontab(minute=0, hour="*/6"),
        "options": {"expires": 3600},
    },

    # Prune old AccessLog entries beyond retention window — weekly Sunday 02:00 UTC
    "prune-access-log": {
        "task": "app.tasks.cleanup.prune_old_access_logs",
        "schedule": crontab(hour=2, minute=0, day_of_week=0),
        "options": {"expires": 7200},
    },

    # ── Notification Jobs ─────────────────────────────────────────────────────

    # Severity escalation alerts — idle Critical/High reports — daily 07:00 UTC
    "severity-escalation-alerts": {
        "task": "app.tasks.notifications.send_severity_escalation_alerts",
        "schedule": crontab(hour=7, minute=0),
        "options": {"expires": 3600},
    },

    # Follow-up dispatch — daily 08:00 UTC
    "dispatch-followups": {
        "task": "app.tasks.followup.dispatch_due_followups",
        "schedule": crontab(hour=8, minute=0),
        "options": {"expires": 3600},
    },

    # Invite expiry warnings — daily 09:00 UTC
    "invite-expiry-warnings": {
        "task": "app.tasks.notifications.send_expiry_warnings",
        "schedule": crontab(hour=9, minute=0),
        "options": {"expires": 3600},
    },

    # Resolved access expiry check — daily 10:00 UTC
    "resolved-access-expiry": {
        "task": "app.tasks.resolved_expiry.check_resolved_access_expiry",
        "schedule": crontab(hour=10, minute=0),
        "options": {"expires": 3600},
    },

    # Retry failed notifications — every hour at :00
    "retry-failed-notifications": {
        "task": "app.tasks.notifications.retry_failed",
        "schedule": crontab(minute=0),
        "options": {"expires": 3000},
    },

    # ── Payment Jobs ──────────────────────────────────────────────────────────

    # Poll PayPal payout statuses — every 15 minutes
    "poll-paypal-payouts": {
        "task": "app.tasks.bounty.poll_pending_paypal_payouts",
        "schedule": crontab(minute="*/15"),
        "options": {"expires": 600},
    },

    # Poll crypto confirmations — every 5 minutes
    "poll-crypto-confirmations": {
        "task": "app.tasks.bounty.poll_pending_crypto_payments",
        "schedule": crontab(minute="*/5"),
        "options": {"expires": 240},
    },
}

celery.conf.beat_scheduler = "celery.beat:PersistentScheduler"
celery.conf.beat_schedule_filename = "/tmp/celerybeat-schedule"
