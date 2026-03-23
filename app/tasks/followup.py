# GhostPortal follow-up tasks
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from datetime import datetime, timezone
from app.extensions import celery

logger = logging.getLogger(__name__)

@celery.task
def dispatch_due_followups():
    from app.models import FollowUpSchedule, InviteActivity
    from app.extensions import db
    now = datetime.now(timezone.utc)
    due = FollowUpSchedule.query.filter(
        FollowUpSchedule.scheduled_at <= now,
        FollowUpSchedule.status == "pending",
    ).all()
    for schedule in due:
        invite = schedule.invite
        if not invite or not invite.is_active or invite.is_locked:
            schedule.status = "skipped"
            db.session.add(schedule)
            continue
        has_reply = InviteActivity.query.filter_by(
            invite_id=invite.id, action="reply_posted").first()
        if has_reply:
            schedule.status = "skipped"
        else:
            schedule.status = "sent"
            schedule.sent_at = now
            logger.info(f"Sending day-{schedule.scheduled_days} follow-up for invite {invite.id}")
        db.session.add(schedule)
    db.session.commit()
