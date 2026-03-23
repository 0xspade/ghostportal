# GhostPortal cleanup tasks
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from datetime import datetime, timezone, timedelta
from app.extensions import celery

logger = logging.getLogger(__name__)

@celery.task
def purge_expired_tokens():
    from app.models import User, SecurityTeamMember
    from app.extensions import db
    now = datetime.now(timezone.utc)
    expired_owners = User.query.filter(
        User.token_expiry < now, User.token_used == False).all()
    for u in expired_owners:
        u.login_url_token_hash = None
        u.login_otp_hash = None
        u.token_expiry = None
        u.token_used = True
        db.session.add(u)
    expired_members = SecurityTeamMember.query.filter(
        SecurityTeamMember.token_expiry < now,
        SecurityTeamMember.token_used == False).all()
    for m in expired_members:
        m.login_url_token_hash = None
        m.login_otp_hash = None
        m.token_expiry = None
        m.token_used = True
        db.session.add(m)
    db.session.commit()
    logger.info(f"Purged {len(expired_owners)+len(expired_members)} expired tokens")

@celery.task
def purge_expired_portal_sessions():
    from app.models import SecurityTeamSession
    from app.extensions import db
    now = datetime.now(timezone.utc)
    expired = SecurityTeamSession.query.filter(SecurityTeamSession.expires_at < now).all()
    for s in expired:
        db.session.delete(s)
    db.session.commit()
    logger.info(f"Purged {len(expired)} expired portal sessions")

@celery.task
def prune_old_access_logs():
    from app.models import AccessLog
    from app.extensions import db
    cutoff = datetime.now(timezone.utc) - timedelta(days=730)
    AccessLog.query.filter(AccessLog.created_at < cutoff).delete()
    db.session.commit()
    logger.info("Pruned old access logs")

@celery.task
def purge_old_ai_jobs():
    from app.models import AIGenerationJob
    from app.extensions import db
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    AIGenerationJob.query.filter(
        AIGenerationJob.status.in_(["completed","failed"]),
        AIGenerationJob.created_at < cutoff,
    ).delete()
    db.session.commit()
    logger.info("Purged old AI generation jobs")
