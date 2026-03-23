# GhostPortal AI generation tasks
# Copyright (C) 2026 Spade - AGPL-3.0
import logging
from datetime import datetime, timezone
from app.extensions import celery

logger = logging.getLogger(__name__)

@celery.task(bind=True, max_retries=2)
def run_ai_generation(self, job_id):
    from app.models import AIGenerationJob
    from app.extensions import db
    import uuid
    try:
        jid = uuid.UUID(job_id)
        job = AIGenerationJob.query.get(jid)
        if not job:
            return
        job.status = "running"
        db.session.add(job)
        db.session.commit()
        from app.ai.provider import get_provider
        provider = get_provider(job.provider)
        import asyncio
        context = job.input_context or {}
        result = asyncio.run(provider.generate(
            prompt=str(context),
            system="You are a professional penetration tester writing a vulnerability report.",
        ))
        job.status = "completed"
        job.output_text = result.text
        job.tokens_used = result.tokens_used
        job.completed_at = datetime.now(timezone.utc)
        db.session.add(job)
        db.session.commit()
    except Exception as exc:
        logger.error(f"AI generation failed for job {job_id}: {exc}")
        try:
            from app.models import AIGenerationJob
            from app.extensions import db
            import uuid
            job = AIGenerationJob.query.get(uuid.UUID(job_id))
            if job:
                job.status = "failed"
                db.session.add(job)
                db.session.commit()
        except Exception:
            pass
        try:
            self.retry(exc=exc)
        except Exception:
            pass
