# GhostPortal AI generation routes
from flask import jsonify, request, session
from app.blueprints.ai_bp import ai_bp

@ai_bp.route("/ai/generate", methods=["POST"])
def generate():
    if session.get("role") != "owner":
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json() or {}
    from app.models import AIGenerationJob
    from app.extensions import db
    job = AIGenerationJob(
        provider=data.get("provider","anthropic"),
        model=data.get("model","claude-opus-4-5"),
        prompt_type=data.get("prompt_type","full_report"),
        status="pending", input_context=data,
    )
    db.session.add(job)
    db.session.commit()
    try:
        from app.tasks.ai_generation import run_ai_generation
        run_ai_generation.delay(str(job.id))
    except Exception:
        pass
    return jsonify({"job_id": str(job.id), "status": "pending"})

@ai_bp.route("/ai/generate/<job_uuid>/status")
def job_status(job_uuid):
    if session.get("role") != "owner":
        return jsonify({"error": "unauthorized"}), 401
    import uuid as ul
    from app.models import AIGenerationJob
    try:
        jid = ul.UUID(job_uuid)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    job = AIGenerationJob.query.get(jid)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({"job_id": str(job.id), "status": job.status, "tokens_used": job.tokens_used})

@ai_bp.route("/ai/generate/<job_uuid>/result")
def job_result(job_uuid):
    if session.get("role") != "owner":
        return jsonify({"error": "unauthorized"}), 401
    import uuid as ul
    from app.models import AIGenerationJob
    try:
        jid = ul.UUID(job_uuid)
    except ValueError:
        return jsonify({"error": "invalid id"}), 400
    job = AIGenerationJob.query.get(jid)
    if not job or job.status != "completed":
        return jsonify({"error": "not ready"}), 404
    return jsonify({"output": job.output_text, "tokens_used": job.tokens_used})
