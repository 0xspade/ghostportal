# GhostPortal -- Project-Apocalypse -- Program Names Autocomplete Blueprint
# Copyright (C) 2026 Spade -- AGPL-3.0 License

from flask import jsonify, request, session
from app.blueprints.programs import programs_bp
from app.blueprints.decorators import owner_required, parse_uuid
from app.extensions import db, limiter
from app.models import ProgramName


@programs_bp.route("/api/programs/search")
@owner_required
@limiter.limit("60 per minute")
def search():
    q = (request.args.get("q") or "").strip()
    from app.utils.program_names import search_program_names
    results = search_program_names(q, limit=20)
    return jsonify([{
        "id": str(r.id),
        "name": r.name,
        "use_count": r.use_count,
        "last_used": r.last_used_at.isoformat() if r.last_used_at else None,
    } for r in results])


@programs_bp.route("/api/programs", methods=["POST"])
@owner_required
def create():
    data = request.get_json(force=True, silent=True) or {}
    name = str(data.get("name") or "").strip()[:300]
    if not name:
        return jsonify({"error": "name required"}), 400
    from app.utils.program_names import save_program_name as upsert_program_name
    prog = upsert_program_name(name)
    db.session.commit()
    return jsonify({"id": str(prog.id), "name": prog.name}), 201


@programs_bp.route("/api/programs/<program_uuid>", methods=["DELETE"])
@owner_required
def delete(program_uuid):
    pid = parse_uuid(program_uuid)
    prog = ProgramName.query.get_or_404(pid)
    db.session.delete(prog)
    db.session.commit()
    return jsonify({"ok": True})
