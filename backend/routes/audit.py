from flask import Blueprint, jsonify

audit_bp = Blueprint('audit', __name__)

@audit_bp.route("/api/audit", methods=["GET"])
def get_audit_logs():
    from app import db
    if db is None:
        return jsonify([]), 200

    cursor = db.policy_runs.find().sort("timestamp", -1).limit(50)
    runs = []
    for doc in cursor:
        doc.pop("_id", None)
        runs.append(doc)
    return jsonify(runs), 200

@audit_bp.route("/api/audit/<run_id>", methods=["GET"])
def get_audit_log(run_id):
    from app import db
    if db is None:
        return jsonify({"error": "No database connection"}), 500

    doc = db.policy_runs.find_one({"run_id": run_id})
    if not doc:
        return jsonify({"error": "Run not found"}), 404
        
    doc.pop("_id", None)
    return jsonify(doc), 200
