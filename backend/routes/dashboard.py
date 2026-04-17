from flask import Blueprint, jsonify

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    from app import db
    if db is None:
        return jsonify({
            "compliance_score": 0,
            "pass_rate": 0,
            "total_runs": 0,
            "top_violations": []
        }), 200

    total_runs = db.policy_runs.count_documents({})
    if total_runs == 0:
        return jsonify({
            "compliance_score": 100,
            "pass_rate": 100,
            "total_runs": 0,
            "top_violations": []
        }), 200

    success_runs = db.policy_runs.count_documents({"status": {"$in": ["PASSED", "ADVISORY"]}})
    pass_rate = (success_runs / total_runs) * 100
    compliance_score = pass_rate

    pipeline = [
        {"$unwind": "$violations"},
        {"$group": {"_id": "$violations.what_failed", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    
    top_viols_cursor = db.policy_runs.aggregate(pipeline)
    top_violations = [{"issue": doc["_id"], "count": doc["count"]} for doc in top_viols_cursor]

    return jsonify({
        "compliance_score": round(compliance_score, 1),
        "pass_rate": round(pass_rate, 1),
        "total_runs": total_runs,
        "top_violations": top_violations
    }), 200
