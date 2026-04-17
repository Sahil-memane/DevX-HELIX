from flask import Blueprint, request, jsonify
from engine.artifact_parser import parse_artifact
from engine.policy_loader import load_all_policies
from engine.evaluators import EVALUATORS
from models.models import RunResult
from datetime import datetime, timezone
import uuid

validate_bp = Blueprint('validate', __name__)

@validate_bp.route("/api/validate", methods=["POST"])
def validate_artifact():
    data = request.json or {}
    art_type = data.get("type")
    content = data.get("content")
    team = data.get("team", "unknown")
    commit_sha = data.get("commit_sha", "unknown")
    environment = data.get("environment", "unknown")

    if not art_type or not content:
        return jsonify({"error": "Missing 'type' or 'content'"}), 400

    try:
        artifact = parse_artifact(art_type, content)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    policies = load_all_policies()
    
    all_violations = []

    for policy in policies:
        policy_id = policy.get("id")
        if art_type not in policy.get("applies_to", []):
            continue

        eval_func = EVALUATORS.get(policy_id)
        if eval_func:
            try:
                violations = eval_func(artifact, policy)
                all_violations.extend(violations)
            except Exception as e:
                print(f"Error evaluating {policy_id}: {e}")

    blocking = [v for v in all_violations if v.mode == "enforce"]
    advisory = [v for v in all_violations if v.mode == "audit"]

    status = "BLOCKED" if blocking else ("ADVISORY" if advisory else "PASSED")
    counts = {
        "blocking": len(blocking),
        "advisory": len(advisory),
        "total": len(all_violations)
    }

    run_id = str(uuid.uuid4())
    run_result = RunResult(
        run_id=run_id,
        status=status,
        counts=counts,
        violations=all_violations
    )

    result_dict = run_result.to_dict()

    from app import db
    if db is not None:
        doc = {
            "run_id": run_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc),
            "team": team,
            "commit_sha": commit_sha,
            "environment": environment,
            "counts": counts,
            "violations": [v.to_dict() for v in all_violations],
            "artifact_type": art_type
        }
        db.policy_runs.insert_one(doc)

    if status == "BLOCKED":
        return jsonify(result_dict), 422
    
    return jsonify(result_dict), 200

@validate_bp.route("/api/auto-fix", methods=["POST"])
def auto_fix_artifact():
    # Advanced logic for autofix - placeholder returning suggestions
    return jsonify({"message": "Auto-fix feature not fully implemented. Re-run after applying suggestions manually."}), 200
