from flask import Blueprint, jsonify, request
from engine.policy_loader import load_all_policies
import os
import glob
import yaml

policies_bp = Blueprint('policies', __name__)

@policies_bp.route("/api/policies", methods=["GET"])
def get_policies():
    policies = load_all_policies()
    return jsonify(policies), 200

@policies_bp.route("/api/policies/<policy_id>/mode", methods=["PATCH"])
def update_policy_mode(policy_id):
    data = request.json or {}
    new_mode = data.get("mode")
    if new_mode not in ["enforce", "audit"]:
        return jsonify({"error": "Invalid mode. Must be 'enforce' or 'audit'"}), 400

    policies_path = os.environ.get("POLICIES_PATH", "./policies")
    if not os.path.isdir(policies_path):
        possible_path = os.path.join(os.path.dirname(__file__), "..", "..", "policies")
        if os.path.isdir(possible_path):
            policies_path = possible_path

    pattern = os.path.join(policies_path, "**", "*.yaml")
    policy_files = glob.glob(pattern, recursive=True)

    target_file = None
    target_data = None

    for filepath in policy_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                p_data = yaml.safe_load(f)
            if p_data and isinstance(p_data, dict) and p_data.get("id") == policy_id:
                target_file = filepath
                target_data = p_data
                break
        except Exception:
            continue
            
    if not target_file:
        return jsonify({"error": "Policy not found"}), 404

    target_data["mode"] = new_mode

    with open(target_file, "w", encoding="utf-8") as f:
        yaml.safe_dump(target_data, f, default_flow_style=False, sort_keys=False)

    return jsonify({"message": f"Updated {policy_id} mode to {new_mode}"}), 200
