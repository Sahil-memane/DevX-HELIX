from dataclasses import dataclass
from typing import List, Dict

@dataclass
class Violation:
    policy_id: str
    policy_name: str
    severity: str
    mode: str
    resource: str
    what_failed: str
    why_it_matters: str
    remediation: str

    def to_dict(self):
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "severity": self.severity,
            "mode": self.mode,
            "resource": self.resource,
            "what_failed": self.what_failed,
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
        }

@dataclass
class RunResult:
    run_id: str
    status: str
    counts: Dict[str, int]
    violations: List[Violation]

    def to_dict(self):
        return {
            "run_id": self.run_id,
            "status": self.status,
            "counts": self.counts,
            "violations": [v.to_dict() for v in self.violations],
        }
