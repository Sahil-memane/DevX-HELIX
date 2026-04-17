export interface Policy {
  id: string;
  name: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Enforced" | "Audit";
  updated: string;
}

export interface AuditLog {
  id: string;
  resource: string;
  policy: string;
  user: string;
  status: "FAIL" | "PASS";
  time: string;
}

export interface DashboardMetrics {
  complianceScore: number;
  activePolicies: number;
  criticalViolations: number;
  scansToday: string;
  pieData: { name: string; value: number }[];
  barData: { name: string; violations: number }[];
  lineData: { name: string; score: number }[];
  recentActivity: { time: string; evt: string; env: string; status: string }[];
}

const API_BASE = "http://localhost:8080/api";

export const mockApi = {
  getDashboardMetrics: async (): Promise<DashboardMetrics> => {
    try {
      const [statsRes, policiesRes, auditRes] = await Promise.all([
        fetch(`${API_BASE}/dashboard/stats`).then(r => r.json()),
        fetch(`${API_BASE}/policies`).then(r => r.json()),
        fetch(`${API_BASE}/audit`).then(r => r.json())
      ]);

      const complianceScore = statsRes.compliance_score || 0;
      const activePolicies = policiesRes.length || 0;
      
      const criticalViolations = auditRes.filter((log: any) => 
        log.violations && log.violations.some((v: any) => v.severity && v.severity.toUpperCase() === 'CRITICAL')
      ).length || 0;

      const pieData = [
        { name: 'Compliant', value: complianceScore },
        { name: 'Non-Compliant', value: 100 - complianceScore },
      ];

      const barData = (statsRes.top_violations || []).map((v: any) => ({
        name: (v.issue || 'Unknown').substring(0, 15),
        violations: v.count
      }));

      const recentActivity = (auditRes || []).slice(0, 5).map((log: any) => ({
        time: new Date(log.timestamp).toLocaleTimeString(),
        evt: log.artifact_type ? `Validated ${log.artifact_type}` : 'Validation',
        env: log.environment || 'N/A',
        status: log.status === 'PASSED' ? 'Pass' : 'Fail'
      }));

      const lineData = [
        { name: 'Prev', score: Math.max(0, complianceScore - 2) },
        { name: 'Now', score: complianceScore }
      ];

      return {
        complianceScore,
        activePolicies,
        criticalViolations,
        scansToday: `${statsRes.total_runs || 0}`,
        pieData,
        barData,
        lineData,
        recentActivity
      };
    } catch(e) {
      console.error("Dashboard fetch error:", e);
      return {
        complianceScore: 0, activePolicies: 0, criticalViolations: 0, scansToday: "0",
        pieData: [], barData: [], lineData: [], recentActivity: []
      };
    }
  },
  
  getPolicies: async (): Promise<Policy[]> => {
    try {
      const res = await fetch(`${API_BASE}/policies`);
      const data = await res.json();
      return (data || []).map((p: any) => ({
        id: p.id,
        name: p.name,
        category: p.category,
        severity: p.severity,
        status: p.mode === "enforce" ? "Enforced" : "Audit",
        updated: "Just now"
      }));
    } catch(e) {
      console.error("Policy fetch error:", e);
      return [];
    }
  },

  getAuditLogs: async (): Promise<AuditLog[]> => {
    try {
      const res = await fetch(`${API_BASE}/audit`);
      const data = await res.json();
      return (data || []).map((log: any) => ({
        id: log.run_id,
        resource: log.artifact_type || 'Unknown',
        policy: log.status,
        user: log.team || 'Unknown',
        status: log.status === 'PASSED' ? 'PASS' : 'FAIL',
        time: new Date(log.timestamp).toLocaleString()
      }));
    } catch(e) {
      console.error("Audit log fetch error:", e);
      return [];
    }
  }
};
