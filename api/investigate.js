export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const target = (req.body && req.body.node_id) || "pod-ingress-7b4d";

  res.status(200).json({
    status: "success",
    node_id: target,
    target_compromised: true,
    blast_radius: {
      score: 9.8,
      severity: "CRITICAL",
      at_risk_assets_count: 4,
      records_at_risk: 2400000
    },
    remediation: {
      edges_severed: 1,
      action: "DELETED relationship (iam-prod-reader)-[:ACCESSES_DB]->(rds-customer-prod)",
      quarantined_pod: target,
      execution_time_ms: 3.1
    },
    post_remediation: {
      active_attack_paths: 0,
      new_blast_radius_score: 0.0,
      status: "SECURE"
    },
    trace: [
      { step: 1, phase: "INGRESS DETECTED", query: "MATCH (p:Pod {id:'pod-ingress-7b4d'})-[:EXPOSES]->(v:Vulnerability)", detail: "CVE-2026-9912 confirmed · CVSS 9.8 · public-facing pod", ms: 12 },
      { step: 2, phase: "ATTACK PATH TRAVERSED", query: "MATCH path = (p:Pod)-[*1..5]->(d:Database) RETURN path", detail: "4-hop chain found · 2,400,000 PII records within blast radius", ms: 38 },
      { step: 3, phase: "TOXIC PERMISSION SEVERED", action: "DELETE relationship (iam-prod-reader)-[:UNLOCKS_DATABASE]->(rds-customer-prod)", detail: "IAM trust edge revoked · lateral movement contained", ms: 64 },
      { step: 4, phase: "ZERO-TRUST VERIFIED", query: "MATCH path = (p:Pod)-[*1..5]->(d:Database) RETURN count(path)", detail: "Reachable paths: 0 · containment verified", ms: 83 }
    ]
  });
}
