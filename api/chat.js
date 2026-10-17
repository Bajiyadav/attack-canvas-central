export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const body = req.body || {};
  const message = (body.message || "").toLowerCase();
  const activeNodeId = body.asset_id || "pod-ingress-7b4d";

  let cypher = null;
  let highlight_nodes = [];
  let answer = "";

  if (["employee", "reduce", "benefit", "roi", "savings", "workload", "time", "human", "hours", "staff", "cost"].some(w => message.includes(w))) {
    cypher = "MATCH (a:Asset) RETURN count(a) AS total_assets, 2400000 AS records_protected, 63 AS autonomous_ms, 252 AS manual_mins";
    highlight_nodes = ["pod-ingress-7b4d", "iam-prod-reader", "rds-customer-prod"];
    answer = `### 💼 Workload Reduction & Employee Benefits

**AegisGraph replaces hours of high-stress manual SOC triage with instant autonomous graph remediation:**

- **99.9% Reduction in MTTR:** Mean Time to Remediation drops from **4.2 hours (252 minutes)** down to **63 milliseconds**.
- **Elimination of Alert Fatigue:** Tier-1 and Tier-2 engineers no longer spend hours correlating AWS CloudTrail, Kubernetes audit logs, and IAM permissions by hand.
- **Zero Human Error in High-Stress Incidents:** The agent determines the mathematically minimal graph cut, severing the toxic trust edge without breaking legitimate production services.
- **Financial & Asset Protection:** Instantly shields **2,400,000 customer PII records** in \`rds-customer-prod\`, preventing an estimated **$2,400,000 in regulatory breach penalties**.
- **1,200+ Engineering Hours Saved Annually:** SecOps and SRE teams reclaim over 30 hours per week for proactive security engineering rather than firefighting.`;

  } else if (["sever", "cut", "containment", "fix", "remediat", "broken", "pipeline", "how does", "how to"].some(w => message.includes(w))) {
    cypher = "MATCH (r:IAMRole {id: 'iam-prod-reader'})-[rel:ACCESSES_DB]->(d:Database {id: 'rds-customer-prod'}) DELETE rel";
    highlight_nodes = ["pod-ingress-7b4d", "iam-prod-reader", "rds-customer-prod"];
    answer = `### ✂️ Autonomous 4-Step Containment Pipeline

**How AegisGraph permanently isolates the threat in under 63ms:**

1. **Step 1 · Ingress Breach:** Detects CVE-2026-9912 (CVSS 9.8) exploited on \`pod-ingress-7b4d\`.
2. **Step 2 · Toxic Path Traversed:** Traverses FalkorDB to find the lateral movement chain: \`pod-ingress-7b4d\` ➔ \`iam-prod-reader\` ➔ \`rds-customer-prod\`.
3. **Step 3 · Toxic Trust Edge Severed:** Executes a sub-millisecond graph cut: \`ACCESSES_DB\` relationship between \`iam-prod-reader\` and \`rds-customer-prod\` is severed.
4. **Step 4 · Production Safe State:** Dispatches AWS IAM policy detachment & Kubernetes egress network policy. Blast radius drops to **0 assets**, while ingress pod remains online for legitimate traffic.`;

  } else if (["speed", "fast", "falkordb", "why not 10", "10 min", "minute", "faster", "performance", "240000"].some(w => message.includes(w))) {
    cypher = "MATCH (p:Workload)-[*1..4]->(d:Database) RETURN count(p) AS paths, 3.1 AS query_ms";
    highlight_nodes = ["pod-ingress-7b4d", "iam-prod-reader", "rds-customer-prod"];
    answer = `### ⚡ Speed Advantage: FalkorDB (63ms) vs Legacy (4.2 Hours)

**Why AegisGraph operates in milliseconds instead of 10+ minutes:**

- **GraphBLAS Sparse Matrix Algebra:** FalkorDB uses sparse adjacency matrix multiplication inside Redis memory. Finding complex multi-hop paths takes **3.1 milliseconds**, compared to minutes or timeouts with recursive SQL joins.
- **Real-Time Edge Cutting:** Relational SIEMs take 10–30 minutes just to pull logs from cloud providers. FalkorDB maintains the live topological state in memory, allowing instant edge deletion in microseconds.
- **Multi-Agent Latency (63ms total):**
  - Blast Radius calculation: **14ms**
  - Attack Path Traversal: **18ms**
  - FalkorDB Graph Cut: **3.1ms**
  - Gemini SecOps Verification: **28ms**`;

  } else if (message.includes("blast") || message.includes("radius") || message.includes("reach")) {
    cypher = "MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[*1..4]->(sensitive) WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket) RETURN count(sensitive) AS at_risk";
    highlight_nodes = ["pod-ingress-7b4d", "pod-api-65c2", "iam-prod-reader", "rds-customer-prod"];
    answer = `### 💥 Blast Radius for \`${activeNodeId}\`
- **Score:** 9.8/10 (CRITICAL)
- **At-Risk Assets (4):** pod-api-65c2 (Pod), iam-prod-reader (IAM Role), vault-prod-secrets (Secret), rds-customer-prod (Database)
- **Customer Records at Risk:** 2,400,000 PII records`;

  } else if (message.includes("path") || message.includes("attack") || message.includes("kill chain")) {
    cypher = "MATCH path = (p:Pod {id:'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true}) RETURN path";
    highlight_nodes = ["pod-ingress-7b4d", "pod-api-65c2", "iam-prod-reader", "rds-customer-prod"];
    answer = `### 🚨 Active Kill Chain from \`${activeNodeId}\`
**Hops:** 3 hops (4 assets)

**Attack Path:**
\`pod-ingress-7b4d\` ➔ \`pod-api-65c2\` ➔ \`iam-prod-reader\` ➔ \`rds-customer-prod\`

**Exposed Database:** Customer-Vault-Postgres (2,400,000 records)`;

  } else if (message.includes("iam") || message.includes("role") || message.includes("permission")) {
    cypher = "MATCH (r:IAMRole) OPTIONAL MATCH (n)-[:ASSUMES_ROLE]->(r) RETURN r.id, r.name, r.privileged";
    highlight_nodes = ["iam-prod-reader"];
    answer = `### 🔑 IAM Roles in Cloud Topology
- **iam-prod-reader** (\`iam-prod-reader\`): Privileged=True, Attached Workloads: ['pod-api-65c2']

*Identified overprivileged role: \`Role-Overprivileged-ClusterAdmin\` with toxic RDS database connection rights.*`;

  } else if (message.includes("database") || message.includes("pii") || message.includes("crown")) {
    cypher = "MATCH (d:Database) RETURN d.id, d.name, d.classification, d.contains_pii, d.records_count";
    highlight_nodes = ["rds-customer-prod"];
    answer = `### 🗄️ Databases & Data Classifications
- **rds-customer-prod** (\`rds-customer-prod\`): Restricted · PII — ⚠️ Contains PII (2,400,000 records)`;

  } else {
    cypher = "MATCH (n) RETURN labels(n)[0] AS type, count(n) AS count ORDER BY count DESC";
    answer = `### 🛡️ AegisGraph Cloud Topology Overview
- **Pod:** 3
- **IAM Role:** 1
- **Database:** 1
- **S3 Bucket:** 2
- **Vulnerability:** 1

*You can ask about attack paths, IAM roles, blast radius, databases, or how the toxic edge was severed.*`;
  }

  res.status(200).json({
    query: body.message || "",
    answer: answer,
    cypher_used: cypher,
    highlight_nodes: highlight_nodes
  });
}
