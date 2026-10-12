# 🛡️ AegisGraph: Autonomous Incident Commander & Blast-Radius Agent

> **Hackathon Submission:** [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb)  
> **Track 01:** Agents That Act on Connected Data  
> **Team:** SUVI — Leader: Baji Baddela (@bajibaddela)  
> **Core Engine:** [FalkorDB](https://www.falkordb.com/) Low-Latency Graph Database  

---

## ⚡ The Problem: Why SecOps Fails Without Graphs

When an alert triggers (e.g., an internet-facing Kubernetes pod exploited with a Critical CVE), traditional security tools generate isolated alerts without topological context:
* Is the compromised pod connected to sensitive crown-jewel customer data?
* Can the attacker traverse through overprivileged IAM roles, unencrypted backup buckets, and leaked vault secrets?
* What is the true blast radius, and how can an autonomous agent neutralize the breach in milliseconds without human delay?

**Vector databases and isolated relational tables cannot solve this.** Multi-hop blast-radius analysis requires **instant graph traversals**.

---

## 🎯 The Shift: FalkorDB as the Agent's Context Layer

**AegisGraph** models entire cloud environments into **FalkorDB**:
* **Nodes:** `Kubernetes Pods`, `Microservices`, `IAM Roles`, `S3 Buckets`, `Secrets`, `Crown Jewel Databases`, `Vulnerabilities`.
* **Relationships:** `[:ROUTES_TO]`, `[:RUNS_ON]`, `[:HAS_VULNERABILITY]`, `[:ASSUMES_ROLE]`, `[:CAN_READ]`, `[:EXPOSES_SECRET]`, `[:UNLOCKS_DATABASE]`.

When a breach is detected, the **AegisGraph Autonomous Agent**:
1. **Multi-Hop Traversal:** Runs deep Cypher path queries to discover the exact multi-hop kill-chain (`Pod -> Toxic IAM Role -> S3 Backup -> Master Secret -> Customer PII Database`).
2. **Blast Radius Analysis:** Computes reachable sensitive assets and severity scores via FalkorDB traversals.
3. **Autonomous Containment (Graph Action):** Autonomously executes dynamic graph mutations, severing toxic IAM role attachment edges and quarantining the workload.
4. **Post-Remediation Verification:** Proves that attack paths to crown-jewel assets drop to **0**.
5. **Real-time Explainable UI:** Visualizes the live physics-based cloud topology, highlighting the breach path and animating the containment cut.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AegisGraph Cyber HUD                     │
│         (Interactive Physics Graph Canvas + Live Feed)       │
│  - Real-Time Attack Path Highlighting                       │
│  - Interactive Node Inspector (Click any asset)             │
│  - 1-Click "Autonomous Investigate & Remediate" Demo        │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / JSON
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 AegisGraph Agent Core                       │
│                   (Python FastAPI)                          │
│  - Multi-Hop Graph Reasoner & Incident Commander            │
│  - FalkorDB Tool Call Registry                              │
│  - Autonomous Containment & Severing Engine                 │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
┌──────────────────────────────┐ ┌───────────────────────────┐
│       FalkorDB Engine        │ │    Cloud Action Engine    │
│   (Low-Latency Graph DB)     │ │   (Simulated Containment) │
│ - Graph Multi-Hop Traversal  │ │ - Revoke IAM Attachment   │
│ - Shortest Path Algorithms   │ │ - Quarantine Container    │
│ - Sub-Millisecond Cypher     │ │ - Real-Time State Update  │
└──────────────────────────────┘ └───────────────────────────┘
```

---

## 🔍 Key Cypher Queries Powering Agent Decisions

### 1. Multi-Hop Kill-Chain Discovery
```cypher
MATCH path = (p:Pod {id: $compromised_pod})-[*1..5]->(target:Database {contains_pii: true})
RETURN [n in nodes(path) | n.name] AS attack_chain, 
       length(path) AS total_hops,
       target.records_count AS records_exposed
```

### 2. Reachable Sensitive Assets (Blast Radius)
```cypher
MATCH (p:Pod {id: $compromised_pod})-[*1..4]->(sensitive)
WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket)
RETURN DISTINCT labels(sensitive)[0] AS type, sensitive.name AS name, sensitive.id AS id
```

### 3. Shortest Attack Path
```cypher
MATCH (start:Pod {id: $compromised_pod}), (target:Database {id: 'db-customer-pii'})
RETURN shortestPath((start)-[*..6]->(target)) AS path
```

### 4. Autonomous Edge Severing (Remediation Action)
```cypher
MATCH (p:Pod {id: $compromised_pod})-[r:ASSUMES_ROLE]->(role:IAMRole {id: 'role-toxic-admin'})
DELETE r
RETURN count(r) AS revoked_links
```

---

## 🚀 Quickstart: Run in 60 Seconds

### Prerequisites
* Docker & Docker Compose
* Python 3.10+

### 1. Clone & Start FalkorDB
```bash
git clone <your-repo-url>
cd "new hackthon of agents"

# Start FalkorDB Container
docker compose up -d
```

### 2. Set Up Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 3. Seed Graph Topology
```bash
python backend/seed_graph.py
```

### 4. Launch AegisGraph
```bash
python backend/main.py
```

Open your browser to: **`http://localhost:8000`**

---

## 🎮 How to Demo AegisGraph (Judge Walkthrough)

1. **Observe the Initial Threat:**
   * Notice the red badge: **`BREACH DETECTED`**.
   * Blast Radius: **`9.8 (CRITICAL)`**.
   * Pod `pod-ingress-7b4d` is exploited via **CVE-2026-9912** (SpringCloud RCE).
2. **Inspect Any Node:**
   * Click on `Customer-Vault-Postgres` to see 2.4M PII records at risk.
   * Click on `Role-Overprivileged-ClusterAdmin` to see toxic IAM flags.
3. **Trigger the Agent:**
   * Click the glowing button: **`AUTONOMOUS INVESTIGATE & REMEDIATE`**.
   * Watch the Agent Reason step-by-step in the right-hand panel.
   * Watch the 4-hop path illuminate in real time.
4. **Observe Autonomous Remediation:**
   * The Agent deletes the toxic `[ASSUMES_ROLE]` edge in FalkorDB.
   * The pod status transitions to `QUARANTINED`.
   * Threat level drops to **`0.0 (SECURE)`**.
5. **Reset Topology Anytime:**
   * Click **`RESET TOPOLOGY`** to rerun the demonstration!

---

## 🏆 Hackathon Track Alignment (Track 01)

| Requirement | How AegisGraph Satisfies It |
| :--- | :--- |
| **Multi-Hop Reasoning** | Discovers hidden multi-hop paths from internet workloads to databases across 4 hops. |
| **Graph Queries & Algorithms as Agent Tools** | Agent invokes Cypher multi-hop pattern matching, blast radius calculations, and shortest-path checks. |
| **Actions Based on What the Graph Shows** | Agent dynamically severs dangerous IAM edges and quarantines compromised workloads based on graph discovery. |
| **Explainable Results** | Real-time visual timeline showing each Cypher query, reasoning step, and the exact path saved from exfiltration. |

---

## 📝 License
MIT License. Built for **Graph Hacks: Context for AI Agents** Hackathon.
