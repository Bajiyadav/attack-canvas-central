# 🛡️ AegisGraph: Autonomous Incident Commander & Blast-Radius Agent

> **Live Interactive Demo:** [https://aegisgraph-lemon.vercel.app](https://aegisgraph-lemon.vercel.app)  
> **Hackathon Submission:** [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb) (WeMakeDevs & FalkorDB)  
> **Track 01:** Agents That Act on Connected Data  
> **Side Prize Submission:** Best Blog Post (AirPods 5) — See [`BLOG_POST.md`](./BLOG_POST.md)  
> **Team:** SUVI — Leader: Baji Baddela ([@bajibaddela](https://github.com/bajibaddela))  
> **Core Graph Engine:** [FalkorDB](https://www.falkordb.com/) Low-Latency Graph Database  
> **Reasoning LLM:** Google Gemini (`google-genai`)  

---

## ⚡ The Problem: Why SecOps Fails Without Graphs

When a security alert fires (e.g., an internet-facing Kubernetes pod exploited with a Critical CVE), traditional security tools generate isolated, fragmented alerts without topological context:
* **The Vector RAG Fallacy:** Vector embeddings can summarize a CVE description or deployment YAML, but they cannot answer: *"Can this exploited container reach our customer PII database?"*
* **The Relational SQL Bottleneck:** Multi-hop recursive joins across pods, IAM policies, cloud storage, vault secrets, and RDS clusters are computationally expensive and fail to compute blast radiuses in real time.
* **The Human Delay:** The average Mean Time to Remediate (MTTR) a cloud breach is 45 minutes to 4 hours. By the time an on-call engineer evaluates IAM attachments, customer data has already been exfiltrated.

**Multi-hop blast-radius analysis requires instant graph traversals.**

---

## 🎯 The Shift: FalkorDB as the Agent's Context Layer

**AegisGraph** transforms raw cloud infrastructure into a high-performance **FalkorDB** graph context layer:
* **Nodes:** `Kubernetes Pods`, `Microservices`, `IAM Roles`, `S3 Buckets`, `Secrets`, `Crown Jewel Databases`, `Vulnerabilities`.
* **Relationships:** `[:ROUTES_TO]`, `[:RUNS_ON]`, `[:HAS_VULNERABILITY]`, `[:ASSUMES_ROLE]`, `[:CAN_READ]`, `[:EXPOSES_SECRET]`, `[:UNLOCKS_DATABASE]`.

When an incident triggers, the **AegisGraph Autonomous Agent**:
1. **Multi-Hop Traversal (< 2ms):** Executes deep Cypher path queries across the FalkorDB topology to discover the exact 4-hop kill-chain:
   $$\text{pod-ingress-7b4d} \xrightarrow{\text{:ASSUMES\_ROLE}} \text{Role-Overprivileged-ClusterAdmin} \xrightarrow{\text{:CAN\_READ}} \text{acme-internal-db-snapshots} \xrightarrow{\text{:EXPOSES\_SECRET}} \text{RDS\_POSTGRES\_CREDENTIAL} \xrightarrow{\text{:UNLOCKS\_DATABASE}} \text{Customer-Vault-Postgres}$$
2. **Blast Radius Computation:** Identifies all reachable databases, credentials, and buckets, computing exposed record counts (2.4M PII records) and an aggregate threat score of **9.8 (CRITICAL)**.
3. **Autonomous Containment (Graph Action):** Surgically mutates the FalkorDB graph, deleting the toxic `[ASSUMES_ROLE]` edge and quarantining the container without human intervention.
4. **Post-Remediation Zero-Trust Verification:** Proves that attack paths to crown-jewel assets drop to **0**.
5. **Interactive Cyber HUD & Lovable UI:** Visualizes the live physics-based cloud topology, pulsing laser attack vectors, step-by-step reasoning logs, and an interactive Gemini SecOps Copilot.

---

## 🏗️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│             AegisGraph Cyber HUD / Lovable React UI                     │
│               (http://localhost:8000 or Lovable Preview)               │
│  - Physics Network Canvas (Pulsing Attack Chain Highlighting)          │
│  - Dual Panel: Agent Thought Trace + Gemini SecOps AI Copilot          │
│  - Real-Time Node Inspector (Click any asset to inspect properties)    │
│  - 1-Click "Autonomous Investigate & Remediate" Command                │
│  - Dynamic Breach Simulator (Target any pod/service)                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST JSON (CORS Enabled)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      AegisGraph Agent Core                             │
│                         (Python FastAPI)                               │
│  - Multi-Hop Graph Reasoner & Incident Commander                       │
│  - FalkorDB Tool Call Registry (Cypher Traversal & Severing Engine)    │
│  - Gemini SecOps NL-to-Graph Copilot                                   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
     ┌──────────────────────────────┐ ┌───────────────────────────┐
     │       FalkorDB Engine        │ │    Cloud Action Engine    │
     │   (Low-Latency Graph DB)     │ │   (Simulated Containment) │
     │ - Sub-2ms Cypher Queries     │ │ - Revoke Toxic IAM Links  │
     │ - Shortest Path Traversal    │ │ - Quarantine Workloads    │
     │ - Topology Graph Mutations   │ │ - Zero-Trust State Update │
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

### 2. Reachable Sensitive Assets (Blast Radius Calculation)
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

## ⚡ Real-World FalkorDB Performance Benchmarks

We measured latency and throughput across 100 iterations on a single FalkorDB instance using [`backend/benchmark.py`](./backend/benchmark.py):

| Query / Operation Pattern | Mean Latency | p50 Latency | p95 Latency | p99 Latency | Sustained QPS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1-Hop Direct Neighbor Lookup** | **0.45 ms** | 0.38 ms | 0.83 ms | 1.29 ms | **2,217 QPS** |
| **2-Hop IAM & Permission Traversal** | **0.45 ms** | 0.44 ms | 0.57 ms | 0.89 ms | **2,231 QPS** |
| **4-Hop Full Attack Kill-Chain Discovery** | **0.60 ms** | 0.46 ms | 1.31 ms | 1.82 ms | **1,674 QPS** |
| **Shortest Path Algorithm (Ingress ➔ DB)** | **0.66 ms** | 0.53 ms | 1.41 ms | 4.40 ms | **1,517 QPS** |
| **Blast Radius Reachable Assets Aggregation** | **0.51 ms** | 0.50 ms | 0.61 ms | 0.97 ms | **1,970 QPS** |
| **Autonomous IAM Edge Severing (Graph Mutation)** | **0.84 ms** | 0.84 ms | 1.83 ms | 1.83 ms | **1,185 QPS** |

> **Key Takeaway:** FalkorDB executes multi-hop traversals and dynamic graph mutations in **sub-millisecond (< 1 ms)** time, allowing the autonomous agent loop to finish in under **70 milliseconds total**.

---

## 📡 Complete REST API Reference

The backend exposes clean, fully-typed REST endpoints with CORS enabled for any frontend (Lovable, React, Vue, or the built-in Cyber HUD):

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Healthcheck returning FalkorDB engine and graph status |
| `GET` | `/api/graph` | Full topology: all nodes and directional edges |
| `GET` | `/api/nodes` | Lightweight asset catalog for target selection |
| `GET` | `/api/asset/{id}` | Deep inspection of a single node and its connected edges |
| `POST` | `/api/investigate` | Triggers the autonomous agent investigation & edge-severing |
| `POST` | `/api/reset-graph` | Re-seeds FalkorDB back to initial compromised breach state |
| `POST` | `/api/simulate-breach` | Simulates a breach on any selected asset |
| `POST` | `/api/chat` | Natural-language SecOps questions grounded in FalkorDB |

---

## 🚀 Quickstart: Run in 60 Seconds

### Prerequisites
* Docker & Docker Compose
* Python 3.10+

### 1. Start FalkorDB
```bash
docker compose up -d
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### 3. Seed Topology & Start Server
```bash
python backend/seed_graph.py
python backend/main.py
```

Open your browser to: **`http://localhost:8000`**

---

## 🎨 Connecting with Lovable Frontend

If you built or customized a frontend using **[Lovable.dev](https://lovable.dev)**:

### Option A: Local Lovable Dev
1. In your Lovable project `.env`, configure:
   ```env
   VITE_API_URL=http://localhost:8000
   ```
2. Run `npm run dev` in your Lovable folder. The Lovable UI connects directly to your local FalkorDB backend with zero CORS issues.

### Option B: Direct Bundle Export into AegisGraph
1. In your Lovable repository, build the production bundle:
   ```bash
   npm run build
   ```
2. Copy the contents of the generated `dist/` folder into `frontend/`:
   ```bash
   cp -r dist/* "new hackthon of agents/frontend/"
   ```
3. Restart `python backend/main.py` — FastAPI will serve the Lovable React UI directly at `http://localhost:8000`!

---

## 🎮 How to Demo AegisGraph (Judge Walkthrough)

1. **Observe the Initial Threat:**
   * The top indicator flashes red: **`BREACH DETECTED: CVE-2026-9912`**.
   * Blast Radius: **`9.8 (CRITICAL)`**.
   * Pod `pod-ingress-7b4d` is exploited via a critical Remote Code Execution vulnerability.
2. **Inspect Any Node:**
   * Click `Customer-Vault-Postgres` to see 2.4M PII records at risk in the inspector.
   * Click `Role-Overprivileged-ClusterAdmin` to see toxic IAM flags.
3. **Trigger Autonomous Containment:**
   * Click **`AUTONOMOUS INVESTIGATE & REMEDIATE`**.
   * Watch the Agent Thought Trace execute each Cypher query step-by-step.
   * The 4-hop kill chain illuminates in real time with laser traces.
   * The agent deletes the toxic `[ASSUMES_ROLE]` edge in FalkorDB.
   * The pod transitions to `QUARANTINED`, and the threat meter drops to **`0.0 (SECURE)`**.
4. **Interact with the SecOps AI Copilot:**
   * Switch to the **SecOps AI Chat** tab.
   * Ask: *"Which IAM roles have cluster-admin privileges?"* or *"What databases are reachable?"*
   * Gemini translates your query and grounds the answer directly in the FalkorDB graph!
5. **Reset Topology Anytime:**
   * Click **`RESET GRAPH`** to re-seed and rerun the demo.

---

## 🏆 Hackathon Track Alignment (Track 01)

| Requirement | How AegisGraph Satisfies It |
| :--- | :--- |
| **Multi-Hop Reasoning** | Discovers hidden multi-hop paths from internet workloads to databases across 4 hops in < 2ms. |
| **Graph Queries & Algorithms as Agent Tools** | Agent invokes Cypher multi-hop pattern matching, blast radius calculations, and shortest-path checks. |
| **Actions Based on What the Graph Shows** | Agent dynamically severs dangerous IAM edges and quarantines compromised workloads based on graph discovery. |
| **Explainable Results** | Real-time visual timeline showing each Cypher query, reasoning step, and the exact path saved from exfiltration. |

---

## 📝 License & Credits
* Built for **[Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb)**
* Team SUVI — Lead: Baji Baddela
* License: MIT
