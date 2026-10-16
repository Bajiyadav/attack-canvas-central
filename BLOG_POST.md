# Why We Replaced Vector RAG with FalkorDB to Build an Autonomous Cloud Incident Commander

*By Baji Baddela ([@bajibaddela](https://github.com/bajibaddela)) — Team SUVI*  
*Submitted to [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb) (WeMakeDevs & FalkorDB)*  
*Track 01: Agents That Act on Connected Data*

---

## ⚡ The Vector RAG Trap in Cloud Security

When developers think about giving AI agents context, their default reaction is almost always:  
> *"Let's chunk our documents and embed them into a vector database!"*

In cybersecurity and cloud infrastructure, **Vector RAG fails completely**.

Imagine a high-priority alert triggers on your Kubernetes cluster:
```
[CRITICAL ALERT] Pod 'pod-ingress-7b4d' compromised via CVE-2026-9912 (CVSS 9.8 RCE)
```

A vector database can retrieve the CVE description or the pod's deployment YAML. But it cannot answer the single, life-or-death question every SecOps team needs to know within seconds:
> **"Can the attacker pivot from this pod to our customer PII database?"**

That answer does not exist in any document, paragraph, or vector embedding. It exists in the **connected relationships** between disparate cloud assets:
1. The Pod assumes an overprivileged IAM Role.
2. The IAM Role grants read access to an unencrypted internal S3 backup bucket.
3. The S3 bucket contains a leaked database snapshot file (`env.backup.json`).
4. That file exposes a master superuser secret (`RDS_POSTGRES_CROWN_CREDENTIAL`).
5. The secret unlocks your crown jewel: `Customer-Vault-Postgres`, containing **2.4 million customer PII records**.

This is a **4-hop kill-chain**. To discover and neutralize it in real time before data exfiltration occurs, an AI agent needs a graph context layer.

Enter **[FalkorDB](https://www.falkordb.com/)**.

---

## 🛡️ What We Built: AegisGraph

We built **AegisGraph**: an Autonomous Cloud Incident Commander powered by FalkorDB as its low-latency context layer, paired with Google Gemini for explainable natural-language SecOps intelligence.

```
┌────────────────────────────────────────────────────────────────────────┐
│             AegisGraph Cyber HUD / Lovable React UI                     │
│               (Interactive Physics Canvas + AI Terminal)               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ REST JSON (CORS Enabled)
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

Rather than treating the database as static storage, AegisGraph equips the AI Agent with **Cypher queries as active sensory and operational tools**.

---

## 🔬 How It Works: Step-by-Step

### 1. Modeling Cloud Infrastructure as a Graph
We modeled a complete multi-tier enterprise cloud topology inside FalkorDB:
* **Nodes (20 assets):** Public Gateways, Microservices, Kubernetes Pods, Vulnerabilities (CVEs), IAM Roles, S3 Buckets, Database Secrets, and Crown Jewel RDS clusters.
* **Relationships (17 edges):** `[:ROUTES_TO]`, `[:RUNS_ON]`, `[:HAS_VULNERABILITY]`, `[:ASSUMES_ROLE]`, `[:CAN_READ]`, `[:EXPOSES_SECRET]`, `[:UNLOCKS_DATABASE]`.

### 2. Multi-Hop Kill-Chain Discovery (< 2ms)
When `pod-ingress-7b4d` is compromised, the agent executes a multi-hop path traversal in FalkorDB:

```cypher
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN [n in nodes(path) | n.name] AS attack_chain, 
       length(path) AS total_hops,
       target.records_count AS records_exposed
```

In less than **2 milliseconds**, FalkorDB uncovers the exact path to `Customer-Vault-Postgres` and flags **2,400,000 sensitive records** in the direct line of fire.

### 3. Blast Radius Calculation
Next, the agent computes the blast radius across all reachable sensitive assets within 4 hops:

```cypher
MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[*1..4]->(sensitive)
WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket)
RETURN DISTINCT labels(sensitive)[0] AS type, sensitive.name AS name, sensitive.id AS id
```

The agent calculates a Blast Radius Score of **9.8 / 10 (CRITICAL)**.

### 4. Autonomous Containment (Graph Action)
Instead of waiting 45 minutes for a human on-call engineer, the agent takes immediate, surgical action by severing the toxic `[ASSUMES_ROLE]` edge in FalkorDB:

```cypher
MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[r:ASSUMES_ROLE]->(role:IAMRole {id: 'role-toxic-admin'})
DELETE r
RETURN count(r) AS revoked_links
```

The agent also updates the pod's status to `QUARANTINED`.

### 5. Post-Remediation Verification
The agent re-traverses the graph to verify zero-trust containment:

```cypher
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN count(path) AS remaining_paths
```

*Result:* `0 paths`. The blast radius score plummets from **9.8 (CRITICAL)** to **0.0 (SECURE)** in just **63.8 milliseconds** total execution time!

---

## 💡 What We Learned Along the Way

Building AegisGraph during **Graph Hacks** taught our team several key architectural lessons:

### Lesson 1: Graphs Turn O(N^k) Nightmares into O(1) Traversals
Attempting multi-hop analysis in relational databases requires recursive SQL CTEs that quickly choke under production loads. In FalkorDB, path queries run in sub-2ms because relationships are first-class citizens stored natively in memory.

### Lesson 2: Agent Tools Should Be Graph Queries, Not Raw Dumps
Giving an LLM an entire JSON dump of cloud infrastructure blows up the context window and invites hallucinations. By exposing atomic Cypher queries as agent tools (`find_attack_paths`, `calculate_blast_radius`, `sever_edge`), the LLM receives precise, high-signal context with zero bloat.

### Lesson 3: Containment Is an Act on Connected Data
Traditional SecOps "containment" usually means shutting down the VM or killing the pod—causing costly customer downtime. Graph-driven containment allows **surgical severing**: by removing the single toxic IAM edge connecting the pod to the admin role, the ingress service stays online serving benign customer traffic, while the attacker's path to the database is completely blocked.

### Lesson 4: Speed Is Security
Human incident response operates on the order of tens of minutes. FalkorDB's extreme query throughput enabled our agent to complete detection, multi-hop path analysis, blast radius calculation, autonomous severing, and post-containment verification in **63 milliseconds**.

We measured query latency across 100 iterations using `backend/benchmark.py`:

| Operation | Mean Latency | p95 Latency | Throughput |
| :--- | :--- | :--- | :--- |
| **1-Hop Neighbor Lookup** | **0.45 ms** | 0.83 ms | 2,217 QPS |
| **2-Hop IAM Traversal** | **0.45 ms** | 0.57 ms | 2,231 QPS |
| **4-Hop Full Kill-Chain Traversal** | **0.60 ms** | 1.31 ms | 1,674 QPS |
| **Shortest Path Algorithm** | **0.66 ms** | 1.41 ms | 1,517 QPS |
| **Autonomous IAM Edge Severing** | **0.84 ms** | 1.83 ms | 1,185 QPS |

Sub-millisecond traversals mean the agent can run multiple graph queries per second within its reasoning loop without perceptible delay.

---

## 🎮 The User Experience: Cyber HUD & Lovable UI

To make the system transparent and explainable for security operators and hackathon judges, we built:
* **Interactive Physics Canvas:** Real-time topology with glowing red laser animations along the attack chain.
* **Agent Thought Trace:** Live step-by-step logs showing the exact Cypher query, execution time, and operational rationale for each decision.
* **SecOps AI Copilot:** A conversational terminal where operators can ask natural-language questions (*"Which IAM roles have cluster-admin privileges?"*) and receive graph-grounded answers.
* **Universal Frontend Compatibility:** Built to seamlessly connect with modern React frontends generated in **Lovable.dev** via typed REST APIs.

---

## 🏁 Conclusion

AI agents are only as smart as the context they can access. When problems involve interconnected relationships—whether in cloud security, fraud rings, identity permissions, or supply chains—**graphs are the missing context layer**.

FalkorDB gave our agent the speed and expressive power to act on connected data in real time, turning what used to be a 45-minute security nightmare into a 63-millisecond autonomous response.

---

### 🔗 Project Links
* **GitHub Repository:** [github.com/bajibaddela/aegis-graph](https://github.com/bajibaddela/aegis-graph)
* **Hackathon:** [Graph Hacks by WeMakeDevs & FalkorDB](https://www.wemakedevs.org/hackathons/falkordb)
* **Graph Engine:** [FalkorDB](https://www.falkordb.com/)
