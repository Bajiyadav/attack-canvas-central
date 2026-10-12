# How We Built an Autonomous Cloud SecOps Agent Using FalkorDB to Trace and Sever Multi-Hop Breaches

*By Baji Baddela (@bajibaddela) — Team SUVI*  
*Submitted to [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb)*

---

### Introduction: The Vector RAG Trap in Cloud Security

When developers think about giving AI agents context, their default reaction is almost always: *"Let's embed our documents into a vector database!"*

In cybersecurity and cloud infrastructure, **Vector RAG fails completely**.

Imagine an alert fires:
> `Alert: Pod 'pod-ingress-7b4d' compromised via CVE-2026-9912 (CVSS 9.8 RCE)`

A vector database can retrieve the CVE description or the pod's deployment YAML. But it cannot answer the single question every SecOps engineer desperately needs to know:
> **"Can the attacker jump from this pod to our customer PII database?"**

That answer does not live in any single document or paragraph. It exists in the **relationships** between systems:
* The Pod assumes an IAM Role.
* The IAM Role has excessive S3 permissions.
* The S3 bucket contains a database snapshot with hardcoded credentials.
* The credentials unlock your Crown Jewel RDS Database.

This is a **4-hop kill-chain**. To reason across it in real-time, your AI agent needs a graph. Enter **[FalkorDB](https://www.falkordb.com/)**.

---

### The Architecture: AegisGraph

We built **AegisGraph**: an Autonomous Cloud Incident Commander powered by FalkorDB as its context layer.

```
┌─────────────────────────────────────────────────────────────┐
│                    AegisGraph Cyber HUD                     │
│         (Interactive Physics Graph Canvas + Live Feed)       │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 AegisGraph Agent Core                       │
│                   (Python FastAPI)                          │
│  - Multi-Hop Graph Reasoner & Incident Commander            │
│  - FalkorDB Tool Call Registry                              │
│  - Autonomous Containment Engine                            │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
┌──────────────────────────────┐ ┌───────────────────────────┐
│       FalkorDB Engine        │ │    Cloud Action Engine    │
│   (Low-Latency Graph DB)     │ │   (Simulated Containment) │
└──────────────────────────────┘ └───────────────────────────┘
```

FalkorDB stores the entire cloud topology:
* **Nodes:** Pods, Microservices, Gateways, IAM Roles, S3 Buckets, Secrets, Databases.
* **Edges:** Traffic routes, vulnerability bindings, IAM attachments, read permissions, credential unlocks.

---

### FalkorDB as Agent Tools

Rather than treating the database as static storage, our AI Agent interacts with FalkorDB using Cypher queries as its primary reasoning tools:

#### 1. Multi-Hop Attack Path Discovery
When the alert triggers, the agent runs a multi-hop traversal in FalkorDB:
```cypher
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN [n in nodes(path) | n.name] AS attack_chain, 
       length(path) AS total_hops,
       target.records_count AS records_exposed
```
*Result:* In less than **5 milliseconds**, FalkorDB returns the exact 4-hop chain reaching `Customer-Vault-Postgres`, exposing **2,400,000 sensitive records**!

#### 2. Blast Radius Calculation
The agent queries all sensitive cloud resources within 4 hops:
```cypher
MATCH (compromised:Pod {id: 'pod-ingress-7b4d'})-[*1..4]->(sensitive)
WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket)
RETURN DISTINCT labels(sensitive)[0] AS type, sensitive.name AS name, sensitive.id AS id
```
The agent computes a Blast Radius score of **9.8 / 10 (CRITICAL)**.

#### 3. Autonomous Remediation (Edge Severing)
Instead of waiting 45 minutes for an on-call engineer to wake up, the agent takes immediate, surgical action by severing the dangerous `[ASSUMES_ROLE]` relationship directly in the graph:
```cypher
MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[r:ASSUMES_ROLE]->(role:IAMRole {id: 'role-toxic-admin'})
DELETE r
RETURN count(r) AS revoked_links
```

The agent then verifies the containment:
```cypher
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN count(path) AS remaining_paths
```
*Result:* `0 paths`. The blast radius drops immediately to **0.0 (SECURE)**.

---

### The Interactive Visual Interface

We designed an ultra-responsive Cyber Incident Commander HUD featuring:
1. **Interactive Physics Graph Canvas:** Nodes represent cloud assets; when an attack is investigated, the 4-hop kill chain pulses with glowing red telemetry.
2. **Real-Time Agent Thought Trace:** Judges and operators can watch each Cypher query execute, view the agent's multi-hop reasoning, and inspect the exact remediation steps.
3. **One-Click Live Simulation:** A clean demo flow that allows anyone to trigger the breach, watch the agent contain it, and reset the environment in under 30 seconds.

---

### Key Takeaway

Agents are only as good as the context they work with. When your agent's problem involves relationships—like infrastructure, fraud, identity permissions, or supply chains—**giving your agent a graph is a superpower**.

FalkorDB's sub-millisecond query latency allows the agent to execute multiple graph traversals on every turn of its reasoning loop without slowing down.

---

### Links & Resources
* **GitHub Repository:** [AegisGraph on GitHub](https://github.com/bajibaddela/aegis-graph)
* **Hackathon:** [Graph Hacks WeMakeDevs](https://www.wemakedevs.org/hackathons/falkordb)
* **FalkorDB:** [falkordb.com](https://www.falkordb.com/)
