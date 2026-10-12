# 🏆 AegisGraph: Autonomous Incident Commander & Blast-Radius Agent
**Hackathon:** Graph Hacks: Context for AI Agents (WeMakeDevs & FalkorDB)  
**Track:** Track 01 — Agents That Act on Connected Data  
**Target Prize:** iPhone 18 Pro (1st Place in Track 1)  
**Team:** SUVI (Lead: Baji Baddela)

---

## 1. The Winning Value Proposition
Most security tools dump 500 alerts on human engineers without context.  
When an internet-facing workload is compromised, traditional tools can't tell if the attacker can reach crown-jewel customer databases.

**AegisGraph** puts cloud infrastructure, IAM permissions, network routes, and vulnerabilities into **FalkorDB**.  
When an alert fires, our **Autonomous SecOps Agent**:
1. **Performs Multi-Hop Graph Traversal:** Discovers hidden attack paths from the compromised node to sensitive databases (`Pod -> IAM Role -> Secret -> S3 Bucket -> RDS DB`).
2. **Executes Graph Algorithms as Tools:** Calls FalkorDB's `shortestPath` and Centrality to compute blast radius and risk scores.
3. **Takes Remediation Actions:** Dynamically severs malicious edges (e.g., revokes IAM permission, updates security group, isolates container).
4. **Delivers Visual Explainability:** Interactive glowing graph UI showing the exact path the agent investigated and neutralized.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AegisGraph Cyber UI                      │
│     (React / Vite + Cytoscape / Vis Network Canvas)          │
│  - Live Glowing Attack Graph Visualizer                     │
│  - Real-Time Agent Thought Stream                           │
│  - 1-Click "Simulate Breach & Neutralize" Demo               │
└──────────────────────────────┬──────────────────────────────┘
                               │ WebSocket / REST
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 AegisGraph Agent Core                       │
│                   (Python FastAPI)                          │
│  - Autonomous LLM Agent Loop (Gemini / Anthropic / OpenAI)   │
│  - Tool Registry / FalkorDB Cypher Tools                     │
│  - Multi-Hop Reasoner & Incident Commander                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
┌──────────────────────────────┐ ┌───────────────────────────┐
│       FalkorDB Engine        │ │    Remediation Engine     │
│   (Low-Latency Graph DB)     │ │  (Simulated Cloud Action) │
│ - Infrastructure Graph Nodes │ │ - Sever IAM Permission    │
│ - Attack Path Relationships  │ │ - Quarantine Container    │
│ - Cypher Multi-Hop Queries   │ │ - Rotate Leaked Secret    │
│ - Graph Algorithms Engine    │ │ - Update Security Group   │
└──────────────────────────────┘ └───────────────────────────┘
```

---

## 3. FalkorDB Graph Schema (The Context Layer)

### Node Types:
* `(:Internet)` - Public internet entry points.
* `(:APIGateway {name, port, status})`
* `(:Service {name, type, ip, namespace})`
* `(:Vulnerability {cve, severity, cvss})`
* `(:IAMRole {name, arn, privileged})`
* `(:Secret {name, type, vault})`
* `(:Database {name, type, contains_pii, classification})`
* `(:S3Bucket {name, is_public, encrypted})`

### Relationship Types (Edges):
* `[:EXPOSES]` / `[:ROUTES_TO]`
* `[:HAS_VULNERABILITY]`
* `[:ASSUMES_ROLE]`
* `[:CAN_ACCESS]` / `[:CAN_READ]`
* `[:CONTAINS_CREDENTIAL_FOR]`
* `[:CALLS_SERVICE]`

---

## 4. FalkorDB Native Graph Queries & Algorithms Used by Agent

1. **Attack Path Discovery (Multi-hop):**
   ```cypher
   MATCH path = (entry:APIGateway)-[*1..5]->(target:Database {contains_pii: true})
   RETURN path, length(path) AS hops
   ORDER BY hops ASC LIMIT 3
   ```
2. **Shortest Attack Path (Algorithm):**
   ```cypher
   MATCH (src:Service {name: $compromised_node}), (dst:Database {name: $target_db})
   MATCH p = shortestPath((src)-[*..6]->(dst))
   RETURN p
   ```
3. **Blast Radius Calculation:**
   Count how many sensitive resources are reachable within 3 hops of the compromised node.
4. **Autonomous Remediation (Dynamic Edge Severing):**
   ```cypher
   MATCH (r:IAMRole {name: $role})-[rel:CAN_ACCESS]->(d:Database {name: $target})
   DELETE rel
   RETURN 'IAM link revoked, attack path severed' AS status
   ```

---

## 5. Implementation Roadmap (Zero to Hero)

- [x] **Phase 0: Environment Ready** (Docker, FalkorDB pulled & verified, Python, Node.js).
- [ ] **Phase 1: FalkorDB Graph Seeder** (Realistic cloud infrastructure topology with deliberate attack paths).
- [ ] **Phase 2: Agent Tools & Reasoner** (Cypher queries, blast-radius calculator, path finder, containment executor).
- [ ] **Phase 3: Fast Backend API** (FastAPI backend connecting the LLM agent + FalkorDB + streaming event logs).
- [ ] **Phase 4: Stunning Cyber Commander UI** (Interactive graph canvas with glowing nodes, live containment triggers).
- [ ] **Phase 5: Hackathon Demo & Submission Pack** (2-min demo video script, README, and winning blog post for the AirPods 5 prize).
