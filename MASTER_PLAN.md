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

---

## 5. Official Rules & Hackathon Window (October 15 – October 18, 2026)

- **Official Start:** October 15, 2026 at 12:01 AM IST
- **Official Close:** October 18, 2026 at 11:59 PM IST
- **Pre-event Policy:** Preparation is strictly limited to planning notes, architecture diagrams, data models, and specifications. Main coding, feature implementation, and UI design work must happen during the official event.
- **Core Technology Mandate:** FalkorDB must be central to the application.
- **Required Deliverables:** Public repository, graph data model, relevant Cypher queries, demo video, and local/deployment setup instructions.

---

## 6. AegisGraph Implementation Blueprint (Track 1 Target)

### Technology Stack:
* **LLM Engine:** Google Gemini API (`google-genai` SDK) with strict Function Calling.
* **Context Layer:** FalkorDB on Docker (port 6379) as the primary graph store for topology, attack paths, and remediation evidence.
* **Agent Core & API:** FastAPI + Python for agent orchestration, tool execution, safety boundaries, and REST API.
* **Cyber HUD:** HTML, CSS, JavaScript, vis-network for physics-based graph rendering, audio telemetry, and live timeline.

### Planned Tool Registry:

| Tool | Responsibility |
| :--- | :--- |
| `get_asset` | Inspect an asset and its security properties |
| `find_attack_paths` | Discover paths from a selected asset to sensitive targets |
| `calculate_blast_radius` | Identify reachable resources and quantify exposure |
| `inspect_permissions` | Examine IAM roles and access relationships |
| `propose_containment` | Recommend a narrowly scoped remediation |
| `execute_containment` | Execute a policy-approved graph mutation (sever edge, quarantine) |
| `verify_containment` | Re-query the graph and validate the outcome (alternate path check) |

> **Safety Boundary:** `execute_containment` is strictly restricted to validated, parameterized operations. Arbitrary raw Cypher execution will never be exposed as an unconstrained destructive tool.

### Planned API Contract:

| Endpoint | Purpose |
| :--- | :--- |
| `GET /api/graph` | Retrieve full graph topology (nodes and relationships) |
| `POST /api/investigate` | Start an investigation for a selected asset |
| `POST /api/contain` | Submit a containment proposal for validation and execution |
| `GET /api/investigations/{id}` | Retrieve investigation progress and evidence logs |
| `POST /api/chat` | Ask graph-grounded SecOps questions in natural language |
| `POST /api/reset` | Reset the synthetic demonstration environment to breach state |

---

## 7. Four-Day Delivery Plan (October 15 – October 18, 2026)

### Day 1 — Agent & Graph Foundation (Oct 15)
- Establish a clean, reproducible baseline environment.
- Validate FalkorDB connectivity and parameterized Cypher queries.
- Implement Gemini tool-calling loop using `google-genai` with bounded iteration limits.
- Add dynamic starting-asset selection (breach any node).
- Implement deterministic fallback mode when API keys are absent.

### Day 2 — Containment & Interface (Oct 16)
- Add containment proposals and policy safety checks.
- Implement post-remediation verification ensuring alternate paths are caught.
- Connect real agent trace events to the Cyber HUD.
- Add node selection, interactive progress indicators, and evidence panels.

### Day 3 — Testing & Differentiation (Oct 17)
- Test diverse starting assets and multi-hop attack routes.
- Test edge cases: unreachable targets, dead ends, and parallel routes.
- Test resilience: API timeouts, connection drops, and repeated requests.
- Add natural-language graph query interface (`/api/chat`).
- Capture reproducible before-and-after evidence snapshots.

### Day 4 — Submission & Demo (Oct 18)
- Finalize architecture, graph schema, and Cypher query documentation.
- Document the Cypher queries and tool-calling flow in `README.md`.
- Verify clean-room installation instructions on a fresh setup.
- Record crisp 2-3 minute demo video showcasing complete incident lifecycle.
- Finalize `BLOG_POST.md` for the AirPods 5 prize and submit before 11:59 PM IST.

---

## 8. Acceptance Test Matrix

| Test | Required Result |
| :--- | :--- |
| **Dynamic Starting Asset** | Investigation uses the selected asset, not a hardcoded ID |
| **Multi-Hop Discovery** | Returns actual graph-backed paths and their relationships |
| **Agent Autonomy** | Tool selection dynamically varies based on evidence returned |
| **Containment Boundary** | Only validated, permitted actions execute |
| **Alternate Path Verification** | Deleting one edge must not report success if another route exists |
| **LLM Fallback** | Deterministic mode runs smoothly if Gemini API is unreachable |
| **Repeatability** | Resetting restores the exact synthetic scenario reliably |
| **Explainability** | Tool inputs, results, decisions, and actions are fully inspectable |
| **Graph Dependency** | Removing FalkorDB breaks the agent, proving graph necessity |

---

## 9. Final Submission Package Checklist

- [ ] Public source repository with 1-click Docker setup.
- [ ] Graph schema diagram and architecture specifications.
- [ ] Cypher queries documentation and tool-calling trace examples.
- [ ] Automated test suite (`pytest`) for attack paths and remediation.
- [ ] 2-3 minute crisp demo video with voiceover walkthrough.
- [ ] Technical blog post (`BLOG_POST.md`) submitted for AirPods 5 prize.
- [ ] AI-assistance disclosure and clear summary of team technical contributions.

