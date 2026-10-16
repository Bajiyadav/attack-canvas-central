# 🎬 AegisGraph: 3-Minute Video Pitch & Judge Demo Script

> **Hackathon:** [Graph Hacks: Context for AI Agents](https://www.wemakedevs.org/hackathons/falkordb) (WeMakeDevs & FalkorDB)  
> **Track 01:** Agents That Act on Connected Data  
> **Team:** SUVI — Presenter: Baji Baddela ([@bajibaddela](https://github.com/bajibaddela))  
> **Target Video Duration:** 2 minutes 45 seconds  

---

## ⏱️ Video Timeline Overview

| Timestamp | Phase | What to Show on Screen | Key Audio Talking Point |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:35** | **The Hook** | Slide / Architecture Diagram or initial HUD with flashing red alert badge | Why Vector RAG fails for SecOps and why relationships require a graph. |
| **0:35 - 1:15** | **Topology & Attack Chain** | Browser on `http://localhost:8000` showing the interactive graph canvas | Click on `pod-ingress-7b4d` and `Customer-Vault-Postgres`; explain the 4-hop kill-chain. |
| **1:15 - 1:55** | **Autonomous Agent Action** | Click `AUTONOMOUS INVESTIGATE & REMEDIATE` | Watch the step-by-step trace stream, Cypher queries execute, and the toxic IAM edge get severed. |
| **1:55 - 2:25** | **AI Copilot & Natural Language** | Switch to "SecOps AI Chat" tab; click prompt chip | Ask Gemini about toxic IAM roles; show the graph-grounded response. |
| **2:25 - 2:45** | **Benchmark & Conclusion** | Terminal running `python backend/benchmark.py` | Sub-millisecond (0.60ms) traversals; summarize why graphs are the future of AI agents. |

---

## 🎙️ Word-for-Word Voiceover Script

### [0:00 - 0:35] Part 1: The Problem (The Vector RAG Trap)
> *"Hello everyone! I'm Baji from Team SUVI, presenting **AegisGraph: Autonomous Incident Commander & Blast-Radius Agent** for Track 01 of Graph Hacks.*
>
> *When an internet-facing Kubernetes pod is exploited with a Critical CVE, traditional security tools fail. Vector databases can summarize the CVE description, but they cannot answer the single question SecOps engineers care about: **Can the attacker pivot from this pod to our customer PII database?***
>
> *That answer doesn't live in documents—it lives in the **relationships** between pods, IAM roles, S3 buckets, secrets, and databases. To solve this in real time, an AI agent needs a graph context layer. We chose **FalkorDB**."*

---

### [0:35 - 1:15] Part 2: The FalkorDB Context Layer & 4-Hop Kill-Chain
> *(Action: Show the Cyber HUD at `http://localhost:8000`)*
>
> *"Here is the AegisGraph Cyber Command Center. Our entire cloud infrastructure is modeled natively in FalkorDB: microservices, IAM roles, S3 buckets, and RDS databases.*
>
> *Right now, our ingress pod has been compromised with an RCE vulnerability. In the bottom inspector, we can see it's connected to `Role-Overprivileged-ClusterAdmin`. That role has read access to an unencrypted S3 backup bucket, which leaks a database credential, unlocking our crown jewel: `Customer-Vault-Postgres`, exposing **2.4 million customer PII records**!*
>
> *Our blast radius is sitting at a critical **9.8 out of 10**."*

---

### [1:15 - 1:55] Part 3: Autonomous Investigation & Edge Severing
> *(Action: Click the glowing button: `AUTONOMOUS INVESTIGATE & REMEDIATE`)*
>
> *"Instead of waiting 45 minutes for a human on-call engineer, I trigger the AegisGraph Autonomous Agent.*
>
> *Watch the Agent Thought Trace on the right panel. In less than 2 milliseconds, the agent invokes a FalkorDB Cypher traversal, discovering the full 4-hop path to the database.*
>
> *Now watch the containment action: The agent surgically executes a graph mutation—it deletes the toxic `[:ASSUMES_ROLE]` edge directly in FalkorDB and quarantines the pod.*
>
> *Immediately, it runs a post-remediation zero-trust audit: active paths drop from 1 to **0**, and the blast radius plummets to **0.0 (SECURE)**. The entire investigation and containment finished in just **63 milliseconds** without any human delay!"*

---

### [1:55 - 2:25] Part 4: SecOps AI Copilot (Powered by Google Gemini)
> *(Action: Click the `SECOPS AI CHAT` tab, click the chip `🔑 Toxic IAM Roles`)*
>
> *"Operators can also collaborate with the agent. Let's switch to the SecOps AI Chat powered by Google Gemini.*
>
> *When we ask: 'Which IAM roles have toxic privileges?', the agent executes a targeted Cypher query against FalkorDB, analyzes the attached workloads, and highlights the affected nodes directly on the graph canvas in real time."*

---

### [2:25 - 2:45] Part 5: Performance Benchmarks & Closing Pitch
> *(Action: Switch to terminal and show the output of `python backend/benchmark.py`)*
>
> *"We benchmarked FalkorDB across 100 iterations: 4-hop kill-chain queries run in **0.60 milliseconds**, and autonomous edge mutations execute in **0.84 milliseconds**, sustaining over 1,600 queries per second.*
>
> *Agents are only as powerful as the context they act on. By combining FalkorDB with autonomous graph actions, AegisGraph proves that graphs are the ultimate context layer for AI agents.*
>
> *Thank you, WeMakeDevs and FalkorDB, for hosting Graph Hacks!"*

---

## 💡 Quick Tips for Recording
1. **Resolution:** Record your screen at 1080p (1920x1080) for crisp typography.
2. **Audio:** Enable sound in the HUD by clicking the speaker icon (🔊) so the cyber telemetry tones play during the demo!
3. **Resetting:** If you need to re-record a take, simply click **`RESET GRAPH`** in the top navigation bar to reset the environment in 1 second.
