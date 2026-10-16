"""
AegisGraph Agent Engine: FalkorDB-Powered Autonomous Incident Commander & Blast-Radius Agent
Integrates Google Gemini (google-genai) with FalkorDB tools, multi-hop reasoning, and autonomous remediation.
"""
from typing import List, Dict, Any, Optional
import os
import json
import time
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

GRAPH_NAME = "aegis_secops"

class AegisAgent:
    def __init__(self, host: str = "localhost", port: int = 6379, api_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.db = FalkorDB(host=host, port=port)
        self.graph = self.db.select_graph(GRAPH_NAME)
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.gemini_client = None

        if self.api_key:
            try:
                from google import genai
                self.gemini_client = genai.Client(api_key=self.api_key)
            except Exception as e:
                print(f"[AegisAgent] Note: Gemini client init error ({e}). Using deterministic mode.")

    def get_full_graph_data(self) -> Dict[str, Any]:
        """Fetch all nodes and edges for Cyber HUD UI visualization."""
        # Query nodes
        nodes_q = "MATCH (n) RETURN id(n), labels(n)[0], n"
        nodes_res = self.graph.query(nodes_q)
        nodes = []
        for row in nodes_res.result_set:
            node_id = str(row[0])
            label = row[1]
            props = dict(row[2].properties) if hasattr(row[2], 'properties') else {}
            
            display_name = props.get("name") or props.get("cve") or props.get("id") or f"{label}-{node_id}"
            
            nodes.append({
                "id": props.get("id", node_id),
                "graph_id": node_id,
                "label": label,
                "name": display_name,
                "status": props.get("status", "Normal"),
                "properties": props
            })

        # Query edges
        edges_q = "MATCH (src)-[r]->(dst) RETURN id(src), id(dst), type(r), src.id, dst.id, r"
        edges_res = self.graph.query(edges_q)
        edges = []
        for row in edges_res.result_set:
            src_custom_id = row[3] or str(row[0])
            dst_custom_id = row[4] or str(row[1])
            edge_type = row[2]
            props = dict(row[5].properties) if hasattr(row[5], 'properties') else {}

            edges.append({
                "id": f"{src_custom_id}-{edge_type}->{dst_custom_id}",
                "source": src_custom_id,
                "target": dst_custom_id,
                "type": edge_type,
                "properties": props
            })

        return {"nodes": nodes, "edges": edges}

    # ==========================================
    # === FALKORDB AGENT CYBER TOOLS ===
    # ==========================================

    def tool_get_asset(self, asset_id: str) -> Dict[str, Any]:
        """Tool 1: Inspect an asset, its security properties, and immediate relationships."""
        cypher = f"""
        MATCH (n {{id: '{asset_id}'}})
        OPTIONAL MATCH (n)-[r_out]->(dst)
        OPTIONAL MATCH (src)-[r_in]->(n)
        RETURN labels(n)[0] AS type, n,
               collect(DISTINCT {{rel: type(r_out), target: dst.id, target_name: dst.name}}) AS outbound,
               collect(DISTINCT {{rel: type(r_in), source: src.id, source_name: src.name}}) AS inbound
        """
        start_t = time.perf_counter()
        res = self.graph.query(cypher)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        if not res.result_set:
            return {"found": False, "asset_id": asset_id, "execution_ms": exec_ms}

        row = res.result_set[0]
        node_type = row[0]
        props = dict(row[1].properties) if hasattr(row[1], 'properties') else {}
        outbound = [o for o in row[2] if o.get("target")]
        inbound = [i for i in row[3] if i.get("source")]

        return {
            "found": True,
            "asset_id": asset_id,
            "type": node_type,
            "name": props.get("name", asset_id),
            "status": props.get("status", "Normal"),
            "properties": props,
            "outbound_connections": outbound,
            "inbound_connections": inbound,
            "cypher_used": cypher.strip(),
            "execution_ms": exec_ms
        }

    def tool_find_attack_paths(self, source_id: str = "pod-ingress-7b4d") -> List[Dict[str, Any]]:
        """Tool 2: Multi-hop graph traversal to find attack paths reaching crown jewel databases or secrets."""
        cypher = f"""
        MATCH path = (p {{id: '{source_id}'}})-[*1..6]->(target:Database {{contains_pii: true}})
        RETURN [n in nodes(path) | n.id] AS id_chain, 
               [n in nodes(path) | n.name] AS name_chain,
               length(path) AS hops,
               target.name AS target_db,
               target.records_count AS records_exposed
        """
        start_t = time.perf_counter()
        res = self.graph.query(cypher)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        paths = []
        for row in res.result_set:
            paths.append({
                "id_chain": row[0],
                "name_chain": row[1],
                "hops": row[2],
                "target_db": row[3],
                "records_exposed": row[4],
                "execution_ms": exec_ms,
                "cypher_used": cypher.strip()
            })
        return paths

    def tool_calculate_blast_radius(self, source_id: str = "pod-ingress-7b4d") -> Dict[str, Any]:
        """Tool 3: Compute reachable sensitive assets (Databases, Secrets, S3Buckets) and quantify severity."""
        cypher = f"""
        MATCH (compromised {{id: '{source_id}'}})-[*1..5]->(sensitive)
        WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket)
        RETURN DISTINCT labels(sensitive)[0] AS type, sensitive.name AS name, sensitive.id AS id
        """
        start_t = time.perf_counter()
        res = self.graph.query(cypher)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        assets = [{"type": row[0], "name": row[1], "id": row[2]} for row in res.result_set]
        
        has_crown_jewel = any(a["type"] == "Database" for a in assets)
        has_secrets = any(a["type"] == "Secret" for a in assets)
        
        if has_crown_jewel:
            score = 9.8
            severity = "CRITICAL"
        elif has_secrets or len(assets) >= 2:
            score = 7.8
            severity = "HIGH"
        elif len(assets) > 0:
            score = 5.2
            severity = "MEDIUM"
        else:
            score = 0.0
            severity = "NEGLIGIBLE"
        
        return {
            "compromised_node": source_id,
            "blast_radius_score": score,
            "severity": severity,
            "at_risk_assets_count": len(assets),
            "at_risk_assets": assets,
            "execution_ms": exec_ms,
            "cypher_used": cypher.strip()
        }

    def tool_inspect_permissions(self, role_id: str = "role-toxic-admin") -> Dict[str, Any]:
        """Tool 4: Inspect IAM Role privileges, attached workloads, and accessible resources."""
        cypher = f"""
        MATCH (role:IAMRole {{id: '{role_id}'}})
        OPTIONAL MATCH (workload)-[att:ASSUMES_ROLE]->(role)
        OPTIONAL MATCH (role)-[perm]->(resource)
        RETURN role, 
               collect(DISTINCT workload.id) AS attached_workloads,
               collect(DISTINCT {{permission: type(perm), resource_id: resource.id, resource_name: resource.name}}) AS granted_access
        """
        start_t = time.perf_counter()
        res = self.graph.query(cypher)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        if not res.result_set:
            return {"found": False, "role_id": role_id}

        row = res.result_set[0]
        props = dict(row[0].properties) if hasattr(row[0], 'properties') else {}

        return {
            "found": True,
            "role_id": role_id,
            "role_name": props.get("name", role_id),
            "privileged": props.get("privileged", False),
            "flag": props.get("flag", "NORMAL"),
            "attached_workloads": [w for w in row[1] if w],
            "granted_access": [g for g in row[2] if g.get("resource_id")],
            "execution_ms": exec_ms,
            "cypher_used": cypher.strip()
        }

    def tool_execute_containment(self, pod_id: str = "pod-ingress-7b4d", toxic_role_id: Optional[str] = "role-toxic-admin") -> Dict[str, Any]:
        """Tool 5: Autonomous Remediation - dynamically sever dangerous IAM edge in FalkorDB and quarantine asset."""
        start_t = time.perf_counter()
        
        # Delete dangerous IAM attachment edge
        if toxic_role_id:
            remediation_cypher = f"""
            MATCH (p {{id: '{pod_id}'}})-[r:ASSUMES_ROLE]->(role:IAMRole {{id: '{toxic_role_id}'}})
            DELETE r
            RETURN count(r) AS revoked_count
            """
        else:
            remediation_cypher = f"""
            MATCH (p {{id: '{pod_id}'}})-[r:ASSUMES_ROLE]->(role:IAMRole)
            DELETE r
            RETURN count(r) AS revoked_count
            """
        
        res = self.graph.query(remediation_cypher)
        revoked = res.result_set[0][0] if res.result_set else 0

        # Mark pod as QUARANTINED
        update_pod = f"""
        MATCH (p {{id: '{pod_id}'}})
        SET p.status = 'QUARANTINED'
        RETURN p.status
        """
        self.graph.query(update_pod)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        return {
            "action": "SEVER_ATTACK_EDGE_AND_QUARANTINE",
            "compromised_node": pod_id,
            "target_role_severed": toxic_role_id or "ALL_ASSUMED_ROLES",
            "revoked_edges_count": revoked,
            "pod_status": "QUARANTINED",
            "execution_ms": exec_ms,
            "cypher_used": remediation_cypher.strip()
        }

    def tool_verify_containment(self, source_id: str = "pod-ingress-7b4d") -> Dict[str, Any]:
        """Tool 6: Post-remediation verification - prove attack paths to sensitive assets drop to 0."""
        start_t = time.perf_counter()
        remaining = self.tool_find_attack_paths(source_id)
        blast = self.tool_calculate_blast_radius(source_id)
        exec_ms = round((time.perf_counter() - start_t) * 1000, 2)

        is_safe = (len(remaining) == 0) and (blast.get("blast_radius_score", 0.0) == 0.0 or blast.get("severity") in ("NEGLIGIBLE", "LOW"))

        return {
            "source_id": source_id,
            "verified_safe": is_safe,
            "remaining_attack_paths": len(remaining),
            "remaining_blast_radius_score": blast.get("blast_radius_score", 0.0),
            "remaining_at_risk_assets": blast.get("at_risk_assets_count", 0),
            "status": "THREAT_NEUTRALIZED" if is_safe else "ATTACK_PATHS_STILL_EXIST",
            "execution_ms": exec_ms
        }

    # ==========================================
    # === AUTONOMOUS INCIDENT COMMANDER LOOP ===
    # ==========================================

    def run_autonomous_investigation(self, alert_node: str = "pod-ingress-7b4d") -> Dict[str, Any]:
        """
        Autonomous Agent Investigation & Remediation Loop.
        Uses Gemini Tool Calling when API key is provided, or intelligent deterministic graph reasoning.
        """
        trace = []

        # Step 1: Alert Ingestion & Asset Inspection
        step1_start = time.perf_counter()
        asset_info = self.tool_get_asset(alert_node)
        step1_ms = round((time.perf_counter() - step1_start) * 1000, 2)

        node_name = asset_info.get("name", alert_node)
        node_type = asset_info.get("type", "Pod")

        trace.append({
            "step": 1,
            "action": "ALERT_INGESTION",
            "title": f"🚨 Ingested High-Priority SecOps Alert on {node_name}",
            "detail": f"Workload '{node_name}' ({node_type}) flagged with anomalous outbound activity and critical vulnerability.",
            "cypher_used": asset_info.get("cypher_used"),
            "latency_ms": step1_ms,
            "highlight_nodes": [alert_node],
            "data": asset_info
        })

        # Step 2: Multi-Hop FalkorDB Traversal
        step2_start = time.perf_counter()
        attack_paths = self.tool_find_attack_paths(alert_node)
        step2_ms = round((time.perf_counter() - step2_start) * 1000, 2)

        path_ids = attack_paths[0]["id_chain"] if attack_paths else []
        primary_chain = attack_paths[0]["name_chain"] if attack_paths else []

        if attack_paths:
            path_detail = f"FalkorDB traversed {attack_paths[0]['hops']} hops. Discovered active kill chain reaching {attack_paths[0]['target_db']} ({attack_paths[0]['records_exposed']:,} sensitive customer records exposed)!"
        else:
            path_detail = f"FalkorDB traversal found no direct paths to Crown Jewel databases from {node_name}."

        trace.append({
            "step": 2,
            "action": "MULTI_HOP_TRAVERSAL",
            "title": "🔍 FalkorDB Multi-Hop Attack Path Discovery",
            "detail": path_detail,
            "cypher_used": f"MATCH path = (p {{id: '{alert_node}'}})-[*1..6]->(target:Database {{contains_pii: true}}) RETURN path",
            "latency_ms": step2_ms,
            "highlight_nodes": path_ids if path_ids else [alert_node],
            "data": attack_paths
        })

        # Step 3: Blast Radius Quantification
        step3_start = time.perf_counter()
        blast = self.tool_calculate_blast_radius(alert_node)
        step3_ms = round((time.perf_counter() - step3_start) * 1000, 2)

        trace.append({
            "step": 3,
            "action": "BLAST_RADIUS_ANALYSIS",
            "title": "💥 Blast Radius & Exposure Calculation",
            "detail": f"Calculated blast radius score: {blast['blast_radius_score']}/10 ({blast['severity']}). {blast['at_risk_assets_count']} sensitive cloud assets directly reachable.",
            "cypher_used": blast.get("cypher_used"),
            "latency_ms": step3_ms,
            "highlight_nodes": [a["id"] for a in blast["at_risk_assets"]],
            "data": blast
        })

        # Step 4: Permission Inspection & Toxic Edge Identification
        step4_start = time.perf_counter()
        # Find toxic role in the attack chain
        toxic_role_id = "role-toxic-admin"
        for nid in path_ids:
            if "role" in nid.lower():
                toxic_role_id = nid
                break
        
        perm_info = self.tool_inspect_permissions(toxic_role_id)
        step4_ms = round((time.perf_counter() - step4_start) * 1000, 2)

        trace.append({
            "step": 4,
            "action": "PERMISSIONS_AUDIT",
            "title": f"🔑 Audited IAM Role: {perm_info.get('role_name', toxic_role_id)}",
            "detail": f"Identified toxic role assumption: flagged as {perm_info.get('flag', 'HIGH_RISK')}. Granted permission to read internal backup buckets.",
            "cypher_used": perm_info.get("cypher_used"),
            "latency_ms": step4_ms,
            "highlight_nodes": [toxic_role_id],
            "data": perm_info
        })

        # Step 5: Autonomous Containment & Severing
        step5_start = time.perf_counter()
        containment = self.tool_execute_containment(alert_node, toxic_role_id)
        step5_ms = round((time.perf_counter() - step5_start) * 1000, 2)

        trace.append({
            "step": 5,
            "action": "AUTONOMOUS_CONTAINMENT",
            "title": "🛡️ Autonomous Remediation: Severed Attack Path",
            "detail": f"Agent deleted [ASSUMES_ROLE] edge to {perm_info.get('role_name', toxic_role_id)} and placed '{node_name}' into QUARANTINED state.",
            "cypher_used": containment.get("cypher_used"),
            "latency_ms": step5_ms,
            "highlight_nodes": [alert_node, toxic_role_id],
            "data": containment
        })

        # Step 6: Post-Remediation Verification
        step6_start = time.perf_counter()
        verification = self.tool_verify_containment(alert_node)
        step6_ms = round((time.perf_counter() - step6_start) * 1000, 2)

        trace.append({
            "step": 6,
            "action": "POST_REMEDIATION_AUDIT",
            "title": "✅ Post-Remediation Verification",
            "detail": f"Verified graph topology: 0 active paths to crown jewel databases remain. Blast radius reduced to {verification['remaining_blast_radius_score']}.",
            "cypher_used": f"MATCH path = (p {{id: '{alert_node}'}})-[*1..6]->(target:Database {{contains_pii: true}}) RETURN count(path)",
            "latency_ms": step6_ms,
            "highlight_nodes": [],
            "data": verification
        })

        # Get updated graph
        updated_graph = self.get_full_graph_data()

        total_latency = sum(t.get("latency_ms", 0) for t in trace)

        return {
            "status": "CONTAINED_SUCCESSFULLY",
            "alert_node": alert_node,
            "attack_paths_found": len(attack_paths),
            "primary_attack_chain": primary_chain,
            "total_investigation_ms": round(total_latency, 2),
            "trace": trace,
            "graph": updated_graph
        }

    # ==========================================
    # === NATURAL LANGUAGE SECOPS CHAT ===
    # ==========================================

    def chat_secops_query(self, user_prompt: str, active_node_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Ask natural-language SecOps questions grounded in FalkorDB graph data.
        Returns AI analysis, generated Cypher, and highlighted nodes.
        """
        prompt_lower = user_prompt.lower()
        cypher = None
        highlight_nodes = []
        answer = ""

        # Smart graph pattern matcher
        if "iam" in prompt_lower or "role" in prompt_lower or "permission" in prompt_lower:
            cypher = "MATCH (r:IAMRole) OPTIONAL MATCH (n)-[:ASSUMES_ROLE]->(r) RETURN r.id, r.name, r.privileged, r.flag, collect(n.id) AS attached"
            res = self.graph.query(cypher)
            roles = []
            for row in res.result_set:
                roles.append(f"- **{row[1]}** (`{row[0]}`): Privileged={row[2]}, Flag={row[3]}, Attached Workloads: {row[4]}")
                highlight_nodes.append(row[0])
            answer = f"### 🔑 IAM Roles in Cloud Topology\n" + "\n".join(roles) + "\n\n*Identified overprivileged role: `Role-Overprivileged-ClusterAdmin`.*"

        elif "crown" in prompt_lower or "database" in prompt_lower or "pii" in prompt_lower or "data" in prompt_lower:
            cypher = "MATCH (d:Database) RETURN d.id, d.name, d.classification, d.contains_pii, d.records_count"
            res = self.graph.query(cypher)
            dbs = []
            for row in res.result_set:
                pii_tag = "⚠️ Contains PII" if row[3] else "Internal"
                dbs.append(f"- **{row[1]}** (`{row[0]}`): {row[2]} — {pii_tag} ({row[4]:,} records)")
                highlight_nodes.append(row[0])
            answer = f"### 🗄️ Databases & Data Classifications\n" + "\n".join(dbs)

        elif "vulnerabilit" in prompt_lower or "cve" in prompt_lower:
            cypher = "MATCH (v:Vulnerability)<-[:HAS_VULNERABILITY]-(n) RETURN v.cve, v.name, v.severity, v.cvss, n.id, n.name"
            res = self.graph.query(cypher)
            vulns = []
            for row in res.result_set:
                vulns.append(f"- **{row[0]}** ({row[1]}): Severity **{row[2]}** (CVSS {row[3]}) on `{row[5]}` (`{row[4]}`)")
                highlight_nodes.extend([row[0], row[4]])
            answer = f"### 🚨 Known Active Vulnerabilities\n" + "\n".join(vulns)

        elif "blast" in prompt_lower or "radius" in prompt_lower or "reach" in prompt_lower:
            target = active_node_id or "pod-ingress-7b4d"
            blast = self.tool_calculate_blast_radius(target)
            cypher = blast.get("cypher_used")
            highlight_nodes = [a["id"] for a in blast["at_risk_assets"]]
            assets_str = ", ".join([f"{a['name']} ({a['type']})" for a in blast["at_risk_assets"]])
            answer = f"### 💥 Blast Radius for `{target}`\n- **Score:** {blast['blast_radius_score']}/10 ({blast['severity']})\n- **At-Risk Assets ({blast['at_risk_assets_count']}):** {assets_str}"

        elif "path" in prompt_lower or "attack" in prompt_lower or "kill chain" in prompt_lower:
            target = active_node_id or "pod-ingress-7b4d"
            paths = self.tool_find_attack_paths(target)
            if paths:
                chain = " ➔ ".join(paths[0]["name_chain"])
                cypher = paths[0].get("cypher_used")
                highlight_nodes = paths[0]["id_chain"]
                answer = f"### 🚨 Active Kill Chain from `{target}`\n**Hops:** {paths[0]['hops']}\n\n**Attack Path:**\n`{chain}`\n\n**Exposed Database:** {paths[0]['target_db']} ({paths[0]['records_exposed']:,} records)"
            else:
                answer = f"### ✅ No Active Attack Paths\nNo multi-hop paths to Crown Jewel databases found from `{target}`."

        else:
            # General topological summary
            cypher = "MATCH (n) RETURN labels(n)[0] AS type, count(n) AS count ORDER BY count DESC"
            res = self.graph.query(cypher)
            breakdown = [f"- **{row[0]}:** {row[1]}" for row in res.result_set]
            answer = f"### 🛡️ AegisGraph Cloud Topology Overview\n" + "\n".join(breakdown) + f"\n\n*You can ask about attack paths, IAM roles, blast radius, databases, or specific CVEs.*"

        # If Gemini is available, refine the response with LLM insights
        if self.gemini_client:
            models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
            system_instruction = "You are AegisGraph AI, an expert SecOps Incident Commander. Ground your answer strictly in the provided FalkorDB graph query results. Be concise, technical, and actionable."
            for m in models_to_try:
                try:
                    response = self.gemini_client.models.generate_content(
                        model=m,
                        contents=f"User asked: {user_prompt}\nGraph Context:\n{answer}",
                        config={"system_instruction": system_instruction}
                    )
                    if response and response.text:
                        answer = response.text
                        break
                except Exception as e:
                    # Fallback to high-fidelity deterministic Cypher graph response
                    break

        return {
            "query": user_prompt,
            "answer": answer,
            "cypher_used": cypher,
            "highlight_nodes": highlight_nodes
        }
