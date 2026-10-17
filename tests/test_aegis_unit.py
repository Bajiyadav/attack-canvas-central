"""
AegisGraph Unit & Integration Test Suite
Validates FalkorDB graph topology, multi-hop Cypher queries, agent tools,
FastAPI REST endpoints, and frontend asset integrity.
"""
import os
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.agent import AegisAgent
from backend.seed_graph import seed_graph


@pytest.fixture(scope="session", autouse=True)
def setup_graph():
    """Ensure graph is freshly seeded before running tests."""
    seed_graph()
    yield
    # Re-seed after tests finish to leave system in pristine breach state
    seed_graph()


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def agent():
    """AegisAgent instance."""
    return AegisAgent()


# ==============================================================================
# 1. FALKORDB TOPOLOGY & SEED DATA TESTS
# ==============================================================================

class TestFalkorDBTopology:
    def test_graph_has_nodes_and_edges(self, agent):
        """Graph should contain all cloud assets and relationship edges."""
        data = agent.get_full_graph_data()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) >= 8, f"Expected at least 8 nodes, got {len(data['nodes'])}"
        assert len(data["edges"]) >= 7, f"Expected at least 7 edges, got {len(data['edges'])}"

    def test_crown_jewel_database_properties(self, agent):
        """Crown Jewel database should be flagged with contains_pii and 2.4M records."""
        q = "MATCH (d:Database {id: 'db-customer-pii'}) RETURN d.name, d.contains_pii, d.records_count, d.classification"
        res = agent.graph.query(q)
        assert len(res.result_set) == 1
        row = res.result_set[0]
        assert row[1] is True, "Database must have contains_pii=True"
        assert row[2] == 2400000, f"Expected 2,400,000 records, got {row[2]}"
        assert row[3] == "CROWN_JEWEL"

    def test_vulnerability_cvss_score(self, agent):
        """CVE-2026-9912 should be Critical severity with CVSS 9.8."""
        q = "MATCH (v:Vulnerability {cve: 'CVE-2026-9912'}) RETURN v.cvss, v.severity"
        res = agent.graph.query(q)
        assert len(res.result_set) == 1
        row = res.result_set[0]
        assert row[0] == 9.8, f"Expected CVSS 9.8, got {row[0]}"
        assert row[1] == "CRITICAL"

    def test_ingress_pod_exposes_vulnerability(self, agent):
        """pod-ingress-7b4d must be connected to CVE-2026-9912."""
        q = "MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[:HAS_VULNERABILITY]->(v:Vulnerability) RETURN v.cve"
        res = agent.graph.query(q)
        assert len(res.result_set) >= 1
        assert res.result_set[0][0] == "CVE-2026-9912"


# ==============================================================================
# 2. AEGIS AGENT MULTI-HOP REASONING & ALGORITHM TESTS
# ==============================================================================

class TestAegisAgentTools:
    def test_find_attack_paths_before_remediation(self, agent):
        """Agent should detect the active multi-hop kill chain to the database."""
        paths = agent.tool_find_attack_paths("pod-ingress-7b4d")
        assert len(paths) >= 1, "Expected at least 1 attack path before remediation"
        p = paths[0]
        assert p["hops"] >= 2
        assert "db-customer-pii" in p["id_chain"]
        assert p["records_exposed"] == 2400000

    def test_calculate_blast_radius(self, agent):
        """Agent should calculate a high critical blast radius from the compromised ingress."""
        blast = agent.tool_calculate_blast_radius("pod-ingress-7b4d")
        assert blast["blast_radius_score"] >= 8.0, f"Expected critical blast radius, got {blast['blast_radius_score']}"
        assert blast["severity"] == "CRITICAL"
        assert blast["at_risk_assets_count"] >= 3

    def test_get_single_asset(self, agent):
        """tool_get_asset should return asset properties, incoming, and outgoing edges."""
        asset = agent.tool_get_asset("pod-ingress-7b4d")
        assert asset["asset_id"] == "pod-ingress-7b4d"
        assert asset["found"] is True
        assert "properties" in asset
        assert "outbound_connections" in asset
        assert len(asset["outbound_connections"]) >= 1

    def test_autonomous_investigation_and_severing(self, agent):
        """run_autonomous_investigation should sever toxic edge and drop blast radius to 0."""
        # Run autonomous investigation
        result = agent.run_autonomous_investigation("pod-ingress-7b4d")
        assert result["status"] == "CONTAINED_SUCCESSFULLY"
        assert len(result["trace"]) >= 4, f"Expected at least 4 trace steps, got {len(result['trace'])}"

        # Post-check: verifying with tool directly
        remaining_paths = agent.tool_find_attack_paths("pod-ingress-7b4d")
        assert len(remaining_paths) == 0, "No paths should remain after autonomous severing"

        # Re-seed for subsequent tests
        seed_graph()


# ==============================================================================
# 3. SECOPS AI COPILOT GROUNDING & PATTERN MATCHING TESTS
# ==============================================================================

class TestSecOpsChatGrounding:
    def test_chat_employee_workload_reduction(self, agent):
        """Asking about employee savings should return MTTR drop (4.2h to 63ms) and ROI."""
        res = agent.chat_secops_query("how much work we reduce the employees")
        assert "answer" in res
        assert "99.9% Reduction in MTTR" in res["answer"]
        assert "63 milliseconds" in res["answer"]
        assert "2,400,000" in res["answer"]
        assert res["cypher_used"] is not None
        assert "pod-ingress-7b4d" in res["highlight_nodes"]

    def test_chat_containment_pipeline(self, agent):
        """Asking how attack was contained should explain 4-step pipeline and edge cut."""
        res = agent.chat_secops_query("How was the attack contained and fixed?")
        assert "4-Step Containment Pipeline" in res["answer"]
        assert "Step 1 · Ingress Breach" in res["answer"]
        assert "Step 3 · Toxic Trust Edge Severed" in res["answer"]
        assert "DELETE rel" in res["cypher_used"]

    def test_chat_falkordb_speed_advantage(self, agent):
        """Asking about speed should explain GraphBLAS and 63ms latency."""
        res = agent.chat_secops_query("Why is FalkorDB 240,000x faster than legacy SQL?")
        assert "GraphBLAS" in res["answer"]
        assert "63ms" in res["answer"]
        assert "3.1 milliseconds" in res["answer"]

    def test_chat_blast_radius(self, agent):
        """Asking about blast radius should compute score and at-risk assets."""
        res = agent.chat_secops_query("What is the blast radius?")
        assert "Blast Radius" in res["answer"]
        assert "Score:" in res["answer"]

    def test_chat_iam_roles(self, agent):
        """Asking about IAM roles should inspect role permissions."""
        res = agent.chat_secops_query("Show me all IAM roles")
        assert "IAM Roles" in res["answer"]
        assert "MATCH (r:IAMRole)" in res["cypher_used"]

    def test_chat_databases(self, agent):
        """Asking about databases should report PII databases."""
        res = agent.chat_secops_query("Which databases contain PII?")
        assert "Databases" in res["answer"]
        assert "PII" in res["answer"]


# ==============================================================================
# 4. FASTAPI REST API ENDPOINT TESTS
# ==============================================================================

class TestFastAPIEndpoints:
    def test_health_endpoint(self, client):
        """GET /api/health should return 200 OK and FalkorDB status."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["engine"] == "FalkorDB"

    def test_get_graph_endpoint(self, client):
        """GET /api/graph should return valid nodes and edges."""
        response = client.get("/api/graph")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data

    def test_get_nodes_endpoint(self, client):
        """GET /api/nodes should return catalog for selection dropdown."""
        response = client.get("/api/nodes")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert len(data["nodes"]) > 0

    def test_get_asset_details(self, client):
        """GET /api/asset/pod-ingress-7b4d should return asset properties."""
        response = client.get("/api/asset/pod-ingress-7b4d")
        assert response.status_code == 200
        data = response.json()
        assert data["asset_id"] == "pod-ingress-7b4d"

    def test_investigate_endpoint(self, client):
        """POST /api/investigate should trigger multi-hop analysis and edge cut."""
        response = client.post("/api/investigate", json={"node_id": "pod-ingress-7b4d"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "CONTAINED_SUCCESSFULLY"
        assert "trace" in data
        assert len(data["trace"]) >= 4

    def test_remediate_cloud_endpoint(self, client):
        """POST /api/remediate-cloud should return AWS, K8s, and Terraform dispatches."""
        response = client.post("/api/remediate-cloud", json={})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "remediated"
        assert len(data["actions_dispatched"]) == 3
        assert data["records_secured"] == 2400000

    def test_chat_endpoint(self, client):
        """POST /api/chat should return structured answer with cypher_used."""
        response = client.post("/api/chat", json={
            "message": "What is the blast radius?",
            "asset_id": "pod-ingress-7b4d"
        })
        assert response.status_code == 200
        data = response.json()
        assert "answer" in data
        assert "cypher_used" in data
        assert "highlight_nodes" in data

    def test_reset_graph_endpoint(self, client):
        """POST /api/reset-graph should re-seed and return reset_success."""
        response = client.post("/api/reset-graph")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "reset_success"


# ==============================================================================
# 5. FRONTEND ASSETS & CONFIGURATION INTEGRITY
# ==============================================================================

class TestFrontendAndConfigIntegrity:
    def test_index_html_has_critical_elements(self):
        """index.html must contain all IDs required by app.js."""
        index_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
        assert os.path.exists(index_path), "frontend/index.html must exist"
        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_ids = [
            "risk-donut",
            "chat-messages",
            "chat-input",
            "chat-form",
            "assistant-terminal",
            "btn-investigate",
            "btn-reset",
            "btn-cloud-fix",
            "btn-roi",
            "pipeline-hero",
            "pipeline-flow",
            "pipeline-broken-visual",
            "cloud-fix-modal",
            "roi-modal"
        ]
        for el_id in required_ids:
            assert f'id="{el_id}"' in content, f"Missing required element #{el_id} in index.html"

    def test_app_js_syntax_and_critical_functions(self):
        """app.js must define key functions and markdown parser."""
        app_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "app.js")
        assert os.path.exists(app_path), "frontend/app.js must exist"
        with open(app_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_tokens = [
            "formatMarkdown",
            "handleChatSubmit",
            "renderSvgTopology",
            "runAutonomousInvestigation",
            "toggleAssistant",
            "toggleCloudFixModal",
            "toggleRoiModal",
            "node-ai-highlighted"
        ]
        for token in required_tokens:
            assert token in content, f"Missing required token '{token}' in app.js"

    def test_vercel_json_validity(self):
        """vercel.json must be valid JSON with rewrites."""
        vercel_path = os.path.join(os.path.dirname(__file__), "..", "vercel.json")
        assert os.path.exists(vercel_path), "vercel.json must exist"
        with open(vercel_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "rewrites" in data
        rewrites = [r["source"] for r in data["rewrites"]]
        assert "/api/(.*)" in rewrites
        assert "/static/(.*)" in rewrites
        assert "/" in rewrites
