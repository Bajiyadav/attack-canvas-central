"""
AegisGraph: Cloud Infrastructure & Attack Path Seeder
Seeds a realistic multi-tier cloud topology in FalkorDB.
"""

from falkordb import FalkorDB
import sys

def seed_graph(graph_name: str = "aegis_secops"):
    print(f"Connecting to FalkorDB on localhost:6379...")
    db = FalkorDB(host="localhost", port=6379)
    graph = db.select_graph(graph_name)

    print(f"Clearing existing graph '{graph_name}'...")
    try:
        graph.delete()
        graph = db.select_graph(graph_name)
    except Exception as e:
        print(f"Graph initialization note: {e}")

    print("Seeding Cloud Security Topology nodes & edges...")

    # Build Cypher batch creation query
    cypher_query = """
    // 1. Internet & Ingress
    CREATE (net:Network {id: 'net-ext', name: 'Public Internet', type: 'Internet', risk_level: 'High'})
    CREATE (gw:Gateway {id: 'gw-ingress', name: 'api.acme-corp.cloud', port: 443, status: 'Active'})

    // 2. Microservices
    CREATE (svc_ingress:Service {id: 'svc-ingress', name: 'Ingress-Gateway-API', tier: 'Public', runtime: 'Java/SpringBoot', status: 'Active'})
    CREATE (svc_auth:Service {id: 'svc-auth', name: 'Auth-Microservice', tier: 'Internal', runtime: 'Go', status: 'Active'})
    CREATE (svc_order:Service {id: 'svc-order', name: 'Order-Processing', tier: 'Internal', runtime: 'NodeJS', status: 'Active'})
    CREATE (svc_payment:Service {id: 'svc-payment', name: 'Payment-Processor', tier: 'PCI-Protected', runtime: 'Rust', status: 'Active'})

    // 3. Kubernetes Pods
    CREATE (pod_ingress:Pod {id: 'pod-ingress-7b4d', name: 'pod-ingress-7b4d', ip: '10.244.1.42', namespace: 'public-zone', status: 'COMPROMISED'})
    CREATE (pod_auth:Pod {id: 'pod-auth-8f2a', name: 'pod-auth-8f2a', ip: '10.244.2.11', namespace: 'core-backend', status: 'Healthy'})
    CREATE (pod_order:Pod {id: 'pod-order-3c1e', name: 'pod-order-3c1e', ip: '10.244.2.89', namespace: 'core-backend', status: 'Healthy'})
    CREATE (pod_pay:Pod {id: 'pod-pay-9a0d', name: 'pod-pay-9a0d', ip: '10.244.3.5', namespace: 'pci-zone', status: 'Healthy'})

    // 4. Vulnerabilities
    CREATE (vuln_rce:Vulnerability {id: 'cve-2026-9912', cve: 'CVE-2026-9912', name: 'SpringCloud Remote Code Execution', severity: 'CRITICAL', cvss: 9.8, exploit_public: true})
    CREATE (vuln_proto:Vulnerability {id: 'cve-2025-4102', cve: 'CVE-2025-4102', name: 'NodeJS Prototype Pollution', severity: 'MEDIUM', cvss: 5.3, exploit_public: false})

    // 5. IAM Roles & Security Boundaries
    CREATE (role_pub:IAMRole {id: 'role-ingress-std', name: 'Role-Ingress-Standard', privileged: false, max_session_hrs: 1})
    CREATE (role_toxic:IAMRole {id: 'role-toxic-admin', name: 'Role-Overprivileged-ClusterAdmin', privileged: true, max_session_hrs: 12, flag: 'TOXIC_COMBINATION'})
    CREATE (role_payment:IAMRole {id: 'role-pci-worker', name: 'Role-PaymentVault-Worker', privileged: true, max_session_hrs: 2})

    // 6. Cloud Storage & Secrets Vault
    CREATE (s3_public:S3Bucket {id: 's3-public-cdn', name: 'acme-static-assets-cdn', is_public: true, encrypted: true})
    CREATE (s3_backups:S3Bucket {id: 's3-internal-backups', name: 'acme-internal-db-snapshots', is_public: false, encrypted: false, flag: 'UNENCRYPTED_BACKUP'})
    CREATE (secret_db:Secret {id: 'sec-db-master', name: 'RDS_POSTGRES_CROWN_CREDENTIAL', type: 'DatabaseCredential', rotation_days: 90})

    // 7. Databases (Crown Jewels)
    CREATE (db_customer:Database {id: 'db-customer-pii', name: 'Customer-Vault-Postgres', classification: 'CROWN_JEWEL', contains_pii: true, records_count: 2400000, encrypted_at_rest: true})
    CREATE (db_analytics:Database {id: 'db-clickhouse-analytics', name: 'ClickHouse-EventStream', classification: 'INTERNAL', contains_pii: false, records_count: 150000000, encrypted_at_rest: true})

    // Relationships (Edges)
    // Traffic routing
    CREATE (net)-[:ROUTES_TO {port: 443}]->(gw)
    CREATE (gw)-[:FORWARDS_TO]->(svc_ingress)
    CREATE (svc_ingress)-[:RUNS_ON]->(pod_ingress)

    // The Exploited Vulnerability
    CREATE (pod_ingress)-[:HAS_VULNERABILITY]->(vuln_rce)

    // Normal microservice communication
    CREATE (svc_ingress)-[:CALLS {protocol: 'gRPC'}]->(svc_auth)
    CREATE (svc_auth)-[:RUNS_ON]->(pod_auth)
    CREATE (svc_auth)-[:CALLS {protocol: 'REST'}]->(svc_order)
    CREATE (svc_order)-[:RUNS_ON]->(pod_order)
    CREATE (svc_order)-[:CALLS {protocol: 'mTLS'}]->(svc_payment)
    CREATE (svc_payment)-[:RUNS_ON]->(pod_pay)
    CREATE (pod_order)-[:HAS_VULNERABILITY]->(vuln_proto)

    // Legitimate IAM attachment
    CREATE (pod_pay)-[:ASSUMES_ROLE]->(role_payment)

    // === THE CRITICAL MULTI-HOP ATTACK PATH ===
    // Toxic flaw: Misconfigured service account token allows pod-ingress to assume ClusterAdmin!
    CREATE (pod_ingress)-[:ASSUMES_ROLE {via: 'Misconfigured ServiceAccount Token'}]->(role_toxic)
    // Overprivileged role can read internal backup bucket
    CREATE (role_toxic)-[:CAN_READ {policy: 's3:GetObjectOnAll'}]->(s3_backups)
    // Leaked DB credential stored in unencrypted backup
    CREATE (s3_backups)-[:EXPOSES_SECRET {discovered_in: 'env.backup.json'}]->(secret_db)
    // Master secret directly unlocks Crown Jewel database!
    CREATE (secret_db)-[:UNLOCKS_DATABASE {access_level: 'SUPERUSER'}]->(db_customer)

    // Normal analytics feed
    CREATE (pod_order)-[:WRITES_TO]->(db_analytics)
    """

    result = graph.query(cypher_query)
    print("Graph seeded successfully!")
    print(f"Nodes created: {result.nodes_created}, Relationships created: {result.relationships_created}")

    # Verify with a quick test query
    verify = graph.query("MATCH (n) RETURN count(n) AS total_nodes")
    for row in verify.result_set:
        print(f"Total nodes in '{graph_name}': {row[0]}")

if __name__ == "__main__":
    seed_graph()
