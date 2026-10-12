"""
Test remediation: Autonomous edge severing in FalkorDB
"""
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("aegis_secops")

print("\n--- BEFORE REMEDIATION ---")
check_q = """
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN count(path) AS paths_count
"""
before = graph.query(check_q).result_set[0][0]
print(f"Active Attack Paths to Crown Jewel DB: {before}")

print("\n--- AGENT ACTION: Revoke Overprivileged IAM Role Attachment ---")
remediation_q = """
MATCH (p:Pod {id: 'pod-ingress-7b4d'})-[r:ASSUMES_ROLE]->(role:IAMRole {id: 'role-toxic-admin'})
DELETE r
RETURN count(r) AS revoked_links
"""
res = graph.query(remediation_q)
print(f"Remediation result: Revoked {res.result_set[0][0]} dangerous IAM attachment edge(s)")

print("\n--- AFTER REMEDIATION ---")
after = graph.query(check_q).result_set[0][0]
print(f"Active Attack Paths to Crown Jewel DB: {after}")
if after == 0:
    print("✅ SUCCESS: Threat completely neutralized! Blast radius reduced to 0.")
