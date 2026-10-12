"""
Test script for FalkorDB multi-hop queries & graph algorithms
"""
from falkordb import FalkorDB

db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("aegis_secops")

print("\n--- 1. Multi-Hop Attack Path Discovery (From Pod to Database) ---")
q1 = """
MATCH path = (p:Pod {id: 'pod-ingress-7b4d'})-[*1..5]->(target:Database {contains_pii: true})
RETURN [n in nodes(path) | n.name] AS attack_chain, length(path) AS total_hops
"""
res1 = graph.query(q1)
for row in res1.result_set:
    print(f"🚨 Path Found ({row[1]} hops): {' -> '.join(row[0])}")

print("\n--- 2. Crown Jewel Blast Radius Check ---")
q2 = """
MATCH (compromised:Pod {id: 'pod-ingress-7b4d'})-[*1..4]->(sensitive)
WHERE (sensitive:Database) OR (sensitive:Secret) OR (sensitive:S3Bucket)
RETURN DISTINCT labels(sensitive)[0] AS type, sensitive.name AS name, sensitive.id AS id
"""
res2 = graph.query(q2)
for row in res2.result_set:
    print(f"⚠️ At-Risk Asset [{row[0]}]: {row[1]} (id: {row[2]})")

print("\n--- 3. Shortest Path from Ingress Gateway to Crown Jewel ---")
q3 = """
MATCH (start:Pod {id: 'pod-ingress-7b4d'}), (target:Database {id: 'db-customer-pii'})
RETURN shortestPath((start)-[*..6]->(target)) AS path
"""
res3 = graph.query(q3)
for row in res3.result_set:
    p = row[0]
    print(f"⚡ Shortest Attack Path: {p}")

