import os
from neo4j import GraphDatabase

class CVEGraph:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def create_cve_and_cna(self, cve_id, cna_name):
        with self.driver.session() as session:
            session.write_transaction(self._create_and_link, cve_id, cna_name)

    @staticmethod
    def _create_and_link(tx, cve_id, cna_name):
        query = (
            "MERGE (c:CVE {id: $cve_id}) "
            "MERGE (a:CNA {name: $cna_name}) "
            "MERGE (a)-[:ASSIGNED]->(c)"
        )
        tx.run(query, cve_id=cve_id, cna_name=cna_name)

if __name__ == "__main__":
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "CVEData2025")

    cve_graph = CVEGraph(uri, user, password)
    
    # Example data
    cve_graph.create_cve_and_cna("CVE-2021-34527", "Microsoft")
    cve_graph.create_cve_and_cna("CVE-2021-44228", "Apache")
    
    cve_graph.close()
