import os
from git import Repo
import json
import pandas as pd
from neo4j import GraphDatabase

def clone_or_update_repo(repo_url, local_path):
    if os.path.exists(local_path):
        print(f"Updating the repository at {local_path}...")
        repo = Repo(local_path)
        origin = repo.remotes.origin
        origin.pull()
        print(f"Repository updated at {local_path}")
    else:
        print(f"Cloning the repository to {local_path}...")
        Repo.clone_from(repo_url, local_path)
        print(f"Repository cloned to {local_path}")

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

    def add_cve_data(self, df):
        with self.driver.session() as session:
            for index, row in df.iterrows():
                session.write_transaction(self._add_cve_data, row)

    @staticmethod
    def _add_cve_data(tx, row):
        query = (
            "MERGE (c:CVE {id: $cve_id}) "
            "SET c.state = $state, "
            "c.date_reserved = $date_reserved, "
            "c.date_published = $date_published, "
            "c.date_updated = $date_updated, "
            "c.description = $description, "
            "c.cvss_v3_1 = $cvss_v3_1, "
            "c.cvss_v4_0 = $cvss_v4_0, "
            "c.cvss_v2_0 = $cvss_v2_0, "
            "c.cwe_id = $cwe_id, "
            "c.affected_products = $affected_products, "
            "c.credits = $credits, "
            "c.impacts = $impacts, "
            "c.references = $references "
            "MERGE (a:CNA {name: $cna_name}) "
            "MERGE (a)-[:ASSIGNED]->(c)"
        )
        tx.run(query, 
               cve_id=row["CVE ID"], 
               state=row["State"], 
               date_reserved=row["Date Reserved"], 
               date_published=row["Date Published"], 
               date_updated=row["Date Updated"], 
               description=row["CVE Description"], 
               cvss_v3_1=row["CVSS Score (v3.1)"], 
               cvss_v4_0=row["CVSS Score (v4.0)"], 
               cvss_v2_0=row["CVSS Score (v2.0)"], 
               cwe_id=row["CWE ID"], 
               affected_products=row["Affected Products"], 
               credits=row["Credits"], 
               impacts=row["Impacts"], 
               references=row["References"], 
               cna_name=row["CNA Short Name"])

if __name__ == "__main__":
    repo_url = "https://github.com/CVEProject/cvelistV5.git"
    local_path = "CVEs"
    
    clone_or_update_repo(repo_url, local_path)
    
    all_rows = []
    base_dir = os.path.join(local_path, "cves")

    print("Processing CVE JSON files...")
    # Loop through each year directory
    for year_dir in os.listdir(base_dir):
        if year_dir.isdigit():
            year_path = os.path.join(base_dir, year_dir)
            if os.path.isdir(year_path):
                for root, dirs, files in os.walk(year_path):
                    for filename in files:
                        if filename.endswith(".json"):
                            filepath = os.path.join(root, filename)
                            try:
                                with open(filepath, "r") as file:
                                    cve_data = json.load(file)

                                    meta = cve_data.get("cveMetadata", {})
                                    containers = cve_data.get("containers", {})
                                    cna = containers.get("cna", {})

                                    cve_id = meta.get("cveId", None)
                                    state = meta.get("state", None)
                                    assigner_short = meta.get("assignerShortName", None)
                                    date_reserved = meta.get("dateReserved", None)
                                    date_published = meta.get("datePublished", None)
                                    date_updated = meta.get("dateUpdated", None)
                                    
                                    desc_en = next(
                                        (d.get("value") for d in cna.get("descriptions", []) if d.get("lang") == "en"),
                                        None
                                    )

                                    # Collect any CVSS base scores by version
                                    cvss_scores_v3 = [
                                        metric["cvssV3_1"]["baseScore"]
                                        for metric in cna.get("metrics", [])
                                        if "cvssV3_1" in metric
                                    ]
                                    cvss_scores_v4 = [
                                        metric["cvssV4_0"]["baseScore"]
                                        for metric in cna.get("metrics", [])
                                        if "cvssV4_0" in metric
                                    ]
                                    cvss_scores_v2 = [
                                        metric["cvssV2_0"]["baseScore"]
                                        for metric in cna.get("metrics", [])
                                        if "cvssV2_0" in metric
                                    ]

                                    # Only take the first score if available
                                    cvss_score_v3_1 = cvss_scores_v3[0] if cvss_scores_v3 else None
                                    cvss_score_v4_0 = cvss_scores_v4[0] if cvss_scores_v4 else None
                                    cvss_score_v2_0 = cvss_scores_v2[0] if cvss_scores_v2 else None

                                    # Only take the first CWE if present
                                    cwe_ids = []
                                    for problem_type in cna.get("problemTypes", []):
                                        for desc in problem_type.get("descriptions", []):
                                            if "cweId" in desc:
                                                cwe_ids.append(desc["cweId"])
                                    cwe_id = cwe_ids[0] if cwe_ids else None
                                    
                                    provider_meta = cna.get("providerMetadata", {})
                                    cna_short_name = provider_meta.get("shortName", None)

                                    # Collect affected products and versions
                                    affected_products = [
                                        f"{aff.get('vendor', 'n/a')} {aff.get('product', 'n/a')} {ver.get('version', 'n/a')}"
                                        for aff in cna.get("affected", [])
                                        for ver in aff.get("versions", [])
                                    ]

                                    # Collect credits
                                    credits = [
                                        f"{credit['value']} ({credit.get('type', 'unknown')})"
                                        for credit in cna.get("credits", [])
                                    ]

                                    # Collect impacts
                                    impacts = [
                                        impact.get("capecId", "unknown")
                                        for impact in cna.get("impacts", [])
                                    ]

                                    # Collect references
                                    references = [
                                        ref.get("url", "unknown")
                                        for ref in cna.get("references", [])
                                    ]

                                    all_rows.append({
                                        "CVE ID": cve_id,
                                        "State": state,
                                        "Assigner Org": assigner_short,
                                        "Date Reserved": date_reserved,
                                        "Date Published": date_published,
                                        "Date Updated": date_updated,
                                        "CVE Description": desc_en,
                                        "CVSS Score (v3.1)": cvss_score_v3_1,
                                        "CVSS Score (v4.0)": cvss_score_v4_0,
                                        "CVSS Score (v2.0)": cvss_score_v2_0,
                                        "CWE ID": cwe_id,
                                        "CNA Short Name": cna_short_name,
                                        "Affected Products": affected_products,
                                        "Credits": credits,
                                        "Impacts": impacts,
                                        "References": references
                                    })
                            except Exception as e:
                                print(f"Error processing file {filepath}: {e}")

    df = pd.DataFrame(all_rows)
    print("DataFrame created with CVE data:")
    print(df.head())

    # Add data to Neo4j
    print("Adding data to Neo4j database...")
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "CVEData2025")

    cve_graph = CVEGraph(uri, user, password)
    cve_graph.add_cve_data(df)
    cve_graph.close()
    print("Data added to Neo4j database successfully.")
