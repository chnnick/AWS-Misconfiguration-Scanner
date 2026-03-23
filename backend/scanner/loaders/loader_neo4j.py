#!/usr/bin/env python3
"""
Neo4j Data Loader - Loads nodes and relationships from collectors into Neo4j
"""

import json
import os
from neo4j import GraphDatabase
from dotenv import load_dotenv


class Neo4jLoader:
    def __init__(self):
        load_dotenv()
        
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER")
        password = os.getenv("NEO4J_PASSWORD")
        
        if not user or not password:
            raise ValueError("NEO4J_USER and NEO4J_PASSWORD must be set in .env")
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        print(f"Connected to Neo4j at {uri}")
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def load_collector_output(self, json_file):
        # Load nodes and relationships from collector JSON
        print(f"\nLoading {json_file}...")
        
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        nodes = data.get("nodes", {})
        relationships = data.get("relationships", [])
        
        # Load nodes
        for node_type, node_list in nodes.items():
            if node_list:
                print(f"  Creating {len(node_list)} {node_type} nodes...")
                with self.driver.session() as session:
                    for node in node_list:
                        session.execute_write(self._create_node, node_type, node)
        
        # Load relationships
        if relationships:
            print(f"  Creating {len(relationships)} relationships...")
            with self.driver.session() as session:
                for rel in relationships:
                    session.execute_write(self._create_relationship, rel)
        
        print(f"Loaded {json_file}")
    
    @staticmethod
    def _create_node(tx, node_type, node_data):
        # Create or update node in Neo4j
        
        if node_type == "EC2Instance":
            query = """
            MERGE (n:EC2Instance {instance_id: $instance_id})
            SET n.instance_type = $instance_type,
                n.region = $region,
                n.public_ip = $public_ip,
                n.private_ip = $private_ip,
                n.imdsv1_enabled = $imdsv1_enabled,
                n.has_public_ip = $has_public_ip
            """
            tx.run(query, **node_data)
        
        elif node_type == "S3Bucket":
            query = """
            MERGE (n:S3Bucket {bucket_name: $bucket_name})
            SET n.arn = $arn,
                n.region = $region
            """
            tx.run(query, **node_data)
        
        elif node_type == "S3Object":
            query = """
            MERGE (n:S3Object {object_key: $object_key, bucket_name: $bucket_name})
            SET n.size = $size,
                n.last_modified = $last_modified
            """
            tx.run(query, **node_data)
        
        elif node_type == "SecurityGroup":
            query = """
            MERGE (n:SecurityGroup {group_id: $group_id})
            SET n.group_name = $group_name,
                n.description = $description
            """
            tx.run(query, **node_data)
        
        elif node_type == "IAMRole":
            query = """
            MERGE (n:IAMRole {role_name: $role_name})
            SET n.arn = $arn
            """
            # Handle optional role_id field
            params = {k: v for k, v in node_data.items() if v is not None}
            tx.run(query, **params)
        
        elif node_type == "IAMUser":
            query = """
            MERGE (n:IAMUser {username: $username})
            SET n.arn = $arn,
                n.user_id = $user_id
            """
            tx.run(query, **node_data)
        
        elif node_type == "LambdaFunction":
            query = """
            MERGE (n:LambdaFunction {function_name: $function_name})
            SET n.arn = $arn,
                n.runtime = $runtime,
                n.region = $region,
                n.role = $role
            """
            tx.run(query, **node_data)
        
        elif node_type == "Secret":
            query = """
            MERGE (n:Secret {location: $location})
            SET n.type = $type,
                n.pattern = $pattern,
                n.exposure_level = $exposure_level
            """
            tx.run(query, **node_data)
        
        elif node_type == "Finding":
            query = """
            MERGE (n:Finding {finding_id: $finding_id})
            SET n.type = $type,
                n.severity = $severity,
                n.description = $description,
                n.remediation = $remediation,
                n.cis_control = $cis_control,
                n.owasp = $owasp
            """
            tx.run(query, **node_data)
    
    @staticmethod
    def _create_relationship(tx, rel_data):
        # Create relationship between nodes
        rel_type = rel_data["type"]
        from_type = rel_data["from_type"]
        from_id = rel_data["from_id"]
        to_type = rel_data["to_type"]
        to_id = rel_data["to_id"]
        
        # Node type to ID property mapping
        id_map = {
            "EC2Instance": "instance_id",
            "S3Bucket": "bucket_name",
            "S3Object": "object_key",
            "SecurityGroup": "group_id",
            "IAMRole": "role_name",
            "IAMUser": "username",
            "LambdaFunction": "function_name",
            "Secret": "location",
            "Finding": "finding_id"
        }
        
        from_prop = id_map.get(from_type, "id")
        to_prop = id_map.get(to_type, "id")
        
        query = f"""
        MATCH (from:{from_type} {{{from_prop}: $from_id}})
        MATCH (to:{to_type} {{{to_prop}: $to_id}})
        MERGE (from)-[r:{rel_type}]->(to)
        """
        
        tx.run(query, from_id=from_id, to_id=to_id)


def main():
    loader = Neo4jLoader()
    
    try:
        print("\n" + "=" * 60)
        print("CSPM Scanner - Neo4j Data Loader")
        print("=" * 60)
        
        # Collector output files
        files = [
            "findings_ec2.json",
            "findings_s3.json",
            "findings_iam.json",
            "findings_lambda.json"
        ]
        
        loaded = 0
        for filename in files:
            if os.path.exists(filename):
                loader.load_collector_output(filename)
                loaded += 1
            else:
                print(f"Skipping {filename} (not found)")
        
        if loaded == 0:
            print("\nNo collector outputs found!")
            print("\nRun collectors first:")
            print("  python collector_ec2.py")
            print("  python collector_s3.py")
            print("  python collector_iam.py")
            print("  python collector_lambda.py")
        else:
            print("\n" + "=" * 60)
            print(f"Successfully loaded {loaded} files into Neo4j")
            print("=" * 60)
            print("\nView your data:")
            print("  1. Open: http://localhost:7474")
            print("  2. Login: neo4j / cspm-password-123")
            print("  3. Query: MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 50")
        
    finally:
        loader.close()


if __name__ == "__main__":
    main()