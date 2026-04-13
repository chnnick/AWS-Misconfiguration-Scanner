"""
Neo4j Client: Handles all database connections and queries
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()


class Neo4jClient:
    def __init__(self):
        uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        user = os.getenv("NEO4J_USER")
        password = os.getenv("NEO4J_PASSWORD")
        
        if not user or not password:
            raise ValueError("NEO4J_USER and NEO4J_PASSWORD must be set in .env")
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        print(f"Neo4j client connected to {uri}")
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def get_all_findings(self):
        # Get all findings from Neo4j
        with self.driver.session() as session:
            result = session.run("""
                MATCH (resource)-[:HAS_FINDING]->(f:Finding)
                RETURN f.finding_id as id,
                       f.type as type,
                       f.severity as severity,
                       f.description as description,
                       f.remediation as remediation,
                       f.cis_control as cis_control,
                       f.owasp as owasp,
                       labels(resource)[0] as resource_type
                ORDER BY 
                    CASE f.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            """)
            return [dict(record) for record in result]
    
    def get_findings_by_severity(self, severity):
        # Get findings filtered by severity level: CRITICAL, HIGH, MEDIUM, LOW
        with self.driver.session() as session:
            result = session.run("""
                MATCH (resource)-[:HAS_FINDING]->(f:Finding {severity: $severity})
                RETURN f.finding_id as id,
                       f.type as type,
                       f.severity as severity,
                       f.description as description,
                       f.remediation as remediation,
                       f.cis_control as cis_control,
                       f.owasp as owasp,
                       labels(resource)[0] as resource_type
            """, severity=severity)
            return [dict(record) for record in result]
    
    def get_graph_data(self, limit=100):
        # Get nodes and relationships for graph visualization
        with self.driver.session() as session:
            result = session.run("""
                MATCH (n)-[r]->(m)
                RETURN n, r, m
                LIMIT $limit
            """, limit=limit)
            
            nodes = []
            edges = []
            node_ids = set()
            
            for record in result:
                # Add source node
                source_node = record['n']
                source_id = source_node.element_id
                
                if source_id not in node_ids:
                    nodes.append({
                        'id': source_id,
                        'label': list(source_node.labels)[0],
                        'properties': dict(source_node)
                    })
                    node_ids.add(source_id)
                
                # Add target node
                target_node = record['m']
                target_id = target_node.element_id
                
                if target_id not in node_ids:
                    nodes.append({
                        'id': target_id,
                        'label': list(target_node.labels)[0],
                        'properties': dict(target_node)
                    })
                    node_ids.add(target_id)
                
                # Add relationship
                rel = record['r']
                edges.append({
                    'source': source_id,
                    'target': target_id,
                    'type': rel.type
                })
            
            return {'nodes': nodes, 'edges': edges}
    
    def get_statistics(self):
        # Get summary statistics about the environment
        with self.driver.session() as session:
            # Count findings by severity
            severity_result = session.run("""
                MATCH (f:Finding)
                RETURN f.severity as severity, count(f) as count
                ORDER BY 
                    CASE f.severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            """)
            
            # Count resources by type
            resource_result = session.run("""
                MATCH (n)
                WHERE NOT n:Finding
                WITH labels(n)[0] as type, count(n) as count
                WHERE type IS NOT NULL
                RETURN type, count
                ORDER BY count DESC
            """)
            
            # Get total counts
            totals_result = session.run("""
                MATCH (f:Finding)
                WITH count(f) as total_findings
                MATCH (n)
                WHERE NOT n:Finding
                RETURN total_findings, count(n) as total_resources
            """)
            totals = totals_result.single()
            
            return {
                'findings_by_severity': [dict(r) for r in severity_result],
                'resources_by_type': [dict(r) for r in resource_result],
                'total_findings': totals['total_findings'] if totals else 0,
                'total_resources': totals['total_resources'] if totals else 0
            }
    
    def get_ec2_instances(self):
        # Get all EC2 instances
        with self.driver.session() as session:
            result = session.run("""
                MATCH (e:EC2Instance)
                OPTIONAL MATCH (e)-[:HAS_FINDING]->(f:Finding)
                RETURN e.instance_id as instance_id,
                       e.instance_type as instance_type,
                       e.region as region,
                       e.public_ip as public_ip,
                       e.imdsv1_enabled as imdsv1_enabled,
                       collect(f.severity) as findings
            """)
            return [dict(record) for record in result]
    
    def get_s3_buckets(self):
        # Get all S3 buckets
        with self.driver.session() as session:
            result = session.run("""
                MATCH (s:S3Bucket)
                OPTIONAL MATCH (s)-[:HAS_FINDING]->(f:Finding)
                RETURN s.bucket_name as bucket_name,
                       s.region as region,
                       s.arn as arn,
                       collect(f.severity) as findings
            """)
            return [dict(record) for record in result]

    def get_findings_with_resources(self):
        # Get all findings with their parent resource type and properties for in-memory scoring
        with self.driver.session() as session:
            result = session.run("""
                MATCH (resource)-[:HAS_FINDING]->(f:Finding)
                RETURN f.finding_id as finding_id,
                       f.type as type,
                       f.severity as severity,
                       f.description as description,
                       f.remediation as remediation,
                       f.cis_control as cis_control,
                       f.owasp as owasp,
                       labels(resource)[0] as resource_type,
                       properties(resource) as resource_props
            """)
            return [dict(record) for record in result]

    def get_finding_with_resource(self, finding_id):
        # Get a single finding with its parent resource type and properties
        with self.driver.session() as session:
            result = session.run("""
                MATCH (resource)-[:HAS_FINDING]->(f:Finding {finding_id: $finding_id})
                RETURN f.finding_id as finding_id,
                       f.type as type,
                       f.severity as severity,
                       f.description as description,
                       f.remediation as remediation,
                       f.cis_control as cis_control,
                       f.owasp as owasp,
                       labels(resource)[0] as resource_type,
                       properties(resource) as resource_props
            """, finding_id=finding_id)
            record = result.single()
            return dict(record) if record else None

neo4j_client = Neo4jClient()