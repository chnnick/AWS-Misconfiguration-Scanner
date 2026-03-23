# Neo4j Data Loader for AWS resource data from collectors into graph database

import json
from neo4j import GraphDatabase


class Neo4jLoader:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="cspm-password-123"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def close(self):
        self.driver.close()
    
    def load_s3_data(self, json_file="data/s3_data.json"):
        #Load S3 bucket data from collector JSON into Neo4j
        with open(json_file, 'r') as f:
            buckets = json.load(f)
        
        with self.driver.session() as session:
            for bucket in buckets:
                session.execute_write(self._create_s3_bucket, bucket)
        
        print(f"Loaded {len(buckets)} S3 buckets into Neo4j")
    
    def load_ec2_data(self, json_file="data/ec2_data.json"):
        #Load EC2 instance data from collector JSON into Neo4j
        with open(json_file, 'r') as f:
            instances = json.load(f)
        
        with self.driver.session() as session:
            for instance in instances:
                # Create EC2 instance node
                session.execute_write(self._create_ec2_instance, instance)
                
                # Create security groups and relationships
                if instance.get('security_groups'):
                    for sg in instance['security_groups']:
                        session.execute_write(self._create_security_group, sg)
                        session.execute_write(
                            self._link_ec2_to_sg, 
                            instance['instance_id'], 
                            sg['group_id']
                        )
                
                # Create IAM role and relationship
                if instance.get('iam_role_name'):
                    session.execute_write(self._create_iam_role, instance)
                    session.execute_write(
                        self._link_ec2_to_role,
                        instance['instance_id'],
                        instance['iam_role_name']
                    )
        
        print(f"Loaded {len(instances)} EC2 instances into Neo4j")
    
    def create_findings(self):
        # Run detection queries and create Finding nodes
        with self.driver.session() as session:
            # Finding: Public S3 buckets
            session.execute_write(self._detect_public_s3_buckets)
            
            # Finding: EC2 with IMDSv1 enabled
            session.execute_write(self._detect_imdsv1_instances)
            
            # Finding: Cloud breach S3 attack path
            session.execute_write(self._detect_cloud_breach_s3)
        
        print("Created findings based on detection queries")
    
    @staticmethod
    def _create_s3_bucket(tx, bucket):
        # Create or update S3 bucket node
        query = """
        MERGE (b:S3Bucket {bucket_name: $bucket_name})
        SET b.arn = $arn,
            b.region = $region,
            b.is_public = $is_public,
            b.acl = $acl,
            b.encryption_enabled = $encryption_enabled,
            b.versioning_enabled = $versioning_enabled,
            b.block_public_access = $block_public_access,
            b.risk_score = $risk_score,
            b.severity = $severity,
            b.tags = $tags
        """
        tx.run(query, 
            bucket_name=bucket['bucket_name'],
            arn=bucket.get('arn', ''),
            region=bucket.get('region', 'us-east-1'),
            is_public=bucket.get('is_public', False),
            acl=bucket.get('acl', 'private'),
            encryption_enabled=bucket.get('encryption_enabled', False),
            versioning_enabled=bucket.get('versioning_enabled', False),
            block_public_access=bucket.get('block_public_access', {}).get('BlockPublicAcls', False),
            risk_score=bucket.get('risk_score', 0),
            severity=bucket.get('severity', 'LOW'),
            tags=json.dumps(bucket.get('tags', {}))
        )
    
    @staticmethod
    def _create_ec2_instance(tx, instance):
        # Create or update EC2 instance node
        query = """
        MERGE (e:EC2Instance {instance_id: $instance_id})
        SET e.instance_type = $instance_type,
            e.region = $region,
            e.public_ip = $public_ip,
            e.private_ip = $private_ip,
            e.imdsv1_enabled = $imdsv1_enabled,
            e.has_public_ip = $has_public_ip,
            e.risk_score = $risk_score,
            e.severity = $severity,
            e.state = $state
        """
        tx.run(query,
            instance_id=instance['instance_id'],
            instance_type=instance.get('instance_type', 't2.micro'),
            region=instance.get('region', 'us-east-1'),
            public_ip=instance.get('public_ip'),
            private_ip=instance.get('private_ip'),
            imdsv1_enabled=instance.get('imdsv1_enabled', False),
            has_public_ip=instance.get('has_public_ip', False),
            risk_score=instance.get('risk_score', 0),
            severity=instance.get('severity', 'LOW'),
            state=instance.get('state', 'unknown')
        )
    
    @staticmethod
    def _create_security_group(tx, sg):
        # Create or update security group node
        query = """
        MERGE (sg:SecurityGroup {group_id: $group_id})
        SET sg.group_name = $group_name,
            sg.description = $description,
            sg.vpc_id = $vpc_id,
            sg.open_ssh = $open_ssh,
            sg.open_rdp = $open_rdp
        """
        tx.run(query,
            group_id=sg['group_id'],
            group_name=sg.get('group_name', ''),
            description=sg.get('description', ''),
            vpc_id=sg.get('vpc_id', ''),
            open_ssh=sg.get('has_open_ssh', False),
            open_rdp=sg.get('has_open_rdp', False)
        )
    
    @staticmethod
    def _create_iam_role(tx, instance):
        # Create or update IAM role node
        query = """
        MERGE (r:IAMRole {role_name: $role_name})
        SET r.arn = $arn,
            r.managed_policies = $managed_policies
        """
        tx.run(query,
            role_name=instance['iam_role_name'],
            arn=instance.get('iam_role_arn', ''),
            managed_policies=instance.get('managed_policies', [])
        )
    
    @staticmethod
    def _link_ec2_to_sg(tx, instance_id, group_id):
        # Create HAS_SECURITY_GROUP relationship
        query = """
        MATCH (e:EC2Instance {instance_id: $instance_id})
        MATCH (sg:SecurityGroup {group_id: $group_id})
        MERGE (e)-[:HAS_SECURITY_GROUP]->(sg)
        """
        tx.run(query, instance_id=instance_id, group_id=group_id)
    
    @staticmethod
    def _link_ec2_to_role(tx, instance_id, role_name):
        # Create HAS_ROLE relationship
        query = """
        MATCH (e:EC2Instance {instance_id: $instance_id})
        MATCH (r:IAMRole {role_name: $role_name})
        MERGE (e)-[:HAS_ROLE]->(r)
        """
        tx.run(query, instance_id=instance_id, role_name=role_name)
    
    @staticmethod
    def _detect_public_s3_buckets(tx):
        # Detect and create findings for public S3 buckets
        query = """
        MATCH (b:S3Bucket {is_public: true})
        MERGE (f:Finding {finding_id: 'PUBLIC_S3_' + b.bucket_name})
        SET f.type = 'PUBLIC_S3_BUCKET',
            f.severity = 'CRITICAL',
            f.cis_control = '2.1.5',
            f.owasp = 'A01:2021',
            f.description = 'S3 bucket ' + b.bucket_name + ' is publicly accessible',
            f.remediation = 'Enable Block Public Access settings on the bucket'
        MERGE (b)-[:HAS_FINDING]->(f)
        """
        tx.run(query)
    
    @staticmethod
    def _detect_imdsv1_instances(tx):
        # Detect and create findings for EC2 instances with IMDSv1 enabled
        query = """
        MATCH (e:EC2Instance {imdsv1_enabled: true})
        MERGE (f:Finding {finding_id: 'IMDSV1_' + e.instance_id})
        SET f.type = 'EC2_IMDSV1_ENABLED',
            f.severity = 'HIGH',
            f.cis_control = '5.6',
            f.owasp = 'A05:2021',
            f.description = 'EC2 instance ' + e.instance_id + ' has IMDSv1 enabled, vulnerable to SSRF attacks',
            f.remediation = 'Enable IMDSv2 by setting http_tokens = required in metadata_options'
        MERGE (e)-[:HAS_FINDING]->(f)
        """
        tx.run(query)
    
    @staticmethod
    def _detect_cloud_breach_s3(tx):
        # Detect cloud_breach_s3 attack pattern: EC2 with IMDSv1 + IAM role with S3FullAccess
        query = """
        MATCH (e:EC2Instance {imdsv1_enabled: true})-[:HAS_ROLE]->(r:IAMRole)
        WHERE 'AmazonS3FullAccess' IN r.managed_policies
        MERGE (f:Finding {finding_id: 'CLOUD_BREACH_S3_' + e.instance_id})
        SET f.type = 'CLOUD_BREACH_S3_PATTERN',
            f.severity = 'CRITICAL',
            f.cis_control = '5.6, 1.16',
            f.owasp = 'A05:2021',
            f.description = 'CRITICAL: EC2 instance ' + e.instance_id + ' has IMDSv1 enabled AND overly permissive IAM role with S3FullAccess. This is the cloud_breach_s3 attack pattern.',
            f.remediation = '1) Enable IMDSv2, 2) Replace S3FullAccess with least-privilege policy'
        MERGE (e)-[:HAS_FINDING]->(f)
        """
        tx.run(query)


def main():
    loader = Neo4jLoader()
    try:
        print("Starting data load into Neo4j...")
        
        # Load S3 data
        loader.load_s3_data("data/s3_data.json")
        
        # Load EC2 data
        loader.load_ec2_data("data/ec2_data.json")
        
        # Run detection queries and create findings
        loader.create_findings()
        
        print("\nData load complete")
        print("Access Neo4j Browser at http://localhost:7474")
        print("Run this query to view graph: MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 50")
        
    finally:
        loader.close()


if __name__ == "__main__":
    main()