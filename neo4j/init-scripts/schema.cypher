// ============================================
// Scanner - Neo4j Schema Initialization
// Runs automatically when Neo4j container starts
// ============================================

// Indexes
CREATE INDEX s3_bucket_name IF NOT EXISTS
FOR (n:S3Bucket) ON (n.bucket_name);

CREATE INDEX s3_bucket_region IF NOT EXISTS
FOR (n:S3Bucket) ON (n.region);

CREATE INDEX ec2_instance_id IF NOT EXISTS
FOR (n:EC2Instance) ON (n.instance_id);

CREATE INDEX ec2_instance_region IF NOT EXISTS
FOR (n:EC2Instance) ON (n.region);

CREATE INDEX security_group_id IF NOT EXISTS
FOR (n:SecurityGroup) ON (n.group_id);

CREATE INDEX secret_type IF NOT EXISTS
FOR (n:Secret) ON (n.type);

CREATE INDEX secret_location IF NOT EXISTS
FOR (n:Secret) ON (n.location);

CREATE INDEX finding_severity IF NOT EXISTS
FOR (n:Finding) ON (n.severity);

CREATE INDEX finding_type IF NOT EXISTS
FOR (n:Finding) ON (n.type);

CREATE CONSTRAINT s3_bucket_unique IF NOT EXISTS
FOR (n:S3Bucket) REQUIRE n.bucket_name IS UNIQUE;

CREATE CONSTRAINT ec2_instance_unique IF NOT EXISTS
FOR (n:EC2Instance) REQUIRE n.instance_id IS UNIQUE;

CREATE CONSTRAINT security_group_unique IF NOT EXISTS
FOR (n:SecurityGroup) REQUIRE n.group_id IS UNIQUE;

// Consider uniqueness instead of just location
CREATE CONSTRAINT secret_unique IF NOT EXISTS
FOR (n:Secret) REQUIRE (n.location, n.type) IS UNIQUE;

CREATE CONSTRAINT finding_id_unique IF NOT EXISTS
FOR (n:Finding) REQUIRE n.finding_id IS UNIQUE;