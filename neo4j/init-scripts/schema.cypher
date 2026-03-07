// ============================================
// Scanner - Neo4j Schema Initialization
// Runs automatically when Neo4j container starts
// Uses MERGE thus is safe to run multiple times
// ============================================


// Indexes for fast lookups
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


// Unique constraints
CREATE CONSTRAINT s3_bucket_unique IF NOT EXISTS
FOR (n:S3Bucket) REQUIRE n.bucket_name IS UNIQUE;

CREATE CONSTRAINT ec2_instance_unique IF NOT EXISTS
FOR (n:EC2Instance) REQUIRE n.instance_id IS UNIQUE;

CREATE CONSTRAINT security_group_unique IF NOT EXISTS
FOR (n:SecurityGroup) REQUIRE n.group_id IS UNIQUE;

CREATE CONSTRAINT secret_location_unique IF NOT EXISTS
FOR (n:Secret) REQUIRE n.location IS UNIQUE;

CREATE CONSTRAINT finding_id_unique IF NOT EXISTS
FOR (n:Finding) REQUIRE n.finding_id IS UNIQUE;


// Test data - delete when using real AWS resources
// Public S3 bucket with exposed secrets
MERGE (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
ON CREATE SET
  b.arn                  = "arn:aws:s3:::cspm-test-public-anjl",
  b.region               = "us-east-1",
  b.is_public            = true,
  b.acl                  = "public-read",
  b.encryption_enabled   = false,
  b.versioning_enabled   = false,
  b.block_public_access  = false,
  b.risk_score           = 95,
  b.severity             = "CRITICAL";

// Private bucket without encryption
MERGE (b2:S3Bucket {bucket_name: "cspm-test-unencrypted-anjl"})
ON CREATE SET
  b2.arn                  = "arn:aws:s3:::cspm-test-unencrypted-anjl",
  b2.region               = "us-east-1",
  b2.is_public            = false,
  b2.acl                  = "private",
  b2.encryption_enabled   = false,
  b2.versioning_enabled   = false,
  b2.block_public_access  = true,
  b2.risk_score           = 50,
  b2.severity             = "MEDIUM";

MERGE (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
ON CREATE SET
  o.size         = 512,
  o.content_type = "text/plain";

MERGE (s:Secret {location: "cspm-test-public-anjl/.env"})
ON CREATE SET
  s.type           = "AWS_ACCESS_KEY",
  s.pattern        = "AKIA...",
  s.exposure_level = "PUBLIC";

// EC2 with IMDSv1 vulnerability
MERGE (e:EC2Instance {instance_id: "i-0abc123def456"})
ON CREATE SET
  e.instance_type    = "t2.micro",
  e.region           = "us-east-1",
  e.public_ip        = "54.123.45.67",
  e.private_ip       = "10.0.1.5",
  e.imdsv1_enabled   = true,
  e.has_public_ip    = true,
  e.risk_score       = 80,
  e.severity         = "HIGH";

MERGE (sg:SecurityGroup {group_id: "sg-0abc123"})
ON CREATE SET
  sg.group_name   = "cspm-test-open-ssh",
  sg.description  = "Allows SSH from anywhere",
  sg.vpc_id       = "vpc-0abc123",
  sg.open_ssh     = true,
  sg.open_rdp     = false,
  sg.cidr_block   = "0.0.0.0/0";

MERGE (f:Finding {finding_id: "FINDING-001"})
ON CREATE SET
  f.type         = "PUBLIC_S3_BUCKET",
  f.severity     = "CRITICAL",
  f.cis_control  = "2.1.5",
  f.owasp        = "A01:2021",
  f.description  = "S3 bucket is publicly accessible",
  f.remediation  = "Enable Block Public Access settings on the bucket";


// Relationships
MATCH (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
MATCH (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
MERGE (b)-[:CONTAINS]->(o);

MATCH (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
MATCH (s:Secret {location: "cspm-test-public-anjl/.env"})
MERGE (o)-[:CONTAINS]->(s);

MATCH (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
MATCH (f:Finding {finding_id: "FINDING-001"})
MERGE (b)-[:HAS_FINDING]->(f);

MATCH (e:EC2Instance {instance_id: "i-0abc123def456"})
MATCH (sg:SecurityGroup {group_id: "sg-0abc123"})
MERGE (e)-[:HAS_SECURITY_GROUP]->(sg);