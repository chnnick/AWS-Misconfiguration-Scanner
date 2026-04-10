// ============================================
// Test Seed Data
// ============================================

// --- S3 Buckets ---
MERGE (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
ON CREATE SET
  b.arn = "arn:aws:s3:::cspm-test-public-anjl",
  b.region = "us-east-1",
  b.is_public = true,
  b.acl = "public-read",
  b.encryption_enabled = false,
  b.versioning_enabled = false,
  b.block_public_access = false,
  b.is_test = true
ON MATCH SET
  b.region = "us-east-1",
  b.is_public = true,
  b.acl = "public-read",
  b.encryption_enabled = false,
  b.versioning_enabled = false,
  b.block_public_access = false;

MERGE (b2:S3Bucket {bucket_name: "cspm-test-unencrypted-anjl"})
ON CREATE SET
  b2.arn = "arn:aws:s3:::cspm-test-unencrypted-anjl",
  b2.region = "us-east-1",
  b2.is_public = false,
  b2.acl = "private",
  b2.encryption_enabled = false,
  b2.versioning_enabled = false,
  b2.block_public_access = true,
  b2.is_test = true
ON MATCH SET
  b2.encryption_enabled = false;


// --- Objects + Secrets ---
MERGE (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
ON CREATE SET
  o.size = 512,
  o.content_type = "text/plain",
  o.is_test = true;

MERGE (s:Secret {location: "cspm-test-public-anjl/.env", type: "AWS_ACCESS_KEY"})
ON CREATE SET
  s.pattern = "AKIA...",
  s.exposure_level = "PUBLIC",
  s.is_test = true;


// --- EC2 ---
MERGE (e:EC2Instance {instance_id: "i-0abc123def456"})
ON CREATE SET
  e.instance_type = "t2.micro",
  e.region = "us-east-1",
  e.public_ip = "54.123.45.67",
  e.private_ip = "10.0.1.5",
  e.imdsv1_enabled = true,
  e.has_public_ip = true,
  e.is_test = true;


// --- Security Group ---
MERGE (sg:SecurityGroup {group_id: "sg-0abc123"})
ON CREATE SET
  sg.group_name = "cspm-test-open-ssh",
  sg.description = "Allows SSH from anywhere",
  sg.vpc_id = "vpc-0abc123",
  sg.open_ssh = true,
  sg.cidr_block = "0.0.0.0/0",
  sg.is_test = true;


// --- Finding ---
MERGE (f:Finding {finding_id: "FINDING-001"})
ON CREATE SET
  f.type = "PUBLIC_S3_BUCKET",
  f.severity = "CRITICAL",
  f.description = "S3 bucket is publicly accessible",
  f.is_test = true;


// --- Relationships ---
MATCH (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
MATCH (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
MERGE (b)-[:CONTAINS]->(o);

MATCH (o:S3Object {key: ".env", bucket_name: "cspm-test-public-anjl"})
MATCH (s:Secret {location: "cspm-test-public-anjl/.env", type: "AWS_ACCESS_KEY"})
MERGE (o)-[:CONTAINS]->(s);

MATCH (b:S3Bucket {bucket_name: "cspm-test-public-anjl"})
MATCH (f:Finding {finding_id: "FINDING-001"})
MERGE (b)-[:HAS_FINDING]->(f);

MATCH (e:EC2Instance {instance_id: "i-0abc123def456"})
MATCH (sg:SecurityGroup {group_id: "sg-0abc123"})
MERGE (e)-[:HAS_SECURITY_GROUP]->(sg);