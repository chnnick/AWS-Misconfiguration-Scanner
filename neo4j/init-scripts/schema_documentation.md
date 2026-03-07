# Neo4j Graph Database - Documentation

## Table of Contents
1. [Overview](#overview)
2. [Graph Structure](#graph-structure)
3. [Node Types](#node-types)
4. [Relationship Types](#relationship-types)
5. [Attack Path Analysis](#attack-path-analysis)
6. [Determining Damage & Blast Radius](#determining-damage--blast-radius)
7. [Accessing Stored Information](#accessing-stored-information)
8. [Example Queries](#example-queries)
9. [Risk Scoring Model](#risk-scoring-model)

---

## Overview

Our CSPM scanner uses a **graph database (Neo4j)** to store AWS resource configurations and their relationships. Unlike traditional relational databases, graph databases excel at finding **connections** and **attack paths** across resources.

**Why Graph Database?**
- **Attack Path Discovery:** Easily trace how an attacker moves from one resource to another
- **Blast Radius Calculation:** Quickly find all resources affected by a single compromise
- **Relationship Queries:** Answer questions like "Which EC2 instances can access my sensitive S3 buckets?"
- **Visual Representation:** See the entire infrastructure and vulnerabilities in one view

---

## Graph Structure

### Visual Representation

```
                    ┌──────────────┐
                    │   Finding    │
                    │ (IMDSv1)     │
                    └──────────────┘
                           ↑
                           │ HAS_FINDING
                           │
    ┌──────────────────────┴───────────────────────┐
    │         EC2 Instance                         │
    │  - IMDSv1 enabled (SSRF vulnerable)          │
    │  - Public IP: 54.123.45.67                   │
    │  - Risk Score: 90/100                        │
    └──────┬───────────────────────┬───────────────┘
           │                       │
           │ HAS_ROLE              │ HAS_SECURITY_GROUP
           ↓                       ↓
    ┌─────────────┐         ┌─────────────┐
    │  IAM Role   │         │Security Grp │
    │S3FullAccess │         │  Open SSH   │
    └──────┬──────┘         └─────────────┘
           │
           │ CAN_ACCESS
           ↓
    ┌─────────────────────────────────────┐
    │      S3 Bucket (Public)              │
    │  - Block Public Access: OFF          │
    │  - Contains secrets                  │
    │  - Risk Score: 95/100                │
    └──────┬──────────────────────────────┘
           │
           │ CONTAINS
           ↓
    ┌─────────────┐         ┌──────────────┐
    │  S3 Object  │────────>│    Secret    │
    │   .env      │ CONTAINS│ AWS_KEY_ID   │
    └─────────────┘         └──────────────┘
                                    │
                                    │ triggers
                                    ↓
                            ┌──────────────┐
                            │   Finding    │
                            │(Public Data) │
                            └──────────────┘
```

This graph shows the attack chain from the `cloud_breach_s3` scenario:
1. Attacker exploits IMDSv1 on EC2
2. Steals IAM credentials
3. Uses credentials to access S3 bucket
4. Exfiltrates secrets from bucket

---

## Node Types

### 1. S3Bucket Node

**Represents:** AWS S3 storage buckets

**Properties:**
```
bucket_name:          String (unique) - Bucket identifier
arn:                  String - AWS Resource Name
region:               String - AWS region (e.g., "us-east-1")
is_public:            Boolean - Whether bucket is publicly accessible
acl:                  String - Access Control List setting
encryption_enabled:   Boolean - Server-side encryption status
versioning_enabled:   Boolean - Version control enabled
block_public_access:  Boolean - Block Public Access enabled
risk_score:           Integer (0-100) - Calculated risk
severity:             String - "CRITICAL", "HIGH", "MEDIUM", "LOW"
```

**Example:**
```json
{
  "bucket_name": "cspm-test-public-anjl",
  "is_public": true,
  "acl": "public-read",
  "encryption_enabled": false,
  "risk_score": 95,
  "severity": "CRITICAL"
}
```

---

### 2. EC2Instance Node

**Represents:** AWS EC2 virtual machines

**Properties:**
```
instance_id:       String (unique) - EC2 identifier
instance_type:     String - Instance size (e.g., "t2.micro")
region:            String - AWS region
public_ip:         String - Public IP address
private_ip:        String - Private IP address
imdsv1_enabled:    Boolean - IMDSv1 allowed (SSRF vulnerable)
has_public_ip:     Boolean - Internet-accessible
risk_score:        Integer (0-100) - Calculated risk
severity:          String - "CRITICAL", "HIGH", "MEDIUM", "LOW"
```

**Example:**
```json
{
  "instance_id": "i-0abc123def456",
  "public_ip": "54.123.45.67",
  "imdsv1_enabled": true,
  "risk_score": 90,
  "severity": "CRITICAL"
}
```

---

### 3. IAMRole Node

**Represents:** AWS IAM roles attached to EC2

**Properties:**
```
role_name:         String (unique) - Role identifier
arn:               String - AWS Resource Name
managed_policies:  Array[String] - Attached AWS policies
```

**Example:**
```json
{
  "role_name": "cg-banking-WAF-Role-anjl",
  "managed_policies": ["AmazonS3FullAccess", "CloudWatchLogsFullAccess"]
}
```

---

### 4. Secret Node

**Represents:** Hardcoded credentials found in resources

**Properties:**
```
location:         String (unique) - Where secret was found
type:             String - Credential type
pattern:          String - Matched pattern
exposure_level:   String - "PUBLIC" or "PRIVATE"
```

**Example:**
```json
{
  "location": "cspm-test-public-anjl/.env",
  "type": "AWS_ACCESS_KEY",
  "pattern": "AKIA...",
  "exposure_level": "PUBLIC"
}
```

---

### 5. Finding Node

**Represents:** Detected security misconfigurations

**Properties:**
```
finding_id:    String (unique) - Finding identifier
type:          String - Misconfiguration type
severity:      String - "CRITICAL", "HIGH", "MEDIUM", "LOW"
cis_control:   String - CIS Benchmark reference
owasp:         String - OWASP Top 10 reference
description:   String - What's wrong
remediation:   String - How to fix
```

**Example:**
```json
{
  "finding_id": "FINDING-001",
  "type": "PUBLIC_S3_BUCKET",
  "severity": "CRITICAL",
  "cis_control": "2.1.5",
  "owasp": "A01:2021",
  "description": "S3 bucket is publicly accessible",
  "remediation": "Enable Block Public Access settings"
}
```

---

## Relationship Types

### Summary Table

| Relationship | From | To | Meaning |
|--------------|------|-----|---------|
| CONTAINS | S3Bucket | S3Object | Bucket contains files |
| CONTAINS | S3Object | Secret | File contains secrets |
| HAS_FINDING | S3Bucket/EC2 | Finding | Resource has security issue |
| HAS_SECURITY_GROUP | EC2Instance | SecurityGroup | EC2 has firewall rules |
| HAS_ROLE | EC2Instance | IAMRole | EC2 has permissions |
| CAN_ACCESS | IAMRole | S3Bucket | Role can access bucket |

### Detailed Relationship Descriptions

#### 1. CONTAINS
- `(S3Bucket)-[:CONTAINS]->(S3Object)` - Bucket contains file
- `(S3Object)-[:CONTAINS]->(Secret)` - File contains secret

#### 2. HAS_FINDING
- `(S3Bucket)-[:HAS_FINDING]->(Finding)` - Bucket has issue
- `(EC2Instance)-[:HAS_FINDING]->(Finding)` - Instance has issue

#### 3. HAS_SECURITY_GROUP
- `(EC2Instance)-[:HAS_SECURITY_GROUP]->(SecurityGroup)` - Instance has firewall

#### 4. HAS_ROLE
- `(EC2Instance)-[:HAS_ROLE]->(IAMRole)` - Instance has permissions

#### 5. CAN_ACCESS
- `(IAMRole)-[:CAN_ACCESS]->(S3Bucket)` - Role can access bucket (models attack path!)

---

## Attack Path Analysis

### Finding Attack Paths

**Query: Find complete cloud_breach_s3 attack chain**
```cypher
MATCH path = (e:EC2Instance {imdsv1_enabled: true})
             -[:HAS_ROLE]->(r:IAMRole)
             -[:CAN_ACCESS]->(b:S3Bucket)
             -[:CONTAINS*]->(s:Secret)
WHERE 'AmazonS3FullAccess' IN r.managed_policies
RETURN path;
```

**What this finds:**
1. EC2 with IMDSv1 vulnerability
2. IAM role with S3FullAccess attached
3. S3 buckets the role can access
4. Secrets inside those buckets

**Attack steps:**
```
Attacker → SSRF exploit → Steal IAM creds → Access S3 → Download secrets
```

---

## Determining Damage & Blast Radius

### Use Case 1: "If this EC2 is compromised, what's the damage?"

**Query:**
```cypher
MATCH (e:EC2Instance {instance_id: "i-0abc123def456"})
      -[:HAS_ROLE]->(r:IAMRole)
      -[:CAN_ACCESS]->(b:S3Bucket)
OPTIONAL MATCH (b)-[:CONTAINS*]->(s:Secret)
RETURN e.instance_id as Instance,
       r.role_name as Role,
       collect(DISTINCT b.bucket_name) as AccessibleBuckets,
       count(DISTINCT s) as SecretsExposed;
```

**Output:**
```
Instance         | Role          | AccessibleBuckets              | SecretsExposed
i-0abc123def456  | banking-role  | ["prod-db", "customer-data"]   | 15
```

**Interpretation:** Compromising this EC2 exposes 15 secrets across 2 buckets. **High blast radius!**

---

### Use Case 2: "Which EC2 instances can access my sensitive bucket?"

**Query:**
```cypher
MATCH (b:S3Bucket {bucket_name: "prod-customer-data"})
      <-[:CAN_ACCESS]-(r:IAMRole)
      <-[:HAS_ROLE]-(e:EC2Instance)
RETURN e.instance_id,
       e.public_ip,
       e.imdsv1_enabled,
       e.risk_score
ORDER BY e.risk_score DESC;
```

**Output:**
```
instance_id    | public_ip     | imdsv1_enabled | risk_score
i-0abc123      | 54.123.45.67  | true           | 90
i-0def456      | 10.0.1.10     | false          | 30
```

**Interpretation:** 2 instances can access this bucket. First one is CRITICAL (public + IMDSv1), second is relatively safe.

---

### Use Case 3: "Show all publicly exposed secrets"

**Query:**
```cypher
MATCH (b:S3Bucket {is_public: true})-[:CONTAINS*]->(s:Secret)
RETURN b.bucket_name,
       s.type,
       s.location,
       b.risk_score
ORDER BY b.risk_score DESC;
```

**Output:**
```
bucket_name           | type           | location                  | risk_score
cspm-test-public-anjl | AWS_ACCESS_KEY | .../...env               | 95
prod-backup           | DB_PASSWORD    | .../config.json          | 95
```

**Interpretation:** 2 secrets publicly exposed. **Immediate action required!**

---

## Accessing Stored Information

### Method 1: Neo4j Browser (Visual Interface)

**URL:** `http://localhost:7474`

**Login:**
- Username: `neo4j`
- Password: `cspm-password-123`

**Steps:**
1. Open browser and navigate to `http://localhost:7474`
2. Login with credentials
3. Type Cypher query in command bar at top
4. Press Enter or click blue play button
5. View results as:
   - **Graph visualization** (default) - see nodes and relationships
   - **Table view** - structured data in rows/columns
   - **Text view** - raw data

**Example session:**
```cypher
// View all S3 buckets
MATCH (b:S3Bucket) RETURN b LIMIT 10;
```

---

### Method 2: Python Scripts

**Install driver:**
```bash
pip install neo4j
```

**Example script:**
```python
from neo4j import GraphDatabase

class Neo4jConnection:
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="cspm-password-123"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def close(self):
        self.driver.close()
    
    def query(self, cypher_query):
        with self.driver.session() as session:
            result = session.run(cypher_query)
            return [record.data() for record in result]

# Usage
conn = Neo4jConnection()

# Find CRITICAL findings
findings = conn.query("""
    MATCH (resource)-[:HAS_FINDING]->(f:Finding {severity: 'CRITICAL'})
    RETURN resource, f
""")

for finding in findings:
    print(finding)

conn.close()
```

---

### Method 3: Command Line (cypher-shell)

**Access Neo4j shell:**
```bash
docker exec -it cspm-neo4j cypher-shell -u neo4j -p cspm-password-123
```

**Interactive queries:**
```cypher
neo4j> MATCH (n:Finding) RETURN count(n);
+----------+
| count(n) |
+----------+
| 5        |
+----------+

neo4j> :exit
```

---

## Example Queries

### Security Analysis Queries

**1. List all CRITICAL findings:**
```cypher
MATCH (resource)-[:HAS_FINDING]->(f:Finding {severity: "CRITICAL"})
RETURN labels(resource)[0] as ResourceType,
       COALESCE(resource.bucket_name, resource.instance_id) as ResourceID,
       f.type as FindingType,
       f.description as Description;
```

---

**2. Find resources with multiple vulnerabilities:**
```cypher
MATCH (resource)-[:HAS_FINDING]->(f:Finding)
WITH resource, count(f) as vulnerability_count, collect(f.type) as vulnerabilities
WHERE vulnerability_count >= 2
RETURN labels(resource)[0] as ResourceType,
       COALESCE(resource.bucket_name, resource.instance_id) as ResourceID,
       vulnerability_count,
       vulnerabilities
ORDER BY vulnerability_count DESC;
```

---

**3. Count findings by severity:**
```cypher
MATCH (f:Finding)
RETURN f.severity as Severity,
       count(f) as Count
ORDER BY 
  CASE f.severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
  END;
```

---

### Compliance Queries

**4. OWASP Top 10 compliance report:**
```cypher
MATCH (f:Finding)
WHERE f.owasp IS NOT NULL
RETURN f.owasp as OWASP_Category,
       count(f) as Violation_Count,
       collect(DISTINCT f.severity) as Severities
ORDER BY Violation_Count DESC;
```

---

**5. CIS Benchmark compliance report:**
```cypher
MATCH (f:Finding)
WHERE f.cis_control IS NOT NULL
RETURN f.cis_control as CIS_Control,
       count(f) as Violation_Count,
       collect(DISTINCT f.type) as Finding_Types
ORDER BY Violation_Count DESC;
```

---

### Operational Queries

**6. Top 10 riskiest resources:**
```cypher
MATCH (n)
WHERE n.risk_score IS NOT NULL
RETURN labels(n)[0] as Type,
       COALESCE(n.bucket_name, n.instance_id) as Resource,
       n.risk_score as Risk,
       n.severity as Severity
ORDER BY n.risk_score DESC
LIMIT 10;
```

---

**7. Summary dashboard statistics:**
```cypher
MATCH (s:S3Bucket) WITH count(s) as s3_count
MATCH (e:EC2Instance) WITH s3_count, count(e) as ec2_count
MATCH (f:Finding {severity: "CRITICAL"}) WITH s3_count, ec2_count, count(f) as critical_count
MATCH (f2:Finding) WITH s3_count, ec2_count, critical_count, count(f2) as total_findings
RETURN s3_count as S3Buckets,
       ec2_count as EC2Instances,
       critical_count as CriticalFindings,
       total_findings as TotalFindings;
```

---

## Risk Scoring Model

> **NOTE:** Risk scoring criteria and formulas are currently under development and will be updated in future iterations.. The scoring system will be based on industry-standard frameworks.
---

## Summary

### What You Can Do With This Graph

**Find attack paths** - Trace how attackers move through your infrastructure  
**Calculate blast radius** - See total impact of a single compromise  
**Answer relationship questions** - "Which EC2s can access sensitive data?"  
**Generate compliance reports** - OWASP Top 10, CIS Benchmarks  
**Prioritize fixes** - Focus on highest risk resources first  
**Visualize infrastructure** - See everything at once  

### Quick Reference

| Task | Where | Tool |
|------|-------|------|
| Visual exploration | `http://localhost:7474` | Neo4j Browser |
| Automated queries | Python scripts | neo4j-driver |
| Quick checks | Command line | cypher-shell |
| Export data | Neo4j Browser | Export CSV/JSON |

---

**For more queries, see `verification-queries.cypher`**