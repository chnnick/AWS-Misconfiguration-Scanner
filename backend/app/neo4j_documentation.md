# CloudSight: Neo4j Documentation

## Overview

This document describes the Neo4j integration  and how the frontend should interact with the API

---

## Primary File

### `backend/app/neo4j_client.py`
**Location:** `backend/app/neo4j_client.py`  
**Purpose:** Handles all Neo4j database connections and queries  

**Key Features:**
- Singleton client that manages Neo4j driver connection
- Methods to query findings, graph data, statistics, EC2 instances, and S3 buckets
- Automatic connection cleanup
- Error handling

**Methods:**
- `get_all_findings()`: Returns all security findings
- `get_findings_by_severity(severity)`: Filters findings by severity level
- `get_graph_data(limit)`: Returns nodes and edges for graph visualization
- `get_statistics()`: Returns summary statistics (counts by severity, resource type)
- `get_ec2_instances()`: Returns all EC2 instances with their findings
- `get_s3_buckets()`: Returns all S3 buckets with their findings
- `close()`: Closes the Neo4j connection

---

## Updated Files

### 1. `backend/app/main.py`

**New Endpoints:**
```python
@app.get("/api/findings")           # Get all findings
@app.get("/api/graph")              # Get graph visualization data
@app.get("/api/stats")              # Get summary statistics
@app.get("/api/ec2")                # Get EC2 instances
@app.get("/api/s3")                 # Get S3 buckets
```


## API Endpoints

### Base URL
```
http://localhost:8000
```

---

## Scanner Endpoints (POST)

These endpoints scan AWS resources and automatically load results into Neo4j.

### 1. Scan EC2 Instances
```http
POST /api/scanner/ec2
```

**Response:**
```json
{
  "scan_start": "2026-03-23T18:30:00Z",
  "duration_seconds": 5.2,
  "resource": "EC2",
  "total_findings": 3,
  "findings": [
    {
      "finding_id": "FINDING-ABC123",
      "type": "IMDSV1_ENABLED",
      "severity": "HIGH",
      "description": "IMDSv1 is enabled...",
      "remediation": "Set http_tokens = 'required'...",
      "cis_control": "5.6",
      "owasp": "A05:2021"
    }
  ],
  "relationships": [...]
}
```

---

### 2. Scan S3 Buckets
```http
POST /api/scanner/s3
```

**Response:** Same format as EC2

---

### 3. Scan Lambda Functions
```http
POST /api/scanner/lambda
```

**Response:** Same format as EC2

---

### 4. Scan IAM Resources
```http
POST /api/scanner/iam
```

**Response:** Same format as EC2

---

### 5. Scan All Resources
```http
POST /api/scanner/all
```

**Response:**
```json
{
  "scan_start": "2026-03-23T18:30:00Z",
  "duration_seconds": 25.8,
  "scans_completed": 4,
  "total_findings": 15,
  "results": {
    "ec2": {"findings": 3},
    "s3": {"findings": 7},
    "lambda": {"findings": 2},
    "iam": {"findings": 3}
  }
}
```

---

## Data Endpoints (GET)

These endpoints query data from Neo4j only after data is loaded

### 1. Get All Findings
```http
GET /api/findings
```

**Response:**
```json
[
  {
    "id": "FINDING-ABC123",
    "type": "IMDSV1_ENABLED",
    "severity": "HIGH",
    "description": "IMDSv1 is enabled. Unauthenticated requests allowed...",
    "remediation": "Set http_tokens = 'required' in metadata_options...",
    "cis_control": "5.6",
    "owasp": "A05:2021",
    "resource_type": "EC2Instance"
  },
  {
    "id": "FINDING-DEF456",
    "type": "BLOCK_PUBLIC_ACCESS_DISABLED",
    "severity": "CRITICAL",
    "description": "S3 bucket may be publicly accessible...",
    "remediation": "Enable all four Block Public Access settings...",
    "cis_control": "2.1.5",
    "owasp": "A01:2021",
    "resource_type": "S3Bucket"
  }
]
```

---

### 2. Get Findings by Severity
```http
GET /api/findings?severity=CRITICAL
```

**Query Parameters:**
- `severity` (string): CRITICAL, HIGH, MEDIUM, or LOW

**Response:** Same format as "Get All Findings" but filtered

---

### 3. Get Graph Visualization Data
```http
GET /api/graph?limit=100
```

**Query Parameters:**
- `limit`: Maximum number of relationships to return (default: 100)

**Response:**
```json
{
  "nodes": [
    {
      "id": "4:abc123:0",
      "label": "EC2Instance",
      "properties": {
        "instance_id": "i-0abc123",
        "instance_type": "t2.micro",
        "region": "us-east-1",
        "imdsv1_enabled": true,
        "has_public_ip": true
      }
    },
    {
      "id": "4:abc123:1",
      "label": "Finding",
      "properties": {
        "finding_id": "FINDING-ABC123",
        "type": "IMDSV1_ENABLED",
        "severity": "HIGH"
      }
    }
  ],
  "edges": [
    {
      "source": "4:abc123:0",
      "target": "4:abc123:1",
      "type": "HAS_FINDING"
    }
  ]
}
```

---

### 4. Get Summary Statistics
```http
GET /api/stats
```

**Response:**
```json
{
  "total_findings": 15,
  "total_resources": 42,
  "findings_by_severity": [
    {"severity": "CRITICAL", "count": 3},
    {"severity": "HIGH", "count": 7},
    {"severity": "MEDIUM", "count": 3},
    {"severity": "LOW", "count": 2}
  ],
  "resources_by_type": [
    {"type": "S3Bucket", "count": 15},
    {"type": "EC2Instance", "count": 8},
    {"type": "IAMRole", "count": 12},
    {"type": "LambdaFunction", "count": 5},
    {"type": "SecurityGroup", "count": 2}
  ]
}
```

---

### 5. Get EC2 Instances
```http
GET /api/ec2
```

**Response:**
```json
[
  {
    "instance_id": "i-0abc123",
    "instance_type": "t2.micro",
    "region": "us-east-1",
    "public_ip": "1.2.3.4",
    "imdsv1_enabled": true,
    "findings": ["HIGH", "MEDIUM"]
  }
]
```

---

### 6. Get S3 Buckets
```http
GET /api/s3
```

**Response:**
```json
[
  {
    "bucket_name": "my-bucket",
    "region": "us-east-1",
    "arn": "arn:aws:s3:::my-bucket",
    "findings": ["CRITICAL", "HIGH"]
  }
]
```

---

### 7. Health Check
```http
GET /api/health
```

**Response:**
```json
{
  "status": "ok"
}
```

---

## Frontend Integration Examples

### Example: Scan EC2 and Display Results

```typescript
import { useState } from 'react';

interface Finding {
  id: string;
  type: string;
  severity: string;
  description: string;
  remediation: string;
  resource_type: string;
}

function ScannerComponent() {
  const [scanning, setScanning] = useState(false);
  const [findings, setFindings] = useState<Finding[]>([]);

  const scanEC2 = async () => {
    setScanning(true);
    
    try {
      // 1. Trigger EC2 scan
      const scanResponse = await fetch('http://localhost:8000/api/scanner/ec2', {
        method: 'POST',
      });
      
      const scanResult = await scanResponse.json();
      console.log('Scan complete:', scanResult);
      
      // 2. Fetch findings from Neo4j
      const findingsResponse = await fetch('http://localhost:8000/api/findings');
      const findingsData = await findingsResponse.json();
      
      setFindings(findingsData);
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div>
      <button onClick={scanEC2} disabled={scanning}>
        {scanning ? 'Scanning...' : 'Scan EC2'}
      </button>
      
      <div>
        <h2>Findings ({findings.length})</h2>
        {findings.map(finding => (
          <div key={finding.id} className={`finding-${finding.severity.toLowerCase()}`}>
            <h3>{finding.type}</h3>
            <span>{finding.severity}</span>
            <p>{finding.description}</p>
            <p><strong>Fix:</strong> {finding.remediation}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

### Example: Scan All Resources

```typescript
const scanAll = async () => {
  setScanning(true);
  
  try {
    const response = await fetch('http://localhost:8000/api/scanner/all', {
      method: 'POST',
    });
    
    const result = await response.json();
    console.log(`Scanned ${result.scans_completed} resource types`);
    console.log(`Found ${result.total_findings} total findings`);
    
    // Fetch all findings
    const findingsResponse = await fetch('http://localhost:8000/api/findings');
    const findings = await findingsResponse.json();
    setFindings(findings);
  } catch (error) {
    console.error('Scan failed:', error);
  } finally {
    setScanning(false);
  }
};
```

---

### Example: Get Critical Findings Only

```typescript
const getCriticalFindings = async () => {
  try {
    const response = await fetch('http://localhost:8000/api/findings?severity=CRITICAL');
    const criticalFindings = await response.json();
    setCriticalFindings(criticalFindings);
  } catch (error) {
    console.error('Failed to fetch findings:', error);
  }
};
```

---

### Example: Display Statistics Dashboard

```typescript
interface Stats {
  total_findings: number;
  total_resources: number;
  findings_by_severity: Array<{severity: string; count: number}>;
  resources_by_type: Array<{type: string; count: number}>;
}

const StatsDashboard = () => {
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    fetch('http://localhost:8000/api/stats')
      .then(res => res.json())
      .then(data => setStats(data));
  }, []);

  if (!stats) return <div>Loading...</div>;

  return (
    <div className="dashboard">
      <div className="stat-card">
        <h3>Total Findings</h3>
        <p>{stats.total_findings}</p>
      </div>
      
      <div className="stat-card">
        <h3>Total Resources</h3>
        <p>{stats.total_resources}</p>
      </div>
      
      <div className="severity-breakdown">
        <h3>Findings by Severity</h3>
        {stats.findings_by_severity.map(item => (
          <div key={item.severity} className={`severity-${item.severity.toLowerCase()}`}>
            {item.severity}: {item.count}
          </div>
        ))}
      </div>
      
      <div className="resource-breakdown">
        <h3>Resources by Type</h3>
        {stats.resources_by_type.map(item => (
          <div key={item.type}>
            {item.type}: {item.count}
          </div>
        ))}
      </div>
    </div>
  );
};
```

---

### Example: Graph Visualization

```typescript
import { useEffect, useState } from 'react';

interface GraphData {
  nodes: Array<{
    id: string;
    label: string;
    properties: any;
  }>;
  edges: Array<{
    source: string;
    target: string;
    type: string;
  }>;
}

const GraphVisualization = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  useEffect(() => {
    fetch('http://localhost:8000/api/graph?limit=50')
      .then(res => res.json())
      .then(data => setGraphData(data));
  }, []);

  // Use graphData with preferred graph library
  
  return (
    <div>
      <h2>Attack Path Graph</h2>
      {graphData && (
        <div>
          <p>{graphData.nodes.length} nodes</p>
          <p>{graphData.edges.length} relationships</p>
          {/* Render graph visualization here */}
        </div>
      )}
    </div>
  );
};
```

---

## Workflow

### 1. User triggers scan from frontend
```
User clicks "Scan EC2" button
  ↓
Frontend: POST /api/scanner/ec2
  ↓
Backend: Runs EC2ScannerService
  ↓
Backend: Saves /data/findings_ec2.json
  ↓
Backend: Auto-loads into Neo4j (schema + data)
  ↓
Backend: Returns scan results to frontend
```

### 2. User views findings
```
Frontend: GET /api/findings
  ↓
Backend: Queries Neo4j
  ↓
Backend: Returns findings array
  ↓
Frontend: Displays findings to user
```

---

## Environment Variables

Required in `.env` (change password field as wanted):
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password123
```

---

## Testing the API

### Using curl:

```bash
# Trigger EC2 scan
curl -X POST http://localhost:8000/api/scanner/ec2

# Get all findings
curl http://localhost:8000/api/findings

# Get critical findings
curl "http://localhost:8000/api/findings?severity=CRITICAL"

# Get statistics
curl http://localhost:8000/api/stats

# Get graph data
curl "http://localhost:8000/api/graph?limit=50"

# Health check
curl http://localhost:8000/api/health
```

### Using Swagger UI:

Open: http://localhost:8000/docs

Interactive API documentation with "Try it out" buttons for all endpoints.