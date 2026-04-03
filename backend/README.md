# CloudWatch Backend

A graph-based cloud security analysis tool that ingests AWS infrastructure data, detects misconfigurations, and visualizes attack paths across resources.

> Currently supports scanning EC2 and S3 resources against the `cloud_breach_s3` scenario specific misconfigurations.


---

## Prerequisites

- Python 3.8+
- AWS CLI
- An AWS account with deployed target resources

---

## Setup

### 1. Clone the Repository

```bash
git clone <repo-url>
cd CAPSTONE
```

### 2. Create and Activate a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip3 install -r requirements.txt
```

### 4. Configure AWS Credentials

```bash
aws configure
```

You will be prompted for:

```
AWS Access Key ID:
AWS Secret Access Key:
Default region name: us-east-1
Default output format: json
```

Verify credentials are working:

```bash
aws sts get-caller-identity
```

---

## Deploying the Target Environment (cloud_breach_s3)

The scanner is currently built to detect misconfigurations in the `cloud_breach_s3` scenario. To deploy it:

### 1. Get the Terraform Files

```bash
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat/scenarios/cloud_breach_s3/terraform
```

### 2. Create `terraform.tfvars`

```hcl
cgid                    = "demo"
cg_whitelist            = ["<YOUR_PUBLIC_IP>/32"]
profile                 = "default"
region                  = "us-east-1"
ssh-public-key-for-ec2  = "~/.ssh/id_rsa.pub"
ssh-private-key-for-ec2 = "~/.ssh/id_rsa"
```

Find your public IP:

```bash
curl ifconfig.me
```

### 3. Deploy

```bash
terraform init
terraform apply
```

### 4. Tear Down When Done

```bash
terraform destroy
```

> ⚠️ This environment is intentionally vulnerable and publicly exposed. Do not leave it running longer than needed.

### 5. Add Neo4J Environment Variables
Required in `.env` (change password field as wanted):
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password123
```

6. Run the API:
`uvicorn app.main:app --reload --host 127.0.0.1 --port 8000`
Should See: 
```
CloudSight API — http://127.0.0.1:8000
docs: http://127.0.0.1:8000/docs
health: http://127.0.0.1:8000/api/health
scanners:
        POST http://127.0.0.1:8000/api/scanner/ec2
        POST http://127.0.0.1:8000/api/scanner/s3
        POST http://127.0.0.1:8000/api/scanner/lambda
        POST http://127.0.0.1:8000/api/scanner/iam
```

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

