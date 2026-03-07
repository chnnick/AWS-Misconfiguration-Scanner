# AWS Cloud Misconfiguration & Risk Scanner

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
pip install boto3
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

---

## Running the Scanner

Run each collector independently from the project root:

```bash
# Scan EC2 resources
python3 scanner/collectors/collector_ec2.py

# Scan S3 resources
python3 scanner/collectors/collector_s3.py
```

Each collector outputs a `findings.json` file in the directory it is run from.

---

## Expected Findings (cloud_breach_s3)

| # | Collector | Resource | Check | Expected |
|---|---|---|---|---|
| 1 | EC2 | `ec2-vulnerable-proxy-server` | IMDSv1 Enabled | FAIL |
| 2 | S3 | `cg-cardholder-data-bucket-demo` | No Bucket Policy | FAIL |

### Notes

- **Open SSH** — passes because the security group restricts port 22 to `cg_whitelist` (your IP), not `0.0.0.0/0`.
- **Encryption at Rest** — passes because AWS enforces SSE-S3 by default on all new buckets (since January 2023). CloudGoat does not explicitly disable it.
- **Block Public Access** — passes because AWS enables BPA by default at the account level on newer accounts.

---

## Output Format

Each collector produces a JSON findings report:

```json
{
  "scan_timestamp": "2026-03-06T17:44:37.950138Z",
  "total_findings": 1,
  "findings": [
    {
      "resource_type": "S3",
      "resource_id": "cg-cardholder-data-bucket-demo",
      "check": "No Bucket Policy",
      "detail": "Bucket has no resource-based policy. Access controlled by IAM only.",
      "status": "FAIL"
    }
  ]
}
```