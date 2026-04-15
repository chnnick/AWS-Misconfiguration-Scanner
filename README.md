# AWS Misconfiguration Scanner
CY4930 Capstone Project

A full stack cloud security scanning platform that detects AWS misconfigurations and visualizes them as an interactive graph using Neo4j.

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- AWS credentials configured on your machine via `aws configure`

---

## Setup

**1. Clone the repo and configure environment variables**

Copy `.env.example` to `.env` (or edit `.env` directly) and set your Neo4j credentials:

```
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password_here
NEO4J_URI=bolt://localhost:7687
API_BASE_URL=http://localhost:8000
```

**2. Start the system**

```bash
docker compose up -d
```

This starts all four services in the correct order:
- Neo4j starts and waits until healthy
- Schema is automatically applied to Neo4j
- Backend (FastAPI) starts once Neo4j is ready
- Frontend (React) starts

**3. Open the app**

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API docs | http://localhost:8000/docs |
| Neo4j Browser | http://localhost:7474 |

**4. Run a scan**

Select the AWS resources you want to scan (EC2, S3, Lambda, IAM) in the UI and click **Scan**. Results populate the graph and findings panel automatically.

**5. Tear down**
Run either:
```bash
docker compose down        # stop containers, keep Neo4j data
docker compose down -v     # stop containers and delete all data
```

---

## Testing with Vulnerable Scenarios

The project includes CloudGoat-based Terraform scenarios for testing against intentionally vulnerable AWS environments instead of your real infrastructure.

### Prerequisites
- [Terraform >= 1.5](https://developer.hashicorp.com/terraform/install) installed

### Available scenarios

| Scenario | Resources | Difficulty |
|---|---|---|
| `iam_privesc_by_rollback` | IAM users + policy versions | Easy |
| `iam_privesc_by_key_rotation` | IAM users + Secrets Manager | Easy |
| `iam_privesc_by_ec2` | EC2 + IAM | Easy |
| `iam_privesc_by_attachment` | EC2 + IAM | Moderate |
| `cloud_breach_s3` | EC2 + S3 + VPC | Moderate |
| `ec2_ssrf` | EC2 + Lambda + S3 | Moderate |
| `vulnerable_lambda` | Lambda + IAM + Secrets Manager | Medium |

### Deploy a scenario

```bash
cd backend/terraform/scenarios/<scenario-name>/terraform
terraform init
terraform apply -var="profile=default" -var="cgid=test1"
```

Scenarios that include EC2 or VPC resources also require your public IP for security group whitelisting:

Find your public IP with: `curl ifconfig.co`

```bash
terraform apply -var="profile=default" -var="cgid=test1" -var='cg_whitelist=["YOUR_IP/32"]'
```


### Make sure to destroy when done

```bash
terraform destroy -var="profile=default" -var="cgid=test1"
```
---

## Architecture

```
React Frontend (port 3000)
      ↕ REST API
FastAPI Backend (port 8000)
      ↕ boto3
AWS (EC2, S3, Lambda, IAM)
      ↓ findings
Neo4j Graph DB (ports 7474, 7687)
      ↑ graph queries
FastAPI → React GraphView
```

### What the scanner checks

| Service | Checks |
|---|---|
| EC2 | IMDSv1 enabled, open SSH ports, unencrypted volumes |
| S3 | Public access block settings, hardcoded credentials in objects |
| Lambda | Hardcoded credentials in environment variables |
| IAM | Overprivileged policies, unused permissions |

---

## Acknowledgments & Third-Party Notices

This project uses [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs for deploying intentionally vulnerable AWS environments. CloudGoat is licensed under the [BSD 3-Clause License](https://github.com/RhinoSecurityLabs/cloudgoat/blob/master/LICENSE).

We do not claim ownership of CloudGoat scenarios. All CloudGoat-related code and configurations remain under their original license and copyright by Rhino Security Labs.
