# [Scenario Name] — Misconfiguration Report

## Environment Overview

A brief description of the target environment and its key components:

- **[Principal 1]** — Description of the starting user/role and its initial permissions.
- **[Principal 2]** — Description of an intermediate role and its capabilities.
- **[Service/Function]** — Description of the vulnerable service or function and what it does.
- **[Sensitive Resource]** — Description of the target secret, data, or resource to be exfiltrated.

---

## Attack Chain Summary

```text
[Starting Principal]
    ↓ [action, e.g. assumes]
[Intermediate Role/Service]
    ↓ [action, e.g. invokes]
[Vulnerable Component] ([vulnerability type])
    ↓ [action, e.g. attaches / modifies]
[Escalated Privilege State]
    ↓ [action, e.g. accesses]
[Target Resource]
```

### Exploit Steps

1. The attacker begins with [initial credentials or access].
2. Using those credentials, they enumerate [relevant services/roles/functions] to discover [key components].
3. They [lateral movement step, e.g. assume a role], gaining permission to [new capabilities].
4. By inspecting [artifact, e.g. source code / policy / config], they identify that [vulnerable logic description].
5. The attacker crafts a malicious payload that [exploit mechanism description].
6. They [deliver the exploit], causing [vulnerable component] to [unintended action].
7. With [escalated privileges], the attacker [achieves final objective, e.g. exfiltrates secrets].

### Attacker POV

```bash
# Step 1: Configure initial credentials
[command]

# Step 2: Enumerate / discover attack surface
[command]

# Step 3: Lateral movement (e.g. assume role)
[command]

# Step 4: Craft malicious payload
PAYLOAD='[payload structure]'

# Step 5: Deliver exploit
[command]

# Step 6: Use escalated privileges to achieve objective
[command]
```

---

## Misconfiguration Findings

### 1. [Vulnerability Name]

**What:** [Description of the vulnerability — what the code/config does and why it is exploitable.]

```[language]
# Vulnerable code or configuration snippet
[snippet]
```

[Explain what an attacker can do by exploiting this and why it matters in context.]

**Mitigation:**

- [Specific fix #1]
- [Specific fix #2]
- [Specific fix #3]

**Why bother:** [One to two sentences on the business/security impact if left unaddressed.]

---

### 2. [Vulnerability Name]

**What:** [Description of the misconfiguration — what permissions exist and why they are excessive.]

```[language]
# Policy or configuration snippet showing the over-privilege
[snippet]
```

[Explain how this combines with other findings or enables the attack path.]

**Mitigation:**

- [Specific fix #1]
- [Specific fix #2]
- [Specific fix #3]

**Why bother:** [One to two sentences on the business/security impact if left unaddressed.]

---

### 3. [Vulnerability Name]

**What:** [Description of why the initial access is more powerful than intended.]

- `[permission]` on `[resource]` — [what it enables]
- `[permission]` on `[resource]` — [what it enables]

[Explain the real-world analogy, e.g. how phished credentials could reach this state.]

**Mitigation:**

- [Specific fix #1]
- [Specific fix #2]
- [Specific fix #3]

**Why bother:** [One to two sentences on the business/security impact if left unaddressed.]

---

## Severity & Impact

| Factor | Reality |
|---|---|
| Skill Required | [Low / Medium / High] — [brief justification] |
| Exploit Time | [Low / Medium / High] — [brief justification] |
| Detection Likelihood | [Low / Medium / High] — [brief justification] |
| Data Obtained | [What sensitive data or access is gained] |
| Blast Radius | [Scope of affected principals, resources, or systems] |

[One to two sentence summary of the overall risk posture.]

---

## Bottom Line

[Two to three sentence summary covering: what the core vulnerability chain is, what fixing individual pieces would accomplish, and what the path to defense-in-depth looks like.]