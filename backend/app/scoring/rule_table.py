"""
Rule Table: Default 5-factor risk ratings for each (resource_type, finding_type) pair.

Factors (each rated 1–5):
  ease_of_exploit     — 1=requires chained advanced skills, 5=follow a tutorial / one command
  exposure            — 1=internal-only, no network path, 5=internet-facing with no auth
  whats_at_risk       — 1=defense-in-depth layer only, 5=direct credentials/secrets
  blast_radius        — 1=isolated single resource, 5=account-wide lateral movement
  detection_likelihood — 1=invisible to CloudTrail, 5=actively alerted by GuardDuty/SIEM

Detection is INVERTED in the composite score: low detection = higher risk.
"""

RULE_TABLE = {

    # -------------------------------------------------------------------------
    # S3
    # -------------------------------------------------------------------------

    ("S3Bucket", "BLOCK_PUBLIC_ACCESS_DISABLED"): {
        "ease_of_exploit": 3,
        "exposure": 4,
        "whats_at_risk": 3,
        "blast_radius": 2,
        "detection_likelihood": 2,
        "rationale_ease": "Requires the attacker to also find a permissive ACL or policy; disabling Block Public Access alone doesn't expose objects.",
        "rationale_exposure": "Removes the account-level safety net; any permissive ACL or policy now takes effect and exposes the bucket to the internet.",
        "rationale_risk": "All objects in the bucket become potentially reachable; actual exposure depends on ACLs and policies that Block Public Access was suppressing.",
        "rationale_blast": "Impact is contained to objects in this single bucket.",
        "rationale_detection": "S3 server-access logging is disabled by default; CloudTrail S3 data events require explicit opt-in.",
    },

    ("S3Bucket", "PLAINTEXT_CREDENTIALS_IN_S3"): {
        "ease_of_exploit": 4,
        "exposure": 4,
        "whats_at_risk": 5,
        "blast_radius": 4,
        "detection_likelihood": 2,
        "rationale_ease": "Any principal with S3 read access (or public access if the bucket is open) can retrieve the file with a single API call.",
        "rationale_exposure": "Exposure depends on bucket ACLs; if the bucket is public the credentials are internet-accessible with no authentication.",
        "rationale_risk": "Plaintext credentials are immediately usable; no decryption, privilege escalation, or further access required.",
        "rationale_blast": "Stolen credentials are long-lived and usable from any internet host, bridging to every service they permit.",
        "rationale_detection": "S3 access logs are not enabled by default; credential use may only surface in CloudTrail after significant abuse.",
    },

    ("S3Bucket", "NO_BUCKET_POLICY"): {
        "ease_of_exploit": 2,
        "exposure": 3,
        "whats_at_risk": 3,
        "blast_radius": 2,
        "detection_likelihood": 2,
        "rationale_ease": "Requires finding and enumerating the exposed bucket; no single-step public exploit.",
        "rationale_exposure": "Bucket is reachable depending on ACLs and Block Public Access settings, but policy absence alone does not guarantee public read.",
        "rationale_risk": "Without a policy, no explicit deny exists; any misconfigured ACL or future grant silently exposes data.",
        "rationale_blast": "Impact is contained to objects in this single bucket.",
        "rationale_detection": "S3 server-access logging is disabled by default; CloudTrail S3 data events require explicit opt-in.",
    },

    ("S3Bucket", "PUBLIC_ACL"): {
        "ease_of_exploit": 5,
        "exposure": 5,
        "whats_at_risk": 3,
        "blast_radius": 2,
        "detection_likelihood": 2,
        "rationale_ease": "Bucket contents are listable and downloadable with a single AWS CLI command; no credentials needed.",
        "rationale_exposure": "Internet-facing with no authentication required — anyone with the bucket name can access it.",
        "rationale_risk": "Exposes all objects; severity depends on contents, but data exfiltration requires zero further privilege.",
        "rationale_blast": "Contained to this bucket's contents; does not grant write or cross-account access on its own.",
        "rationale_detection": "S3 access logs are not enabled by default; unauthenticated reads leave no CloudTrail trail.",
    },

    ("S3Bucket", "NO_ENCRYPTION"): {
        "ease_of_exploit": 3,
        "exposure": 2,
        "whats_at_risk": 2,
        "blast_radius": 1,
        "detection_likelihood": 3,
        "rationale_ease": "Attacker must first obtain valid IAM credentials before accessing unencrypted objects.",
        "rationale_exposure": "Requires IAM authentication; no direct internet exposure from this misconfiguration alone.",
        "rationale_risk": "Weakens defense-in-depth; an attacker who already has S3 access gets cleartext data without an extra decryption step.",
        "rationale_blast": "Confined to this bucket; no lateral movement vector introduced.",
        "rationale_detection": "S3 API calls require credentials, so CloudTrail logs are present when data is accessed.",
    },

    ("S3Bucket", "NO_VERSIONING"): {
        "ease_of_exploit": 3,
        "exposure": 1,
        "whats_at_risk": 1,
        "blast_radius": 1,
        "detection_likelihood": 3,
        "rationale_ease": "Requires write access to the bucket to carry out a destructive overwrite or ransomware attack.",
        "rationale_exposure": "No direct external exposure; exploiting this requires prior write-level IAM compromise.",
        "rationale_risk": "Absence of versioning enables irreversible data loss or overwrite; it is a data-integrity control, not a confidentiality control.",
        "rationale_blast": "Damage confined to objects in this bucket; no path to other resources.",
        "rationale_detection": "Delete and overwrite operations are logged in CloudTrail if S3 data event logging is enabled.",
    },

    ("S3Bucket", "NO_LOGGING"): {
        "ease_of_exploit": 3,
        "exposure": 1,
        "whats_at_risk": 1,
        "blast_radius": 1,
        "detection_likelihood": 1,
        "rationale_ease": "Exploiting this misconfiguration requires leveraging another vulnerability; the gap itself is passive.",
        "rationale_exposure": "No network exposure introduced; this is a visibility gap, not an access-control gap.",
        "rationale_risk": "Disables audit trail for this bucket; an attacker can exfiltrate data without leaving access records.",
        "rationale_blast": "Scoped to this bucket; does not introduce lateral movement.",
        "rationale_detection": "By definition, access events generate no logs — detection likelihood is at its floor.",
    },

    # -------------------------------------------------------------------------
    # EC2
    # -------------------------------------------------------------------------

    ("EC2Instance", "IMDSV1_ENABLED"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 1,
        "rationale_ease": "Requires a server-side request forgery (SSRF) or similar app-layer vulnerability to reach the metadata endpoint.",
        "rationale_exposure": "IMDS is reachable through any application-layer vulnerability on the instance; no direct internet path needed.",
        "rationale_risk": "Directly exposes the IAM role's temporary credentials, usable from any internet host.",
        "rationale_blast": "Stolen credentials provide access to every AWS service and resource the attached role permits.",
        "rationale_detection": "IMDS requests are local HTTP calls; they generate zero CloudTrail events and are invisible to GuardDuty by default.",
    },

    ("EC2Instance", "OPEN_SSH"): {
        "ease_of_exploit": 3,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Requires valid SSH credentials, but credential-spray and brute-force tooling is widely available.",
        "rationale_exposure": "Port 22 is reachable from any internet host with no network-layer filter.",
        "rationale_risk": "Successful login grants interactive OS-level shell access to the instance.",
        "rationale_blast": "Compromised instance enables lateral movement to VPC-internal resources and any IAM role attached to it.",
        "rationale_detection": "VPC Flow Logs record connection attempts if enabled; host-level SSH auth failures are logged but not forwarded by default.",
    },

    ("EC2Instance", "OPEN_RDP"): {
        "ease_of_exploit": 3,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 3,
        "detection_likelihood": 2,
        "rationale_ease": "Multiple RDP credential-spray and brute-force tools are publicly available and require minimal skill.",
        "rationale_exposure": "Port 3389 is exposed to the entire internet with no network-layer restriction.",
        "rationale_risk": "Successful RDP login delivers a full graphical OS session — equivalent to physical access.",
        "rationale_blast": "Compromised Windows host enables lateral movement via pass-the-hash, PsExec, and domain trust abuse.",
        "rationale_detection": "GuardDuty RDP brute-force detection exists but requires volume thresholds; low-and-slow attacks are largely invisible.",
    },

    ("SecurityGroup", "OPEN_SSH"): {
        "ease_of_exploit": 3,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Requires valid SSH credentials, but credential-spray and brute-force tooling is widely available.",
        "rationale_exposure": "Port 22 is reachable from any internet host with no network-layer filter.",
        "rationale_risk": "Successful login grants interactive OS-level shell access to any instance in this security group.",
        "rationale_blast": "Compromised instance enables lateral movement to VPC-internal resources and any IAM role attached to it.",
        "rationale_detection": "VPC Flow Logs record connection attempts if enabled; host-level SSH auth failures are logged but not forwarded by default.",
    },

    ("SecurityGroup", "OPEN_RDP"): {
        "ease_of_exploit": 3,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 3,
        "detection_likelihood": 2,
        "rationale_ease": "Multiple RDP credential-spray and brute-force tools are publicly available and require minimal skill.",
        "rationale_exposure": "Port 3389 is exposed to the entire internet with no network-layer restriction.",
        "rationale_risk": "Successful RDP login delivers a full graphical OS session — equivalent to physical access.",
        "rationale_blast": "Compromised Windows host enables lateral movement via pass-the-hash, PsExec, and domain trust abuse.",
        "rationale_detection": "GuardDuty RDP brute-force detection exists but requires volume thresholds; low-and-slow attacks are largely invisible.",
    },

    ("SecurityGroup", "ALL_TRAFFIC_OPEN"): {
        "ease_of_exploit": 4,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 2,
        "rationale_ease": "Every port and protocol is exposed; attacker can exploit any vulnerable service without additional preparation.",
        "rationale_exposure": "All ports reachable from the entire internet — maximum possible attack surface.",
        "rationale_risk": "Any service running on the instance is directly reachable; OS access, data, and credentials are all potentially exposed.",
        "rationale_blast": "Full port exposure maximises lateral movement paths; all VPC-internal services reachable once a foothold is gained.",
        "rationale_detection": "VPC Flow Logs help if enabled, but broad traffic makes anomaly detection difficult without a tuned baseline.",
    },

    ("EC2Instance", "ALL_TRAFFIC_OPEN"): {
        "ease_of_exploit": 4,
        "exposure": 5,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 2,
        "rationale_ease": "Every port and protocol is exposed; attacker can exploit any vulnerable service without additional preparation.",
        "rationale_exposure": "All ports reachable from the entire internet — maximum possible attack surface.",
        "rationale_risk": "Any service running on the instance is directly reachable; OS access, data, and credentials are all potentially exposed.",
        "rationale_blast": "Full port exposure maximises lateral movement paths; all VPC-internal services reachable once a foothold is gained.",
        "rationale_detection": "VPC Flow Logs help if enabled, but broad traffic makes anomaly detection difficult without a tuned baseline.",
    },

    # -------------------------------------------------------------------------
    # IAM
    # -------------------------------------------------------------------------

    ("IAMRole", "ADMIN_ACCESS_POLICY"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 5,
        "blast_radius": 5,
        "detection_likelihood": 4,
        "rationale_ease": "Attacker must first compromise the principal (user, service, or role) before these permissions are usable.",
        "rationale_exposure": "Requires valid AWS credentials; no direct internet-facing exposure from this misconfiguration alone.",
        "rationale_risk": "AdministratorAccess grants unrestricted control over every AWS service and every resource in the account.",
        "rationale_blast": "Account-wide: any service, any region, any resource — maximum possible blast radius.",
        "rationale_detection": "Admin-level API calls are heavily logged in CloudTrail; GuardDuty has specific findings for anomalous IAM activity.",
    },

    ("IAMUser", "ADMIN_ACCESS_POLICY"): {
        "ease_of_exploit": 2,
        "exposure": 3,
        "whats_at_risk": 5,
        "blast_radius": 5,
        "detection_likelihood": 4,
        "rationale_ease": "Requires compromising the user's credentials (password, access key, or session token).",
        "rationale_exposure": "Human users often authenticate from the internet via the AWS Console or CLI; wider attack surface than roles.",
        "rationale_risk": "AdministratorAccess grants unrestricted control over every AWS service and every resource in the account.",
        "rationale_blast": "Account-wide: any service, any region, any resource — maximum possible blast radius.",
        "rationale_detection": "Admin-level API calls are heavily logged in CloudTrail; GuardDuty has specific findings for anomalous IAM activity.",
    },

    ("IAMUser", "NO_MFA"): {
        "ease_of_exploit": 4,
        "exposure": 4,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Password spray, phishing, and credential-stuffing tools are freely available and require minimal skill.",
        "rationale_exposure": "AWS Console and CLI are internet-accessible; only a password stands between the attacker and the account.",
        "rationale_risk": "Access depends on the user's attached policies; rated medium as the specific permissions vary per user.",
        "rationale_blast": "Blast radius scales with the user's permissions; a least-privilege user is isolated, an over-privileged one is account-wide.",
        "rationale_detection": "Console logins are logged in CloudTrail; GuardDuty detects some anomalous login patterns but not all.",
    },

    ("IAMRole", "WILDCARD_PERMISSIONS"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 3,
        "rationale_ease": "Wildcard permissions are usable only after the underlying principal is compromised.",
        "rationale_exposure": "Requires valid credentials for the role; no direct internet-facing vector.",
        "rationale_risk": "Action:* or Resource:* grants unlimited service access; any service-level data or secret is reachable.",
        "rationale_blast": "Wildcard actions remove all policy-level guardrails; lateral movement is limited only by the trust policy.",
        "rationale_detection": "Individual API calls are logged in CloudTrail, but no alert fires specifically on wildcard policy use.",
    },

    ("IAMUser", "WILDCARD_PERMISSIONS"): {
        "ease_of_exploit": 2,
        "exposure": 3,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 3,
        "rationale_ease": "Wildcard permissions are usable only after compromising the user's credentials.",
        "rationale_exposure": "Users authenticate from the internet; slightly more exposed than roles that require cross-account trust.",
        "rationale_risk": "Action:* or Resource:* grants unlimited service access; any service-level data or secret is reachable.",
        "rationale_blast": "Wildcard actions remove all policy-level guardrails; practically unrestricted movement within permitted services.",
        "rationale_detection": "Individual API calls are logged in CloudTrail, but no alert fires specifically on wildcard policy use.",
    },

    ("IAMUser", "STALE_ACCESS_KEY"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 2,
        "rationale_ease": "Stale keys may appear in old configs, CI/CD logs, or leaked repos; finding them requires some research.",
        "rationale_exposure": "Access keys authenticate directly via API/CLI from any internet host with no MFA required.",
        "rationale_risk": "Key permissions reflect the user's policy; rated medium as the scope is user-specific.",
        "rationale_blast": "Depends on attached policy; stale keys are often forgotten and therefore not subject to active monitoring.",
        "rationale_detection": "Key usage is logged in CloudTrail but stale keys often lack active alerting or review cadence.",
    },

    ("IAMRole", "STALE_ACCESS_KEY"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 2,
        "rationale_ease": "Stale keys may appear in old configs, CI/CD logs, or leaked repos; finding them requires some research.",
        "rationale_exposure": "Access keys authenticate directly via API/CLI from any internet host with no MFA required.",
        "rationale_risk": "Key permissions reflect the role's policy; rated medium as the scope is role-specific.",
        "rationale_blast": "Depends on attached policy; stale keys are often forgotten and therefore not subject to active monitoring.",
        "rationale_detection": "Key usage is logged in CloudTrail but stale keys often lack active alerting or review cadence.",
    },

    # IAM findings without specific resource types (generic fallbacks)
    (None, "ADMIN_ACCESS_POLICY"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 5,
        "blast_radius": 5,
        "detection_likelihood": 4,
        "rationale_ease": "Attacker must first compromise the principal before these permissions are usable.",
        "rationale_exposure": "Requires valid AWS credentials; no direct internet-facing exposure.",
        "rationale_risk": "AdministratorAccess grants unrestricted control over every AWS service and resource.",
        "rationale_blast": "Account-wide impact across every service, region, and resource.",
        "rationale_detection": "Admin API calls are heavily logged; GuardDuty has anomalous IAM findings.",
    },

    (None, "NO_MFA"): {
        "ease_of_exploit": 4,
        "exposure": 4,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Password spray and phishing tools are freely available.",
        "rationale_exposure": "AWS Console and CLI are internet-accessible with only a password as protection.",
        "rationale_risk": "Access scope depends on the principal's attached policies.",
        "rationale_blast": "Blast radius scales with the principal's permissions.",
        "rationale_detection": "Console logins are CloudTrail-logged; GuardDuty covers some anomalous patterns.",
    },

    (None, "WILDCARD_PERMISSIONS"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 3,
        "rationale_ease": "Wildcard permissions require first compromising the principal.",
        "rationale_exposure": "Exploitable only via valid credentials; no direct internet vector.",
        "rationale_risk": "Action:* or Resource:* grants unlimited access within the affected service scope.",
        "rationale_blast": "Removes all policy-level guardrails; near-unrestricted lateral movement.",
        "rationale_detection": "API calls are CloudTrail-logged but no alert fires on wildcard policy use.",
    },

    (None, "STALE_ACCESS_KEY"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 2,
        "rationale_ease": "Stale keys may surface in old configs or leaked repos.",
        "rationale_exposure": "API keys authenticate from any internet host without MFA.",
        "rationale_risk": "Permission scope equals the principal's attached policy.",
        "rationale_blast": "Depends on attached policy; stale keys rarely have active monitoring.",
        "rationale_detection": "Key usage is logged in CloudTrail but often lacks active alerting.",
    },

    # -------------------------------------------------------------------------
    # Lambda
    # -------------------------------------------------------------------------

    ("LambdaFunction", "HARDCODED_CREDENTIALS_IN_ENV"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 5,
        "blast_radius": 4,
        "detection_likelihood": 2,
        "rationale_ease": "Requires Lambda:GetFunction permission or console access; not internet-accessible without prior compromise.",
        "rationale_exposure": "Visible to any IAM principal with Lambda:GetFunction; exposed in CI/CD pipelines and IaC state files.",
        "rationale_risk": "Plaintext credentials are directly usable; no decryption or further privilege escalation needed.",
        "rationale_blast": "Credentials are long-lived and usable outside Lambda from any internet host, bridging to all services they permit.",
        "rationale_detection": "Lambda:GetFunction is not a commonly alerted API call; credential use may trigger GuardDuty only if anomalous.",
    },

    ("LambdaFunction", "HARDCODED_CREDENTIALS_IN_CODE"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 5,
        "blast_radius": 4,
        "detection_likelihood": 2,
        "rationale_ease": "Requires Lambda:GetFunction or source-code repository access; not directly internet-reachable.",
        "rationale_exposure": "Source packages downloadable by any IAM principal with Lambda:GetFunction; often also present in code repositories.",
        "rationale_risk": "Hard-coded credentials are immediately usable with no further effort.",
        "rationale_blast": "Credentials are portable and long-lived; usable from any host, bridging to all permitted services.",
        "rationale_detection": "Code downloads are rarely alerted on; credential abuse may surface in CloudTrail only after significant usage.",
    },

    ("LambdaFunction", "WILDCARD_ROLE_PERMISSIONS"): {
        "ease_of_exploit": 3,
        "exposure": 2,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 3,
        "rationale_ease": "Requires ability to invoke the function or inject malicious input; some application-layer access needed.",
        "rationale_exposure": "Function must be invocable; exposure depends on whether invocation is authenticated.",
        "rationale_risk": "Overly broad execution role grants broad AWS service access from within the function's execution context.",
        "rationale_blast": "Wildcard permissions on the execution role can reach any service the role permits, far beyond Lambda.",
        "rationale_detection": "Lambda invocations and IAM role API calls are both logged in CloudTrail.",
    },

    ("LambdaFunction", "PUBLIC_ACCESS"): {
        "ease_of_exploit": 5,
        "exposure": 5,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Function URL is invocable with a single HTTP request; zero credentials or tooling required.",
        "rationale_exposure": "Internet-facing with no authentication required — the function is a public endpoint.",
        "rationale_risk": "Function logic and any data it touches are exposed; severity depends on what the function does.",
        "rationale_blast": "Function plus any resources its execution role can access; limited if role is least-privilege.",
        "rationale_detection": "Lambda invocation events are logged in CloudTrail; volume anomalies can trigger GuardDuty.",
    },

    # -------------------------------------------------------------------------
    # Collector-specific IAM finding types
    # -------------------------------------------------------------------------

    ("IAMRole", "ROLE_ASSUMABLE_WITHOUT_MFA"): {
        "ease_of_exploit": 3,
        "exposure": 3,
        "whats_at_risk": 4,
        "blast_radius": 4,
        "detection_likelihood": 3,
        "rationale_ease": "Requires valid credentials for a principal in the trust policy, but no MFA token to cross-account assume.",
        "rationale_exposure": "Any principal permitted in the trust policy can assume the role from any network location.",
        "rationale_risk": "Role permissions determine impact; absence of MFA requirement removes a critical authentication barrier.",
        "rationale_blast": "Assumed role credentials are fully usable; blast radius equals the role's permission scope.",
        "rationale_detection": "AssumeRole events are logged in CloudTrail; GuardDuty detects anomalous cross-account assumptions.",
    },

    ("IAMRole", "ROLE_CAN_MODIFY_INSTANCE_ATTRIBUTE"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Requires first assuming or compromising the role; the specific EC2 permission then enables instance tampering.",
        "rationale_exposure": "Requires valid role credentials; no direct internet-facing vector.",
        "rationale_risk": "ModifyInstanceAttribute enables disabling IMDSv2, changing user-data for code execution, or swapping security groups.",
        "rationale_blast": "Attacker can alter instance behaviour across the account wherever the role has EC2 resource scope.",
        "rationale_detection": "EC2 ModifyInstanceAttribute is logged in CloudTrail; unusual attribute changes can be alerted.",
    },

    ("IAMRole", "ROLE_CAN_MODIFY_INSTANCE_USERDATA"): {
        "ease_of_exploit": 2,
        "exposure": 2,
        "whats_at_risk": 3,
        "blast_radius": 3,
        "detection_likelihood": 3,
        "rationale_ease": "Requires first assuming or compromising the role; the EC2 permission then enables userdata modification for arbitrary code execution.",
        "rationale_exposure": "Requires valid role credentials; no direct internet-facing vector.",
        "rationale_risk": "ec2:ModifyInstanceAttribute allows replacing instance userdata, which executes as root on next reboot — a reliable code-execution primitive.",
        "rationale_blast": "Attacker can inject code into instances across the account wherever the role has EC2 resource scope.",
        "rationale_detection": "EC2 ModifyInstanceAttribute is logged in CloudTrail; unusual userdata changes can be alerted on.",
    },

    ("IAMUser", "USER_CAN_DELETE_EC2_TAGS"): {
        "ease_of_exploit": 2,
        "exposure": 3,
        "whats_at_risk": 2,
        "blast_radius": 2,
        "detection_likelihood": 3,
        "rationale_ease": "Requires compromising the user's credentials before the permission is usable.",
        "rationale_exposure": "Users can authenticate from the internet; broader exposure than roles.",
        "rationale_risk": "Tag deletion can disrupt cost allocation, access-control tag-based policies, and automated compliance checks.",
        "rationale_blast": "Limited to EC2 tag manipulation; does not directly grant access to instance data or credentials.",
        "rationale_detection": "EC2 DeleteTags is logged in CloudTrail; alerts can be configured but are not default.",
    },
}
