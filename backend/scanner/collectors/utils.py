import re
import uuid


# Credential Patterns
CREDENTIAL_PATTERNS = [
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'(?i)aws_secret_access_key'),
    re.compile(r'(?i)aws_session_token'),
    re.compile(r'(?i)password\s*=\s*\S+'),
    re.compile(r'(?i)secret\s*=\s*\S+'),
]

def contains_credentials(text):
    for pattern in CREDENTIAL_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None

# Finding Helper
def make_finding(finding_type, severity, description, remediation, cis_control=None, owasp=None):
    return {
        "finding_id": f"FINDING-{uuid.uuid4().hex[:8].upper()}",
        "type": finding_type,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "cis_control": cis_control,
        "owasp": owasp
    }