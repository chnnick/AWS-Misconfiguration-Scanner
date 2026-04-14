"""
Risk Engine: Scores Finding nodes using a 5-factor risk model, computed in-memory.
Neo4j is read-only — no scores are written back to the database.

Each factor is rated 1–5:
  ease_of_exploit     — difficulty for an attacker to execute
  exposure            — how reachable the vulnerable resource is
  whats_at_risk       — category of asset the misconfiguration puts at risk
  blast_radius        — how far damage could spread from this single finding
  detection_likelihood — how likely exploitation is to generate an alert

Detection is inverted in the composite score: a lower detection score means
an attacker can operate more freely, which increases overall risk.
"""

from .rule_table import RULE_TABLE

# Weights for the composite risk score — must sum to 1.0.
# Detection is applied as (6 - score) so that 1 (invisible) contributes
# a full 5 points' worth and 5 (actively alerted) contributes 1 point.
WEIGHTS = {
    "ease_of_exploit": 0.20,
    "exposure": 0.25,
    "whats_at_risk": 0.25,
    "blast_radius": 0.20,
    "detection_likelihood": 0.10,
}

# Maps Neo4j node labels to the property that serves as the primary identifier
RESOURCE_ID_PROPS = {
    "EC2Instance": "instance_id",
    "S3Bucket": "bucket_name",
    "S3Object": "object_key",
    "SecurityGroup": "group_id",
    "IAMRole": "role_name",
    "IAMUser": "username",
    "LambdaFunction": "function_name",
    "Secret": "location",
}


def compute_risk_score(ratings):
    # Compute the weighted composite risk score on a 1.0–5.0 scale.
    # Detection likelihood is inverted so that lower visibility = higher risk.
    score = (
        ratings["ease_of_exploit"] * WEIGHTS["ease_of_exploit"]
        + ratings["exposure"] * WEIGHTS["exposure"]
        + ratings["whats_at_risk"] * WEIGHTS["whats_at_risk"]
        + ratings["blast_radius"] * WEIGHTS["blast_radius"]
        + (6 - ratings["detection_likelihood"]) * WEIGHTS["detection_likelihood"]
    )
    return round(score, 2)


def score_finding(finding):
    # Look up (resource_type, finding_type) in the rule table and return
    # a dict of ratings, rationale strings, and the composite risk_score.
    # Returns None if no matching rule exists (caller should flag for manual review).
    resource_type = finding.get("resource_type", "")
    finding_type = finding.get("type", "")

    rule = RULE_TABLE.get((resource_type, finding_type))

    if rule is None:
        # Fall back to a resource-type-agnostic entry if one exists
        rule = RULE_TABLE.get((None, finding_type))

    if rule is None:
        print(f"[WARN] No rule for ({resource_type}, {finding_type}) — unmatched")
        return None

    ratings = {
        "ease_of_exploit": rule["ease_of_exploit"],
        "exposure": rule["exposure"],
        "whats_at_risk": rule["whats_at_risk"],
        "blast_radius": rule["blast_radius"],
        "detection_likelihood": rule["detection_likelihood"],
    }

    return {
        **ratings,
        "risk_score": compute_risk_score(ratings),
        "rationale_ease": rule["rationale_ease"],
        "rationale_exposure": rule["rationale_exposure"],
        "rationale_risk": rule["rationale_risk"],
        "rationale_blast": rule["rationale_blast"],
        "rationale_detection": rule["rationale_detection"],
    }
