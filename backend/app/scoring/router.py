"""
Risk Router: FastAPI endpoints for retrieving risk-scored findings.
Scores are computed in-memory from Neo4j data — Neo4j is never written to.
"""

from fastapi import APIRouter, HTTPException

from ..neo4j_client import neo4j_client
from ..scoring.engine import RESOURCE_ID_PROPS, score_finding

router = APIRouter()


def _build_response(record):
    # Combine a raw Neo4j finding record with its in-memory risk scores.
    resource_type = record.get("resource_type") or ""
    resource_props = record.get("resource_props") or {}
    id_prop = RESOURCE_ID_PROPS.get(resource_type, "")
    resource_id = resource_props.get(id_prop, "unknown")

    scores = score_finding(record)

    result = {
        "finding_id": record.get("finding_id"),
        "finding_type": record.get("type"),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "severity": record.get("severity"),
        "description": record.get("description"),
        "remediation": record.get("remediation"),
    }

    if record.get("cis_control"):
        result["cis_control"] = record.get("cis_control")
    if record.get("owasp"):
        result["owasp"] = record.get("owasp")

    if scores is not None:
        result["risk_score"] = scores["risk_score"]
        result["ratings"] = {
            "ease_of_exploit": scores["ease_of_exploit"],
            "exposure": scores["exposure"],
            "whats_at_risk": scores["whats_at_risk"],
            "blast_radius": scores["blast_radius"],
            "detection_likelihood": scores["detection_likelihood"],
        }
        result["rationale"] = {
            "ease_of_exploit": scores["rationale_ease"],
            "exposure": scores["rationale_exposure"],
            "whats_at_risk": scores["rationale_risk"],
            "blast_radius": scores["rationale_blast"],
            "detection_likelihood": scores["rationale_detection"],
        }
    else:
        result["risk_score"] = None
        result["unscored"] = True

    return result


@router.get("/risk/findings")
def get_risk_findings():
    # Return all findings with in-memory risk scores, sorted by risk_score descending.
    # Findings with no rule match are included at the end with risk_score=null.
    try:
        records = neo4j_client.get_findings_with_resources()
        results = [_build_response(r) for r in records]
        results.sort(key=lambda x: x["risk_score"] if x["risk_score"] is not None else -1, reverse=True)
        return results
    except Exception as e:
        return {"error": str(e)}


@router.get("/risk/findings/{finding_id}")
def get_risk_finding(finding_id: str):
    # Return a single finding with full 5-factor risk breakdown.
    try:
        record = neo4j_client.get_finding_with_resource(finding_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
        return _build_response(record)
    except HTTPException:
        raise
    except Exception as e:
        return {"error": str(e)}
