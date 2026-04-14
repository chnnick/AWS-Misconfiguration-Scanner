from datetime import datetime
import logging
import os

import boto3
from fastapi import APIRouter, Depends, HTTPException

from scanner.collectors.utils import get_findings_path
from scanner.collectors.collector_ec2 import EC2ScannerService
from scanner.collectors.collector_s3 import S3ScannerService
from scanner.collectors.collector_lambda import LambdaScannerService
from scanner.collectors.collector_iam import IAMScannerService
from scanner.schemas import ScanResponse
from app.neo4j_client import neo4j_client
from app.scoring.engine import RESOURCE_ID_PROPS, score_finding

router = APIRouter(
    prefix="/scanner",
    tags=["scanner"],
)
risk_router = APIRouter(
    prefix="/risk",
    tags=["risk"],
)
logger = logging.getLogger(__name__)

def _boto_client(service_name: str):
    return boto3.client(service_name)


def get_ec2_client():
    return _boto_client("ec2")

def get_s3_client():
    return _boto_client("s3")

def get_lambda_client():
    return _boto_client("lambda")

def get_iam_client():
    return _boto_client("iam")


def _auto_load_to_neo4j(json_file: str):
    try:
        from scanner.loaders.loader_neo4j import Neo4jLoader

        if not os.path.exists(json_file):
            logger.warning(
                "Neo4j auto-load skipped; findings file not found: %s (cwd=%s)",
                json_file,
                os.getcwd(),
            )
            return

        logger.info("Starting Neo4j auto-load for %s", json_file)
        loader = Neo4jLoader()
        try:
            loader.ensure_schema_exists()
            loader.load_collector_output(json_file)
            logger.info("Loaded %s into Neo4j", json_file)
        finally:
            loader.close()
    except Exception:
        logger.exception("Neo4j auto-load failed for %s", json_file)


def _scan_response(resource: str, start: datetime, output: dict) -> ScanResponse:
    end = datetime.now()
    findings = output["nodes"]["Finding"]
    relationships = output["relationships"]

    return ScanResponse(
        scan_start=start.isoformat() + "Z",
        duration_seconds=(end - start).total_seconds(),
        resource=resource,
        total_findings=len(findings),
        findings=findings,
        relationships=relationships,
    )


@router.post("/ec2", response_model=ScanResponse)
def scan_ec2(client=Depends(get_ec2_client)):
    try:
        start = datetime.now()
        output = EC2ScannerService(client).run_scanner()
        _auto_load_to_neo4j(get_findings_path("findings_ec2.json"))
        return _scan_response("EC2", start, output)
    except Exception:
        logger.exception("EC2 scan endpoint failed")
        raise


@router.post("/s3", response_model=ScanResponse)
def scan_s3(client=Depends(get_s3_client)):
    try:
        start = datetime.now()
        output = S3ScannerService(client).run_scanner()
        _auto_load_to_neo4j(get_findings_path("findings_s3.json"))
        return _scan_response("S3", start, output)
    except Exception:
        logger.exception("S3 scan endpoint failed")
        raise


@router.post("/lambda", response_model=ScanResponse)
def scan_lambda(client=Depends(get_lambda_client)):
    try:
        start = datetime.now()
        output = LambdaScannerService(client).run_scanner()
        _auto_load_to_neo4j(get_findings_path("findings_lambda.json"))
        return _scan_response("Lambda", start, output)
    except Exception:
        logger.exception("Lambda scan endpoint failed")
        raise


@router.post("/iam", response_model=ScanResponse)
def scan_iam(client=Depends(get_iam_client)):
    try:
        start = datetime.now()
        output = IAMScannerService(client).run_scanner()
        _auto_load_to_neo4j(get_findings_path("findings_iam.json"))
        return _scan_response("IAM", start, output)
    except Exception:
        logger.exception("IAM scan endpoint failed")
        raise


@router.post("/all")
def scan_all(
    ec2_client=Depends(get_ec2_client),
    s3_client=Depends(get_s3_client),
    lambda_client=Depends(get_lambda_client),
    iam_client=Depends(get_iam_client)
):
    try:
        start = datetime.now()

        results = {
            "ec2": EC2ScannerService(ec2_client).run_scanner(),
            "s3": S3ScannerService(s3_client).run_scanner(),
            "lambda": LambdaScannerService(lambda_client).run_scanner(),
            "iam": IAMScannerService(iam_client).run_scanner(),
        }

        _auto_load_to_neo4j(get_findings_path("findings_ec2.json"))
        _auto_load_to_neo4j(get_findings_path("findings_s3.json"))
        _auto_load_to_neo4j(get_findings_path("findings_lambda.json"))
        _auto_load_to_neo4j(get_findings_path("findings_iam.json"))

        end = datetime.now()

        return {
            "scan_start": start.isoformat() + "Z",
            "duration_seconds": (end - start).total_seconds(),
            "scans_completed": len(results),
            "total_findings": sum(len(r["nodes"]["Finding"]) for r in results.values()),
            "results": results
        }
    except Exception:
        logger.exception("Full scan endpoint failed")
        raise


# ---------------------------------------------------------------------------
# Risk scoring endpoints
# Scores are computed in-memory from Neo4j findings — Neo4j is never written to.
# ---------------------------------------------------------------------------

def _build_risk_response(record):
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


@risk_router.get("/findings")
def get_risk_findings():
    # Return all findings with in-memory risk scores, sorted by risk_score descending.
    # Findings with no rule match are included at the end with risk_score=null.
    try:
        records = neo4j_client.get_findings_with_resources()
        results = [_build_risk_response(r) for r in records]
        results.sort(key=lambda x: x["risk_score"] if x["risk_score"] is not None else -1, reverse=True)
        return results
    except Exception as e:
        return {"error": str(e)}


@risk_router.get("/findings/{finding_id}")
def get_risk_finding(finding_id: str):
    # Return a single finding with full 5-factor risk breakdown.
    try:
        record = neo4j_client.get_finding_with_resource(finding_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Finding not found: {finding_id}")
        return _build_risk_response(record)
    except HTTPException:
        raise
    except Exception as e:
        return {"error": str(e)}
