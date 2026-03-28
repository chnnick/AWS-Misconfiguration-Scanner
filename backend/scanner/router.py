from datetime import datetime
import os
import sys

import boto3
from fastapi import APIRouter, Depends

from scanner.collectors.collector_ec2 import EC2ScannerService
from scanner.collectors.collector_s3 import S3ScannerService
from scanner.collectors.collector_lambda import LambdaScannerService
from scanner.collectors.collector_iam import IAMScannerService
from scanner.schemas import ScanResponse

router = APIRouter(
    prefix="/api/scanner",
    tags=["scanner"],
)

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
    """Auto-load collector output into Neo4j"""
    try:
        sys.path.append(os.path.join(os.path.dirname(__file__), 'loaders'))
        from loader_neo4j import Neo4jLoader
        
        if not os.path.exists(json_file):
            print(f"Warning: {json_file} not found")
            return
        
        loader = Neo4jLoader()
        try:
            loader.ensure_schema_exists()
            loader.load_collector_output(json_file)
            print(f"Loaded {json_file} into Neo4j")
        finally:
            loader.close()
    except Exception as e:
        print(f"Warning: Could not auto-load into Neo4j: {e}")


def _scan_response(resource: str, start: datetime, output: dict) -> ScanResponse:
    """Build scan response and auto-load into Neo4j"""
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
    """Scan EC2 instances and auto-load into Neo4j"""
    start = datetime.now()
    output = EC2ScannerService(client).run_scanner()
    
    # Auto-load into Neo4j
    _auto_load_to_neo4j("/data/findings_ec2.json")
    
    return _scan_response("EC2", start, output)


@router.post("/s3", response_model=ScanResponse)
def scan_s3(client=Depends(get_s3_client)):
    """Scan S3 buckets and auto-load into Neo4j"""
    start = datetime.now()
    output = S3ScannerService(client).run_scanner()
    
    # Auto-load into Neo4j
    _auto_load_to_neo4j("/data/findings_s3.json")
    
    return _scan_response("S3", start, output)


@router.post("/lambda", response_model=ScanResponse)
def scan_lambda(client=Depends(get_lambda_client)):
    """Scan Lambda functions and auto-load into Neo4j"""
    start = datetime.now()
    output = LambdaScannerService(client).run_scanner()
    
    # Auto-load into Neo4j
    _auto_load_to_neo4j("/data/findings_lambda.json")
    
    return _scan_response("Lambda", start, output)


@router.post("/iam", response_model=ScanResponse)
def scan_iam(client=Depends(get_iam_client)):
    """Scan IAM resources and auto-load into Neo4j"""
    start = datetime.now()
    output = IAMScannerService(client).run_scanner()
    
    # Auto-load into Neo4j
    _auto_load_to_neo4j("/data/findings_iam.json")
    
    return _scan_response("IAM", start, output)


@router.post("/all")
def scan_all(
    ec2_client=Depends(get_ec2_client),
    s3_client=Depends(get_s3_client),
    lambda_client=Depends(get_lambda_client),
    iam_client=Depends(get_iam_client)
):
    """Scan all resources and auto-load into Neo4j"""
    start = datetime.now()
    
    results = {
        "ec2": EC2ScannerService(ec2_client).run_scanner(),
        "s3": S3ScannerService(s3_client).run_scanner(),
        "lambda": LambdaScannerService(lambda_client).run_scanner(),
        "iam": IAMScannerService(iam_client).run_scanner(),
    }
    
    # Auto-load all into Neo4j
    _auto_load_to_neo4j("/data/findings_ec2.json")
    _auto_load_to_neo4j("/data/findings_s3.json")
    _auto_load_to_neo4j("/data/findings_lambda.json")
    _auto_load_to_neo4j("/data/findings_iam.json")
    
    end = datetime.now()
    
    return {
        "scan_start": start.isoformat() + "Z",
        "duration_seconds": (end - start).total_seconds(),
        "scans_completed": len(results),
        "total_findings": sum(len(r["nodes"]["Finding"]) for r in results.values()),
        "results": results
    }