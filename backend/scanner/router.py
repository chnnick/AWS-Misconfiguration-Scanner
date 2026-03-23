from datetime import datetime

import boto3
from fastapi import APIRouter, Depends

from app.config import settings
from scanner.collectors.collector_ec2 import EC2ScannerService
from scanner.collectors.collector_s3 import S3ScannerService
from scanner.collectors.collector_lambda import LambdaScannerService
from scanner.collectors.collector_iam import IAMScannerService
from scanner.schemas import ScanResponse

router = APIRouter(
    prefix="/scanner",
    tags=["scanner"],
)


def _boto_client(service_name: str):
    return boto3.client(
        service_name,
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_REGION,
    )


def get_ec2_client():
    return _boto_client("ec2")

def get_s3_client():
    return _boto_client("s3")

def get_lambda_client():
    return _boto_client("lambda")

def get_iam_client():
    return _boto_client("iam")

def _scan_response(resource: str, start: datetime, findings: list) -> ScanResponse:
    end = datetime.now()
    return ScanResponse(
        scan_start=start.isoformat() + "Z",
        duration_seconds=(end - start).total_seconds(),
        resource=resource,
        total_findings=len(findings),
        findings=findings,
    )


@router.post("/ec2", response_model=ScanResponse)
def scan_ec2(client=Depends(get_ec2_client)):
    start = datetime.now()
    findings = EC2ScannerService(client).run_scanner()
    return _scan_response("EC2", start, findings)


@router.post("/s3", response_model=ScanResponse)
def scan_s3(client=Depends(get_s3_client)):
    start = datetime.now()
    findings = S3ScannerService(client).run_scanner()
    return _scan_response("S3", start, findings)


@router.post("/lambda", response_model=ScanResponse)
def scan_lambda(client=Depends(get_lambda_client)):
    start = datetime.now()
    findings = LambdaScannerService(client).run_scanner()
    return _scan_response("Lambda", start, findings)

@router.post("/iam", response_model=ScanResponse)
def scan_iam(client=Depends(get_iam_client)):
    start = datetime.now()
    findings = IAMScannerService(client).run_scanner()
    return _scan_response("IAM", start, findings)
