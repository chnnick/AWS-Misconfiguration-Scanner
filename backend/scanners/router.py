from fastapi import APIRouter, Depends
import boto3
from datetime import datetime
from app.config import settings
from scanners.collectors.collector_ec2 import EC2ScannerService
from scanners.collectors.collector_s3 import S3ScannerService

router = APIRouter(
    prefix="/scanners",
    tags=["scanners"],
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


@router.post("/ec2")
def scan_ec2(client=Depends(get_ec2_client)):
    start = datetime.now()
    findings = EC2ScannerService(client).run_scanner()
    return {
        "scan_start": datetime.now().isoformat() + "Z",
        "duration_seconds": (datetime.now() - start).total_seconds(),
        "total_findings": len(findings),
        "findings": findings
    }
  

@router.post("/s3")
def scan_s3(client=Depends(get_s3_client)):
    start = datetime.now()
    findings = EC2ScannerService(client).run_scanner()
    return {
        "scan_start": datetime.now().isoformat() + "Z",
        "duration_seconds": (datetime.now() - start).total_seconds(),
        "resource": "S3",
        "total_findings": len(findings),
        "findings": findings
    }