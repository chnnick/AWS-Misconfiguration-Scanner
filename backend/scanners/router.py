from fastapi import APIRouter, Depends
import boto3
from app.config import Settings
from scanners.collectors.collector_ec2 import EC2ScannerService
from scanners.collectors.collector_s3 import S3ScannerService

router = APIRouter(
    prefix="/scanners",
    tags=["scanners"],
)

settings = Settings()

def get_client(service: str):
    return boto3.client(
        service,
        AWS_ACCESS_KEY_ID=settings.AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY=settings.AWS_SECRET_ACCESS_KEY,
        AWS_REGION=settings.AWS_REGION
    )

@router.post("/ec2")
def scan_ec2(client=Depends(get_client("ec2"))):
    findings = EC2ScannerService(client).run_scanner()
    return {
        "resource": "EC2",
        "total_findings": len(findings),
        "findings": findings
    }

@router.post("/s3")
def scan_s3():
    findings = S3ScannerService(client=Depends(get_client("s3"))).run_scanner()
  
    return {
        "resource": "EC2",
        "total_findings": len(findings),
        "findings": findings
    }