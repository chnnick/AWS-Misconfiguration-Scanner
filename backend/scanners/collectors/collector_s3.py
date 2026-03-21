import boto3
import json
from datetime import datetime



s3_client = boto3.client("s3")


def check_public_access_block(bucket_name):
    """Flag if Block Public Access is not fully enabled
    
    NOTE: this is a basic check and may not catch all cases of public access, but it's a good starting point.
    AWS enables Block Public Access by default at the account level on newer accounts, but existing buckets may not have it enabled at the bucket level.
    """
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        if not all([
            config.get("BlockPublicAcls"),
            config.get("IgnorePublicAcls"),
            config.get("BlockPublicPolicy"),
            config.get("RestrictPublicBuckets")
        ]):
            return {
                "resource_type": "S3",
                "resource_id": bucket_name,
                "check": "Block Public Access Disabled",
                "detail": "One or more Block Public Access settings are not enabled.",
                "status": "FAIL"
            }
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {
            "resource_type": "S3",
            "resource_id": bucket_name,
            "check": "Block Public Access Disabled",
            "detail": "No Block Public Access configuration found. Bucket may be publicly accessible.",
            "status": "FAIL"
        }
    return None


def check_encryption(bucket_name):
    """Flag if encryption at rest is not configured
    
    NOTE: most likely deprecated since server side encryption is enabled by default as of 2023
    """
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
    except s3_client.exceptions.ClientError as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            return {
                "resource_type": "S3",
                "resource_id": bucket_name,
                "check": "Encryption at Rest Disabled",
                "detail": "No server-side encryption configuration found on bucket.",
                "status": "FAIL"
            }
    return None


def check_bucket_policy(bucket_name):
    """Flag if no bucket policy is defined"""
    try:
        s3_client.get_bucket_policy(Bucket=bucket_name)
    except s3_client.exceptions.ClientError as e:
        if "NoSuchBucketPolicy" in str(e):
            return {
                "resource_type": "S3",
                "resource_id": bucket_name,
                "check": "No Bucket Policy",
                "detail": "Bucket has no resource-based policy. Access controlled by IAM only.",
                "status": "FAIL"
            }
    return None


def scan_s3():
    findings = []
    buckets = s3_client.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        for check in [check_public_access_block, check_encryption, check_bucket_policy]:
            result = check(name)
            if result:
                findings.append(result)

    return findings



def run_scanner():
    print("Running detection engine...\n")

    findings = []
    findings.extend(scan_s3())

    output = {
        "scan_timestamp": datetime.now().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings
    }

    print(json.dumps(output, indent=2))

    with open("findings.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nScan complete. {len(findings)} finding(s) written to findings.json")


if __name__ == "__main__":
    run_scanner()