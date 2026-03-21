import json
from datetime import datetime

class S3ScannerService:
    def __init__(self, client):
        self.client = client

    def run_scanner(self):
        print("Running detection engine...\n")

        findings = []
        findings.extend(self.scan_s3())

        # output = {
        #     "scan_timestamp": datetime.now().isoformat() + "Z",
        #     "total_findings": len(findings),
        #     "findings": findings
        # }

        # print(json.dumps(output, indent=2))

        # with open("findings.json", "w") as f:
        #     json.dump(output, f, indent=2)

        # print(f"\nScan complete. {len(findings)} finding(s) written to findings.json")

        return findings

    def check_public_access_block(self, bucket_name):
        """Flag if Block Public Access is not fully enabled
        
        NOTE: this is a basic check and may not catch all cases of public access, but it's a good starting point.
        AWS enables Block Public Access by default at the account level on newer accounts, but existing buckets may not have it enabled at the bucket level.
        """
        try:
            config = self.client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
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
        except self.client.exceptions.NoSuchPublicAccessBlockConfiguration:
            return {
                "resource_type": "S3",
                "resource_id": bucket_name,
                "check": "Block Public Access Disabled",
                "detail": "No Block Public Access configuration found. Bucket may be publicly accessible.",
                "status": "FAIL"
            }
        return None


    def check_encryption(self, bucket_name):
        """Flag if encryption at rest is not configured
        
        NOTE: most likely deprecated since server side encryption is enabled by default as of 2023
        """
        try:
            self.client.get_bucket_encryption(Bucket=bucket_name)
        except self.client.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                return {
                    "resource_type": "S3",
                    "resource_id": bucket_name,
                    "check": "Encryption at Rest Disabled",
                    "detail": "No server-side encryption configuration found on bucket.",
                    "status": "FAIL"
                }
        return None


    def check_bucket_policy(self, bucket_name):
        """Flag if no bucket policy is defined"""
        try:
            self.client.get_bucket_policy(Bucket=bucket_name)
        except self.client.exceptions.ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                return {
                    "resource_type": "S3",
                    "resource_id": bucket_name,
                    "check": "No Bucket Policy",
                    "detail": "Bucket has no resource-based policy. Access controlled by IAM only.",
                    "status": "FAIL"
                }
        return None


    def scan_s3(self):
        findings = []
        buckets = self.client.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            for check in [self.check_public_access_block, self.check_encryption, self.check_bucket_policy]:
                result = check(bucket_name)
                if result:
                    findings.append(result)

        return findings