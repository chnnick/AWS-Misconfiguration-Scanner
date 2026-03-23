#!/usr/bin/env python3
from scanner.collectors.utils import contains_credentials, make_finding

SCANNABLE_EXTENSIONS = ('.txt', '.env', '.json', '.yaml', '.yml', '.config', '.ini', '.properties', '.py', '.js', '.sh', '.md')

class S3ScannerService:
    def __init__(self, client):
        self.client = client

    def check_public_access_block(self, bucket_name):
        try:
            config = self.client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
            if not all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets")
            ]):
                return make_finding(
                    finding_type="BLOCK_PUBLIC_ACCESS_DISABLED",
                    severity="CRITICAL",
                    description="One or more Block Public Access settings are disabled. Bucket may be publicly accessible.",
                    remediation="Enable all four Block Public Access settings on the bucket.",
                    cis_control="2.1.5",
                    owasp="A01:2021"
                )
        except self.client.exceptions.ClientError:
            return make_finding(
                finding_type="BLOCK_PUBLIC_ACCESS_DISABLED",
                severity="CRITICAL",
                description="No Block Public Access configuration found. Bucket may be publicly accessible.",
                remediation="Enable all four Block Public Access settings on the bucket.",
                cis_control="2.1.5",
                owasp="A01:2021"
            )
        return None

    def check_bucket_policy(self, bucket_name):
        try:
            self.client.get_bucket_policy(Bucket=bucket_name)
        except self.client.exceptions.ClientError as e:
            if "NoSuchBucketPolicy" in str(e):
                return make_finding(
                    finding_type="NO_BUCKET_POLICY",
                    severity="MEDIUM",
                    description="Bucket has no resource-based policy. Access is controlled by IAM only.",
                    remediation="Add a bucket policy restricting access by VPC endpoint or source IP.",
                    cis_control="2.1.2",
                    owasp="A01:2021"
                )
        return None

    def scan_s3(self):
        nodes = {"S3Bucket": [], "S3Object": [], "Secret": [], "Finding": []}
        relationships = []

        buckets = self.client.list_buckets().get("Buckets", [])
        if not buckets:
            print("No S3 buckets found.")
            return nodes, relationships

        for bucket in buckets:
            name = bucket["Name"]

            bucket_node = {
                "bucket_name": name,
                "arn": f"arn:aws:s3:::{name}",
                "region": self.client.meta.region_name,
            }
            nodes["S3Bucket"].append(bucket_node)

            for check in [self.check_public_access_block, self.check_bucket_policy]:
                finding = check(name)
                if finding:
                    nodes["Finding"].append(finding)
                    relationships.append({
                        "type": "HAS_FINDING",
                        "from_type": "S3Bucket",
                        "from_id": name,
                        "to_type": "Finding",
                        "to_id": finding["finding_id"]
                    })

            try:
                objects = self.client.list_objects_v2(Bucket=name).get("Contents", [])
                for obj in objects:
                    key = obj["Key"]
                    if not key.endswith(SCANNABLE_EXTENSIONS):
                        continue

                    obj_node = {
                        "object_key": key,
                        "bucket_name": name,
                        "size": obj.get("Size"),
                        "last_modified": obj["LastModified"].isoformat()
                    }
                    nodes["S3Object"].append(obj_node)
                    relationships.append({
                        "type": "CONTAINS",
                        "from_type": "S3Bucket",
                        "from_id": name,
                        "to_type": "S3Object",
                        "to_id": key
                    })

                    try:
                        body = self.client.get_object(Bucket=name, Key=key)["Body"].read().decode("utf-8", errors="ignore")
                        match = contains_credentials(body)
                        if match:
                            secret_node = {
                                "location": f"{name}/{key}",
                                "type": "AWS_ACCESS_KEY" if match.startswith("AKIA") else "CREDENTIAL",
                                "pattern": match[:10] + "...",
                                "exposure_level": "PRIVATE"
                            }
                            nodes["Secret"].append(secret_node)
                            relationships.append({
                                "type": "CONTAINS",
                                "from_type": "S3Object",
                                "from_id": key,
                                "to_type": "Secret",
                                "to_id": secret_node["location"]
                            })

                            finding = make_finding(
                                finding_type="PLAINTEXT_CREDENTIALS_IN_S3",
                                severity="CRITICAL",
                                description=f"Plaintext credentials found in object '{key}'.",
                                remediation="Remove credentials from S3. Use AWS Secrets Manager or Parameter Store.",
                                cis_control="2.1.4",
                                owasp="A02:2021"
                            )
                            nodes["Finding"].append(finding)
                            relationships.append({
                                "type": "HAS_FINDING",
                                "from_type": "S3Bucket",
                                "from_id": name,
                                "to_type": "Finding",
                                "to_id": finding["finding_id"]
                            })

                    except Exception as e:
                        print(f"[WARN] Could not read {name}/{key}: {e}")

            except Exception as e:
                print(f"[WARN] Could not list objects in {name}: {e}")

        return nodes, relationships

    def run_scanner(self):
        nodes, relationships = self.scan_s3()

        return nodes["Finding"], relationships
