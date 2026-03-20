#!/usr/bin/env python3
import boto3
import json
import uuid
import re
from datetime import datetime

from utils import contains_credentials, make_finding, CREDENTIAL_PATTERNS

s3_client = boto3.client("s3")




# -------------------------
# S3 Detections
# -------------------------

def check_public_access_block(bucket_name):
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
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
    except s3_client.exceptions.ClientError:
        return make_finding(
            finding_type="BLOCK_PUBLIC_ACCESS_DISABLED",
            severity="CRITICAL",
            description="No Block Public Access configuration found. Bucket may be publicly accessible.",
            remediation="Enable all four Block Public Access settings on the bucket.",
            cis_control="2.1.5",
            owasp="A01:2021"
        )
    return None


def check_bucket_policy(bucket_name):
    try:
        s3_client.get_bucket_policy(Bucket=bucket_name)
    except s3_client.exceptions.ClientError as e:
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


# -------------------------
# S3 Scanner
# -------------------------

def scan_s3():
    nodes = {"S3Bucket": [], "S3Object": [], "Secret": [], "Finding": []}
    relationships = []

    buckets = s3_client.list_buckets().get("Buckets", [])
    if not buckets:
        print("No S3 buckets found.")
        return nodes, relationships

    for bucket in buckets:
        name = bucket["Name"]

        # S3Bucket node
        bucket_node = {
            "bucket_name": name,
            "arn": f"arn:aws:s3:::{name}",
            "region": s3_client.meta.region_name,
        }
        nodes["S3Bucket"].append(bucket_node)

        # Bucket-level findings + HAS_FINDING relationships
        for check in [check_public_access_block, check_bucket_policy]:
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

        # Scan objects for plaintext credentials
        try:
            objects = s3_client.list_objects_v2(Bucket=name).get("Contents", [])
            for obj in objects:
                key = obj["Key"]
                if not key.endswith(SCANNABLE_EXTENSIONS):
                    continue

                # S3Object node + CONTAINS relationship from bucket
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

                # Scan object contents for credentials
                try:
                    body = s3_client.get_object(Bucket=name, Key=key)["Body"].read().decode("utf-8", errors="ignore")
                    match = contains_credentials(body)
                    if match:
                        # Secret node + CONTAINS relationship from object
                        secret_node = {
                            "location": f"{name}/{key}",
                            "type": "AWS_ACCESS_KEY" if match.startswith("AKIA") else "CREDENTIAL",
                            "pattern": match[:10] + "...",  # truncate for safety
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

                        # Finding + HAS_FINDING relationship from bucket
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


# -------------------------
# Runner
# -------------------------

def run_scanner():
    print("Running S3 detection engine...\n")
    start = datetime.now()

    nodes, relationships = scan_s3()

    output = {
        "scan_timestamp": datetime.now().isoformat() + "Z",
        "nodes": nodes,
        "relationships": relationships
    }

    print(json.dumps(output, indent=2))

    with open("findings_s3.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nScan complete in {datetime.now() - start}. {len(nodes['Finding'])} finding(s) written to findings_s3.json")


if __name__ == "__main__":
    run_scanner()