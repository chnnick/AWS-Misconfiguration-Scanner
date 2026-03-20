#!/usr/bin/env python3
import boto3
import json
import uuid
from datetime import datetime

from utils import contains_credentials, make_finding, CREDENTIAL_PATTERNS

ec2_client = boto3.client("ec2", region_name="us-east-1")



# -------------------------
# EC2 Detections
# -------------------------

def check_imdsv1(instance):
    metadata_options = instance.get("MetadataOptions", {})
    if metadata_options.get("HttpTokens") != "required":
        return make_finding(
            finding_type="IMDSV1_ENABLED",
            severity="HIGH",
            description="IMDSv1 is enabled. Unauthenticated requests to the metadata service are allowed, enabling credential theft via SSRF.",
            remediation="Set http_tokens = 'required' in metadata_options to enforce IMDSv2.",
            cis_control="5.6",
            owasp="A05:2021"
        )
    return None


def check_open_ssh(instance):
    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    if not sg_ids:
        return None

    sgs = ec2_client.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return make_finding(
                            finding_type="OPEN_SSH",
                            severity="HIGH",
                            description=f"Security group {sg['GroupId']} allows SSH (port 22) from 0.0.0.0/0.",
                            remediation="Restrict SSH access to known IP ranges. Remove 0.0.0.0/0 from port 22 ingress rules.",
                            cis_control="5.2",
                            owasp="A01:2021"
                        )
    return None


# -------------------------
# EC2 Scanner
# -------------------------

def scan_ec2():
    nodes = {"EC2Instance": [], "IAMRole": [], "SecurityGroup": [], "Finding": []}
    relationships = []

    response = ec2_client.describe_instances()

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
            iam_profile = instance.get("IamInstanceProfile", {})
            metadata_options = instance.get("MetadataOptions", {})

            # EC2Instance node
            ec2_node = {
                "instance_id": instance["InstanceId"],
                "instance_type": instance.get("InstanceType"),
                "region": ec2_client.meta.region_name,
                "public_ip": instance.get("PublicIpAddress"),
                "private_ip": instance.get("PrivateIpAddress"),
                "imdsv1_enabled": metadata_options.get("HttpTokens") != "required",
                "has_public_ip": "PublicIpAddress" in instance,
            }
            nodes["EC2Instance"].append(ec2_node)

            # SecurityGroup nodes + HAS_SECURITY_GROUP relationships
            if sg_ids:
                sgs = ec2_client.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
                for sg in sgs:
                    nodes["SecurityGroup"].append({
                        "group_id": sg["GroupId"],
                        "group_name": sg["GroupName"],
                        "description": sg.get("Description")
                    })
                    relationships.append({
                        "type": "HAS_SECURITY_GROUP",
                        "from_type": "EC2Instance",
                        "from_id": instance["InstanceId"],
                        "to_type": "SecurityGroup",
                        "to_id": sg["GroupId"]
                    })

            # IAMRole node + HAS_ROLE relationship
            if iam_profile:
                role_name = iam_profile.get("Arn", "").split("/")[-1]
                nodes["IAMRole"].append({
                    "role_name": role_name,
                    "arn": iam_profile.get("Arn")
                })
                relationships.append({
                    "type": "HAS_ROLE",
                    "from_type": "EC2Instance",
                    "from_id": instance["InstanceId"],
                    "to_type": "IAMRole",
                    "to_id": role_name
                })

            # Findings + HAS_FINDING relationships
            for check in [check_imdsv1, check_open_ssh]:
                finding = check(instance)
                if finding:
                    nodes["Finding"].append(finding)
                    relationships.append({
                        "type": "HAS_FINDING",
                        "from_type": "EC2Instance",
                        "from_id": instance["InstanceId"],
                        "to_type": "Finding",
                        "to_id": finding["finding_id"]
                    })

    return nodes, relationships


# -------------------------
# Runner
# -------------------------

def run_scanner():
    print("Running EC2 detection engine...\n")
    start = datetime.now()

    nodes, relationships = scan_ec2()

    output = {
        "scan_timestamp": datetime.now().isoformat() + "Z",
        "nodes": nodes,
        "relationships": relationships
    }

    print(json.dumps(output, indent=2))

    with open("findings_ec2.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nScan complete in {datetime.now() - start}. {len(nodes['Finding'])} finding(s) written to findings_ec2.json")


if __name__ == "__main__":
    run_scanner()