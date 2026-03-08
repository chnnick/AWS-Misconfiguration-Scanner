#!/usr/bin/env python3

import boto3
import json
from datetime import datetime



#import clients
ec2_client = boto3.client("ec2", region_name="us-east-1") 


# EC2 Detections
def check_imdsv1(instance):
    """Flag if IMDSv1 is enabled (http_tokens != 'required')"""
    metadata_options = instance.get("MetadataOptions", {})
    iam_role = instance.get("IamInstanceProfile", {})

    if metadata_options.get("HttpTokens") != "required" and iam_role is None:
        return {
            "resource_type": "EC2",
            "resource_id": instance["InstanceId"],
            "check": "IMDSv1 Enabled",
            "detail": "MetadataOptions.HttpTokens is not set to 'required'. IMDSv2 is not enforced.",
            "status": "FAIL"
        }
    return None


def check_open_ssh(instance):
    """Flag if any attached security group allows SSH (port 22) from 0.0.0.0/0"""
    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
    if not sg_ids:
        return None

    sgs = ec2_client.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            if rule.get("FromPort") == 22 and rule.get("ToPort") == 22:
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return {
                            "resource_type": "EC2",
                            "resource_id": instance["InstanceId"],
                            "check": "Open SSH",
                            "detail": f"Security group {sg['GroupId']} allows port 22 from 0.0.0.0/0.",
                            "status": "FAIL"
                        }
    return None


def scan_ec2():
    findings = []
    response = ec2_client.describe_instances()

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            for check in [check_imdsv1, check_open_ssh]:
                result = check(instance)
                if result:
                    findings.append(result)

    return findings



def run_scanner():
    print("Running detection engine...\n")
    start = datetime.now()

    findings = []
    findings.extend(scan_ec2())

    output = {
        "scan_timestamp": datetime.now().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings
    }

    print(json.dumps(output, indent=2))

    with open("findings.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nScan complete in {datetime.now() - start}. {len(findings)} finding(s) written to findings.json")


if __name__ == "__main__":
    run_scanner()