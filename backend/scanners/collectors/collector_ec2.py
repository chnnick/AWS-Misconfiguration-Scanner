#!/usr/bin/env python3

import json
from datetime import datetime

class EC2ScannerService:
    def __init__(self, client):
        self.client = client  

    def run_scanner(self, instance):
        print("Running detection engine...\n")
        start = datetime.now()

        findings = []
        findings.extend(self.scan_ec2(instance))

        # Output the findings to a JSON file
        output = {
            "scan_timestamp": datetime.now().isoformat() + "Z",
            "total_findings": len(findings),
            "findings": findings
        }

        print(json.dumps(output, indent=2))

        with open("findings.json", "w") as f:
            json.dump(output, f, indent=2)

        print(f"\nScan complete in {datetime.now() - start}. {len(findings)} finding(s) written to findings.json")

    # EC2 Detections
    def check_imdsv1(self, instance):
        """Flag if IMDSv1 is enabled (http_tokens != 'required')"""
        metadata_options = instance.get("MetadataOptions", {})
        if metadata_options.get("HttpTokens") != "required":
            return {
                "resource_type": "EC2",
                "resource_id": instance["InstanceId"],
                "check": "IMDSv1 Enabled",
                "detail": "MetadataOptions.HttpTokens is not set to 'required'. IMDSv2 is not enforced.",
                "status": "FAIL"
            }
        return None
        
    def check_open_ssh(self, instance):
        """Flag if any attached security group allows SSH (port 22) from 0.0.0.0/0"""
        sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        if not sg_ids:
            return None

        sgs = self.client.describe_security_groups(GroupIds=sg_ids)["SecurityGroups"]
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

    def scan_ec2(self, instance):
        findings = []
        response = self.client.describe_instances()

        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                for check in [self.check_imdsv1, self.check_open_ssh]:
                    result = check(instance)
                    if result:
                        findings.append(result)

        return findings

