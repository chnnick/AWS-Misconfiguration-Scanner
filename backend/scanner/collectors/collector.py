# runs both scans and outputs findings to a JSON file
#!/usr/bin/env python3

import boto3
import json
from datetime import datetime   

from collector_ec2 import scan_ec2
from collector_s3 import scan_s3

def run_scanner():
    print("Running detection engine...\n")
    start = datetime.now()

    findings = []
    findings.extend(scan_ec2())
    findings.extend(scan_s3())

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