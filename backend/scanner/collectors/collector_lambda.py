#!/usr/bin/env python3
import boto3
import json
import urllib.request
import zipfile
import io
from datetime import datetime

from scanner.collectors.utils import contains_credentials, make_finding


class LambdaScannerService:
    def __init__(self, client):
        self.client = client

    def check_env_vars(self, function):
        env_vars = function.get("Environment", {}).get("Variables", {})
        for key, value in env_vars.items():
            match = contains_credentials(f"{key}={value}")
            if match:
                return make_finding(
                    finding_type="HARDCODED_CREDENTIALS_IN_ENV",
                    severity="CRITICAL",
                    description=f"Potential credential found in environment variable '{key}' of function '{function['FunctionName']}'.",
                    remediation="Remove credentials from environment variables. Use AWS Secrets Manager or IAM roles instead.",
                    cis_control="1.19",
                    owasp="A02:2021"
                )
        return None

    def check_function_code(self, function):
        function_name = function["FunctionName"]
        try:
            code_url = self.client.get_function(FunctionName=function_name)["Code"].get("Location")
            if not code_url:
                return None

            with urllib.request.urlopen(code_url) as response:
                zip_data = response.read()

            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                for filename in z.namelist():
                    if filename.endswith((".py", ".js", ".env", ".json", ".yaml", ".yml", ".txt")):
                        content = z.open(filename).read().decode("utf-8", errors="ignore")
                        match = contains_credentials(content)
                        if match:
                            return make_finding(
                                finding_type="HARDCODED_CREDENTIALS_IN_CODE",
                                severity="CRITICAL",
                                description=f"Potential credential pattern found in '{filename}' of function '{function_name}'.",
                                remediation="Remove hardcoded credentials from source code. Use IAM roles or Secrets Manager.",
                                cis_control="1.19",
                                owasp="A02:2021"
                            )
        except Exception as e:
            print(f"[WARN] Could not scan code for {function_name}: {e}")

        return None

    def scan_lambda(self):
        nodes = {"LambdaFunction": [], "Finding": []}
        relationships = []

        functions = self.client.list_functions().get("Functions", [])
        if not functions:
            print("No Lambda functions found.")
            return nodes, relationships

        for function in functions:
            lambda_node = {
                "function_name": function["FunctionName"],
                "arn": function["FunctionArn"],
                "runtime": function.get("Runtime"),
                "region": self.client.meta.region_name,
                "role": function.get("Role")
            }
            nodes["LambdaFunction"].append(lambda_node)

            for check in [self.check_env_vars, self.check_function_code]:
                finding = check(function)
                if finding:
                    nodes["Finding"].append(finding)
                    relationships.append({
                        "type": "HAS_FINDING",
                        "from_type": "LambdaFunction",
                        "from_id": function["FunctionName"],
                        "to_type": "Finding",
                        "to_id": finding["finding_id"]
                    })

        return nodes, relationships

    def run_scanner(self):
        nodes, relationships = self.scan_lambda()

        output = {
            "scan_timestamp": datetime.now().isoformat() + "Z",
            "nodes": nodes,
            "relationships": relationships
        }

        with open("findings_lambda.json", "w") as f:
            json.dump(output, f, indent=2)

        return output


# if __name__ == "__main__":
#     LambdaScannerService(boto3.client("lambda", region_name="us-east-1")).run_scanner()
