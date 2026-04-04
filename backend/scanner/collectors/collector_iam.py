#!/usr/bin/env python3
from datetime import datetime
import json

from scanner.collectors.utils import get_findings_path, make_finding


class IAMScannerService:
    def __init__(self, client):
        self.client = client

    def get_all_policy_documents(self, entity_type, entity_name):
        statements = []

        if entity_type == "user":
            inline_policies = self.client.list_user_policies(UserName=entity_name)["PolicyNames"]
            for policy_name in inline_policies:
                doc = self.client.get_user_policy(UserName=entity_name, PolicyName=policy_name)["PolicyDocument"]
                statements.extend(doc.get("Statement", []))
        elif entity_type == "role":
            inline_policies = self.client.list_role_policies(RoleName=entity_name)["PolicyNames"]
            for policy_name in inline_policies:
                doc = self.client.get_role_policy(RoleName=entity_name, PolicyName=policy_name)["PolicyDocument"]
                statements.extend(doc.get("Statement", []))

        if entity_type == "user":
            attached = self.client.list_attached_user_policies(UserName=entity_name)["AttachedPolicies"]
        else:
            attached = self.client.list_attached_role_policies(RoleName=entity_name)["AttachedPolicies"]

        for policy in attached:
            version_id = self.client.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = self.client.get_policy_version(PolicyArn=policy["PolicyArn"], VersionId=version_id)["PolicyVersion"]["Document"]
            statements.extend(doc.get("Statement", []))

        return statements

    @staticmethod
    def statement_allows_action(statements, action):
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for a in actions:
                if a == "*" or a.lower() == action.lower() or a.lower() == action.split(":")[0].lower() + ":*":
                    return True
        return False

    @staticmethod
    def has_condition_restriction(trust_statement):
        return bool(trust_statement.get("Condition"))

    def check_assumable_roles_by_users(self, users):
        findings = []
        relationships = []

        roles = self.client.list_roles()["Roles"]
        for role in roles:
            trust_doc = role["AssumeRolePolicyDocument"]
            for stmt in trust_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for user in users:
                    user_arn = user["Arn"]
                    if any(user_arn in p or ":root" in p for p in aws_principals):
                        if not self.has_condition_restriction(stmt):
                            finding = make_finding(
                                finding_type="ROLE_ASSUMABLE_WITHOUT_MFA",
                                severity="HIGH",
                                description=f"IAM user '{user['UserName']}' can assume role '{role['RoleName']}' without MFA or condition restrictions.",
                                remediation="Add a condition requiring MFA to the role's trust policy, or restrict which principals can assume the role.",
                                cis_control="1.15",
                                owasp="A01:2021"
                            )
                            findings.append(finding)
                            relationships.append({
                                "type": "CAN_ASSUME",
                                "from_type": "IAMUser",
                                "from_id": user["UserName"],
                                "to_type": "IAMRole",
                                "to_id": role["RoleName"],
                                "finding_id": finding["finding_id"]
                            })

        return findings, relationships

    def check_modify_instance_attribute(self, roles):
        findings = []
        for role in roles:
            role_name = role["RoleName"]
            try:
                statements = self.get_all_policy_documents("role", role_name)
                if self.statement_allows_action(statements, "ec2:ModifyInstanceAttribute"):
                    findings.append(make_finding(
                        finding_type="ROLE_CAN_MODIFY_INSTANCE_USERDATA",
                        severity="HIGH",
                        description=f"Role '{role_name}' has ec2:ModifyInstanceAttribute permission, allowing userdata modification and potential code execution on EC2 instances.",
                        remediation="Remove ec2:ModifyInstanceAttribute from the role unless explicitly required. Scope to specific resources if needed.",
                        cis_control="1.16",
                        owasp="A01:2021"
                    ))
            except Exception as e:
                print(f"[WARN] Could not check role {role_name}: {e}")
        return findings

    def check_delete_tags_on_users(self, users):
        findings = []
        for user in users:
            username = user["UserName"]
            try:
                statements = self.get_all_policy_documents("user", username)
                if self.statement_allows_action(statements, "ec2:DeleteTags"):
                    findings.append(make_finding(
                        finding_type="USER_CAN_DELETE_EC2_TAGS",
                        severity="HIGH",
                        description=f"IAM user '{username}' has ec2:DeleteTags permission. If access controls rely solely on EC2 tags, this user can remove tags to bypass those restrictions.",
                        remediation="Remove ec2:DeleteTags from the user's permissions, or do not rely on tags as the sole access control mechanism.",
                        cis_control="1.16",
                        owasp="A01:2021"
                    ))
            except Exception as e:
                print(f"[WARN] Could not check user {username}: {e}")
        return findings

    def scan_iam(self):
        nodes = {"IAMUser": [], "IAMRole": [], "Finding": []}
        relationships = []

        users = self.client.list_users()["Users"]
        roles = self.client.list_roles()["Roles"]

        for user in users:
            nodes["IAMUser"].append({
                "username": user["UserName"],
                "arn": user["Arn"],
                "user_id": user["UserId"]
            })

        for role in roles:
            nodes["IAMRole"].append({
                "role_name": role["RoleName"],
                "arn": role["Arn"],
                "role_id": role["RoleId"]
            })

        assumable_findings, assumable_rels = self.check_assumable_roles_by_users(users)
        for finding in assumable_findings:
            nodes["Finding"].append(finding)
        relationships.extend(assumable_rels)

        for finding in self.check_modify_instance_attribute(roles):
            nodes["Finding"].append(finding)
            role_name = finding["description"].split("'")[1]
            relationships.append({
                "type": "HAS_FINDING",
                "from_type": "IAMRole",
                "from_id": role_name,
                "to_type": "Finding",
                "to_id": finding["finding_id"]
            })

        for finding in self.check_delete_tags_on_users(users):
            nodes["Finding"].append(finding)
            username = finding["description"].split("'")[1]
            relationships.append({
                "type": "HAS_FINDING",
                "from_type": "IAMUser",
                "from_id": username,
                "to_type": "Finding",
                "to_id": finding["finding_id"]
            })

        return nodes, relationships

    def run_scanner(self):
        nodes, relationships = self.scan_iam()

        output = {
            "scan_timestamp": datetime.now().isoformat() + "Z",
            "nodes": nodes,
            "relationships": relationships
        }

        with open(get_findings_path("findings_iam.json"), "w") as f:
            json.dump(output, f, indent=2)
        
        return output