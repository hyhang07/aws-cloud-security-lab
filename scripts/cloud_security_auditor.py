"""
AWS Cloud Security Posture Management (CSPM) Automated Auditor
Author: Hong Yee Hang
Scenario: Continuous Security Audit for S3 Public Buckets & IAM Privilege Escalation Risks
Compliance: CIS AWS Foundations Benchmark, BNM RMiT, MAS TRM
"""

import boto3
import json
from botocore.exceptions import ClientError

print("=" * 70)
print("      AWS Automated Cloud Security Auditor (CSPM Tool)       ")
print("      Developed for Cybersecurity Portfolio Project          ")
print("=" * 70)

try:
    # Automatically loads local credentials configured via 'aws configure'
    s3_client = boto3.client('s3')
    iam_client = boto3.client('iam')
    print("[+] AWS credentials loaded successfully. Initializing audit suite...\n")
except Exception as e:
    print(f"[-] Credential loading failed! Please run 'aws configure' in terminal. Error: {e}")
    exit(1)


# ============================================================
# MODULE 1: S3 Bucket Public Access & Exposure Risk Assessment
# ============================================================
print("[+] Executing: [Module 1] S3 Bucket Public Exposure Risk Assessment...")

try:
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        print(f"\n[*] Scanning bucket: {bucket_name}")
        
        # 1. Inspect Block Public Access (BPA) configurations
        try:
            bpa = s3_client.get_public_access_block(Bucket=bucket_name)
            config = bpa['PublicAccessBlockConfiguration']
            
            # Check if all four protective guardrails are active
            is_secure = (
                config.get('BlockPublicAcls', False) and 
                config.get('IgnorePublicAcls', False) and 
                config.get('BlockPublicPolicy', False) and 
                config.get('RestrictPublicBuckets', False)
            )
            
            if not is_secure:
                print(f"  [⚠️ WARNING] Bucket has partial or disabled 'Block Public Access' guardrails!")
            else:
                print(f"  [✓ SECURE] All 'Block Public Access' guardrails are fully enforced.")
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                print(f"  [🚨 CRITICAL] No Block Public Access configuration found! Highly vulnerable to data leakage!")
            else:
                print(f"  [-] Module Error (BPA Check): {e}")

        # 2. Inspect Bucket Policy for wildcard anonymous read grants
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy_response['Policy'])
            
            statements = policy_json.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
                
            is_exposed = False
            for stmt in statements:
                effect = stmt.get('Effect')
                principal = stmt.get('Principal')
                action = stmt.get('Action')
                
                # Check for Effect=Allow, Principal=*, and s3:GetObject
                if effect == 'Allow' and principal == '*':
                    if 's3:GetObject' in action or action == '*':
                        is_exposed = True
            
            if is_exposed:
                print(f"  [🚨 CRITICAL] Public read policy detected! Sensitive objects are exposed to the public Internet!")
            else:
                print(f"  [✓ SECURE] Policy inspection clear: No wildcard public read statements found.")
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print(f"  [✓ SECURE] No bucket policy attached. Zero policy exposure risk.")
            else:
                print(f"  [-] Module Error (Policy Check): {e}")

except Exception as e:
    print(f"[-] S3 scan encountered an unhandled error: {e}")


# ============================================================
# MODULE 2: IAM Custom Policy Excessive Privilege & Escalation Audit
# ============================================================
print("\n" + "=" * 70)
print("[+] Executing: [Module 2] IAM Custom Policy Excessive Privilege & PrivEsc Audit...")

try:
    # Audit customer-managed policies only (Scope='Local')
    policies = iam_client.list_policies(Scope='Local')
    for policy in policies['Policies']:
        p_name = policy['PolicyName']
        p_arn = policy['Arn']
        print(f"\n[*] Evaluating customer-managed IAM policy: {p_name}")
        
        # Retrieve the currently active default version
        default_v_id = policy['DefaultVersionId']
        version_detail = iam_client.get_policy_version(PolicyArn=p_arn, VersionId=default_v_id)
        doc = version_detail['PolicyVersion']['Document']
        
        statements = doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for stmt in statements:
            effect = stmt.get('Effect')
            action = stmt.get('Action')
            resource = stmt.get('Resource')
            
            # 1. Audit for Global Administrator privileges (Allow * on *)
            if effect == 'Allow' and action == '*' and resource == '*':
                print(f"  [🚨 CRITICAL] Overly permissive policy detected! Global Administrator privileges granted (Allow * on *)!")
                
            # 2. Audit for high-risk IAM privilege escalation APIs
            actions_list = action if isinstance(action, list) else [action]
            high_risk_apis = ["iam:CreatePolicyVersion", "iam:AttachUserPolicy", "iam:PutUserPolicy"]
            matched_risks = [act for act in actions_list if act in high_risk_apis]
            
            if effect == 'Allow' and matched_risks:
                print(f"  [⚠️ WARNING] High-risk privilege escalation vector {matched_risks} permitted on resource: {resource}!")

except Exception as e:
    print(f"[-] IAM scan encountered an unhandled error: {e}")

print("\n" + "=" * 70)
print("      Automated Cloud Security Audit (CSPM) Complete.        ")
print("=" * 70)
