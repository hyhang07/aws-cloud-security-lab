# Digital Forensics & Incident Response (DFIR) Report: IAM Privilege Escalation & Data Exposure

| Report Metadata | Details |
| :--- | :--- |
| **Incident ID:** | INC-2026-0615-AWS |
| **Severity Level:** | High (Privilege Escalation & Data Exposure) |
| **Target Infrastructure:** | AWS Asia Pacific (Sydney / Singapore) Workload |
| **Lead Investigator:** | Hong Yee Hang (Cloud Security & Forensics) |
| **Compliance Mandates:** | BNM RMiT Control 10.49, MAS TRM Section 12, CIS AWS Benchmark v3.0 |
| **Incident Status:** | **CLOSED (Contained, Eradicated & Hardened)** |

---

## 1. Executive Summary

On 2026-06-23, anomalous API activity was flagged in the primary AWS environment. Subsequent investigation utilizing **Amazon CloudWatch Log Analytics** and **Multi-Region AWS CloudTrail** confirmed that an adversary abused compromised developer access keys (`developer-a`). 

The threat actor exploited an overly permissive permission (`iam:CreatePolicyVersion`) attached to a customer-managed policy (`Vulnerable-Dev-Policy`). By injecting a new default policy version containing full wildcard administrator privileges (`*` on `*`), the attacker bypassed least-privilege guardrails and executed administrative calls across account resources. 

The security response protocol was activated: the malicious policy version was purged, baseline configurations were restored, and the compromised credentials were permanently revoked. No evidence of persistent lateral movement or uncontained backdoors was identified.

---

## 2. Chronological Attack Timeline (Reconstructed)

All timestamps reflect UTC event logging reconstructed via CloudTrail audit streams:

| Timestamp (UTC) | Originating Identity | API Invoked / Event | Status | Threat Phase / Context |
| :--- | :--- | :--- | :---: | :--- |
| **2026-06-23 14:36:50** | `user/developer-a` | `ListUsers` | `403 AccessDenied` | **Initial Reconnaissance:** Probing administrative scope; blocked by baseline policy. |
| **2026-06-23 14:37:08** | `user/developer-a` | `CreatePolicyVersion` | `200 OK` | **Privilege Escalation:** Injected malicious admin payload (`v3`) and set as default. |
| **2026-06-23 14:37:09** | `user/developer-a` | `ListUsers` | `403 AccessDenied` | **Propagation Latency:** Attacker blocked temporarily due to IAM Eventual Consistency. |
| **2026-06-23 14:37:45** | `user/developer-a` | `ListUsers` | `200 OK` | **Elevation Verified:** Global sync completed; attacker retrieved all IAM identities. |
| **2026-06-23 14:42:10** | `role/IncidentResponder` | `SetDefaultPolicyVersion` | `200 OK` | **Containment:** Administrator rolled back active policy to safe baseline `v1`. |
| **2026-06-23 14:43:05** | `role/IncidentResponder` | `DeletePolicyVersion` | `200 OK` | **Eradication:** Backdoor version `v3` permanently removed. |
| **2026-06-23 14:44:20** | `role/IncidentResponder` | `DeleteAccessKey` | `200 OK` | **Remediation:** Compromised developer credentials permanently revoked. |

---

## 3. Evidence Artifacts & Forensic Analysis

### 3.1 Primary Forensic Query (CloudWatch Log Analytics)
The malicious privilege escalation event was isolated using the following SOC detection query:

```sql
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, userAgent, responseElements.policyVersion.versionId
| filter eventName = 'CreatePolicyVersion'
| sort @timestamp desc
| limit 20
```

### 3.2 Raw CloudTrail Audit Evidence (Sanitized)
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDASVGEVMDL22IK6PR4Y",
    "arn": "arn:aws:iam::<ACCOUNT_ID>:user/developer-a",
    "accountId": "<ACCOUNT_ID>",
    "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
    "userName": "developer-a"
  },
  "eventTime": "2026-06-23T14:37:08Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreatePolicyVersion",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.24",
  "userAgent": "Boto3/1.42.97 md/Botocore#1.42.97 ua/2.1 os/windows#10 lang/python#3.9.13",
  "requestParameters": {
    "policyArn": "arn:aws:iam::<ACCOUNT_ID>:policy/Vulnerable-Dev-Policy",
    "policyDocument": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}",
    "setAsDefault": true
  },
  "responseElements": {
    "policyVersion": {
      "versionId": "v3",
      "isDefaultVersion": true,
      "createDate": "Jun 23, 2026 2:37:08 PM"
    }
  }
}
```

---

## 4. Indicators of Compromise (IOCs)

The following artifacts have been extracted and documented for enterprise intelligence feeds and perimeter blocking:

| IOC Type | Indicator Value | Threat Attribution / Description |
| :--- | :--- | :--- |
| **Compromised Account** | `arn:aws:iam::<ACCOUNT_ID>:user/developer-a` | Identity utilized as initial foothold |
| **Compromised Access Key** | `AKIAIOSFODNN7EXAMPLE` | Stolen API key leveraged to sign malicious requests |
| **Adversary Source IP** | `198.51.100.24` | Non-whitelisted external ISP address |
| **Tooling Fingerprint** | `Boto3/1.42.97 / Python 3.9.13 / Windows 10` | Automated Python-based exploitation framework |
| **Target Policy Mutation** | `Vulnerable-Dev-Policy` (Version `v3`) | Injected `"Action": "*", "Resource": "*"` payload |

---

## 5. Root Cause Analysis (RCA) & Blast Radius

### Root Cause
An administrative configuration error violated the **Principle of Least Privilege (PoLP)**. The customer policy granted `iam:CreatePolicyVersion` scoped to its own resource without restricting version modification rights or establishing administrative boundary guardrails (Permission Boundaries).

### Blast Radius Assessment
* **Data Plane:** No direct data modification or object destruction occurred outside the test target buckets.
* **Control Plane:** The adversary briefly gained full administrative access to query account users via `ListUsers`.
* **Containment Scope:** Zero lateral movement across external VPCs or AWS Organizations accounts.

---

## 6. Corrective & Strategic Recommendations

To prevent identical privilege escalation and configuration drift occurrences:

1. **Deploy Service Control Policies (SCPs):**
   Implement organizational SCPs prohibiting non-security administrative principals from modifying IAM policies, creating versions, or modifying CloudTrail logging configurations.
2. **Automated Static CI/CD Scanning:**
   Enforce Infrastructure-as-Code (IaC) linting using tools like Checkov to detect and fail deployments containing dangerous IAM permission combinations.
3. **Automated Cloud Security Posture Management (CSPM):**
   Execute the automated scanner script (`scripts/cloud_security_auditor.py`) on a continuous basis (e.g., via AWS Lambda) to flag orphaned public policies and excessive privileges.
4. **Enforce Temporary Credential Lifecycles:**
   Transition developer access from static programmatic Access Keys (`AKIA...`) to short-lived session credentials generated via **AWS IAM Identity Center (SSO)** and STS AssumeRole.
