# Enterprise AWS Cloud Security Lab: Threat Emulation, Digital Forensics, and Automated Posture Hardening

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![AWS SDK: Boto3](https://img.shields.io/badge/AWS%20SDK-Boto3-orange.svg)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![Compliance: BNM RMiT | MAS TRM](https://img.shields.io/badge/Compliance-BNM%20RMiT%20%7C%20MAS%20TRM-green.svg)](https://www.mas.gov.sg/)

Hands-on Cloud Security Portfolio Project:
* **Author:** Hong Yee Hang
* **Specialisation:** Cloud Security Engineering | SOC & Threat Detection | DevSecOps
* **Focus Areas:** Identity & Access Management (IAM), Telemetry & Forensics, Security Automation (Boto3)
* **Compliance Alignment:** Bank Negara Malaysia (BNM) RMiT, Monetary Authority of Singapore (MAS) TRM, CIS AWS Foundations Benchmark v3.0

---

## 1. Project Overview

As enterprise workloads migrate to public cloud environments, traditional network perimeters dissolve, establishing **Identity as the primary security boundary**. Under the AWS Shared Responsibility Model, customer-side identity misconfigurations and improper data bucket exposures represent the leading initial access vectors for cyber adversaries.

Standard cloud deployments frequently suffer from critical governance gaps:
* **Public Data Exposure:** Accidental deactivation of S3 Block Public Access (BPA) paired with wildcard bucket policies (`Principal: *`), enabling unauthenticated bulk data exfiltration.
* **Privilege Escalation:** Granting seemingly restrictive development roles dangerous IAM capabilities (e.g., `iam:CreatePolicyVersion`), enabling lateral privilege escalation to full `AdministratorAccess`.
* **Telemetry Blindness:** Fragmented, single-region audit logging vulnerable to log evasion, tampering, and alert fatigue.

This project implements an end-to-end **Cloud Security Operations Lifecycle** encompassing secure baseline provisioning, realistic threat emulation (adversary tradecraft), digital cloud forensics, detection engineering, and automated posture remediation (CSPM).

---

## 2. System Architecture

The architecture implements defense-in-depth across three distinct operational layers:

```text
+---------------------------------------------------------------------------------+
|                                 AWS Cloud Account                               |
|                                                                                 |
|  +-------------------------+             +----------------------------------+   |
|  |     Root Account        |             |      IAM Admin User (MFA)        |   |
|  |  (Isolated & Locked)    |             |       "cloud-sec-admin"          |   |
|  +------------+------------+             +----------------+-----------------+   |
|               |                                           |                     |
|               | (Emergency Only)                          | (Daily Operations)  |
|               v                                           |                     |
|    [ AWS Billing Budget ] <-------------------------------+                     |
|    (Zero-Spend Alert)                                     v                     |
|                                             [ AWS Infrastructure / Services ]   |
|                                             - VPC & Security Group (Custom)     |
|                                               (Restricts SSH to Admin IP Only)  |
|                                                           |                     |
|                                                           | (API Audit Logs)    |
|                                                           v                     |
|                                                [ AWS CloudTrail (Multi-Region) ]|
|                                                - Log File Validation Enabled    |
|                                                           |                     |
|                                       +-------------------+------------------+  |
|                                       | (Archiving / Cold)| (Real-time Stream)  |
|                                       v                   v                  |  |
|                                [ Secure S3 Bucket ]   [ CloudWatch Logs ]    |  |
|                                (Log Integrity)        (Log Analytics/SIEM)   |  |
+---------------------------------------------------------------------------------+
```

### Operational Layers:

1. **Layer 1 — Identity & Ingress Guardrails (Preventative):**
   * **Root Isolation:** Enforced hardware-grade Virtual MFA (TOTP) on the root account and eliminated programmatic access keys.
   * **Administrative Partitioning:** Created a dedicated `cloud-sec-admin` identity bound to least-privilege groups.
   * **Boundary Firewalls:** Deployed custom stateful Security Groups (`sec-admin-sg`) restricting critical ingress vectors (SSH port 22) exclusively to authenticated administrative IP addresses.
   * **Financial Defense:** Deployed an automated zero-spend AWS Budget alert to mitigate rogue compute resource spawning (crypto-mining).

2. **Layer 2 — Telemetry & Forensic Ingestion (Detective):**
   * **Multi-Region CloudTrail:** Deployed global audit trail capturing management plane API activities across all AWS regions.
   * **Cryptographic Integrity:** Enabled **Log File Validation** (SHA-256 with RSA signature hashing) to detect post-compromise log tampering.
   * **Unified Log Streaming:** Piped raw audit streams directly into **Amazon CloudWatch Logs** (`Log Analytics`) for sub-minute forensic analysis and SIEM querying.

3. **Layer 3 — Automated Posture & Threat Detection (Corrective):**
   * **Detection Engineering:** Deployed CloudWatch Metric Filters to flag high-risk administrative mutations (`PutBucketPolicy`, `CreatePolicyVersion`) in real time.
   * **Python-based CSPM Auditor:** Engineered an automated, credential-less Python auditing engine using `boto3` to detect configuration drift and orphaned public bucket policies.

---

## 3. Experimental & Simulation Results

The lab evaluated defensive controls against two simulated attack vectors: anonymous data exfiltration and programmatic privilege escalation:

| Security Dimension | Vulnerable Baseline (Unmanaged) | Hardened & Defended State (This Framework) |
| :--- | :---: | :---: |
| **S3 Anonymous Data Access** | Allowed (`HTTP 200 OK`) — PII Exfiltrated | **Blocked (`HTTP 403 Forbidden` / AccessDenied)** |
| **IAM Privilege Escalation** | Successful (`iam:CreatePolicyVersion` to Admin) | **Contained (Policy Rolled Back & Credentials Revoked)** |
| **Cloud Audit Trail** | Single-Region / Vulnerable to Evasion | **Multi-Region with SHA-256 Log Integrity Checks** |
| **Digital Forensics Visibility**| None (Manual Log Inspections) | **Real-Time IOC Extraction via CloudWatch Analytics** |
| **Orphaned Policy Drift Detection** | 0% (Undetected Configuration Drift) | **100% Automated Detection via Python Boto3 Auditor** |
| **API Management Port Security** | Open to Public (`0.0.0.0/0`) | **Restricted Exclusively to Admin IP (`/32`)** |

---

## 4. Repository Structure

```text
├── architecture/
│   └── architecture_diagram.txt       # ASCII schema of AWS cloud security architecture
│
├── attack-scenarios/
│   ├── s3_exposure.md                 # S3 anonymous exfiltration methodology & mitigation
│   └── iam_privesc.md                 # IAM policy version escalation attack vector writeup
│
├── detection/
│   └── metric_filters.json            # CloudWatch Metric Filters detection-as-code definitions
│
├── report/
│   └── incident_forensic_report.md    # Incident Response report with extracted IOCs and timeline
│
├── scripts/
│   ├── exploit.py                     # Python exploit script demonstrating IAM privilege escalation
│   └── cloud_security_auditor.py      # Custom Python CSPM scanner for S3 and IAM policy drift
│
├── .gitignore                         # Excludes sensitive local configs, virtual environments & keys
└── README.md                          # Master documentation and portfolio report
```

---

## 5. Getting Started

### Prerequisites
* Python 3.9+ installed
* AWS CLI v2 installed and configured (`aws configure`)
* AWS Free Tier or Sandbox Account

### Setup
1. Clone this repository:
```bash
git clone https://github.com/hyhang07/aws-cloud-security-lab.git
cd aws-cloud-security-lab
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# Linux / macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install boto3 botocore
```

---

## 6. Execution Workflow

### Step 1: Threat Emulation — IAM Privilege Escalation
Simulates an insider threat or compromised developer access key exploiting permissive policy versioning:

```bash
# Execute the exploit script against target sandbox
python scripts/exploit.py
```

* **Observation:** The script attempts a restricted call (`iam:ListUsers`), encounters `AccessDenied`, leverages `iam:CreatePolicyVersion` with an administrator payload (`*` on `*`), sets the new version as default, and verifies global access acquisition across AWS endpoints.

### Step 2: Digital Forensics & Log Analytics
Execute forensic query in **AWS CloudWatch Log Analytics** to reconstruct attacker tradecraft:

```sql
fields @timestamp, eventName, userIdentity.arn, sourceIPAddress, userAgent, responseElements.policyVersion.versionId
| filter eventName = 'CreatePolicyVersion'
| sort @timestamp desc
| limit 20
```

* **Extracted Artifacts (Sanitized):**
  * **Compromised Identity:** `arn:aws:iam::<ACCOUNT_ID>:user/developer-a`
  * **Compromised Access Key:** `AKIAIOSFODNN7EXAMPLE`
  * **Attacker IP Address:** `198.51.100.24`
  * **User Agent Signature:** `Boto3/1.42.x Python/3.9.x Windows/10`
  * **Malicious Mutation:** Generated policy version `v3` granting administrative bypass.

### Step 3: Automated Posture Auditing (CSPM)
Execute the automated security auditor tool to scan for residual exposure risks and policy drift:

```bash
python scripts/cloud_security_auditor.py
```

* **Sample Scanner Output:**
```text
======================================================================
      AWS Automated Cloud Security Auditor (CSPM Tool)
      Developed for Cybersecurity Portfolio Project
======================================================================
[+] AWS Credentials loaded successfully. Initializing audit...

[+] Executing: Module 1 - S3 Bucket Public Access Posture Assessment...
[*] Auditing bucket: confidential-customer-data-2026
  [SECURE] Block Public Access is fully enforced.
  [CRITICAL] Public read policy detected! Sensitive objects are exposed to internet!

======================================================================
[+] Executing: Module 2 - IAM Custom Policy Privilege Audit...
[*] Evaluating custom policy: Vulnerable-Dev-Policy
  [CRITICAL] Overly permissive policy detected! Full Administrator granted in: Vulnerable-Dev-Policy

======================================================================
      CSPM Security Audit Run Completed. Anomalies Logged.
======================================================================
```

---

## 7. Regulatory & Compliance Mapping

The controls implemented throughout this project directly address requirements mandated across regional cybersecurity frameworks:

* **Bank Negara Malaysia (BNM) RMiT:**
  * *Control 10.38:* Enforces Least Privilege and Separation of Duties within cloud IAM environments.
  * *Control 10.49:* Mandates tamper-evident, centralized audit logging (fulfilled via CloudTrail Log File Validation).
* **Monetary Authority of Singapore (MAS) TRM Guidelines:**
  * *Section 8.1 - 8.3:* Strict administrative credential protection and multi-factor authentication enforcement.
  * *Section 12.1:* Cyber surveillance, event correlation, and anomaly detection via CloudWatch metrics.
* **CIS AWS Foundations Benchmark v3.0:**
  * *Controls 1.1 - 1.10:* Securing Root, administrative users, and enforcing access key rotation.
  * *Controls 2.1 - 2.3:* Enforcement of S3 Block Public Access across account boundaries.
  * *Controls 3.1 - 3.9:* Multi-region audit log aggregation and critical alarm routing.

---

## 8. License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
