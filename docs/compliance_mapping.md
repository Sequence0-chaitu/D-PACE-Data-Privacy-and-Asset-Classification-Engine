# D-PACE Compliance Mapping

This document maps every D-PACE feature to its corresponding regulatory control,
providing traceability for NIST SP 800-53, PCI DSS v4.0, and GDPR.

---

## 1. NIST SP 800-53 Rev 5

| Control ID | Control Name | D-PACE Implementation |
|---|---|---|
| **AC-1** | Access Control Policy and Procedures | Classification tags (`Restricted`, `Confidential`, `Internal`) enable downstream access policy enforcement. |
| **AC-3** | Access Enforcement | Classification output is consumed by access control systems to enforce need-to-know. |
| **AU-2** | Event Logging | Every scan writes records to `asset_inventory`, `scan_results`, and `policy_violations` tables, forming a tamper-evident audit trail. |
| **AU-9** | Protection of Audit Information | `dpace.db` should be stored on a volume with restricted OS-level permissions. |
| **AU-11** | Audit Record Retention | Retention auditor enforces the NIST SI-12 window (730 days default) for audit records. |
| **CM-8** | Information System Component Inventory | `asset_inventory` table is a continuously updated inventory of all data assets in scope. |
| **IA-5** | Authenticator Management | `AWS_ACCESS_KEY` and `PRIVATE_KEY_HEADER` patterns detect plaintext credential exposure. |
| **RA-2** | Security Categorisation | FIPS 199 impact levels (HIGH / MODERATE / LOW) are mapped directly to classification levels in `mandates.json`. |
| **SA-8** | Security and Privacy Engineering Principles | Privacy-by-design: classification happens at discovery time, before data is further processed. |
| **SC-12** | Cryptographic Key Establishment | `PRIVATE_KEY_HEADER` pattern flags plaintext private keys for immediate remediation. |
| **SC-28** | Protection of Information at Rest | All `Restricted`-classified files are flagged for encryption review in the Grafana dashboard. |
| **SI-12** | Information Management and Retention | Retention auditor checks each file's age against the SI-12 retention window and logs violations. |

---

## 2. PCI DSS v4.0

| Requirement | Title | D-PACE Implementation |
|---|---|---|
| **Req 3.1** | Processes and mechanisms for protecting stored account data | `IBAN` and `CREDIT_CARD_PAN` patterns detect stored account data; violations logged with `CRITICAL` severity. |
| **Req 3.2** | Cardholder data storage minimised | Any file containing a PAN triggers a `CRITICAL` violation in `policy_violations` if it exceeds the 365-day retention window. |
| **Req 3.3** | PANs protected wherever stored | Unmasked PANs are detected by the Luhn-aware regex and classified `Restricted` immediately. |
| **Req 3.5** | Cryptographic keys protected | `PRIVATE_KEY_HEADER` detects plaintext key material; maps to `Restricted`. |
| **Req 7.2** | Access control systems | Classification output informs least-privilege access decisions in downstream IAM. |
| **Req 9.4** | Media containing account data protected | All `Restricted` files are surfaced in the *Active Retention Violations* dashboard panel. |
| **Req 10.2** | Audit logs implemented | `scan_results` and `policy_violations` provide the required audit log. |
| **Req 12.3** | Risk assessment performed | Classification breakdown and violation counts feed risk register workflows. |

---

## 3. GDPR

| Article | Title | D-PACE Implementation |
|---|---|---|
| **Art. 4(1)** | Definition of personal data | `EMAIL`, `PHONE_US`, `IP_ADDRESS` patterns identify personal data at file level. |
| **Art. 5(1)(e)** | Storage limitation | Retention auditor enforces configurable storage limits; violations trigger `HIGH` severity records. |
| **Art. 9** | Special categories of personal data | `SSN`, `DOB`, and `IBAN` patterns map to Art. 9 special categories; always classified `Restricted`. |
| **Art. 17** | Right to erasure | `policy_violations` records of type `RETENTION_EXCEEDED` directly support erasure workflows (Art. 17 storage limitation). |
| **Art. 25** | Data protection by design and by default | Classification occurs at first discovery, before any downstream processing — implementing Privacy by Design. |
| **Art. 30** | Records of processing activities | `asset_inventory` + `scan_results` provide a machine-readable Art. 30 record of processing. |
| **Art. 32** | Security of processing | `Restricted` classification triggers encryption review; integrates with security control workflows. |
| **Art. 83** | General conditions for imposing administrative fines | Violation severity (`CRITICAL` / `HIGH`) aligns with the two-tier fine structure under Art. 83(4) and (5). |

---

## 4. Cross-Framework Matrix

| D-PACE Feature | NIST | PCI DSS | GDPR |
|---|---|---|---|
| File discovery & inventory | CM-8 | Req 9.4 | Art. 30 |
| PAN detection | SC-28 | Req 3.2, 3.3 | Art. 9 |
| SSN detection | AC-3, SC-28 | — | Art. 9, 32 |
| Email / phone detection | AC-3 | — | Art. 4(1), 25 |
| Credential detection (keys, tokens) | IA-5, SC-12 | Req 3.5 | Art. 32 |
| Classification tagging | RA-2 | Req 7.2 | Art. 25 |
| Retention auditing | SI-12, AU-11 | Req 3.1, 9.4 | Art. 5(1)(e), 17 |
| Audit log (scan results) | AU-2, AU-9 | Req 10.2 | Art. 30 |
| Compliance scorecard / reporting | AU-2 | Req 12.3 | Art. 83 |

---

## 5. Severity → Fine Tier Mapping (GDPR Art. 83)

| D-PACE Severity | GDPR Tier | Maximum Fine |
|---|---|---|
| CRITICAL | Art. 83(5) — highest tier | €20M or 4% of global annual turnover |
| HIGH | Art. 83(5) | €20M or 4% |
| MEDIUM | Art. 83(4) — lower tier | €10M or 2% of global annual turnover |
| LOW | Art. 83(4) | €10M or 2% |

> **Disclaimer:** This mapping is a compliance aid, not legal advice. Always engage qualified legal counsel for formal assessments.
