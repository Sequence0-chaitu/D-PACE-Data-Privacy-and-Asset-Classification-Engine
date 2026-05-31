# Rules — Policy Configuration Reference

This directory contains `mandates.json`, the single source of truth for all D-PACE policies.

## Schema Overview

### `classification_levels[]`

Defines the four sensitivity tiers used to tag assets.

| Field | Type | Description |
|---|---|---|
| `name` | string | Display name (`Restricted`, `Confidential`, `Internal`, `Unclassified`) |
| `code` | string | Single-letter code used in reports |
| `nist_fips199` | string | Maps to FIPS 199 impact level (`HIGH` / `MODERATE` / `LOW`) |
| `color` | string | Hex colour for dashboard visualisation |

---

### `regex_patterns[]`

Each entry describes a single PII/PCI detector.

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier used in scan results |
| `pattern` | string | Python-compatible regex (escaped for JSON) |
| `classification` | string | Minimum classification level if this pattern matches |
| `severity` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `frameworks` | string[] | Applicable legal frameworks |
| `nist_controls` | string[] | NIST SP 800-53 control IDs |
| `gdpr_articles` | string[] | GDPR article references |
| `pci_requirements` | string[] | PCI DSS requirement references |

**Adding a custom pattern:**

```json
{
  "id": "EMPLOYEE_ID",
  "name": "Internal Employee ID",
  "pattern": "EMP-\\d{6}",
  "classification": "Internal",
  "severity": "LOW",
  "frameworks": ["NIST"],
  "nist_controls": ["CM-8"],
  "description": "Internal employee identifier."
}
```

---

### `retention_policies[]`

One entry per legal framework.

| Field | Type | Description |
|---|---|---|
| `framework` | string | `GDPR`, `PCI`, `NIST` |
| `default_retention_days` | int | Default retention window in days |
| `categories` | object | Named sub-categories with their own window (days) |
| `violation_severity` | string | Severity level applied to retention violations |

---

### `classification_rules[]`

Ordered rules that map pattern match results to a final classification. Rules are evaluated in order; the first `override: true` match short-circuits evaluation.

---

### `legal_mandate_mapping`

Human-readable mapping from D-PACE capabilities to specific control/article IDs. Primarily used for compliance report generation.

---

### `scan_settings`

| Setting | Default | Description |
|---|---|---|
| `max_file_size_mb` | 100 | Files larger than this are skipped with a warning |
| `follow_symlinks` | false | Whether to follow symbolic links |
| `scan_hidden_files` | false | Whether to scan dot-files |
| `max_matches_per_file` | 1000 | Cap on regex match records per file |
| `batch_size` | 50 | Files processed per DB commit batch |
