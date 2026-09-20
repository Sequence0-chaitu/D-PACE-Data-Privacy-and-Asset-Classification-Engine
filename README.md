# D-PACE — Data Privacy & Asset Classification Engine

> **Asset Governance Architecture** | Arch Linux · Python · SQLite · Grafana · Docker

D-PACE is a local-first data governance tool that scans your file system for sensitive data, classifies assets, audits retention compliance, and surfaces violations through a live Grafana dashboard — all aligned with **NIST SP 800-53**, **PCI DSS v4.0**, and **GDPR** mandates.(Only for educational purposes)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Compliance Coverage](#compliance-coverage)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)
8. [Database Schema](#database-schema)
9. [Grafana Dashboard](#grafana-dashboard)
10. [Legal Mandate Mapping](#legal-mandate-mapping)
11. [Project Structure](#project-structure)
12. [Testing](#testing)
13. [Contributing](#contributing)
14. [License](#license)

---

## Overview

D-PACE automates the classification and compliance auditing of local data assets. It:

- **Discovers** files across a target directory tree (`.csv`, `.txt`, `.json`, and more)
- **Detects** PII and PCI-sensitive data using regex patterns (SSN, email, credit card numbers)
- **Classifies** assets as `Restricted`, `Confidential`, or `Internal`
- **Audits** file retention against configurable GDPR/PCI retention windows
- **Persists** results in a local SQLite database (`dpace.db`)
- **Visualises** findings via a Dockerized Grafana dashboard at `localhost:3000`

---

## Architecture

```
Arch Linux Host System (Laptop)
│
├── Operator Workflow
│   1. CLI Input  →  2. D-PACE Scan  →  3. Report Review (localhost:3000)
│
├── Input Layer
│   └── /home/user/mock_data/  (.csv, .txt, .json, ...)
│
├── Processing Layer
│   ├── Policy Engine  (rules/mandates.json)
│   │   ├── Regex Patterns       — SSN, Email, Credit Card
│   │   ├── Data Retention Limits — GDPR=365 days, PCI=…
│   │   └── Legal Mandate Mapping
│   │
│   └── D-PACE Scanner  (Python application)
│       ├── File Discovery & Reading Module
│       ├── Regex Matching Engine   (PII/PCI Discovery)
│       ├── Classification Logic    (Restricted / Confidential / Internal)
│       └── Retention Auditor       (checks file timestamps)
│
└── Output & Storage Layer
    ├── SQLite Database (dpace.db)
    │   ├── asset_inventory
    │   ├── scan_results
    │   └── policy_violations
    │
    └── Grafana Dashboard (Dockerized)
        ├── Data Classification Breakdown  (Pie Chart)
        ├── Active Retention Violations    (Alert Table)
        └── GDPR/PCI Compliance Scorecard
```

---

## Compliance Coverage

| Framework | Controls Addressed |
|---|---|
| **NIST SP 800-53 Rev 5** | AC-1, AC-3, AU-2, AU-9, CM-8, RA-2, SA-8, SC-28, SI-12 |
| **PCI DSS v4.0** | Req 3.1, 3.2, 3.3, 7.2, 9.4, 10.2, 12.3 |
| **GDPR** | Art. 5(1)(e), Art. 17, Art. 25, Art. 30, Art. 32, Art. 83 |

Full mapping: [`docs/compliance_mapping.md`](docs/compliance_mapping.md)

---

## Prerequisites

| Dependency | Version |
|---|---|
| Python | ≥ 3.11 |
| Docker & Docker Compose | ≥ 24.x |
| SQLite | ≥ 3.40 |
| Arch Linux (or any Linux) | — |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/d-pace.git
cd d-pace

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Initialise the database
python -m dpace.db.init

# 5. Launch Grafana (compose file lives in grafana/, and reads grafana/.env)
docker compose -f grafana/docker-compose.yml up -d
```

---

## Configuration

All policy rules live in **`rules/mandates.json`**. Edit this file to customise:

- Regex patterns for PII/PCI detection
- Retention windows per legal framework
- Classification thresholds

See [`rules/README.md`](rules/README.md) for the full schema reference.

---

## Usage

```bash
# Basic scan of a directory
python -m dpace scan --path /home/user/mock_data/

# Scan with a specific policy file
python -m dpace scan --path /home/user/mock_data/ --policy rules/mandates.json

# Generate a compliance report (JSON)
python -m dpace report --format json --out reports/latest.json

# Show retention violations only
python -m dpace audit --violations-only

# Open the dashboard
xdg-open http://localhost:3000
```

### CLI Reference

| Command | Description |
|---|---|
| `dpace scan` | Run a full discovery + classification scan |
| `dpace audit` | Check retention compliance against policy |
| `dpace report` | Export scan results to JSON / CSV |
| `dpace db stats` | Print database summary |
| `dpace db purge` | Purge records older than retention window |

---

## Database Schema

```sql
-- Asset inventory (one row per file discovered)
CREATE TABLE asset_inventory (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path     TEXT    NOT NULL UNIQUE,
    file_name     TEXT    NOT NULL,
    file_ext      TEXT,
    size_bytes    INTEGER,
    created_at    TEXT,   -- ISO-8601
    modified_at   TEXT,   -- ISO-8601
    scanned_at    TEXT    NOT NULL,
    classification TEXT   CHECK(classification IN ('Restricted','Confidential','Internal','Unclassified'))
);

-- Per-file scan results (one row per pattern match)
CREATE TABLE scan_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      INTEGER REFERENCES asset_inventory(id),
    pattern_name  TEXT    NOT NULL,  -- e.g. 'SSN', 'CREDIT_CARD'
    match_count   INTEGER NOT NULL,
    framework     TEXT,              -- 'PCI' | 'GDPR' | 'NIST'
    scanned_at    TEXT    NOT NULL
);

-- Policy violations
CREATE TABLE policy_violations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id      INTEGER REFERENCES asset_inventory(id),
    violation_type TEXT   NOT NULL,  -- 'RETENTION_EXCEEDED' | 'UNCLASSIFIED_PII' | ...
    mandate       TEXT    NOT NULL,  -- 'GDPR' | 'PCI' | 'NIST'
    severity      TEXT    CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
    detail        TEXT,
    detected_at   TEXT    NOT NULL,
    resolved_at   TEXT
);
```

---

## Grafana Dashboard

After `docker compose -f grafana/docker-compose.yml up -d`, open
**http://localhost:3000**. Credentials come from `grafana/.env`
(`GF_ADMIN_USER` / `GF_ADMIN_PASSWORD`) — copy `grafana/.env.example` to
`grafana/.env` if it is missing, or Grafana will start with an empty password.

Panels are provisioned automatically via
`grafana/provisioning/dashboards/dashboards.yml`:

| Panel | Type | Description |
|---|---|---|
| Data Classification Breakdown | Pie Chart | Distribution of Restricted / Confidential / Internal files |
| Active Retention Violations | Alert Table | Files exceeding their retention window |
| GDPR/PCI Compliance Scorecard | Stat / Table | Pass/fail scorecard per framework |

Dashboard JSON: [`grafana/provisioning/dashboards/dpace.json`](grafana/provisioning/dashboards/dpace.json)

---

## Legal Mandate Mapping

See [`docs/compliance_mapping.md`](docs/compliance_mapping.md) for a full control-by-control breakdown.

**Summary:**

- **NIST RA-2 (Security Categorisation)** → D-PACE classification tags map directly to FIPS 199 impact levels
- **PCI DSS Req 3.2** → Credit card PANs detected and flagged; storage beyond need triggers `CRITICAL` violation
- **GDPR Art. 5(1)(e)** → Retention auditor enforces storage limitation; violations logged to `policy_violations`

---

## Project Structure

```
d-pace/
├── dpace/
│   ├── __init__.py
│   ├── __main__.py             # Enables `python -m dpace ...`
│   ├── cli.py                  # Entry point / argument parsing
│   ├── scanner/
│   │   ├── discovery.py        # File discovery & reading
│   │   ├── regex_engine.py     # PII/PCI pattern matching
│   │   ├── classifier.py       # Classification logic
│   │   └── retention.py        # Retention auditor
│   ├── db/
│   │   ├── init.py             # Schema creation
│   │   ├── models.py           # DB access helpers
│   │   └── dpace.db            # SQLite database (git-ignored)
├── rules/
│   ├── mandates.json           # Master policy & rules file
│   └── README.md               # Rules schema reference
├── grafana/
│   ├── docker-compose.yml
│   ├── .env                    # Grafana admin creds (git-ignored)
│   └── provisioning/
│       ├── datasources/
│       │   └── sqlite.yml
│       └── dashboards/
│           ├── dashboards.yml  # Dashboard provider config (required)
│           └── dpace.json
├── scripts/
│   └── make_mock_data.sh       # Generates backdated demo dataset
├── tests/
│   └── test_scanner.py         # Regex + classifier + retention tests
├── docs/
│   └── compliance_mapping.md
├── reports/                    # Generated reports (git-ignored)
├── pytest.ini
├── requirements.txt
├── .gitignore
├── Dockerfile
└── README.md
```

---

## Testing

```bash
pytest tests/ -v --tb=short
```

Test coverage targets:

- Regex engine: SSN / email / credit card detection accuracy
- Classifier: tag assignment for each sensitivity level
- Retention auditor: boundary conditions for each framework window
- DB models: CRUD round-trips

---

## Contributing

1. Fork the repo and create a feature branch
2. Follow [PEP 8](https://pep8.org/) and include type hints
3. Add / update tests for any changed behaviour
4. Open a pull request with a clear description

---

## License

MIT License — see [`LICENSE`](LICENSE) for details.

> **Disclaimer:** D-PACE is a compliance (For education) not *aid*, not a legal guarantee. Always engage qualified legal counsel for formal GDPR / PCI DSS compliance assessments.(This project is only for educational purposes)
