#!/usr/bin/env bash
# Generates a demo dataset at ./mock_data/ with synthetic PII/PCI values.
#
# Timestamps are deliberately backdated with `touch -d`: retention violations
# are computed from file mtime, so freshly-created files would produce an
# empty violations table and an empty dashboard.
#
# All values below are synthetic. 4111111111111111 is the standard Visa test
# PAN; the SSNs are in ranges reserved for documentation.

set -euo pipefail

TARGET="${1:-./mock_data}"
mkdir -p "$TARGET"

cat > "$TARGET/customers.csv" <<'EOF'
customer_id,full_name,email,ssn,card_pan,signup_ip
1001,John Smith,john.smith@example.com,123-45-6789,4111111111111111,192.168.1.10
1002,Jane Doe,jane.doe@example.org,234-56-7890,4222222222222,192.168.1.11
1003,Alan Turing,alan.t@example.net,345-67-8901,4012888888881881,10.0.0.7
EOF

cat > "$TARGET/hr_records.txt" <<'EOF'
Employee file - CONFIDENTIAL
Name: Maria Garcia   DOB: 1988-04-12
Contact: maria.garcia@example.com / 555-123-4567
Emergency contact: 555-987-6543
Bank: GB82WEST12345698765432
EOF

cat > "$TARGET/app.log" <<'EOF'
2024-01-14 09:11:02 INFO  login ok user=ops@corp.example.com src=203.0.113.44
2024-01-14 09:12:40 WARN  retry from 198.51.100.22
2024-01-14 09:15:01 INFO  session closed src=192.168.1.10
EOF

cat > "$TARGET/deploy_keys.txt" <<'EOF'
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxfakekeymaterialforlocaltestingonlynotarealkey00000
-----END RSA PRIVATE KEY-----
EOF

cat > "$TARGET/public_notice.txt" <<'EOF'
Quarterly office closure notice. No personal data in this document.
The building will be closed for maintenance on the first Monday.
EOF

# Backdate so the retention auditor has something to flag.
touch -d "800 days ago" "$TARGET/customers.csv"    # > GDPR 365, PCI 365, NIST 730
touch -d "500 days ago" "$TARGET/hr_records.txt"   # > GDPR 365 only
touch -d "400 days ago" "$TARGET/app.log"          # > GDPR 365 only
touch -d "900 days ago" "$TARGET/deploy_keys.txt"  # NIST 730
touch -d "900 days ago" "$TARGET/public_notice.txt" # no PII -> must NOT be flagged

echo "Mock data written to: $TARGET"
ls -la "$TARGET"
