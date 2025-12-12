# Acceptance Criteria

Purpose: Enforce requirements

## Authenticated Scanning
- Valid credentials succeed
- Invalid credentials fail gracefully
- Findings include proof of access

## CVE Ingestion
- CVE updates processed automatically
- CVEs include exploitability metadata

## Asset Discovery
- Newly discovered assets appear in inventory within scan cycle

## CI/CD Integration
- Pipeline fails when critical findings exceed policy thresholds
