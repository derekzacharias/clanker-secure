# Acceptance Criteria

- Scans can be created, listed, refreshed, and deleted via API and UI.
- Findings return CVE IDs, severity, evidence, and enrichment (CVSS, references).
- Credentialed agent ingests produce findings and honor external advisory reloads.
- Coverage tab shows rule gaps with stubs; clearing and reload actions work without errors.
- Exports (CSV/JSON) include `rule_source` metadata for traceability.

