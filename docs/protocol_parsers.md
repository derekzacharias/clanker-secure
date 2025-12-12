# Protocol Parser Inventory

Target protocols and their current parser priorities:

- HTTP (priority 5) — header/title/body evidence via `http_response`
- TLS (priority 10) — certificate + cipher evidence via `tls_certificate` and `tls_session`
- SSH (priority 15) — banner parsing via `ssh_banner`
- MySQL (priority 20) — handshake parsing via `mysql_handshake`
- RDP (priority 30) — negotiation probe via `rdp_negotiation`
- SMB (priority 40) — banner reuse via `smb_banner`
- SNMP (priority 45) — banner reuse via `snmp_probe`

Parser entrypoint:
- `parse_fingerprint_artifact(evidence_kind, observation, artifacts, host=None)` selects the matching parser by `evidence_kinds` and writes fingerprint/evidence back onto the `ServiceObservation` for downstream rule/CPE matching.

# Evidence Schema

Parser output is serialized into the `fingerprint` column on findings and carries:

- `protocol`, `port`, `vendor`, `product`, `version`, `source`
- `version_confidence` (0–1) indicating how trustworthy the parsed version is
- `confidence` for the overall protocol identification
- `attributes`: parser-specific metadata (e.g., HTTP titles, TLS SANs)
- `evidence_summary`: concise description for UI/rule-gap tracking
- `evidence`: list of typed evidence blocks, each with:
  - `type` (e.g., `http_response`, `tls_certificate`, `mysql_handshake`)
  - `summary`: short human-readable recap
  - `data`: structured payload (headers, parsed fields, hashes, or hex previews)

Fixtures used by parser unit tests live under `tests/data/fingerprint/` (pcap/handshake/banners).
