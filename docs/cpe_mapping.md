# CPE Mapping Format

Curated CPE mappings live at `src/clanker/core/cpe_map.json` and are consumed by the `CpeInferenceEngine`. Each entry describes how to turn a normalized service identifier into a CPE template with explicit confidence and source metadata.

- The file is JSON with a top-level `services` array.
- Each service object supports:
  - `match` (required): list of normalized service names or aliases (e.g., `["nginx", "httpd"]`).
  - `cpe` (required): CPE 2.3 template that may use `{version}` and `{product}` placeholders.
  - `confidence`: `"low"`, `"medium"`, or `"high"` (default `"medium"` if omitted).
  - `source`: label for provenance (e.g., `"curated/web"`).
  - `ports` (optional): restrict matches to the provided port numbers.
  - `protocols` (optional): restrict matches to the provided protocols (`"tcp"`/`"udp"`).

Example:

```json
{
  "services": [
    {
      "match": ["nginx"],
      "cpe": "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
      "confidence": "high",
      "source": "curated/web",
      "ports": [80, 443],
      "protocols": ["tcp"]
    }
  ]
}
```

Entries are normalized with `normalize_service_name`, so aliases such as `"Apache"` and `"httpd"` can be grouped together. If a file uses the legacy `{ "service": "cpe-template" }` shape it will still load, but the preferred format above should be used for new mappings.
