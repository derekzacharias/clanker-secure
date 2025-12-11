#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import sys

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from clanker.core.coverage import load_rule_gaps, stub_rule_from_gap, summarize_rule_gaps  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize unmatched services for rule authoring",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=Path("scan_artifacts/rule_gaps.jsonl"),
        help="Path to rule gap JSONL log (default: scan_artifacts/rule_gaps.jsonl)",
    )
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=20,
        help="Number of top signatures to show (default: 20)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit full JSON summary instead of human-readable text",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    entries = load_rule_gaps(args.input)
    if not entries:
        print(f"No rule gaps found at {args.input}")
        return

    summary = summarize_rule_gaps(entries)
    top = summary[: args.top]

    if args.as_json:
        payload: dict[str, Any] = {
            "total_entries": len(entries),
            "unique_signatures": len(summary),
            "top": top,
        }
        print(json.dumps(payload, indent=2))
        return

    print(f"Total gaps: {len(entries)} | Unique signatures: {len(summary)}")
    print(f"Top {min(len(top), args.top)} signatures:")
    for idx, item in enumerate(top, start=1):
        proto = item.get("protocol")
        port = item.get("port") or "?"
        service = item.get("service_name") or "unknown"
        count = item.get("count", 0)
        print(f"{idx:>2}. {proto}/{port} {service} — {count} hit(s)")
        for example in item.get("examples", []):
            host = example.get("host") or "-"
            ver = example.get("service_version") or "-"
            reason = example.get("reason") or "-"
            summary_line = example.get("evidence_summary") or "-"
            print(f"    host={host} version={ver} reason={reason} evidence={summary_line}")
        stub = stub_rule_from_gap(item)
        print(f"    stub: {json.dumps(stub)}")


if __name__ == "__main__":
    main()
