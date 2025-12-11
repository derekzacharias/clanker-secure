"""
Example usage of the SSHScanner for credentialed SSH checks.

Install Paramiko first:
    pip install paramiko
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repository's src directory is on the path for direct execution.
ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from clanker.core.ssh_credentialed_scanner import SSHScanner, results_to_json


def main() -> None:
    hosts = [
        {
            "host": "192.0.2.10",
            "port": 22,
            "username": "audit",
            "password": "replace-me",
        },
        {
            "host": "192.0.2.11",
            "username": "audit",
            "key_path": "/path/to/private/key",
            "passphrase": "optional-passphrase",
        },
    ]

    scanner = SSHScanner(max_workers=2, timeout=10, command_timeout=30, verbose=True)
    results = scanner.scan_all(hosts)
    print(results_to_json(results))


if __name__ == "__main__":
    main()
