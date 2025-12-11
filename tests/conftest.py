from __future__ import annotations

import os
import sys
from pathlib import Path

# Disable background NVD sync during tests to avoid long-running network work.
os.environ.setdefault("NVD_SYNC_ENABLED", "0")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
