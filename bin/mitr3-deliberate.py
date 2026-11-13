#!/usr/bin/env python3
"""CLI for MITR3 multi-agent deliberation.

Examples:
  python3 bin/mitr3-deliberate.py run --topic "Review the local fixture" \\
      --phase js-inventory --impact low --agents glyph,ward
  python3 bin/mitr3-deliberate.py show --topic-id tpc-...
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.phantom.deliberate import main

if __name__ == '__main__':
    raise SystemExit(main())
