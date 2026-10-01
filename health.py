#!/usr/bin/env python3
from __future__ import annotations

import json


def main() -> int:
    print(json.dumps({"ok": True, "status": "healthy"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
