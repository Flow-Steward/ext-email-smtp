#!/usr/bin/env python3
"""SMTP outbound email extension subprocess entrypoint."""

from __future__ import annotations

import json
import sys

import smtp_extension


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        print(
            json.dumps(
                {
                    "ok": False,
                    "delivered": False,
                    "error_code": "invalid_json",
                    "error": "Request payload must be JSON",
                    "errors": [{"code": "invalid_json", "message": "Request payload must be JSON"}],
                    "external_effect_status": "failed",
                    "definitely_no_external_effect": True,
                }
            )
        )
        return 2
    response = smtp_extension.handle_payload(payload)
    print(json.dumps(response, sort_keys=True))
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
