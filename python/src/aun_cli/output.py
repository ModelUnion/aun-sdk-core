from __future__ import annotations

import json
import sys
from typing import Any


_json_mode = False


def set_json_mode(enabled: bool) -> None:
    global _json_mode
    _json_mode = enabled


def is_json_mode() -> bool:
    return _json_mode


def output_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def output_table(headers: list[str], rows: list[list[str]]) -> None:
    if _json_mode:
        output_json([dict(zip(headers, row)) for row in rows])
        return
    if not rows:
        print("(empty)")
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


def output_dict(data: dict[str, Any], fields: list[str] | None = None) -> None:
    if _json_mode:
        output_json(data)
        return
    keys = fields or list(data.keys())
    max_key_len = max(len(k) for k in keys) if keys else 0
    for k in keys:
        v = data.get(k, "")
        print(f"  {k:<{max_key_len}}  {v}")


def output_success(message: str) -> None:
    if _json_mode:
        output_json({"status": "ok", "message": message})
        return
    print(message)


def output_error(message: str, hint: str | None = None, code: int = 1) -> None:
    if _json_mode:
        err = {"error": "error", "message": message, "code": code}
        print(json.dumps(err, ensure_ascii=False), file=sys.stderr)
        return
    print(f"Error: {message}", file=sys.stderr)
    if hint:
        print(f"Hint: {hint}", file=sys.stderr)
