"""Structured write-audit sink.

One line of JSON per write attempt. Destination is stderr by default, or a
file when MALCOLM_MCP_AUDIT_FILE is set (opened+closed per write — no
long-lived handle, safe under crashes). Read tools are never audited.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

_MAX_VALUE_LEN = 200


def outcome_for_status(status_code: int) -> str:
    """Map an HTTP status code to an audit outcome token."""
    if 200 <= status_code < 300:
        return "ok"
    if 400 <= status_code < 500:
        return "http_4xx"
    if 500 <= status_code < 600:
        return "http_5xx"
    return "http_other"


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _MAX_VALUE_LEN:
        return value[:_MAX_VALUE_LEN] + "…"
    return value


def record(
    tool: str,
    cls: str,
    target: str,
    params_summary: dict[str, Any],
    outcome: str,
    audit_file: str | None = None,
) -> None:
    """Emit one audit line. Never raises — auditing must not break a tool."""
    row = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": tool,
        "class": cls,
        "target": target,
        "params": {k: _truncate(v) for k, v in params_summary.items()},
        "outcome": outcome,
    }
    line = json.dumps(row, ensure_ascii=False, default=str)
    try:
        if audit_file:
            with open(audit_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        else:
            print(line, file=sys.stderr, flush=True)
    except Exception:  # noqa: BLE001 — auditing is best-effort, never fatal
        pass
