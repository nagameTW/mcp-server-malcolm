"""Shared write-tool plumbing: run a mutating call and audit every outcome.

The three raise-on-error write tools (alerting, arkime-tag, hunt-job) share the
exact same try/except/audit shape. pcap-upload does NOT use this — its FilePond
primitive returns a raw response instead of raising on non-2xx, so it inspects
the status itself.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

import httpx

from mcp_server_malcolm import audit


async def run_write(
    tool: str,
    cls: str,
    target: str,
    params_summary: dict[str, Any],
    audit_file: str | None,
    call: Callable[[], Awaitable[Any]],
) -> tuple[Any | None, str | None]:
    """Run a write ``call``, auditing on success, HTTP error, and other errors.

    Returns ``(result, None)`` on success or ``(None, message)`` on failure,
    where ``message`` is a caller-facing error string (no secrets/URLs).
    """
    try:
        result = await call()
    except httpx.HTTPStatusError as exc:
        audit.record(
            tool,
            cls,
            target,
            params_summary,
            audit.outcome_for_status(exc.response.status_code),
            audit_file,
        )
        return None, f"HTTP {exc.response.status_code}"
    except Exception as exc:  # noqa: BLE001 — MCP boundary: convert to error string
        audit.record(tool, cls, target, params_summary, f"error:{type(exc).__name__}", audit_file)
        return None, str(exc)
    audit.record(tool, cls, target, params_summary, "ok", audit_file)
    return result, None
