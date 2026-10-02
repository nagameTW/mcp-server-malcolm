"""Shared write-tool plumbing: run a mutating call and audit every outcome.

The three raise-on-error write tools (alerting, arkime-tag, hunt-job) share the
exact same try/except/audit shape. pcap-upload does NOT use this -- its FilePond
primitive returns a raw response instead of raising on non-2xx, so it inspects
the status itself.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from mcp_server_malcolm import audit


async def run_write(
    tool: str,
    cls: str,
    target: str,
    params_summary: dict[str, Any],
    audit_file: str | None,
    call: Callable[[], Awaitable[Any]],
) -> Any:
    """Run a write ``call``, auditing success and failure alike.

    A failure is re-raised unchanged, so it reaches the caller as
    ``isError: true``; the audit row is written first, because the write was
    attempted either way and the record of the attempt is the point.

    The status comes off the exception rather than off an ``httpx`` type: the
    client converts every httpx failure to :class:`UpstreamError` before it
    gets here, and that exception carries ``status`` (None when no response
    arrived, so there is no HTTP outcome to record).
    """
    try:
        result = await call()
    except Exception as exc:
        status = getattr(exc, "status", None)
        outcome = (
            audit.outcome_for_status(status)
            if isinstance(status, int)
            else f"error:{type(exc).__name__}"
        )
        audit.record(tool, cls, target, params_summary, outcome, audit_file)
        raise
    audit.record(tool, cls, target, params_summary, "ok", audit_file)
    return result
