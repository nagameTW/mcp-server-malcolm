"""Write class: pcap-upload — POST /upload (Malcolm 26.06.1).

FilePond multipart upload of a capture file for ingestion. The upload endpoint
is one of two routes Malcolm's own read-only mode removes entirely, so this is
a genuine write. Server-side: extension denylist + a downstream libmagic check
route accepted types; everything else is deleted.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from mcp_server_malcolm import audit

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "pcap-upload"


def register_pcap_upload_tools(mcp: FastMCP, client: MalcolmClient, audit_file: str | None) -> None:
    """Register the PCAP upload tool (called only when the class is enabled)."""

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def malcolm_upload_pcap(file_path: str, tags: str = "", max_mb: int = 500) -> str:
        """Upload a local capture file to Malcolm for ingestion.

        Args:
            file_path: Path to a local .pcap/.pcapng (or supported archive).
            tags: Optional comma-separated tags applied to the ingested data.
            max_mb: Client-side size guard in megabytes (default 500).
        """
        path = file_path.strip()
        if not path:
            return "Error: file_path is required."
        if not os.path.isfile(path):
            return f"Error: file not found: {path}"

        # Hard ceiling so a caller-supplied max_mb can't defeat the guard and OOM
        # (the whole file is read into memory before the multipart POST).
        max_mb = min(max_mb, 2048)
        filename = os.path.basename(path)
        target = f"file={filename}"
        params_summary: dict[str, Any] = {"tags": tags}
        try:
            size = os.path.getsize(path)
            if size > max_mb * 1024 * 1024:
                return f"Error: file exceeds max_mb={max_mb} (size is {size / 1024 / 1024:.1f} MB)."
            params_summary["size_bytes"] = size
            with open(path, "rb") as fh:
                content = fh.read()
            resp = await client._write_upload_pcap(filename, content, tags=tags)
        except Exception as exc:  # noqa: BLE001
            audit.record(
                "malcolm_upload_pcap",
                _CLASS,
                target,
                params_summary,
                f"error:{type(exc).__name__}",
                audit_file,
            )
            return f"Upload failed: {exc}"

        outcome = audit.outcome_for_status(resp.status_code)
        audit.record("malcolm_upload_pcap", _CLASS, target, params_summary, outcome, audit_file)
        if outcome != "ok":
            return f"Upload failed: HTTP {resp.status_code}"
        return json.dumps(
            {"uploaded": True, "file": filename, "size_bytes": size, "status": resp.status_code},
            indent=2,
        )
