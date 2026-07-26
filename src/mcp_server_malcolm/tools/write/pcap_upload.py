"""Write class: pcap-upload — POST /upload (Malcolm 26.06.1).

FilePond multipart upload of a capture file for ingestion. The upload endpoint
is one of two routes Malcolm's own read-only mode removes entirely, so this is
a genuine write. Server-side: extension denylist + a downstream libmagic check
route accepted types; everything else is deleted.

file_path is confined to MALCOLM_MCP_UPLOAD_DIR: the tool reads a local file and
ships its bytes off-host, so without a staging boundary a prompt-injected caller
could exfiltrate any file the process can read (~/.ssh/id_rsa, ~/.aws/...). If
the dir is unset, uploads are refused rather than allowed anywhere.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

from mcp_server_malcolm import audit

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "pcap-upload"

# Shared: additive write to the external Malcolm server, never idempotent
# (each call ingests the file's bytes again).
_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}


def _resolve_in_dir(file_path: str, upload_dir: str | None) -> tuple[Path | None, str | None]:
    """Resolve file_path and confirm it sits inside upload_dir.

    Returns (path, None) when the file is valid and contained, or
    (None, error_message) otherwise. Symlinks are resolved before the
    containment check so a link inside the dir can't point outside it.
    """
    if not file_path:
        return None, "Error: file_path is required."
    if not upload_dir:
        return None, (
            "Error: PCAP upload is disabled — set MALCOLM_MCP_UPLOAD_DIR to a "
            "staging directory that holds the files allowed for upload."
        )
    base = Path(upload_dir).resolve()
    resolved = Path(file_path).resolve()
    if not resolved.is_relative_to(base):
        return None, f"Error: file_path must be inside MALCOLM_MCP_UPLOAD_DIR ({base})."
    if not resolved.is_file():
        return None, f"Error: file not found: {resolved}"
    return resolved, None


def register_pcap_upload_tools(
    mcp: FastMCP,
    client: MalcolmClient,
    audit_file: str | None,
    upload_dir: str | None = None,
) -> None:
    """Register the PCAP upload tool (called only when the class is enabled)."""

    @mcp.tool(title="Upload PCAP", annotations=_WRITE)
    async def malcolm_upload_pcap(
        file_path: Annotated[
            str,
            Field(
                description="Path to a local .pcap/.pcapng (or supported archive). Must resolve "
                "inside MALCOLM_MCP_UPLOAD_DIR; paths outside it are rejected."
            ),
        ],
        tags: Annotated[
            str, Field(description="Optional comma-separated tags applied to the ingested data.")
        ] = "",
        max_mb: Annotated[
            int,
            Field(
                description="Client-side size guard in megabytes; the whole file is read into "
                "memory, and the server caps this at 2048.",
                ge=1,
            ),
        ] = 500,
    ) -> str:
        """Upload a local capture file to Malcolm for ingestion (POST /upload).

        Use this to feed a PCAP into Malcolm so Zeek/Suricata parse it and it
        becomes searchable via malcolm_search / arkime_sessions. The file must
        already sit inside the server's staging directory (MALCOLM_MCP_UPLOAD_DIR);
        files outside it, and all uploads when that variable is unset, are
        refused — this boundary stops a prompt-injected caller from shipping
        arbitrary host files off-box. Additive — ingests new data and changes
        nothing already indexed. The action is audited, and the tool is
        registered only when the pcap-upload write class is enabled. Returns
        JSON with the uploaded flag, filename, size, and HTTP status.
        """
        resolved, err = _resolve_in_dir(file_path.strip(), upload_dir)
        if err:
            return err

        # Hard ceiling so a caller-supplied max_mb can't defeat the guard and OOM
        # (the whole file is read into memory before the multipart POST).
        max_mb = min(max_mb, 2048)
        filename = resolved.name
        target = f"file={filename}"
        params_summary: dict[str, Any] = {"tags": tags}
        try:
            size = os.path.getsize(resolved)
            if size > max_mb * 1024 * 1024:
                return f"Error: file exceeds max_mb={max_mb} (size is {size / 1024 / 1024:.1f} MB)."
            params_summary["size_bytes"] = size
            with open(resolved, "rb") as fh:
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
