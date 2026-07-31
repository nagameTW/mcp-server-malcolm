"""Write class: pcap-upload — POST /server/php/submit.php (Malcolm 26.06.1).

FilePond multipart upload of a capture file for ingestion. The bare /upload
path is a rewrite target that 405s on a direct POST, so the request goes to the
FilePond processor itself (see MalcolmClient._write_upload_pcap). The upload
endpoint is one of two routes Malcolm's own read-only mode removes entirely, so
this is a genuine write. Server-side: extension denylist + a downstream libmagic
check route accepted types; everything else is deleted.

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
from mcp_server_malcolm.errors import ToolInputError, UpstreamError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

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


def _resolve_in_dir(file_path: str, upload_dir: str | None) -> Path:
    """Resolve file_path and confirm it sits inside upload_dir.

    Symlinks are resolved before the containment check so a link inside the dir
    can't point outside it.

    Raises:
        ToolInputError: the path is missing, uncontained, or not a file. Every
            one of these is the caller's argument being unusable, not Malcolm
            failing, and each is fixable by passing a different path.
    """
    if not file_path:
        raise ToolInputError("file_path is required — a path inside MALCOLM_MCP_UPLOAD_DIR.")
    if not upload_dir:
        raise ToolInputError(
            "PCAP upload is disabled — set MALCOLM_MCP_UPLOAD_DIR to a staging "
            "directory that holds the files allowed for upload."
        )
    base = Path(upload_dir).resolve()
    resolved = Path(file_path).resolve()
    if not resolved.is_relative_to(base):
        raise ToolInputError(f"file_path must be inside MALCOLM_MCP_UPLOAD_DIR ({base}).")
    if not resolved.is_file():
        raise ToolInputError(f"file not found: {resolved}")
    return resolved


def register_pcap_upload_tools(
    mcp: MCPServer,
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
        """Upload a local capture file to Malcolm for ingestion (POST /server/php/submit.php).

        Use this to feed a PCAP into Malcolm so Zeek/Suricata parse it and it
        becomes searchable via malcolm_search / arkime_sessions. The file must
        already sit inside the server's staging directory (MALCOLM_MCP_UPLOAD_DIR);
        files outside it, and all uploads when that variable is unset, are
        refused — this boundary stops a prompt-injected caller from shipping
        arbitrary host files off-box, and there is no second tool that uploads
        without it, so a refusal means staging the file server-side first.
        Additive — ingests new data and changes nothing already indexed. The
        action is audited, and the tool is registered only when the pcap-upload
        write class is enabled. Ingestion is asynchronous: the reply says
        Malcolm took the file, while a separate service parses it afterwards, so
        a search run straight after the upload still finds nothing — watch
        latest_age_seconds from malcolm_data_coverage instead of re-uploading.
        Returns JSON with the uploaded flag, filename, size, and HTTP status.
        """
        resolved = _resolve_in_dir(file_path.strip(), upload_dir)

        # Hard ceiling so a caller-supplied max_mb can't defeat the guard and OOM
        # (the whole file is read into memory before the multipart POST).
        max_mb = min(max_mb, 2048)
        filename = resolved.name
        target = f"file={filename}"
        params_summary: dict[str, Any] = {"tags": tags}
        # Sized before the audited block: refusing to send is not a write
        # attempt, so it leaves no audit row.
        size = os.path.getsize(resolved)
        if size > max_mb * 1024 * 1024:
            raise ToolInputError(
                f"file exceeds max_mb={max_mb} (size is {size / 1024 / 1024:.1f} MB)."
            )
        params_summary["size_bytes"] = size

        try:
            with open(resolved, "rb") as fh:
                content = fh.read()
            resp = await client._write_upload_pcap(filename, content, tags=tags)
        except Exception as exc:
            audit.record(
                "malcolm_upload_pcap",
                _CLASS,
                target,
                params_summary,
                f"error:{type(exc).__name__}",
                audit_file,
            )
            raise

        outcome = audit.outcome_for_status(resp.status_code)
        audit.record("malcolm_upload_pcap", _CLASS, target, params_summary, outcome, audit_file)
        if outcome != "ok":
            # The FilePond primitive hands back the raw response rather than
            # raising, so the status has to be judged here.
            raise UpstreamError(
                f"Malcolm's upload endpoint answered {resp.status_code} for {filename}.",
                resp.status_code,
            )
        return json.dumps(
            {"uploaded": True, "file": filename, "size_bytes": size, "status": resp.status_code},
            indent=2,
        )
