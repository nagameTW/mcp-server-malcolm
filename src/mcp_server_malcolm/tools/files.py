"""File-analysis tools -- Zeek-extracted files and their scan verdicts."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import quote

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# Malcolm serves Zeek's extract_files directory under this path when
# FILESCAN_HTTP_SERVER_ENABLE is on; zeek.files.extracted_uri is the same path,
# written relative ("extracted-files/<name>").
_EXTRACTED_PREFIX = "extracted-files"

# That directory is flat -- ~90k files, no per-file subdirectory (verified on
# Malcolm v26.07.1) -- so a separator in a name is never legitimate, and it is
# the only shape that could climb out of the directory.
_PATH_CHARS = ("/", "\\")

# The downloaded body is held in memory. Zeek's own ceiling
# (EXTRACTED_FILE_MAX_BYTES) defaults to 128 MB, so cap under it and send
# anything larger to url_only. Same cap as arkime.py's file download.
_MAX_BYTES = 100 * 1024 * 1024

# file.mime_type values Zeek/libmagic assigns to native executables -- the
# shortcut behind executables_only, so an agent hunting dropped binaries does
# not have to know Malcolm records PE files as application/x-dosexec.
_EXECUTABLE_MIMES = (
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-binary",
)

# Lengths of the hex digests Zeek writes lowercase (md5, sha1, sha256).
_HEX_DIGEST_LENGTHS = (32, 40, 64)

# Shared: both tools read from the external Malcolm server, never mutate it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_file_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register extracted-file search and download tools."""

    @mcp.tool(title="Search extracted files and scan verdicts", annotations=_READ)
    async def malcolm_file_scans(
        mime_type: Annotated[
            str,
            Field(
                description="Exact file.mime_type value, or several comma-separated "
                '(OR). E.g. "application/x-dosexec"; "image/png,image/jpeg". Note '
                "Malcolm records PE executables as application/x-dosexec, not "
                "application/x-msdownload. Overrides executables_only when both "
                "are given. Empty = any type."
            ),
        ] = "",
        executables_only: Annotated[
            bool,
            Field(
                description="Shortcut for the executable MIME types (PE, ELF, "
                "Mach-O). Use when hunting dropped binaries."
            ),
        ] = False,
        file_hash: Annotated[
            str,
            Field(
                description="Pivot from a hash IOC to the file records carrying it. "
                "Matched on related.hash, which holds md5, sha1, sha256, ssdeep and "
                "tlsh together, so any of those works. Empty = no hash filter."
            ),
        ] = "",
        filters: Annotated[
            str,
            Field(
                description="Extra JSON filters in Malcolm filter syntax (see "
                "malcolm_search), merged on top of this tool's own. E.g. "
                '{"source.ip":"192.0.2.7"}; {"network.protocol":"smb"}. '
                "Values are matched EXACTLY — no wildcards."
            ),
        ] = "{}",
        limit: Annotated[int, Field(description="Max file records to return.", ge=1, le=500)] = 20,
        time_from: Annotated[
            str,
            Field(
                description='Start time, dateparser format ("2024-01-01", "7 days ago"). '
                "Empty = ALL history."
            ),
        ] = "",
        time_to: Annotated[
            str, Field(description="End time, dateparser format. Empty = now.")
        ] = "",
    ) -> str:
        """List the files Zeek carved out of network traffic, with hashes and scan verdicts.

        Use this to answer "what files crossed the wire": it filters
        event.dataset=files for you and returns one trimmed row per file
        (filename, MIME type, size, md5/sha256, the two endpoints, Malcolm's
        severity, and any Strelka/YARA/ClamAV hits) instead of the very large
        raw document. Each row's `extracted` value is the argument
        malcolm_extract_file takes to fetch the file itself.

        Filenames are matched exactly, like every Malcolm filter — for a
        substring ("*.exe", a path fragment) use search_dsl with a wildcard
        query. To pivot the other way, from an Arkime session's http.md5 /
        http.sha256 to the bytes, use arkime_file_by_hash. Rows with no
        `extracted` value were seen but never written to disk (outside the
        extractor's size limits, pruned since, or extraction disabled).
        """
        try:
            extra = _parse_filters(filters)
        except ValueError as exc:
            return f"Error: {exc}"

        query: dict[str, Any] = {"event.dataset": "files"}
        if executables_only:
            query["file.mime_type"] = list(_EXECUTABLE_MIMES)
        if mimes := [m.strip() for m in mime_type.split(",") if m.strip()]:
            query["file.mime_type"] = mimes[0] if len(mimes) == 1 else mimes
        if h := file_hash.strip():
            query["related.hash"] = _normalize_hash(h)
        query.update(extra)

        data = await client.search(
            filters=query,
            limit=min(max(1, limit), 500),
            time_from=time_from,
            time_to=time_to,
        )

        rows = data.get("results") or []
        if not rows:
            hint = await client.explain_unknown_fields(extra) if extra else ""
            return (f"{hint}\n\n" if hint else "") + (
                "No extracted-file records matched. Widen the time range, or check "
                "that this Malcolm runs Zeek file extraction (ZEEK_EXTRACTOR_MODE) "
                'with malcolm_field_values(field="event.dataset").'
            )

        files = [_file_row(row.get("_source") or {}) for row in rows]
        return json.dumps(
            {"count": len(files), "files": files}, indent=2, ensure_ascii=False, default=str
        )

    @mcp.tool(title="Fetch a Zeek-extracted file", annotations=_READ)
    async def malcolm_extract_file(
        filename: Annotated[
            str,
            Field(
                description="The `extracted` value from a malcolm_file_scans row "
                "(Zeek's zeek.files.extracted). A full "
                '"extracted-files/<name>" URI is accepted too. Names are flat — '
                "the extracted-files directory has no subdirectories."
            ),
        ],
        url_only: Annotated[
            bool,
            Field(
                description="If true, return only the download URL and skip the "
                "download (use for a file larger than the size cap)."
            ),
        ] = False,
    ) -> str:
        """Fetch one Zeek-extracted file from Malcolm's extracted-files server; returns METADATA ONLY.

        Downloads the carved file, hashes it, and returns metadata (size, sha256,
        leading file-magic bytes) — the bytes themselves never enter the
        response and nothing is written to disk, because an extracted file may
        be live malware. Enforces a size cap and refuses an oversized file
        before reading it; use url_only then.

        Get the filename from malcolm_file_scans. To reach a file by its content
        hash instead of its name, use arkime_file_by_hash; for a session's
        packets rather than a carved file, arkime_session_pcap. A 404 here means
        the record exists but the file does not: Malcolm prunes this directory,
        and the preservation setting may keep only quarantined files.
        """
        name = filename.strip()
        if name.startswith(f"{_EXTRACTED_PREFIX}/"):
            name = name[len(_EXTRACTED_PREFIX) + 1 :]
        if not name:
            return "Error: filename is required (the `extracted` value from malcolm_file_scans)."
        if any(sep in name for sep in _PATH_CHARS) or ".." in name:
            return (
                "Error: invalid filename — Malcolm's extracted-files directory is "
                "flat, so a path separator is never part of a name."
            )

        url = f"{client.base_url}/{_EXTRACTED_PREFIX}/{quote(name, safe='')}"
        if url_only:
            return json.dumps(
                {
                    "filename": name,
                    "download_url": url,
                    "note": "Download requires Malcolm authentication (Basic auth).",
                },
                indent=2,
            )

        try:
            status, content = await client.extracted_file(name, max_bytes=_MAX_BYTES)
        except ValueError as exc:
            return f"Error: {exc}; use url_only=true to fetch it outside the agent."
        except Exception as exc:  # noqa: BLE001
            return f"Extracted-file download failed: {exc}"

        if status >= 400:
            return json.dumps(
                {
                    "filename": name,
                    "found": False,
                    "status": status,
                    "note": "No such file on the extracted-files server — it may have "
                    "been pruned, or preservation may keep only quarantined files.",
                },
                indent=2,
            )

        return json.dumps(
            {
                "filename": name,
                "found": True,
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "magic": content[:4].hex(),
                "download_url": url,
            },
            indent=2,
        )


def _parse_filters(raw: str) -> dict[str, Any]:
    """Parse the extra-filters JSON, empty for "no extra filters".

    Unlike malcolm_search, a malformed filter is reported rather than dropped:
    silently ignoring it would answer a narrower question than the one asked
    and read as "no such files".

    Raises:
        ValueError: the string is neither empty nor a JSON object.
    """
    text = raw.strip()
    if not text or text.lower() in ("{}", "null", "none"):
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"filters is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError('filters must be a JSON object, e.g. {"source.ip":"192.0.2.7"}')
    return parsed


def _normalize_hash(value: str) -> str:
    """Lowercase a hex digest, leave every other hash form untouched.

    Zeek writes md5/sha1/sha256 lowercase but tlsh uppercase, and all of them
    land in related.hash — so folding every input to lowercase would silently
    break a tlsh lookup, while leaving an uppercase md5 (how VirusTotal prints
    it) alone would silently break that one.
    """
    if len(value) in _HEX_DIGEST_LENGTHS and all(c in "0123456789abcdefABCDEF" for c in value):
        return value.lower()
    return value


def _first(value: Any) -> Any:
    """Unwrap Malcolm's single-element arrays (file.name, file.mime_type, ...)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _is_true(value: Any) -> bool:
    """Zeek flags arrive as "T"/"F" from the Zeek log and as bools from filescan."""
    return value is True or (isinstance(value, str) and value.upper() == "T")


def _disk_name(source: dict[str, Any]) -> Any:
    """The on-disk name of the carved file, from whichever record type this is.

    A Zeek files record names it in zeek.files.extracted. A Strelka/filescan
    record has no such field, but it does record the path it scanned
    (/zeek/extract_files/<name>) — without that, every scan verdict would come
    back marked "not extracted to disk" while the file sits right there.
    """
    if extracted := (source.get("zeek") or {}).get("files", {}).get("extracted"):
        return extracted
    result = (source.get("strelka") or {}).get("result") or {}
    scanned = _first((result.get("file") or {}).get("name"))
    return scanned.rsplit("/", 1)[-1] if isinstance(scanned, str) and scanned else None


def _file_row(source: dict[str, Any]) -> dict[str, Any]:
    """Reduce one files/strelka document to the fields worth triaging.

    The raw document runs to several KB of hashes, geo, and pipeline metadata;
    twenty of them would crowd out the agent's context for no gain.
    """
    file_info = source.get("file") or {}
    hashes = file_info.get("hash") or {}
    zeek = source.get("zeek") or {}
    zeek_files = zeek.get("files") or {}
    event = source.get("event") or {}
    scan = source.get("filescan") or {}
    rules = scan.get("rules") or {}

    row: dict[str, Any] = {
        "timestamp": source.get("@timestamp"),
        "filename": _first(file_info.get("name")),
        "mime_type": _first(file_info.get("mime_type")) or zeek_files.get("mime_type"),
        "bytes": file_info.get("size") or zeek_files.get("total_bytes"),
        "transport": file_info.get("source"),
        "source_ip": _first((source.get("source") or {}).get("ip")),
        "destination_ip": _first((source.get("destination") or {}).get("ip")),
        "md5": _first(hashes.get("md5")),
        "sha256": _first(hashes.get("sha256")),
        "severity": event.get("severity"),
        "severity_tags": event.get("severity_tags"),
        "scan_hits": scan.get("hits"),
        "scan_rules": rules.get("name"),
        "scan_scanners": rules.get("scanner"),
        "zeek_uid": _first(zeek.get("uid")),
    }

    if extracted := _disk_name(source):
        row["extracted"] = extracted
    else:
        row["note"] = (
            "not extracted to disk (outside the extractor size limits, "
            "pruned, or extraction disabled)"
        )
    if _is_true(zeek_files.get("extracted_cutoff")):
        row["truncated"] = "hit Zeek's extraction size limit — the stored file is partial"

    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
