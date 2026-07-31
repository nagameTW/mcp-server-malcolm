"""File-analysis tools -- Zeek-extracted files and their scan verdicts."""

from __future__ import annotations

import hashlib
import string
from typing import TYPE_CHECKING, Annotated, Any
from urllib.parse import quote

from pydantic import Field
from typing_extensions import TypedDict

from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.tools._parse import parse_json_object

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

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

# The file.mime_type values that mean "native executable" -- the shortcut
# behind executables_only, so an agent hunting dropped binaries does not have to
# know that Malcolm labels a PE application/x-dosexec.
#
# Two labelling vocabularies land in this one field and both are needed. Zeek's
# own signatures (base/frameworks/files/magic/executable.sig, read out of the
# running Zeek) split ELF by e_type -- x-object for ET_REL, x-executable for
# ET_EXEC, x-sharedlib for ET_DYN, which is every PIE binary and so the default
# build on current distros -- and label Mach-O x-mach-o-executable. Strelka
# labels the same files with libmagic, which says
# vnd.microsoft.portable-executable, x-pie-executable and x-mach-binary instead.
# Zeek emits no "application/x-elf" at all. Core dumps (x-coredump) are left
# out: they are not a dropped binary. A deployment can still surprise this list
# -- if the shortcut comes back empty, check the real values with
# malcolm_field_values(field="file.mime_type").
_EXECUTABLE_MIMES = (
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-object",
    "application/x-pie-executable",
    "application/x-mach-o-executable",
    "application/x-mach-binary",
)

# Lengths of the hex digests (md5, sha1, sha256) every pipeline writes lowercase.
_HEX_DIGEST_LENGTHS = (32, 40, 64)


class FileRow(TypedDict, total=False):
    """One carved file. Every key is optional: the server populates what it has
    and the row drops the rest rather than carrying nulls."""

    # Malcolm writes @timestamp as an ISO string on Zeek records and as epoch
    # milliseconds on Arkime session records; both are real, so both are
    # declared. Every other scalar here is normalised through _first(), which is
    # what keeps this declaration true of the data.
    timestamp: str | int
    filename: str
    mime_type: str
    bytes: str | int  # Zeek sends a string, Strelka an int
    transport: str
    source_ip: str
    destination_ip: str
    md5: str
    sha256: str
    severity: int
    severity_tags: list[str]
    scan_hits: int
    scan_rules: list[str]
    scan_scanners: list[str]
    zeek_uid: str
    extracted: str
    note: str
    truncated: str


class FileScanResult(TypedDict):
    """What malcolm_file_scans returns when anything matched."""

    count: int
    files: list[FileRow]


class ExtractedFile(TypedDict, total=False):
    """What malcolm_extract_file returns: metadata, never the bytes."""

    filename: str
    found: bool
    size_bytes: int
    sha256: str
    magic: str
    download_url: str
    status: int
    note: str


# Shared: both tools read from the external Malcolm server, never mutate it.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_file_tools(mcp: MCPServer, client: MalcolmClient) -> None:
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
                description="Shortcut for the eight MIME labels that mean a native "
                "executable — PE, ELF (including the x-sharedlib every PIE binary "
                "gets), and Mach-O — in both the Zeek and the Strelka vocabulary. "
                "Use when hunting dropped binaries. A deployment can still use a "
                "label outside that set; if this returns nothing, check "
                'malcolm_field_values(field="file.mime_type").'
            ),
        ] = False,
        file_hash: Annotated[
            str,
            Field(
                description="Pivot from a hash IOC to the file records carrying it. "
                "Matched on related.hash, which holds md5, sha1, sha256, ssdeep and "
                "tlsh together, so any of those works, in either case (a tlsh is "
                "stored uppercase by Zeek and lowercase by Strelka; both are "
                "searched). One file usually has many records — one per session "
                "that carried it, plus a scan record — and they can exceed limit; "
                'add {"event.dataset":"strelka"} to filters to see the scan '
                "verdict on its own. Empty = no hash filter."
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
    ) -> FileScanResult | str:
        """List the files Zeek saw cross the wire, with their hashes and scan verdicts.

        Use this for any file-centric question — it filters event.dataset=files
        for you and returns one compact row per file instead of the multi-KB raw
        document. Use malcolm_search instead for any other record type (conn,
        dns, http); search_dsl for a substring or wildcard filename match, which
        Malcolm's exact-match filters cannot express; arkime_file_by_hash to
        pull bytes by a hash Arkime recorded on a session rather than by Zeek's
        file record.

        Both record types Malcolm files under this dataset are returned: Zeek's
        record of the transfer and, for a scanned file, Strelka's — which adds
        the scan verdict — so one file can come back as two rows. A row's
        `extracted` value is the argument malcolm_extract_file takes; a row
        carrying `note` instead was seen on the wire but is not on disk.

        Returns JSON {"count", "files"}: per file the timestamp, name, MIME
        type, size, both endpoints, md5/sha256, Malcolm's severity, any
        Strelka/YARA/ClamAV hits, and the `extracted` name — absent values are
        omitted. No match returns a sentence saying so, naming the field if a
        filter used one Malcolm does not index, rather than an empty list.
        """
        extra = parse_json_object(filters, "filters", '{"source.ip":"192.0.2.7"}') or {}

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
                "No extracted-file records matched. Widen the time range, or confirm "
                "this Malcolm records file transfers at all with "
                'malcolm_field_values(field="event.dataset") — the "files" dataset '
                "should be there. If executables_only returned this, check the MIME "
                'labels actually in use with malcolm_field_values(field="file.mime_type").'
            )

        files = [_file_row(row.get("_source") or {}) for row in rows]
        return {"count": len(files), "files": files}

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
    ) -> ExtractedFile | str:
        """Fetch one Zeek-extracted file from Malcolm's extracted-files server; returns METADATA ONLY.

        Use this after malcolm_file_scans, which supplies the filename. Use
        arkime_file_by_hash instead when you hold a content hash but no Zeek
        file record, and arkime_session_pcap for a session's packets rather than
        one carved file.

        The bytes never enter the response and nothing is written to disk — a
        carved file may be live malware. The body is streamed against a size cap
        and an oversized file is refused before it is read; url_only=True
        returns the URL alone, without contacting Malcolm at all. Names are
        flat, so a filename containing a path separator is rejected unsent.

        Returns JSON: found, size_bytes, sha256 of the bytes actually served
        (compare it against the record's sha256), the first four magic bytes as
        hex, and the download URL. A 404 comes back as found:false — the index
        record outlives the file, which Malcolm prunes. Any other error status
        is reported as a failure, not as a missing file: it says nothing about
        whether the file is on disk.
        """
        name = filename.strip()
        if name.startswith(f"{_EXTRACTED_PREFIX}/"):
            name = name[len(_EXTRACTED_PREFIX) + 1 :]
        if not name:
            raise ToolInputError(
                "filename is required (the `extracted` value from a malcolm_file_scans row)."
            )
        if any(sep in name for sep in _PATH_CHARS) or ".." in name:
            raise ToolInputError(
                f"invalid filename {filename!r} — Malcolm's extracted-files directory "
                f"is flat, so a path separator is never part of a name."
            )

        url = f"{client.base_url}/{_EXTRACTED_PREFIX}/{quote(name, safe='')}"
        if url_only:
            return {
                "filename": name,
                "download_url": url,
                "note": "Download requires Malcolm authentication (Basic auth).",
            }

        try:
            status, content = await client.extracted_file(name, max_bytes=_MAX_BYTES)
        except ValueError as exc:
            # The size cap, not a server problem: the caller has a way through.
            raise ToolInputError(
                f"{exc}; use url_only=true to fetch it outside the agent."
            ) from exc

        if status == 404:
            return {
                "filename": name,
                "found": False,
                "status": 404,
                "note": "No such file on the extracted-files server — the index record "
                "outlives the file, which Malcolm prunes, and the preservation "
                "setting may keep only quarantined files.",
            }
        if status >= 400:
            # Anything but a 404 says nothing about whether the file exists, and
            # reporting it as "pruned" would end the hunt on a fixable problem:
            # Malcolm gates /extracted-files behind basic auth and, with
            # role-based access on, ROLE_EXTRACTED_FILES.
            raise UpstreamError(
                f"the extracted-files server answered {status}, so whether {name} is "
                f"on disk is unknown. Check that FILESCAN_HTTP_SERVER_ENABLE is on, "
                f"its container is up, and this account may read extracted files.",
                status,
            )

        return {
            "filename": name,
            "found": True,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "magic": content[:4].hex(),
            "download_url": url,
        }


def _normalize_hash(value: str) -> str | list[str]:
    """Expand a hash into the case forms Malcolm actually indexed.

    related.hash is matched as an exact term and the two pipelines writing it
    disagree on case: Zeek stores md5/sha1/sha256 lowercase but tlsh uppercase
    and ssdeep as-is, while Strelka lowercases all of them. Measured on
    v26.07.1, one TLSH digest matches 17,883 Zeek records in uppercase and zero
    Strelka ones, with the reverse in lowercase — the two forms partition the
    same file's records, so sending one case would return the carve records and
    silently no scan verdicts (or the other way round).

    Returns:
        The single lowercase form for a hex digest — the only case any pipeline
        writes it in — otherwise both forms, which Malcolm's filter ORs.
    """
    if len(value) in _HEX_DIGEST_LENGTHS and all(c in string.hexdigits for c in value):
        return value.lower()
    lowered = value.lower()
    return value if value == lowered else [value, lowered]


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


def _file_row(source: dict[str, Any]) -> FileRow:
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
        "timestamp": _first(source.get("@timestamp")),
        "filename": _first(file_info.get("name")),
        "mime_type": _first(file_info.get("mime_type")) or zeek_files.get("mime_type"),
        # Zeek only sets total_bytes when the protocol declared a length; on a
        # chunked HTTP body it writes seen_bytes alone, which is 12.5% of the
        # files records on the v26.07.1 lab -- without this last fallback every
        # one of those rows comes back with no size at all.
        #
        # _first() matters on both of these: profiled across all 47 datasets on
        # v26.07.1, file.size arrives as list[int] on alert records and
        # file.source as list[str], so passing them through raw put a list where
        # a scalar was declared.
        "bytes": _first(
            file_info.get("size") or zeek_files.get("total_bytes") or zeek_files.get("seen_bytes")
        ),
        "transport": _first(file_info.get("source")),
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
