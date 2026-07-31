"""Tests for the file-analysis tools: malcolm_file_scans, malcolm_extract_file.

Field names and the extracted-files URL shape were verified live against
Malcolm v26.07.1 (Zeek EXTRACT + Strelka/filescan enabled).
"""

import asyncio
import hashlib
import json

import httpx
import pytest
from conftest import raised_by, tool_text
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.server import create_server
from mcp_server_malcolm.tools.files import register_file_tools

# One real /mapi/document row, trimmed of the fields the tool does not surface
# but keeping the ones it does (shape taken from a live Malcolm response).
_FILE_DOC = {
    "_id": "240425-KGjALeZzE4yZUpJqX7Pj0A",
    "_source": {
        "@timestamp": "2024-04-25T13:09:30.055000064Z",
        "source": {"ip": "192.0.2.7", "port": 59188},
        "destination": {"ip": "198.51.100.1", "port": 80},
        "event": {"dataset": "files", "severity": 75, "provider": "zeek"},
        "file": {
            "hash": {
                "md5": "52ad569e4fd4739f640fc3de54a1c063",
                "sha256": "6acb154e1adf5287e82169fd40feef7469efe14689ef377ff2812386091068d3",
                "ssdeep": "192:sxNaQrp4NustAnDE",
            },
            "mime_type": ["application/x-dosexec"],
            "name": ["HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe"],
            "size": "11776",
            "source": "HTTP",
        },
        "zeek": {
            "files": {
                "extracted": "HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe",
                "extracted_uri": (
                    "extracted-files/HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe"
                ),
                "extracted_cutoff": "F",
                "mime_type": "application/x-dosexec",
                "total_bytes": "11776",
            },
            "fuid": ["FsoPNn4V2BTsEGEGE6"],
            "uid": "CkjbVOHoIUv3SvCnc",
        },
    },
}


def _mock_client(handler):
    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example",
        transport=httpx.MockTransport(handler),
    )
    return c


def _tools(handler):
    mcp = MCPServer("t")
    register_file_tools(mcp, _mock_client(handler))
    return mcp


def _docs_handler(results, seen=None):
    """Handler answering /mapi/document, recording the request body in `seen`."""

    def handler(req):
        if seen is not None:
            seen["path"] = req.url.path
            seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"results": results})

    return handler


def test_file_tools_registered():
    names = [t.name for t in asyncio.run(create_server().list_tools())]
    assert "malcolm_file_scans" in names
    assert "malcolm_extract_file" in names


# -- malcolm_file_scans -------------------------------------------------


@pytest.mark.asyncio
async def test_file_scans_filters_the_files_dataset():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert seen["path"] == "/mapi/document"
    assert seen["body"]["filter"]["event.dataset"] == "files"
    assert "6acb154e1adf5287e82169fd40feef7469efe14689ef377ff2812386091068d3" in out
    assert "HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe" in out


@pytest.mark.asyncio
async def test_file_scans_maps_every_row_field():
    """Pin the whole row, not substrings of it.

    A substring assertion cannot tell source_ip from destination_ip, so it would
    pass with the two swapped — the tool would report the transfer direction
    backwards. Compare the parsed row exactly instead.
    """
    mcp = _tools(_docs_handler([_FILE_DOC]))
    out = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))

    assert out["count"] == 1
    assert out["files"][0] == {
        "timestamp": "2024-04-25T13:09:30.055000064Z",
        "filename": "HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe",
        "mime_type": "application/x-dosexec",
        "bytes": "11776",
        "transport": "HTTP",
        "source_ip": "192.0.2.7",
        "destination_ip": "198.51.100.1",
        "md5": "52ad569e4fd4739f640fc3de54a1c063",
        "sha256": "6acb154e1adf5287e82169fd40feef7469efe14689ef377ff2812386091068d3",
        "severity": 75,
        "zeek_uid": "CkjbVOHoIUv3SvCnc",
        "extracted": "HTTP-FsoPNn4V2BTsEGEGE6-CkjbVOHoIUv3SvCnc-20240425130930.exe",
    }


@pytest.mark.asyncio
async def test_file_scans_trims_the_raw_document():
    """The raw files record is huge; only the triage fields may come back."""
    mcp = _tools(_docs_handler([_FILE_DOC]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert "ssdeep" not in out
    assert "extracted_uri" not in out


@pytest.mark.asyncio
async def test_file_scans_unwraps_single_element_arrays():
    """file.name / file.mime_type arrive as arrays from Zeek and as scalars from
    other pipelines; a row must carry the value either way."""
    doc = json.loads(json.dumps(_FILE_DOC))
    doc["_source"]["file"]["name"] = "scalar-name.exe"
    doc["_source"]["file"]["mime_type"] = "text/plain"
    mcp = _tools(_docs_handler([doc]))
    row = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))["files"][0]

    assert row["filename"] == "scalar-name.exe"
    assert row["mime_type"] == "text/plain"


@pytest.mark.asyncio
async def test_file_scans_falls_back_through_the_zeek_size_fields():
    """Zeek writes total_bytes only when the protocol declared a length; on a
    chunked HTTP body only seen_bytes is set (12.5% of the lab's files rows)."""
    doc = json.loads(json.dumps(_FILE_DOC))
    del doc["_source"]["file"]["size"]
    del doc["_source"]["zeek"]["files"]["total_bytes"]
    doc["_source"]["zeek"]["files"]["seen_bytes"] = "146"
    doc["_source"]["file"]["mime_type"] = []
    mcp = _tools(_docs_handler([doc]))
    row = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))["files"][0]

    assert row["bytes"] == "146"
    # file.mime_type empty -> fall back to Zeek's own scalar copy.
    assert row["mime_type"] == "application/x-dosexec"


@pytest.mark.asyncio
async def test_file_scans_executables_only_filters_on_executable_mimes():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"executables_only": True})

    mimes = seen["body"]["filter"]["file.mime_type"]
    # Zeek's own executable.sig splits ELF by e_type and never emits
    # "application/x-elf"; ET_DYN (x-sharedlib) is every PIE binary, i.e. the
    # default build on current distros, so missing it misses Linux drops.
    assert "application/x-dosexec" in mimes
    assert "application/x-sharedlib" in mimes
    assert "application/x-mach-o-executable" in mimes
    assert "application/x-elf" not in mimes


@pytest.mark.asyncio
async def test_file_scans_mime_type_accepts_a_list():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"mime_type": "image/png, application/zip"})

    assert seen["body"]["filter"]["file.mime_type"] == ["image/png", "application/zip"]


@pytest.mark.asyncio
async def test_file_scans_single_mime_type_is_not_wrapped():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"mime_type": "image/png"})

    assert seen["body"]["filter"]["file.mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_file_scans_pivots_on_a_hash():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"file_hash": "52AD569E4FD4739F640FC3DE54A1C063"})

    # related.hash holds md5/sha1/sha256/ssdeep/tlsh together, so one filter
    # covers every hash type. Zeek writes md5/sha* lowercase, so an uppercase
    # md5 (as VirusTotal shows it) has to be folded to match.
    assert seen["body"]["filter"]["related.hash"] == "52ad569e4fd4739f640fc3de54a1c063"


@pytest.mark.asyncio
async def test_file_scans_searches_both_cases_of_a_non_hex_hash():
    """Zeek stores tlsh uppercase, Strelka stores the same digest lowercase, and
    related.hash matches exactly — one case finds one record family and misses
    the other, so both forms have to go into the filter."""
    tlsh = "AB71D80F63A72A0AE7E387A3FE70936790245605A78E65E578DC11BCBF84050C1F63D9"
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"file_hash": tlsh})

    assert seen["body"]["filter"]["related.hash"] == [tlsh, tlsh.lower()]


@pytest.mark.asyncio
async def test_file_scans_does_not_duplicate_an_already_lowercase_hash():
    ssdeep = "12:3gr2klupkxaedoas1myw+1rvq1jsv1zsn6ql:3gnlu3eymywebgjstzsnd"
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"file_hash": ssdeep})

    assert seen["body"]["filter"]["related.hash"] == ssdeep


@pytest.mark.asyncio
async def test_file_scans_merges_extra_filters():
    seen = {}
    mcp = _tools(_docs_handler([_FILE_DOC], seen))
    await mcp.call_tool("malcolm_file_scans", {"filters": '{"source.ip":"192.0.2.7"}'})

    assert seen["body"]["filter"]["source.ip"] == "192.0.2.7"
    assert seen["body"]["filter"]["event.dataset"] == "files"


@pytest.mark.asyncio
async def test_file_scans_reports_no_matches():
    mcp = _tools(_docs_handler([]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert "no extracted-file records" in out.lower()


@pytest.mark.asyncio
async def test_file_scans_marks_a_record_with_no_file_on_disk():
    """A files record without zeek.files.extracted was never written to disk."""
    doc = json.loads(json.dumps(_FILE_DOC))
    del doc["_source"]["zeek"]["files"]["extracted"]
    mcp = _tools(_docs_handler([doc]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert "not extracted" in out.lower()


@pytest.mark.asyncio
async def test_file_scans_takes_the_disk_name_from_a_scan_record():
    """A Strelka record has no zeek.files.extracted, but it does name the path
    it scanned — without that every scan verdict would read "not extracted"."""
    doc = json.loads(json.dumps(_FILE_DOC))
    del doc["_source"]["zeek"]["files"]["extracted"]
    doc["_source"]["strelka"] = {
        "result": {"file": {"name": "/zeek/extract_files/HTTP-abc-def.exe"}}
    }
    mcp = _tools(_docs_handler([doc]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert '"extracted": "HTTP-abc-def.exe"' in out
    assert "not extracted" not in out.lower()


@pytest.mark.asyncio
async def test_file_scans_surfaces_the_strelka_verdict():
    """A filescan/Strelka record carries scan hits and the rules that fired.

    Verified live: the rule names live under filescan.rules.name, NOT rule.name
    (which is Suricata's, and reads "-" on every strelka document).
    """
    doc = json.loads(json.dumps(_FILE_DOC))
    doc["_source"]["event"]["dataset"] = ["files", "strelka"]
    doc["_source"]["filescan"] = {
        "hits": 2,
        "rules": {"name": ["win_dropper", "packed_upx"], "scanner": ["yara", "clamav"]},
    }
    mcp = _tools(_docs_handler([doc]))
    row = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))["files"][0]

    assert row["scan_hits"] == 2
    assert row["scan_rules"] == ["win_dropper", "packed_upx"]
    assert row["scan_scanners"] == ["yara", "clamav"]


@pytest.mark.asyncio
async def test_file_scans_omits_scan_keys_when_nothing_scanned_the_file():
    mcp = _tools(_docs_handler([_FILE_DOC]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert "scan_hits" not in out
    assert "scan_rules" not in out


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["not json", '["source.ip"]'])
async def test_file_scans_rejects_a_malformed_filter(bad):
    def handler(req):
        raise AssertionError("must not query with an unparseable filter")

    raised = await raised_by(_tools(handler), "malcolm_file_scans", {"filters": bad})

    assert isinstance(raised, ToolInputError)
    assert "filters" in str(raised).lower()


@pytest.mark.asyncio
async def test_file_scans_flags_a_truncated_extraction():
    """extracted_cutoff means the stored file is only the first N bytes."""
    doc = json.loads(json.dumps(_FILE_DOC))
    doc["_source"]["zeek"]["files"]["extracted_cutoff"] = "T"
    mcp = _tools(_docs_handler([doc]))
    out = str(await mcp.call_tool("malcolm_file_scans", {}))

    assert "partial" in out.lower()


# -- malcolm_extract_file -----------------------------------------------


@pytest.mark.asyncio
async def test_extract_file_downloads_and_reports_metadata():
    body = b"MZ\x90\x00payload"
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, content=body)

    mcp = _tools(handler)
    out = str(await mcp.call_tool("malcolm_extract_file", {"filename": "HTTP-abc-def.exe"}))

    assert seen["path"] == "/extracted-files/HTTP-abc-def.exe"
    assert hashlib.sha256(body).hexdigest() in out
    assert str(len(body)) in out
    assert body[:4].hex() in out
    # The bytes themselves are never returned — this may be live malware.
    assert "payload" not in out


@pytest.mark.asyncio
async def test_extract_file_accepts_the_extracted_uri_form():
    seen = {}

    def handler(req):
        seen["path"] = req.url.path
        return httpx.Response(200, content=b"MZ")

    mcp = _tools(handler)
    await mcp.call_tool("malcolm_extract_file", {"filename": "extracted-files/HTTP-abc-def.exe"})

    assert seen["path"] == "/extracted-files/HTTP-abc-def.exe"


@pytest.mark.asyncio
async def test_extract_file_percent_encodes_the_name():
    """httpx does not escape '#'/'?' in a path — an unescaped name would be
    truncated into a fragment or a query string."""
    seen = {}

    def handler(req):
        # raw_path is what goes on the wire; .path is decoded again by httpx.
        seen["raw"] = req.url.raw_path.decode()
        seen["path"] = req.url.path
        return httpx.Response(200, content=b"MZ")

    mcp = _tools(handler)
    out = str(await mcp.call_tool("malcolm_extract_file", {"filename": "SMB-C$Temp#odd.exe"}))

    assert seen["raw"] == "/extracted-files/SMB-C%24Temp%23odd.exe"
    # Unescaped, the '#' would have cut the path short at "SMB-C$Temp".
    assert seen["path"] == "/extracted-files/SMB-C$Temp#odd.exe"
    # The reported URL has to be pasteable too, not just the request we sent.
    assert "/extracted-files/SMB-C%24Temp%23odd.exe" in out


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", ["../nginx/nginx.conf", "sub/dir.bin", "back\\slash.bin", "..", "   "]
)
async def test_extract_file_rejects_a_path(name):
    def handler(req):
        raise AssertionError(f"must not fetch for {name!r}")

    raised = await raised_by(_tools(handler), "malcolm_extract_file", {"filename": name})

    assert isinstance(raised, ToolInputError)


@pytest.mark.asyncio
async def test_extract_file_url_only_skips_the_download():
    called = {"n": 0}

    def handler(req):
        called["n"] += 1
        return httpx.Response(200, content=b"MZ")

    mcp = _tools(handler)
    out = str(await mcp.call_tool("malcolm_extract_file", {"filename": "a.exe", "url_only": True}))

    assert called["n"] == 0
    assert "https://malcolm.example/extracted-files/a.exe" in out


@pytest.mark.asyncio
async def test_extract_file_reports_a_pruned_file():
    def handler(req):
        return httpx.Response(404, text="Not Found")

    mcp = _tools(handler)
    out = str(await mcp.call_tool("malcolm_extract_file", {"filename": "gone.exe"}))

    assert "false" in out.lower()
    assert "404" in out
    assert "prune" in out.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 500, 502])
async def test_extract_file_does_not_call_a_server_error_a_missing_file(status):
    """Only a 404 says the file is gone. Malcolm puts /extracted-files behind
    basic auth and, with role-based access on, ROLE_EXTRACTED_FILES — reporting
    a 401/403/502 as "pruned" would end the hunt on a fixable config problem."""

    def handler(req):
        return httpx.Response(status, text="nope")

    raised = await raised_by(_tools(handler), "malcolm_extract_file", {"filename": "a.exe"})

    assert isinstance(raised, UpstreamError)
    assert raised.status == status
    assert "prune" not in str(raised).lower()


@pytest.mark.asyncio
async def test_extract_file_reports_a_transport_failure():
    def handler(req):
        raise httpx.ConnectError("connection refused")

    raised = await raised_by(_tools(handler), "malcolm_extract_file", {"filename": "a.exe"})

    assert isinstance(raised, UpstreamError)
    assert "connection refused" in str(raised)


@pytest.mark.asyncio
async def test_extract_file_refuses_an_oversized_file(monkeypatch):
    from mcp_server_malcolm.tools import files as files_mod

    monkeypatch.setattr(files_mod, "_MAX_BYTES", 4)

    def handler(req):
        return httpx.Response(200, content=b"0123456789")

    raised = await raised_by(_tools(handler), "malcolm_extract_file", {"filename": "big.bin"})

    # The cap is our refusal, not Malcolm failing, and url_only is the way past it.
    assert isinstance(raised, ToolInputError)
    assert "url_only" in str(raised)
    assert "4" in str(raised)


# -- shapes the live server actually sends -------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        # Profiled across all 47 datasets on v26.07.1: file.size arrives as a
        # list on alert records, file.source as a list, and @timestamp as epoch
        # milliseconds on session records. Each of these made the tool fail
        # outright once the return type was declared, because a row that does
        # not match the declared shape cannot fall back to the string arm.
        ("size", [385], 385),
        ("source", ["http"], "http"),
    ],
)
async def test_file_row_unwraps_list_valued_scalars(field, value, expected):
    doc = json.loads(json.dumps(_FILE_DOC))
    doc["_source"]["file"][field] = value
    mcp = _tools(_docs_handler([doc]))
    row = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))["files"][0]

    key = {"size": "bytes", "source": "transport"}[field]
    assert row[key] == expected


@pytest.mark.asyncio
async def test_file_row_accepts_an_epoch_timestamp():
    """Arkime session records carry @timestamp as epoch milliseconds, not an
    ISO string; the tool must return the row rather than fail validation."""
    doc = json.loads(json.dumps(_FILE_DOC))
    doc["_source"]["@timestamp"] = 1785382587946
    mcp = _tools(_docs_handler([doc]))
    row = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))["files"][0]

    assert row["timestamp"] == 1785382587946


@pytest.mark.asyncio
async def test_file_scans_survives_a_row_of_entirely_list_valued_fields():
    """The dataset-override path is documented — the file_hash description tells
    callers to add {"event.dataset":"strelka"} to filters — so the tool meets
    record types whose fields are all arrays."""
    doc = json.loads(json.dumps(_FILE_DOC))
    src = doc["_source"]
    src["@timestamp"] = 1785382587946
    src["file"]["size"] = [385]
    src["file"]["source"] = ["http"]
    src["file"]["mime_type"] = ["text/plain"]
    src["file"]["name"] = ["a.txt"]
    mcp = _tools(_docs_handler([doc]))
    out = json.loads(tool_text(await mcp.call_tool("malcolm_file_scans", {})))

    assert out["count"] == 1
    row = out["files"][0]
    assert (row["bytes"], row["transport"], row["mime_type"], row["filename"]) == (
        385,
        "http",
        "text/plain",
        "a.txt",
    )
