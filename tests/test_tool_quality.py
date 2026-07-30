"""Guards for the tool-definition quality that Glama's TDQS scores.

Every registered tool must carry: a title, read/destructive annotations, a
description on every parameter, and no annotation/description contradiction.
These lock in the A-grade shape so a new tool can't silently regress it.
"""

import asyncio

import pytest

from mcp_server_malcolm.server import create_server

_ALL_WRITE_FLAGS = (
    "MALCOLM_MCP_ENABLE_ALERTING",
    "MALCOLM_MCP_ENABLE_ARKIME_TAGS",
    "MALCOLM_MCP_ENABLE_HUNT_JOBS",
    "MALCOLM_MCP_ENABLE_PCAP_UPLOAD",
    "MALCOLM_MCP_ENABLE_ARKIME_VIEWS",
)
# Words that, in a readOnlyHint=True tool's description, would contradict the
# annotation and force Glama's Behavioral-Transparency score to 1.
_WRITE_WORDS = ("delete", "destroy", "overwrite")


def _all_tools(monkeypatch):
    for f in _ALL_WRITE_FLAGS:
        monkeypatch.setenv(f, "true")
    monkeypatch.setenv("MALCOLM_MCP_UPLOAD_DIR", "/tmp")
    mcp = create_server()
    return asyncio.run(mcp.list_tools())


def test_every_tool_has_a_title(monkeypatch):
    missing = [
        t.name
        for t in _all_tools(monkeypatch)
        if not (t.title or (t.annotations and getattr(t.annotations, "title", None)))
    ]
    assert not missing, f"tools missing a title: {missing}"


def test_every_tool_declares_read_only_hint(monkeypatch):
    missing = [
        t.name
        for t in _all_tools(monkeypatch)
        if not t.annotations or getattr(t.annotations, "readOnlyHint", None) is None
    ]
    assert not missing, f"tools missing readOnlyHint: {missing}"


def test_every_parameter_has_a_description(monkeypatch):
    offenders = []
    for t in _all_tools(monkeypatch):
        props = (t.inputSchema or {}).get("properties", {})
        for pname, spec in props.items():
            if not spec.get("description"):
                offenders.append(f"{t.name}.{pname}")
    assert not offenders, f"parameters missing a description: {offenders}"


def test_read_only_tools_do_not_describe_writes(monkeypatch):
    """A readOnlyHint=True description must not claim to delete/destroy/overwrite."""
    offenders = []
    for t in _all_tools(monkeypatch):
        ann = t.annotations
        if ann and getattr(ann, "readOnlyHint", None) is True:
            desc = (t.description or "").lower()
            hits = [w for w in _WRITE_WORDS if w in desc]
            if hits:
                offenders.append((t.name, hits))
    assert not offenders, f"read-only tools with write words in description: {offenders}"


@pytest.mark.parametrize(
    "name",
    [
        "malcolm_search",
        "arkime_sessions",
        "arkime_create_hunt",
        "malcolm_file_scans",
        "malcolm_extract_file",
    ],
)
def test_representative_tools_name_an_alternative(monkeypatch, name):
    """TDQS Usage Guidelines: a tool's description should point to a sibling.

    Spot-check a few load-bearing tools rather than all — a blanket rule would
    be brittle, but these three must always guide the model to alternatives.
    """
    tools = {t.name: t for t in _all_tools(monkeypatch)}
    desc = tools[name].description or ""
    # each of these names at least one other tool in its guidance
    assert any(other in desc for other in ("malcolm_", "arkime_", "search_dsl", "count")), (
        f"{name} description names no alternative tool"
    )
