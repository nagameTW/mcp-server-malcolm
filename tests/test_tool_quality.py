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
        if not t.annotations or getattr(t.annotations, "read_only_hint", None) is None
    ]
    assert not missing, f"tools missing readOnlyHint: {missing}"


def test_every_parameter_has_a_description(monkeypatch):
    offenders = []
    for t in _all_tools(monkeypatch):
        props = (t.input_schema or {}).get("properties", {})
        for pname, spec in props.items():
            if not spec.get("description"):
                offenders.append(f"{t.name}.{pname}")
    assert not offenders, f"parameters missing a description: {offenders}"


def test_read_only_tools_do_not_describe_writes(monkeypatch):
    """A readOnlyHint=True description must not claim to delete/destroy/overwrite."""
    offenders = []
    for t in _all_tools(monkeypatch):
        ann = t.annotations
        if ann and getattr(ann, "read_only_hint", None) is True:
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


# The tools that build their own payload rather than passing an upstream
# response through. Those are the only ones with a shape this repo can declare,
# so those are the ones that carry a real output schema.
_TYPED_OUTPUT = {
    "malcolm_file_scans",
    "malcolm_extract_file",
    "arkime_views",
    "arkime_shortcuts",
    "arkime_reverse_dns",
    "arkime_pcap_files",
    "arkime_node_stats",
    "malcolm_saved_objects",
    "malcolm_saved_object_detail",
    "malcolm_alerting_monitors",
    "malcolm_alerting_alerts",
    "malcolm_alerting_monitor_detail",
    "malcolm_anomaly_detectors",
    "malcolm_anomaly_results",
}


def test_row_building_tools_declare_a_real_output_schema(monkeypatch):
    """A `-> str` tool auto-generates {"result": {"type": "string"}}, which is a
    schema in name only. A tool that constructs its own rows has a shape it can
    declare, and losing that annotation would silently fall back to the useless
    one."""
    tools = {t.name: t for t in _all_tools(monkeypatch)}
    weak = [
        name for name in sorted(_TYPED_OUTPUT) if not (tools[name].output_schema or {}).get("$defs")
    ]
    assert not weak, f"these lost their typed return: {weak}"


def test_typed_tools_can_still_return_a_sentence(monkeypatch):
    """The prose path is load-bearing — an empty list reads to an agent as "no
    such traffic" while a sentence explains which. The union return keeps it, so
    the schema must admit a bare string alongside the object."""
    tools = {t.name: t for t in _all_tools(monkeypatch)}
    for name in sorted(_TYPED_OUTPUT):
        schema = tools[name].output_schema["properties"]["result"]
        options = schema.get("anyOf") or [schema]
        assert any(o.get("type") == "string" for o in options), (
            f"{name} can no longer return an explanatory sentence"
        )
