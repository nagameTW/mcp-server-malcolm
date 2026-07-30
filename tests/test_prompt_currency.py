"""Guards that the hunt_workflow prompt keeps up with the tool set.

The prompt is the cold-start guide: it is how an agent learns which tools to
chain before it has tried anything. It drifted once — batches of new tools
shipped and the prompt still described the old surface — so the two properties
that matter are asserted here rather than left to notice.
"""

import asyncio
import re

from mcp_server_malcolm.prompts import _HUNT_WORKFLOW
from mcp_server_malcolm.server import create_server

_ALL_WRITE_FLAGS = (
    "MALCOLM_MCP_ENABLE_ALERTING",
    "MALCOLM_MCP_ENABLE_ARKIME_TAGS",
    "MALCOLM_MCP_ENABLE_HUNT_JOBS",
    "MALCOLM_MCP_ENABLE_PCAP_UPLOAD",
    "MALCOLM_MCP_ENABLE_ARKIME_VIEWS",
)

# Tools the workflow is incomplete without: each one answers a question that
# changes what the hunter does next, so an agent that never learns it will
# reach a wrong conclusion rather than merely a slower one. Utility and health
# tools are deliberately absent — the prompt is a worked workflow, not an index.
_LOAD_BEARING = {
    # schema discovery, both vocabularies
    "malcolm_field_search",
    "malcolm_field_values",
    "arkime_field_search",
    # can the data be trusted at all
    "malcolm_data_coverage",
    "arkime_node_stats",
    # what already exists before building your own
    "arkime_views",
    "arkime_shortcuts",
    "malcolm_saved_objects",
    # the standing detections, and both alert mechanisms
    "malcolm_alerts",
    "malcolm_alerting_monitors",
    "malcolm_anomaly_detectors",
    # finding and drilling into sessions
    "malcolm_search",
    "search_dsl",
    "arkime_sessions",
    "arkime_session_detail",
    "arkime_session_pcap",
    # files
    "malcolm_file_scans",
    "malcolm_extract_file",
    "arkime_file_by_hash",
    # pivots and naming
    "malcolm_aggregate",
    "malcolm_related_sessions",
    "arkime_connections",
    "malcolm_netbox_lookup",
    "arkime_reverse_dns",
}


def _all_tools_with_writes(monkeypatch):
    """Every tool object, write classes included — the prompt teaches those too."""
    for flag in _ALL_WRITE_FLAGS:
        monkeypatch.setenv(flag, "true")
    monkeypatch.setenv("MALCOLM_MCP_UPLOAD_DIR", "/tmp")
    return asyncio.run(create_server().list_tools())


def _all_tool_names(monkeypatch) -> set[str]:
    for flag in _ALL_WRITE_FLAGS:
        monkeypatch.setenv(flag, "true")
    monkeypatch.setenv("MALCOLM_MCP_UPLOAD_DIR", "/tmp")
    return {t.name for t in asyncio.run(create_server().list_tools())}


def test_prompt_names_no_tool_that_does_not_exist(monkeypatch):
    """A stale name sends an agent to call something that is not there."""
    tools = _all_tool_names(monkeypatch)
    named = set(re.findall(r"\b(?:malcolm_|arkime_)[a-z_]+\b", _HUNT_WORKFLOW))
    assert not (named - tools), f"prompt names nonexistent tools: {sorted(named - tools)}"


def test_prompt_covers_every_load_bearing_tool(monkeypatch):
    """A new tool that changes the hunt has to be taught, not just registered."""
    tools = _all_tool_names(monkeypatch)
    assert _LOAD_BEARING <= tools, (
        f"this list names tools that no longer exist: {sorted(_LOAD_BEARING - tools)}"
    )
    missing = sorted(name for name in _LOAD_BEARING if name not in _HUNT_WORKFLOW)
    assert not missing, f"hunt_workflow does not mention: {missing}"


def test_prompt_steps_are_numbered_in_order():
    """The prompt is a numbered loop; a duplicated or skipped step reads as a
    branch that does not exist."""
    steps = [int(n) for n in re.findall(r"^(\d+)\. ", _HUNT_WORKFLOW, re.MULTILINE)]
    assert steps == list(range(1, len(steps) + 1)), f"steps out of order: {steps}"


def test_prompt_only_uses_real_parameter_names(monkeypatch):
    """Every keyword the prompt demonstrates must exist on that tool.

    A wrong argument name is worse than an omitted tool: the SDK drops an
    unknown key silently, so the call appears to succeed while doing something
    else. The prompt taught `arkime_create_shortcut(type="ip")` once, which
    created a string list instead of an IP list with no error signal.
    """
    tools = {t.name: t for t in _all_tools_with_writes(monkeypatch)}
    bad = []
    # each "tool_name(arg=..., arg=...)" the prompt demonstrates
    for call in re.finditer(r"\b((?:malcolm|arkime|search)_[a-z_]+)\(([^)]*)\)", _HUNT_WORKFLOW):
        name, arglist = call.group(1), call.group(2)
        if name not in tools:
            continue
        allowed = set(tools[name].input_schema.get("properties", {}))
        # Strip quoted literals first: an Arkime expression argument contains
        # its own "field==value" pairs, which are not keyword arguments.
        outside_strings = re.sub(r"\"[^\"]*\"|'[^']*'", "", arglist)
        for kw in re.findall(r"(\w+)\s*=", outside_strings):
            if kw not in allowed:
                bad.append(f"{name}({kw}=...) — real parameters: {sorted(allowed)}")
    assert not bad, "prompt demonstrates parameters that do not exist:\n  " + "\n  ".join(bad)
