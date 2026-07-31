"""Every tool name the server *says* out loud must be a tool the server has.

Two texts reach a client before it has called anything: the instructions block,
which is injected into every session, and the prompts. Both name tools by hand,
and both have drifted — the instructions taught arkime_session_payload for
weeks before any such tool existed, which sends an agent to call something that
is not there and makes the server look broken.

test_prompt_currency.py already guards the hunt_workflow prompt's own text
against that. This file is the general form: the instructions too, every
registered prompt rather than one imported constant, and the tool names built
from what the server actually registered rather than a hand-kept list.
"""

import asyncio
import re

from mcp_server_malcolm.server import create_server

_ALL_WRITE_FLAGS = (
    "MALCOLM_MCP_ENABLE_ALERTING",
    "MALCOLM_MCP_ENABLE_ARKIME_TAGS",
    "MALCOLM_MCP_ENABLE_HUNT_JOBS",
    "MALCOLM_MCP_ENABLE_PCAP_UPLOAD",
    "MALCOLM_MCP_ENABLE_ARKIME_VIEWS",
)


def _server_with_writes(monkeypatch):
    """Write classes ON: the texts teach gated tools too, and an unregistered
    write tool would otherwise read as a stale name."""
    for flag in _ALL_WRITE_FLAGS:
        monkeypatch.setenv(flag, "true")
    monkeypatch.setenv("MALCOLM_MCP_UPLOAD_DIR", "/tmp")
    return create_server()


def _tool_names(mcp) -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def _mentioned_tools(text: str, tool_names: set[str]) -> set[str]:
    """Tool-looking names in `text`, keyed off the namespaces really in use.

    The prefixes come from the registered tools (malcolm_, arkime_, search_,
    ...), so a module registering a new namespace starts being checked without
    editing this file. Two shapes are deliberately out of reach: a bare name
    with no underscore (`count`) is indistinguishable from the English word,
    and `arkime_*` / `arkime_sessions3-*` do not match because the trailing
    \\b needs a word boundary the glob and the digit do not give.
    """
    prefixes = sorted({name.split("_")[0] for name in tool_names if "_" in name})
    pattern = re.compile(r"\b(?:" + "|".join(prefixes) + r")_[a-z_]+\b")
    return set(pattern.findall(text))


def test_instructions_name_only_registered_tools(monkeypatch):
    """The instructions block is injected into EVERY session, so a stale name
    there misleads every client of this server at once."""
    mcp = _server_with_writes(monkeypatch)
    tools = _tool_names(mcp)
    named = _mentioned_tools(mcp.instructions or "", tools)
    assert named, "extracted no tool names from the instructions — the regex has rotted"
    assert not (named - tools), f"instructions name nonexistent tools: {sorted(named - tools)}"


def test_every_prompt_names_only_registered_tools(monkeypatch):
    """Same rule for prompt text, enumerated from the server rather than
    imported, so a prompt added later is covered the day it is registered."""
    mcp = _server_with_writes(monkeypatch)
    tools = _tool_names(mcp)
    prompts = asyncio.run(mcp.list_prompts())
    assert prompts, "no prompts registered — this test would pass vacuously"

    bad: dict[str, list[str]] = {}
    for prompt in prompts:
        rendered = asyncio.run(mcp.get_prompt(prompt.name))
        text = "\n".join(
            [prompt.description or ""] + [getattr(m.content, "text", "") for m in rendered.messages]
        )
        missing = _mentioned_tools(text, tools) - tools
        if missing:
            bad[prompt.name] = sorted(missing)
    assert not bad, f"prompts name nonexistent tools: {bad}"


def test_the_check_would_catch_a_stale_name(monkeypatch):
    """The guard above is worth nothing if the extractor misses names.

    Pinning it on a fabricated name proves the two tests fail rather than pass
    quietly when the texts drift, without needing to edit real text to find
    out.
    """
    tools = _tool_names(_server_with_writes(monkeypatch))
    text = "then call malcolm_summarise_everything(x=1) to finish."
    assert _mentioned_tools(text, tools) - tools == {"malcolm_summarise_everything"}
