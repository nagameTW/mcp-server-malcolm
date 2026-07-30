"""Write class: arkime-view — save searches and IOC value-lists (Arkime v6.x).

Two additive, non-destructive writes that let an agent persist hunting knowledge
for the human team:
- arkime_create_view: POST /arkime/api/view — a named saved search (expression).
- arkime_create_shortcut: POST /arkime/api/shortcut — a named value list (IOC
  set) referenced in expressions as $<name>.

Both are guarded by checkCookieToken, so the client primes the ARKIME-COOKIE
first (see MalcolmClient._arkime_token_post). Neither deletes or overwrites.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.tools.write._common import run_write

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "arkime-view"
_SHORTCUT_TYPES = ("string", "number", "ip")

# Shared: additive write to the external Arkime server, never idempotent
# (each call creates a new view/shortcut).
_WRITE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}


def register_arkime_view_tools(
    mcp: MCPServer, client: MalcolmClient, audit_file: str | None
) -> None:
    """Register saved-view + shortcut create tools (called only when enabled)."""

    @mcp.tool(title="Save Arkime view", annotations=_WRITE)
    async def arkime_create_view(
        name: Annotated[
            str, Field(description="View name; Arkime keeps only [-a-zA-Z0-9_] server-side.")
        ],
        expression: Annotated[
            str, Field(description="The Arkime search expression to save under this view.")
        ],
    ) -> str:
        """Save an Arkime search view — a named, reusable expression (POST /arkime/api/view).

        Use this to persist a hunt query so the human team can rerun it from the
        Arkime UI. To save a reusable value list (IOC set) instead, use
        arkime_create_shortcut; to actually run a payload search now, use
        arkime_create_hunt. Additive — creates a new view and changes nothing
        existing (calling twice with the same name creates a second view). The
        action is audited, and the tool is registered only when the arkime-view
        write class is enabled. Returns the raw Arkime response.
        """
        if not name.strip():
            return "Error: name is required."
        if not expression.strip():
            return "Error: expression is required."

        view = {"name": name.strip(), "expression": expression.strip()}
        target = f"name={name.strip()}"
        params_summary = {"expression": expression.strip()}
        result, err = await run_write(
            "arkime_create_view",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_arkime_view(view),
        )
        if err:
            return f"View creation failed: {err}"
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Create Arkime shortcut", annotations=_WRITE)
    async def arkime_create_shortcut(
        name: Annotated[
            str,
            Field(
                description="Shortcut name; Arkime keeps only [-a-zA-Z0-9_] server-side. "
                "Referenced in expressions as $name."
            ),
        ],
        value: Annotated[
            str, Field(description="The values making up the list, comma- or newline-separated.")
        ],
        shortcut_type: Annotated[
            str,
            Field(description='Value type; one of "string", "number", "ip".'),
        ] = "string",
        description: Annotated[
            str, Field(description="Optional free-text description of the shortcut.")
        ] = "",
    ) -> str:
        """Create an Arkime shortcut — a named value list / IOC set (POST /arkime/api/shortcut).

        Use this to store a reusable list of values (IPs, hostnames, hashes)
        that any Arkime expression can reference as $<name>, e.g. ip == $c2_ips.
        To save a whole search expression instead, use arkime_create_view.
        Additive — creates a new shortcut and changes nothing existing (calling
        twice with the same name creates a second shortcut). The action is
        audited, and the tool is registered only when the arkime-view write
        class is enabled. Returns the raw Arkime response.
        """
        if not name.strip():
            return "Error: name is required."
        if not value.strip():
            return "Error: value is required."
        if shortcut_type not in _SHORTCUT_TYPES:
            return f"Error: shortcut_type must be one of {', '.join(_SHORTCUT_TYPES)}."

        shortcut = {"name": name.strip(), "type": shortcut_type, "value": value.strip()}
        if description.strip():
            shortcut["description"] = description.strip()
        target = f"name={name.strip()}"
        params_summary = {"type": shortcut_type}
        result, err = await run_write(
            "arkime_create_shortcut",
            _CLASS,
            target,
            params_summary,
            audit_file,
            lambda: client._write_arkime_shortcut(shortcut),
        )
        if err:
            return f"Shortcut creation failed: {err}"
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)
