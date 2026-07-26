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
from typing import TYPE_CHECKING

from mcp_server_malcolm.tools.write._common import run_write

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

_CLASS = "arkime-view"
_SHORTCUT_TYPES = ("string", "number", "ip")


def register_arkime_view_tools(mcp: FastMCP, client: MalcolmClient, audit_file: str | None) -> None:
    """Register saved-view + shortcut create tools (called only when enabled)."""

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def arkime_create_view(name: str, expression: str) -> str:
        """Save an Arkime search view (a named, reusable expression) — additive.

        Persists a hunt query so the human team can rerun it from the Arkime UI.
        Creates a new view; changes nothing existing.

        Args:
            name: View name (Arkime keeps only [-a-zA-Z0-9_]).
            expression: The Arkime search expression to save.
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

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": False})
    async def arkime_create_shortcut(
        name: str,
        value: str,
        shortcut_type: str = "string",
        description: str = "",
    ) -> str:
        """Create an Arkime shortcut (a named value list / IOC set) — additive.

        Stores a reusable list of values (IPs, hostnames, hashes) that can be
        referenced in any Arkime expression as $<name>, e.g. ip == $c2_ips.
        Creates a new shortcut; changes nothing existing.

        Args:
            name: Shortcut name (Arkime keeps only [-a-zA-Z0-9_]); referenced as
                $name in expressions.
            value: The values, comma- or newline-separated.
            shortcut_type: One of "string", "number", "ip" (default "string").
            description: Optional free-text description.
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
