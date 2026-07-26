"""NetBox asset lookup tools via Malcolm's /mapi/netbox/ proxy."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# The path is spliced into /mapi/netbox/<path>. Restrict it to a NetBox REST
# path shape (app/model segments) so it can't traverse out of the proxy or
# smuggle a scheme/host: lowercase words + slashes only, no dots, no "..".
_NETBOX_PATH_RE = re.compile(r"[a-z0-9][a-z0-9/_-]*/?")


def _netbox_path_error(path: str) -> str | None:
    if not path:
        return "Error: path is required (e.g. 'ipam/services/')."
    if not _NETBOX_PATH_RE.fullmatch(path) or ".." in path:
        return f"Error: invalid NetBox path: {path!r} (expected e.g. 'ipam/services/')."
    return None


def register_netbox_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register NetBox asset and network lookup tools."""

    @mcp.tool()
    async def malcolm_netbox_lookup(
        ip: str = "",
        device: str = "",
        prefix: str = "",
    ) -> str:
        """Look up asset information from NetBox via Malcolm.

        Provides context about what a device/IP is, what role it has,
        and which network segment it belongs to. Critical for determining
        whether observed behavior is normal or anomalous.

        Args:
            ip: IP address to look up (e.g. "192.0.2.77").
            device: Device name to search (e.g. "switch-01").
            prefix: Network prefix to query (e.g. "192.0.2.0/24").

        At least one parameter must be provided.
        """
        if not any([ip, device, prefix]):
            return "Error: provide at least one of: ip, device, prefix."

        results: dict = {}

        if ip:
            try:
                data = await client.netbox_get(
                    "api/ipam/ip-addresses/",
                    params={"address": ip},
                )
                entries = data.get("results", []) if isinstance(data, dict) else []
                results["ip_lookup"] = _summarize_ip_results(entries, ip)
            except Exception as exc:  # noqa: BLE001
                results["ip_error"] = f"NetBox IP lookup failed: {exc}"

        if device:
            try:
                data = await client.netbox_get(
                    "api/dcim/devices/",
                    params={"name": device},
                )
                entries = data.get("results", []) if isinstance(data, dict) else []
                results["device_lookup"] = _summarize_device_results(entries, device)
            except Exception as exc:  # noqa: BLE001
                results["device_error"] = f"NetBox device lookup failed: {exc}"

        if prefix:
            try:
                data = await client.netbox_get(
                    "api/ipam/prefixes/",
                    params={"prefix": prefix},
                )
                entries = data.get("results", []) if isinstance(data, dict) else []
                results["prefix_lookup"] = _summarize_prefix_results(entries, prefix)
            except Exception as exc:  # noqa: BLE001
                results["prefix_error"] = f"NetBox prefix lookup failed: {exc}"

        return json.dumps(results, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def malcolm_netbox_sites() -> str:
        """List NetBox sites (the site directory) via Malcolm.

        Returns each site's id, name, and metadata. Useful for mapping the
        physical/logical locations NetBox knows about before drilling into a
        specific device or prefix.
        """
        try:
            data = await client.netbox_sites()
        except Exception as exc:  # noqa: BLE001
            return f"NetBox sites lookup failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(
        annotations={"readOnlyHint": True, "destructiveHint": False},
    )
    async def malcolm_netbox_query(path: str, params: str = "{}") -> str:
        """Query any NetBox REST endpoint via Malcolm (read-only GET).

        The higher-level malcolm_netbox_lookup covers ip/device/prefix; use this
        for the rest of NetBox that it doesn't surface, e.g.:
          path="ipam/services/"           params={"port": "443"}   port -> service
          path="ipam/vlans/"              params={"vid": "100"}
          path="dcim/interfaces/"         params={"mac_address": "..."}
          path="virtualization/virtual-machines/"  params={"name": "vm-01"}
          path="tenancy/contacts/"        params={"name": "..."}   asset owner

        Args:
            path: NetBox API path (app/model form, e.g. "ipam/services/").
                No leading slash, no "..", no scheme/host.
            params: JSON object of query-string filters, e.g. {"port": "443"}.
        """
        path = path.strip().lstrip("/")
        if err := _netbox_path_error(path):
            return err

        parsed: dict | None = None
        if params and params.strip() not in ("", "{}", "null"):
            try:
                loaded = json.loads(params)
            except json.JSONDecodeError as exc:
                return f"Error: invalid JSON in params: {exc}"
            if not isinstance(loaded, dict):
                return "Error: params must be a JSON object."
            parsed = loaded

        try:
            data = await client.netbox_get(path, params=parsed)
        except Exception as exc:  # noqa: BLE001
            return f"NetBox query failed: {exc}"

        return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _summarize_ip_results(entries: list, ip: str) -> dict:
    """Summarize NetBox IP address results."""
    if not entries:
        return {"ip": ip, "found": False}

    summaries = []
    for entry in entries[:5]:
        summary: dict = {
            "address": entry.get("address", ""),
            "status": _nested_label(entry, "status"),
            "dns_name": entry.get("dns_name", ""),
        }
        assigned = entry.get("assigned_object")
        if isinstance(assigned, dict):
            device = assigned.get("device") or assigned.get("virtual_machine")
            if isinstance(device, dict):
                summary["device"] = device.get("name", "")
                summary["device_url"] = device.get("url", "")
            summary["interface"] = assigned.get("name", "")
        tenant = entry.get("tenant")
        if isinstance(tenant, dict):
            summary["tenant"] = tenant.get("name", "")
        summaries.append(summary)

    return {"ip": ip, "found": True, "results": summaries}


def _summarize_device_results(entries: list, name: str) -> dict:
    """Summarize NetBox device results."""
    if not entries:
        return {"device": name, "found": False}

    summaries = []
    for entry in entries[:5]:
        summary: dict = {
            "name": entry.get("name", ""),
            "status": _nested_label(entry, "status"),
            "role": _nested_label(entry, "role") or _nested_label(entry, "device_role"),
            "device_type": _nested_label(entry, "device_type"),
            "site": _nested_label(entry, "site"),
            "primary_ip4": _nested_val(entry, "primary_ip4", "address"),
            "primary_ip6": _nested_val(entry, "primary_ip6", "address"),
        }
        tenant = entry.get("tenant")
        if isinstance(tenant, dict):
            summary["tenant"] = tenant.get("name", "")
        summaries.append(summary)

    return {"device": name, "found": True, "results": summaries}


def _summarize_prefix_results(entries: list, prefix: str) -> dict:
    """Summarize NetBox prefix results."""
    if not entries:
        return {"prefix": prefix, "found": False}

    summaries = []
    for entry in entries[:10]:
        summary: dict = {
            "prefix": entry.get("prefix", ""),
            "status": _nested_label(entry, "status"),
            "vlan": _nested_val(entry, "vlan", "display"),
            "site": _nested_label(entry, "site"),
            "role": _nested_label(entry, "role"),
            "description": entry.get("description", ""),
        }
        tenant = entry.get("tenant")
        if isinstance(tenant, dict):
            summary["tenant"] = tenant.get("name", "")
        summaries.append(summary)

    return {"prefix": prefix, "found": True, "results": summaries}


def _nested_label(obj: dict, key: str) -> str:
    """Extract .display or .label from a nested NetBox object."""
    val = obj.get(key)
    if val is None:
        return ""
    if isinstance(val, dict):
        return val.get("display", val.get("label", val.get("name", "")))
    return str(val)


def _nested_val(obj: dict, key: str, subkey: str) -> str:
    """Extract a subkey from a nested NetBox object."""
    val = obj.get(key)
    if isinstance(val, dict):
        return val.get(subkey, "")
    return ""
