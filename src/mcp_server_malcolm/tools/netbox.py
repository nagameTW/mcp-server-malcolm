"""NetBox asset lookup tools via Malcolm's /mapi/netbox/ proxy."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


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
            except Exception as exc:
                results["ip_error"] = f"NetBox IP lookup failed: {exc}"

        if device:
            try:
                data = await client.netbox_get(
                    "api/dcim/devices/",
                    params={"name": device},
                )
                entries = data.get("results", []) if isinstance(data, dict) else []
                results["device_lookup"] = _summarize_device_results(entries, device)
            except Exception as exc:
                results["device_error"] = f"NetBox device lookup failed: {exc}"

        if prefix:
            try:
                data = await client.netbox_get(
                    "api/ipam/prefixes/",
                    params={"prefix": prefix},
                )
                entries = data.get("results", []) if isinstance(data, dict) else []
                results["prefix_lookup"] = _summarize_prefix_results(entries, prefix)
            except Exception as exc:
                results["prefix_error"] = f"NetBox prefix lookup failed: {exc}"

        return json.dumps(results, indent=2, ensure_ascii=False, default=str)


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
