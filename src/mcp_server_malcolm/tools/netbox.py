"""NetBox asset lookup tools via Malcolm's /mapi/netbox/ proxy."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError, UpstreamError
from mcp_server_malcolm.tools._parse import parse_json_object

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Shared: every NetBox tool here is a read-only GET through Malcolm's proxy.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}

# The path is spliced into /mapi/netbox/<path>. Restrict it to a NetBox REST
# path shape (app/model segments) so it can't traverse out of the proxy or
# smuggle a scheme/host: lowercase words + slashes only, no dots, no "..".
_NETBOX_PATH_RE = re.compile(r"[a-z0-9][a-z0-9/_-]*/?")


def _check_netbox_path(path: str) -> None:
    """Reject a path that could traverse out of Malcolm's NetBox proxy."""
    if not path:
        raise ToolInputError("path is required, in app/model form, e.g. 'ipam/services/'.")
    if not _NETBOX_PATH_RE.fullmatch(path) or ".." in path:
        raise ToolInputError(
            f"invalid NetBox path: {path!r} — expected lowercase app/model segments "
            f"such as 'ipam/services/', with no scheme, host or '..'."
        )


def register_netbox_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register NetBox asset and network lookup tools."""

    @mcp.tool(title="Look up NetBox asset", annotations=_READ)
    async def malcolm_netbox_lookup(
        ip: Annotated[
            str,
            Field(
                description='IP address to resolve to its NetBox asset, e.g. "192.0.2.77". '
                "Empty = skip the IP lookup."
            ),
        ] = "",
        device: Annotated[
            str,
            Field(
                description='Device name to search for, e.g. "switch-01". '
                "Empty = skip the device lookup."
            ),
        ] = "",
        prefix: Annotated[
            str,
            Field(
                description='Network prefix to query, e.g. "192.0.2.0/24". '
                "Empty = skip the prefix lookup."
            ),
        ] = "",
    ) -> str:
        """Resolve an IP, device name, or prefix to its NetBox asset (role, site, tenant).

        Use this to tell whether observed traffic involves a known asset and where it
        sits — the fast path for the three common NetBox lookups. For any other NetBox
        endpoint (services, VLANs, interfaces, VMs, contacts) use `malcolm_netbox_query`;
        to list sites use `malcolm_netbox_sites`. Pass at least one of ip/device/prefix.
        Returns a JSON object with a summarized section per lookup you supplied; a
        lookup that fails carries its own error key while the others still answer,
        and every one failing is reported as an error rather than as a result.
        """
        if not any([ip, device, prefix]):
            raise ToolInputError(
                'provide at least one of: ip (e.g. "192.0.2.77"), device '
                '(e.g. "switch-01"), prefix (e.g. "192.0.2.0/24").'
            )

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

        errors = [v for k, v in results.items() if k.endswith("_error")]
        if errors and len(errors) == len(results):
            # No lookup answered, so an all-errors document would reach the
            # caller as a successful call with nothing in it.
            raise UpstreamError("; ".join(errors))
        return json.dumps(results, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="List NetBox sites", annotations=_READ)
    async def malcolm_netbox_sites() -> str:
        """List every NetBox site in the site directory via Malcolm.

        Use this to map the physical/logical locations NetBox knows about before
        drilling into a specific asset. To then resolve a device, IP, or prefix use
        `malcolm_netbox_lookup`; for any other NetBox endpoint use `malcolm_netbox_query`.
        Returns the raw NetBox sites response (each site's id, name, and metadata).
        """
        data = await client.netbox_sites()
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Query NetBox endpoint", annotations=_READ)
    async def malcolm_netbox_query(
        path: Annotated[
            str,
            Field(
                description='NetBox API path in app/model form, no leading slash, no "..", '
                'no scheme/host. Examples: "ipam/services/" (port -> service), "ipam/vlans/", '
                '"dcim/interfaces/", "virtualization/virtual-machines/", "tenancy/contacts/" '
                "(asset owner)."
            ),
        ],
        params: Annotated[
            str,
            Field(
                description="JSON object of query-string filters for the endpoint, e.g. "
                '{"port": "443"}, {"vid": "100"}, {"name": "vm-01"}. Empty object = no filters.'
            ),
        ] = "{}",
    ) -> str:
        """Query any NetBox REST endpoint via Malcolm's read-only GET proxy.

        Use this as the general escape hatch for NetBox endpoints the shortcuts don't
        cover (services, VLANs, interfaces, VMs, contacts, ...). For the common
        ip/device/prefix lookups prefer `malcolm_netbox_lookup`; to list sites use
        `malcolm_netbox_sites`. The path is validated to a NetBox app/model shape before
        proxying. Returns the raw NetBox JSON response for the endpoint.
        """
        path = path.strip().lstrip("/")
        _check_netbox_path(path)
        parsed = parse_json_object(params, "params", '{"port": "443"}')

        data = await client.netbox_get(path, params=parsed)
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
