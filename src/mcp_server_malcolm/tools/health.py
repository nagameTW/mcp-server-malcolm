"""System health and data coverage tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient


def register_health_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register health check and data coverage tools."""

    @mcp.tool()
    async def malcolm_service_status() -> str:
        """Check Malcolm service health and version info.

        Returns readiness of all services (OpenSearch, Arkime, NetBox,
        Logstash, etc.) plus Malcolm version and OpenSearch cluster health.
        Call this before a hunt to ensure all services are available.
        """
        errors: list[str] = []
        ready_data: dict = {}
        version_data: dict = {}

        try:
            ready_data = await client.ready()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ready check failed: {exc}")

        try:
            version_data = await client.version()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"version check failed: {exc}")

        result = {}

        if version_data:
            result["malcolm_version"] = version_data.get("version", "unknown")
            result["mode"] = version_data.get("mode", "unknown")
            os_info = version_data.get("opensearch", {})
            if isinstance(os_info, dict):
                health = os_info.get("health", {})
                result["opensearch_health"] = (
                    health.get("status", "unknown") if health else "unknown"
                )

        if ready_data:
            result["services"] = ready_data
            ready_count = sum(1 for v in ready_data.values() if v is True)
            total = len(ready_data)
            result["summary"] = f"{ready_count}/{total} services ready"

        if errors:
            result["errors"] = errors

        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool()
    async def malcolm_data_coverage(
        time_from: str = "",
        time_to: str = "",
    ) -> str:
        """Show data freshness, sensor status, and dataset distribution.

        Reports:
        - Which sensors are feeding data and their latest timestamps
        - How old the most recent data is
        - Document counts per event.dataset (conn, dns, ssl, alert, etc.)
        - Index sizes

        Call before a hunt to understand what data is available.

        Args:
            time_from: Start time for dataset counts (dateparser format).
            time_to: End time for dataset counts.
        """
        result: dict = {}

        try:
            stats = await client.ingest_stats()
            result["sensors"] = stats.get("sources", {})
            result["latest_age_seconds"] = stats.get("latest_ingest_age_seconds")
        except Exception as exc:  # noqa: BLE001
            result["ingest_error"] = str(exc)

        try:
            buckets = await client.field_values(
                field="event.dataset",
                limit=50,
                time_from=time_from,
                time_to=time_to,
            )
            result["datasets"] = {b["key"]: b["doc_count"] for b in buckets if "key" in b}
            result["total_documents"] = sum(b.get("doc_count", 0) for b in buckets)
        except Exception as exc:  # noqa: BLE001
            result["dataset_error"] = str(exc)

        try:
            idx_data = await client.indices()
            indices = idx_data.get("indices", [])
            if indices:
                result["index_count"] = len(indices)
                result["index_pattern"] = idx_data.get("malcolm_network_index_pattern", "unknown")
        except Exception as exc:  # noqa: BLE001
            result["index_error"] = str(exc)

        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    async def malcolm_ping() -> str:
        """Quick liveness check of the Malcolm API (GET /mapi/ping)."""
        try:
            data = await client.ping()
        except Exception as exc:  # noqa: BLE001
            return f"ping failed: {exc}"
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(annotations={"readOnlyHint": True, "destructiveHint": False})
    async def malcolm_dashboard_export(dashboard_id: str) -> str:
        """Export an OpenSearch Dashboards saved object as JSON.

        Args:
            dashboard_id: The dashboard's saved-object id.
        """
        did = dashboard_id.strip()
        if not did:
            return "Error: dashboard_id is required."
        try:
            data = await client.dashboard_export(did)
        except Exception as exc:  # noqa: BLE001
            return f"dashboard export failed: {exc}"
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
