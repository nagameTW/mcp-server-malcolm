"""System health and data coverage tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from pydantic import Field

from mcp_server_malcolm.errors import ToolInputError, UpstreamError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# Shared: every health tool here reads Malcolm/OpenSearch status, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_health_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register health check and data coverage tools."""

    @mcp.tool(title="Malcolm service status", annotations=_READ)
    async def malcolm_service_status() -> str:
        """Report readiness of each Malcolm service plus Malcolm version and OpenSearch health.

        Call this before a hunt to confirm the whole stack is up. For a bare
        is-the-API-alive check use `malcolm_ping`; for the OpenSearch cluster's
        green/yellow/red detail alone use `cluster_health`; for data freshness and
        per-dataset counts use `malcolm_data_coverage`. Returns a JSON summary with
        malcolm_version, mode, opensearch_health, a per-service readiness map, and an
        "N/total services ready" line. One probe failing adds an `errors` entry and
        keeps the rest; both failing is reported as an error, since there is then no
        status at all to report.
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

        if len(errors) == 2:
            # Both probes failed, so there is no status to report -- returning
            # only an "errors" list would reach the caller as a successful call.
            # Keyed off the failures, not off empty data: a probe that answers
            # {} succeeded, and calling that a failure would invert the rule
            # this module follows everywhere else.
            raise UpstreamError("; ".join(errors))
        if errors:
            result["errors"] = errors
        if not result:
            return "Malcolm answered both probes but reported no version or service data."

        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Data coverage and freshness", annotations=_READ)
    async def malcolm_data_coverage(
        time_from: Annotated[
            str,
            Field(
                description="Start time for the per-dataset counts, dateparser format. "
                "Empty = Malcolm's recent window."
            ),
        ] = "",
        time_to: Annotated[
            str,
            Field(
                description="End time for the per-dataset counts, dateparser format. Empty = now."
            ),
        ] = "",
    ) -> str:
        """Summarize what data exists: feeding sensors, freshness, and per-dataset volume.

        Use this before a hunt to see which sensors are live, how stale the newest data
        is (latest_age_seconds), document counts per event.dataset (conn, dns, ssl,
        alert, ...), and index count. For overall service/stack health rather than data
        volume, use `malcolm_service_status`. For distinct values of one arbitrary field
        rather than the dataset breakdown, use `malcolm_field_values`. Returns a JSON
        summary; each sub-section reports its own error key on failure instead of
        aborting, unless every one of them fails, which raises.
        """
        result: dict = {}
        errors: list[str] = []

        try:
            stats = await client.ingest_stats()
            result["sensors"] = stats.get("sources", {})
            result["latest_age_seconds"] = stats.get("latest_ingest_age_seconds")
        except Exception as exc:  # noqa: BLE001
            result["ingest_error"] = str(exc)
            errors.append(f"ingest stats: {exc}")

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
            errors.append(f"dataset counts: {exc}")

        try:
            idx_data = await client.indices()
            indices = idx_data.get("indices", [])
            if indices:
                result["index_count"] = len(indices)
                result["index_pattern"] = idx_data.get("malcolm_network_index_pattern", "unknown")
        except Exception as exc:  # noqa: BLE001
            result["index_error"] = str(exc)
            errors.append(f"index list: {exc}")

        if len(errors) == 3:
            # Nothing came back at all; an all-errors document would still read
            # as a successful call to a client.
            raise UpstreamError("; ".join(errors))
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Ping Malcolm API", annotations=_READ)
    async def malcolm_ping() -> str:
        """Quick liveness check that the Malcolm API answers (GET /mapi/ping).

        Use this as the cheapest reachability probe. For readiness of the individual
        services behind the API use `malcolm_service_status`; for the OpenSearch cluster
        status specifically use `cluster_health`. Returns the raw /mapi/ping response;
        an unreachable API is reported as an error, not as an answer.
        """
        data = await client.ping()
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="Export OpenSearch dashboard", annotations=_READ)
    async def malcolm_dashboard_export(
        dashboard_id: Annotated[
            str,
            Field(
                description="The OpenSearch Dashboards saved-object id of the dashboard "
                "to export. Required (non-empty)."
            ),
        ],
    ) -> str:
        """Export one OpenSearch Dashboards saved object (a dashboard) as its JSON definition.

        Use this to retrieve a dashboard's full saved-object definition by id. This is
        unrelated to the querying tools — for index data use `search_dsl` or
        `malcolm_search`. Returns the raw dashboard export JSON; an empty id or a
        failed export is reported as an error rather than as an answer.
        """
        did = dashboard_id.strip()
        if not did:
            raise ToolInputError(
                "dashboard_id is required — take one from a malcolm_saved_objects row "
                'of type "dashboard".'
            )
        data = await client.dashboard_export(did)
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)
