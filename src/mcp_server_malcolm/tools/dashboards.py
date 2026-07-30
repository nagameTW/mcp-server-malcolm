"""OpenSearch Dashboards saved objects, alerting monitors and anomaly detectors."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from mcp_server_malcolm.client import MalcolmClient

# The saved-object types worth searching. Everything else Dashboards stores
# (config, url, augment-vis) is UI state an agent cannot act on, and a bad type
# would otherwise reach the server as an unbounded query.
_OBJECT_TYPES = ("dashboard", "visualization", "search", "index-pattern")

# Shared: every tool here reads, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}


def register_dashboard_tools(mcp: FastMCP, client: MalcolmClient) -> None:
    """Register saved-object, alerting and anomaly-detection reads."""

    @mcp.tool(title="Find Dashboards saved objects", annotations=_READ)
    async def malcolm_saved_objects(
        object_type: Annotated[
            str,
            # No f-string here: with `from __future__ import annotations` the
            # annotation is kept as source text and re-evaluated, and an
            # f-string inside Annotated[...] does not survive that round trip.
            Field(
                description="Which saved-object types to search, comma-separated: "
                'dashboard, visualization, search, index-pattern. E.g. "dashboard"; '
                '"dashboard,search".'
            ),
        ] = "dashboard",
        search: Annotated[
            str,
            Field(
                description='Match against the object TITLE only, e.g. "DNS", '
                '"Zeek*". Wildcards work. Empty = every object of the type.'
            ),
        ] = "",
        limit: Annotated[int, Field(description="Max objects to return.", ge=1, le=200)] = 20,
    ) -> str:
        """Find the dashboards, visualizations and saved searches this Malcolm ships.

        Use this to discover what pre-built analysis already exists before
        building a query by hand — Malcolm ships over a hundred dashboards, and
        one of them usually already covers the protocol you are looking at. Take
        an object's `id` to malcolm_dashboard_export to read how it is built.
        This searches the Dashboards catalogue, NOT network traffic: for traffic
        use malcolm_search, and for the field names behind a visualization use
        malcolm_field_search.

        Returns JSON {"total", "showing", "objects"}: per object the type, id,
        title, description and last-updated time. The panel layout is
        deliberately not included — it is several KB of positioning JSON per
        dashboard and says nothing about what the dashboard shows.
        """
        wanted = [t.strip().lower() for t in object_type.split(",") if t.strip()]
        unknown = [t for t in wanted if t not in _OBJECT_TYPES]
        if unknown or not wanted:
            return (
                f"Error: unsupported object_type {', '.join(unknown) or '(empty)'}. "
                f"Supported: {', '.join(_OBJECT_TYPES)}."
            )

        try:
            data = await client.dashboards_find(
                types=wanted, search=search.strip(), limit=min(max(1, limit), 200)
            )
        except Exception as exc:  # noqa: BLE001
            return f"Saved-object search failed: {exc}"

        rows = data.get("saved_objects") or []
        if not rows:
            scope = f" matching {search!r}" if search.strip() else ""
            return (
                f"No saved objects of type {', '.join(wanted)}{scope}. "
                "Titles are matched as whole words, so try a shorter term or a "
                'trailing wildcard ("dns*").'
            )

        objects = [
            _drop_empty(
                {
                    "type": row.get("type"),
                    "id": row.get("id"),
                    "title": (row.get("attributes") or {}).get("title"),
                    "description": (row.get("attributes") or {}).get("description"),
                    "updated_at": row.get("updated_at"),
                }
            )
            for row in rows
        ]
        return json.dumps(
            {"total": data.get("total", len(objects)), "showing": len(objects), "objects": objects},
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    @mcp.tool(title="List alerting monitors", annotations=_READ)
    async def malcolm_alerting_monitors(
        limit: Annotated[int, Field(description="Max monitors to return.", ge=1, le=200)] = 50,
    ) -> str:
        """List OpenSearch alerting monitors, what each watches, and whether any have fired.

        Use this to find the standing detections someone already configured, and
        to check they are actually running — a disabled monitor is silent in
        exactly the way a healthy one is. These are OpenSearch alerting rules,
        which are a different thing from Suricata's IDS alerts: for those use
        malcolm_alerts. To record a new finding rather than read a rule, use
        malcolm_create_alert (needs the alerting write class).

        Returns JSON {"count", "active_alerts", "monitors"}: per monitor the
        name, id, type, whether it is enabled, its schedule in words, the
        indices it searches and its trigger names. `active_alerts` is the number
        currently raised across all monitors; it is omitted if that lookup
        fails, since it only enriches the list. When every monitor is disabled
        the response says so.
        """
        try:
            data = await client.alerting_monitors(limit=min(max(1, limit), 200))
        except Exception as exc:  # noqa: BLE001
            return f"Alerting monitor lookup failed: {exc}"

        hits = ((data.get("hits") or {}).get("hits")) or []
        if not hits:
            return (
                "No alerting monitors are configured. Malcolm ships none by "
                "default; they are created in the OpenSearch Dashboards "
                "Alerting plugin."
            )

        monitors = []
        for hit in hits:
            src = hit.get("_source") or {}
            monitors.append(
                _drop_empty(
                    {
                        "name": src.get("name"),
                        "id": hit.get("_id"),
                        "monitor_type": src.get("monitor_type"),
                        "enabled": src.get("enabled"),
                        "schedule": _schedule(src.get("schedule")),
                        "indices": _monitor_indices(src.get("inputs")),
                        "triggers": _trigger_names(src.get("triggers")),
                    }
                )
            )

        result: dict[str, Any] = {"count": len(monitors), "monitors": monitors}
        try:
            alerts = await client.alerting_alerts()
            result["active_alerts"] = alerts.get("totalAlerts", len(alerts.get("alerts") or []))
        except Exception as exc:  # noqa: BLE001
            # An enrichment failing must not cost the caller the monitor list.
            result["active_alerts_error"] = str(exc)

        if all(m.get("enabled") is False for m in monitors):
            result["note"] = (
                "every monitor here is disabled, so none of them can fire — "
                "the absence of alerts says nothing about the traffic"
            )
        return json.dumps(result, indent=2, ensure_ascii=False, default=str)

    @mcp.tool(title="List anomaly detectors", annotations=_READ)
    async def malcolm_anomaly_detectors(
        limit: Annotated[int, Field(description="Max detectors to return.", ge=1, le=200)] = 50,
    ) -> str:
        """List OpenSearch anomaly detectors, what each models, and whether any anomalies exist.

        Use this to see what machine-learning baselines Malcolm is maintaining
        over the traffic and whether they have produced anything. This reads the
        detector configuration, not the traffic: for the underlying documents
        use malcolm_search, and for Suricata's signature-based alerts use
        malcolm_alerts, which is a different detection method entirely.

        Returns JSON {"count", "recorded_anomalies", "detectors"}: per detector
        the name, id, description, indices modelled, detector type, category
        fields, run interval in words and the feature names it tracks. The
        aggregation definitions behind those features are configuration detail
        and are left out. `recorded_anomalies` counts results across all
        detectors; zero with detectors configured usually means they were never
        started, which reads identically to "nothing anomalous happened".
        """
        try:
            data = await client.anomaly_detectors(limit=min(max(1, limit), 200))
        except Exception as exc:  # noqa: BLE001
            return f"Anomaly detector lookup failed: {exc}"

        hits = ((data.get("hits") or {}).get("hits")) or []
        if not hits:
            return (
                "No anomaly detectors are configured. They are created in the "
                "OpenSearch Dashboards Anomaly Detection plugin."
            )

        detectors = []
        for hit in hits:
            src = hit.get("_source") or {}
            detectors.append(
                _drop_empty(
                    {
                        "name": src.get("name"),
                        "id": hit.get("_id"),
                        "description": src.get("description"),
                        "indices": src.get("indices"),
                        "detector_type": src.get("detector_type"),
                        "category_fields": src.get("category_field"),
                        "interval": _schedule(
                            {"period": (src.get("detection_interval") or {}).get("period")}
                        ),
                        "features": [
                            f.get("feature_name")
                            for f in (src.get("feature_attributes") or [])
                            if f.get("feature_name")
                        ],
                    }
                )
            )

        result: dict[str, Any] = {"count": len(detectors), "detectors": detectors}
        try:
            counted = await client.anomaly_result_count()
            total = ((counted.get("hits") or {}).get("total") or {}).get("value", 0)
            result["recorded_anomalies"] = total
            if not total:
                result["note"] = (
                    "no anomaly results recorded — detectors that have never "
                    "been started produce exactly this, so it is not evidence "
                    "that the traffic was normal"
                )
        except Exception as exc:  # noqa: BLE001
            result["recorded_anomalies_error"] = str(exc)

        return json.dumps(result, indent=2, ensure_ascii=False, default=str)


def _schedule(schedule: Any) -> Any:
    """Render OpenSearch's {"period": {"interval": 10, "unit": "MINUTES"}} in words."""
    period = (schedule or {}).get("period") if isinstance(schedule, dict) else None
    if not isinstance(period, dict):
        return None
    interval, unit = period.get("interval"), period.get("unit")
    return f"every {interval} {unit}" if interval and unit else None


def _monitor_indices(inputs: Any) -> list[str]:
    """The indices a monitor searches, across all of its inputs.

    Every input shape other than a search input is skipped rather than assumed
    away: OpenSearch also has document-level and remote-monitor inputs, and one
    unexpected entry must not cost the caller the whole monitor list.
    """
    found: list[str] = []
    for item in inputs or []:
        if not isinstance(item, dict):
            continue
        search = item.get("search")
        if not isinstance(search, dict):
            continue
        for index in search.get("indices") or []:
            if index not in found:
                found.append(index)
    return found


def _trigger_names(triggers: Any) -> list[str]:
    """Trigger names, whatever trigger flavour the monitor uses.

    OpenSearch wraps each trigger in a key naming its type
    (query_level_trigger, bucket_level_trigger, ...), so the name is one level
    down and the key varies by monitor type.
    """
    names: list[str] = []
    for trigger in triggers or []:
        if not isinstance(trigger, dict):
            continue
        for value in trigger.values():
            if isinstance(value, dict) and value.get("name"):
                names.append(value["name"])
    return names


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys the server did not populate, keeping False and 0 (both real)."""
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
