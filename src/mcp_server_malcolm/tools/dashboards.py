"""OpenSearch Dashboards saved objects, alerting monitors and anomaly detectors."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from mcp_server_malcolm.errors import ToolInputError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# The saved-object types worth searching. Everything else Dashboards stores
# (config, url, augment-vis) is UI state an agent cannot act on, and a bad type
# would otherwise reach the server as an unbounded query.
_OBJECT_TYPES = ("dashboard", "visualization", "search", "index-pattern")

# The alerting plugin's alert lifecycle. Checked here rather than upstream:
# measured on v26.07.1, alertState=BOGUS answers 200 with an empty list instead
# of a 400, so a typo would read to an agent as "nothing ever fired".
_ALERT_STATES = ("ALL", "ACTIVE", "ACKNOWLEDGED", "COMPLETED", "ERROR", "DELETED")
_SEVERITY_LEVELS = ("1", "2", "3", "4", "5")

# _topAnomalies ranking. Lowercase only -- measured, "SEVERITY" is a 400
# reading "Ordering by SEVERITY is not a valid option".
_ANOMALY_ORDERS = ("severity", "occurrence")

# Epoch milliseconds below this are a seconds-shaped value: 1e11 ms is
# 1973-03-03, earlier than any capture this server can search, while 1e11
# seconds is the year 5138. See _check_ms.
_MS_FLOOR = 100_000_000_000


class SavedObject(TypedDict, total=False):
    """One Dashboards saved object. The panel layout is deliberately absent —
    several KB of positioning JSON that says nothing about what it shows."""

    type: str
    id: str
    title: str
    description: str
    updated_at: str


class SavedObjectList(TypedDict):
    total: int
    showing: int
    objects: list[SavedObject]


class Monitor(TypedDict, total=False):
    """One alerting monitor. `schedule` is rendered in words and is absent for
    a schedule shape this server does not recognise."""

    name: str
    id: str
    monitor_type: str
    enabled: bool
    schedule: str
    indices: list[str]
    triggers: list[str]


class MonitorList(TypedDict, total=False):
    """`total` is the server's count, `showing` this page — a short page is not
    the whole set. `active_alerts` is replaced by `active_alerts_error` when
    that second lookup fails, since it only enriches the list."""

    total: int
    showing: int
    monitors: list[Monitor]
    active_alerts: int
    active_alerts_error: str
    note: str


class AlertList(TypedDict, total=False):
    """Alerts raised by alerting monitors. `alerts` is typed as a list of
    anything on purpose: the rows are the plugin's own documents, whose keys
    vary by monitor type and alert state, and this lab holds zero alerts, so a
    narrower declaration would be a guess that could reject a real answer."""

    total: int
    showing: int
    alerts: list[Any]


class MonitorDetail(TypedDict, total=False):
    """One monitor's full definition. `note` appears only when the monitor
    cannot fire at all, which looks identical from outside to a healthy monitor
    with nothing to report."""

    name: str
    id: str
    monitor_type: str
    enabled: bool
    schedule: str
    inputs: list[dict[str, Any]]
    triggers: list[dict[str, Any]]
    note: str


class AnomalyResults(TypedDict, total=False):
    """Top anomalies from one detector. `window` echoes the requested window as
    UTC so a millisecond/second mix-up is visible in the answer rather than
    hiding as an empty result. `anomalies` holds the plugin's own buckets,
    typed loosely for the same reason as AlertList."""

    detector_id: str
    detector_state: str
    detector_state_error: str
    window: str
    showing: int
    anomalies: list[Any]


class SavedObjectDetail(TypedDict, total=False):
    """One saved object with its query resolved. `columns`/`sort` exist on a
    saved search only; `based_on_search` on a visualization only. Aggregation
    (visState) and panel (panelsJSON) blobs are deliberately absent.

    `query` is always a string, which upstream's is not: on one v26.07.1
    install, 25 of its 141 saved searches store the pre-7.x shape
    {"query_string": {"query": "event.dataset:x509", ...}} instead. See
    _query_text."""

    type: str
    id: str
    title: str
    description: str
    updated_at: str
    query: str
    language: str
    filters: list[Any]
    index_pattern: str
    columns: list[str]
    sort: list[Any]
    based_on_search: str
    note: str


class Detector(TypedDict, total=False):
    """One anomaly detector and what it models."""

    name: str
    id: str
    description: str
    indices: list[str]
    detector_type: str
    category_fields: list[str]
    interval: str
    features: list[str]


class DetectorList(TypedDict, total=False):
    """`recorded_anomalies` counts results with anomaly_grade above zero, NOT
    detector runs, of which there is one per interval per entity."""

    total: int
    showing: int
    detectors: list[Detector]
    recorded_anomalies: int
    recorded_anomalies_error: str
    note: str


# Shared: every tool here reads, never mutates.
_READ = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}

# Why every tool below returns `X | str` rather than a bare TypedDict, even the
# two that always answer with a row. A bare TypedDict return is built into an
# output schema by the SDK's _create_model_from_typeddict, which gives every
# total=False key `default=None` and leaves its declared type alone. The
# advertised schema then reads {"sort": {"type": "array", "default": null}}
# while the dump -- model_dump with no exclude_unset -- puts "sort": null on the
# wire for every key the row did not populate. The 2026-07-28 spec says a server
# MUST provide structured results that conform to its outputSchema and a client
# SHOULD validate them, and null is not an array, so the official SDK client
# raises instead of returning the answer: measured against this lab, every
# saved-object type failed with "None is not of type 'array'".
#
# The union sends the same TypedDict through pydantic's own NotRequired
# handling: an unpopulated key is absent from `required`, absent from the wire,
# and the row rides inside {"result": ...} like every other typed tool here.
# Declaring the keys `X | None` instead would also validate, but it would put an
# explicit null on the wire for each one, which is the noise _drop_empty exists
# to remove and would contradict every docstring that says a key is present only
# when it means something.


def register_dashboard_tools(mcp: MCPServer, client: MalcolmClient) -> None:
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
    ) -> SavedObjectList | str:
        """Find the dashboards, visualizations and saved searches this Malcolm ships.

        Use this to discover what pre-built analysis already exists before
        building a query by hand — Malcolm ships over a hundred dashboards, and
        one of them usually already covers the protocol you are looking at. Take
        a DASHBOARD's `id` to malcolm_dashboard_export to read how it is built —
        that endpoint resolves ids as dashboards only, and answers 200 with an
        embedded 404 for a visualization or saved-search id.
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
            raise ToolInputError(
                f"unsupported object_type {', '.join(unknown) or '(empty)'} — expected "
                f"one or more of {', '.join(_OBJECT_TYPES)}, comma-separated."
            )

        data = await client.dashboards_find(
            types=wanted, search=search.strip(), limit=min(max(1, limit), 200)
        )

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
        return {
            "total": data.get("total", len(objects)),
            "showing": len(objects),
            "objects": objects,
        }

    @mcp.tool(title="Read one saved object's query and filters", annotations=_READ)
    async def malcolm_saved_object_detail(
        object_id: Annotated[
            str,
            Field(
                description="The object's id as malcolm_saved_objects returns it, e.g. "
                '"bc940221-83d5-416e-a353-dc8fc2f84141". Ids are not unique across '
                "types, so object_type has to match."
            ),
        ],
        object_type: Annotated[
            str,
            Field(
                description="The object's type, one of: search (a curated query, the "
                "usual case), visualization, dashboard, index-pattern. A right id with "
                "the wrong type reads upstream as no such object."
            ),
        ] = "search",
        # `| str` is load-bearing, not decoration -- see the note above _READ.
    ) -> SavedObjectDetail | str:
        """Read one saved object with its query, filters and index pattern already resolved.

        Use this on a saved SEARCH to recover the query a human curated —
        Malcolm ships 141 of them, and the Arkime-side equivalent is
        arkime_views — and on a visualization to find the search it is built
        from. malcolm_saved_objects lists titles and ids and stops there;
        malcolm_dashboard_export resolves DASHBOARD ids only and answers 200
        with an embedded 404 for a visualization or saved-search id, so for
        those two this is the only route. For the traffic a query matches, take
        the string to malcolm_search or search_dsl.

        Three indirections are followed here instead of being handed back: the
        query sits in kibanaSavedObjectMeta.searchSourceJSON as a JSON *string*
        needing a second parse, the index is a reference NAME that means nothing
        until it is looked up in the object's own references[] array, and the
        query itself is stored in two shapes — a sixth of one install's saved
        searches used the pre-7.x {"query_string": {"query": "..."}} object
        rather than a plain string. `query` is always the string.

        Returns JSON: type, id, title, description, updated_at, then query and
        `language` — "lucene" or "kuery", and they are not interchangeable, so
        check it before reusing the string — plus filters, index_pattern, and
        for a saved search the columns and sort order the analyst chose. On this
        Malcolm the index-pattern reference id is the pattern itself
        ("arkime_sessions3-*"); elsewhere it can be a UUID, which this tool
        resolves with object_type="index-pattern". A visualization has no query
        of its own: `based_on_search` is the id of the saved search it inherits
        one from. Aggregation (visState) and panel-layout (panelsJSON) blobs are
        left out; malcolm_dashboard_export returns them for everything on a
        dashboard. Raises if nothing has that type and id.
        """
        wanted = object_type.strip().lower()
        if wanted not in _OBJECT_TYPES:
            raise ToolInputError(
                f"unsupported object_type {object_type!r} — expected one of "
                f"{', '.join(_OBJECT_TYPES)}."
            )

        obj = await client.saved_object(wanted, object_id.strip())
        attrs = obj.get("attributes") or {}
        source = obj.get("search_source") or {}

        row: dict[str, Any] = _drop_empty(
            {
                "type": obj.get("type"),
                "id": obj.get("id"),
                "title": attrs.get("title"),
                "description": attrs.get("description"),
                "updated_at": obj.get("updated_at"),
                "query": _query_text(source.get("query")),
                "language": source.get("language"),
                "filters": source.get("filters"),
                "index_pattern": source.get("index_pattern"),
                "columns": attrs.get("columns"),
                "sort": attrs.get("sort"),
                "based_on_search": _referenced_search(obj),
            }
        )
        if not row.get("query"):
            row["note"] = _no_query_note(wanted, row.get("based_on_search", ""))
        return row

    @mcp.tool(title="List alerting monitors", annotations=_READ)
    async def malcolm_alerting_monitors(
        limit: Annotated[int, Field(description="Max monitors to return.", ge=1, le=200)] = 50,
    ) -> MonitorList | str:
        """List OpenSearch alerting monitors, what each watches, and whether any have fired.

        Use this to find the standing detections someone already configured, and
        to check they are actually running — a disabled monitor is silent in
        exactly the way a healthy one is. These are OpenSearch alerting rules,
        which are a different thing from Suricata's IDS alerts: for those use
        malcolm_alerts. To record a new finding rather than read a rule, use
        malcolm_create_alert (needs the alerting write class).

        Returns JSON {"total", "showing", "active_alerts", "monitors"}: per monitor the
        name, id, type, whether it is enabled, its schedule in words, the
        indices it searches and its trigger names. `active_alerts` counts only
        alerts in the ACTIVE state, not the COMPLETED history the API returns by
        default; it is replaced by an error key if that second lookup fails,
        since it only enriches the list. When every monitor is disabled the
        response says so, and says whether it is speaking for all of them or
        only the page returned.
        """
        data = await client.alerting_monitors(limit=min(max(1, limit), 200))

        hits = ((data.get("hits") or {}).get("hits")) or []
        if not hits:
            return (
                "No alerting monitors are configured. Malcolm normally imports "
                "one (the API loopback monitor) at startup, so an empty list "
                "may mean monitors were removed rather than never created. "
                "They are managed in the OpenSearch Dashboards Alerting plugin."
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

        result: dict[str, Any] = {
            "total": _server_total(data, len(monitors)),
            "showing": len(monitors),
            "monitors": monitors,
        }
        try:
            alerts = await client.alerting_alerts()
            result["active_alerts"] = alerts.get("totalAlerts", len(alerts.get("alerts") or []))
        except Exception as exc:  # noqa: BLE001
            # An enrichment failing must not cost the caller the monitor list.
            result["active_alerts_error"] = str(exc)

        if all(m.get("enabled") is False for m in monitors):
            complete = result["showing"] >= result["total"]
            result["note"] = (
                "every monitor "
                + ("configured" if complete else "on this page")
                + " is disabled, so none of them can fire"
                + (
                    " — the absence of alerts says nothing about the traffic"
                    if complete
                    else "; raise limit to see the rest before concluding anything"
                )
            )
        return result

    @mcp.tool(title="List alerts raised by alerting monitors", annotations=_READ)
    async def malcolm_alerting_alerts(
        alert_state: Annotated[
            str,
            Field(
                description="Lifecycle state to return: ALL (default), ACTIVE (firing "
                "now), ACKNOWLEDGED (an analyst has seen it, still firing), COMPLETED "
                "(fired and has since recovered — the overnight history), ERROR (the "
                "monitor itself failed to run), DELETED (the alert outlived the monitor "
                "that raised it — a state to read, nothing here removes anything). "
                "Case-insensitive."
            ),
        ] = "ALL",
        monitor_id: Annotated[
            str,
            Field(
                description="Keep only one monitor's alerts, using the `id` "
                "malcolm_alerting_monitors returns (not the monitor name). Empty = "
                "every monitor."
            ),
        ] = "",
        severity: Annotated[
            str,
            Field(
                description="Keep only alerts whose trigger is configured at this "
                'severity, "1" (highest) through "5". This is the level a human set on '
                "the trigger, not a score computed from the traffic. Empty = any."
            ),
        ] = "",
        search: Annotated[
            str,
            Field(
                description="Free-text match across the alert fields (monitor name, "
                "trigger name). Empty = no text filter."
            ),
        ] = "",
    ) -> AlertList | str:
        """Read what OpenSearch alerting monitors have actually fired, in any state.

        Use this for "what fired overnight". malcolm_alerting_monitors lists the
        standing rules and counts only ACTIVE alerts, so a monitor that fired and
        then recovered — state COMPLETED — is invisible there, as are the
        per-monitor, per-severity and free-text filters. That tool answers "what
        is being watched", this one answers "what happened". These are OpenSearch
        alerting alerts, a different mechanism from Suricata's IDS alerts: for
        those use malcolm_alerts. To read the rule behind an alert, take its
        monitor id to malcolm_alerting_monitor_detail.

        alert_state and severity are validated here rather than passed through:
        measured on this Malcolm, an unknown alertState or severityLevel answers
        200 with an empty list rather than 400, so a typo would look exactly like
        a quiet night.

        Returns JSON {"total", "showing", "alerts"} with each alert as the
        plugin sends it — monitor id and name, trigger name, state, severity and
        the start/end/acknowledged timestamps. The rows are passed through
        unrenamed: their keys differ by monitor type and by state, and trimming
        to a fixed set risks dropping the one field that explains a firing. An
        empty list is a successful answer and a common one, since no alert can
        exist while every monitor is disabled.
        """
        state = alert_state.strip().upper()
        if state not in _ALERT_STATES:
            raise ToolInputError(
                f"unsupported alert_state {alert_state!r} — expected one of "
                f"{', '.join(_ALERT_STATES)}. Upstream does not reject an unknown "
                "state; it answers an empty list, which reads as 'nothing fired'."
            )
        level = severity.strip()
        if level and level not in _SEVERITY_LEVELS:
            raise ToolInputError(
                f"unsupported severity {severity!r} — trigger severity is "
                f"{' through '.join((_SEVERITY_LEVELS[0], _SEVERITY_LEVELS[-1]))}, "
                "1 being the highest. An unknown level is not rejected upstream "
                "either; it just answers empty."
            )
        monitor = monitor_id.strip()
        text = search.strip()

        data = await client.alerting_alerts(
            alert_state=state, monitor_id=monitor, severity=level, search=text
        )
        alerts = data.get("alerts") or []
        if not alerts:
            narrowed = ", ".join(
                part
                for part in (
                    f"monitor {monitor}" if monitor else "",
                    f"severity {level}" if level else "",
                    f"matching {text!r}" if text else "",
                )
                if part
            )
            return (
                ("No alerts in any state" if state == "ALL" else f"No alerts in state {state}")
                + (f" for {narrowed}" if narrowed else "")
                + ". This is an answer, not a failure: an alert exists only while a "
                "monitor is enabled and its trigger condition has been met. Check "
                "malcolm_alerting_monitors for whether any monitor runs at all, and "
                "malcolm_alerting_monitor_detail for whether its condition is "
                "reachable — a condition no traffic can satisfy produces exactly this."
            )
        return {
            "total": data.get("totalAlerts", len(alerts)),
            "showing": len(alerts),
            "alerts": alerts,
        }

    @mcp.tool(title="Read one alerting monitor's query and triggers", annotations=_READ)
    async def malcolm_alerting_monitor_detail(
        monitor_id: Annotated[
            str,
            Field(
                description="The monitor's OpenSearch document id, returned as `id` by "
                'malcolm_alerting_monitors (e.g. "NYUZsZ8Bao8axaN3ef1f"). Not the '
                "monitor name."
            ),
        ],
        # `| str` is load-bearing, not decoration -- see the note above _READ.
    ) -> MonitorDetail | str:
        """Read one alerting monitor in full: the query it runs and the conditions that fire it.

        Use this to decide whether a monitor's SILENCE means anything.
        malcolm_alerting_monitors says a monitor exists and whether it is
        enabled, but cannot show the query or the trigger condition, so it
        cannot separate a monitor that watches the right traffic from one whose
        condition no traffic can satisfy — measured on this Malcolm, the shipped
        loopback monitor fires on `ctx.results[0].hits.total.value > 999999999`.
        Take the id from malcolm_alerting_monitors; for the alerts a monitor has
        raised use malcolm_alerting_alerts with monitor_id.

        Returns JSON: name, id, monitor_type, enabled, the schedule in words,
        one `inputs` entry per search input with its indices and its whole
        OpenSearch query (mustache placeholders such as {{period_end}} left as
        the monitor stores them), and one `triggers` entry per trigger with
        name, severity, firing condition and action names. `note` is present
        only when the monitor cannot raise an alert at all — disabled, or
        carrying no triggers — because from outside that is indistinguishable
        from a healthy monitor with nothing to report. Raises if no monitor has
        that id.
        """
        data = await client.alerting_monitor(monitor_id.strip())
        src = data.get("monitor") or {}

        row: dict[str, Any] = _drop_empty(
            {
                "name": src.get("name"),
                "id": data.get("_id") or monitor_id.strip(),
                "monitor_type": src.get("monitor_type"),
                "enabled": src.get("enabled"),
                "schedule": _schedule(src.get("schedule")),
                "inputs": _search_inputs(src.get("inputs")),
                "triggers": _trigger_details(src.get("triggers")),
            }
        )
        reasons = [
            reason
            for reason, applies in (
                ("it is disabled", src.get("enabled") is False),
                ("it has no triggers", not row.get("triggers")),
            )
            if applies
        ]
        if reasons:
            row["note"] = (
                "this monitor cannot raise an alert: "
                + " and ".join(reasons)
                + " — its silence says nothing about the traffic"
            )
        return row

    @mcp.tool(title="List anomaly detectors", annotations=_READ)
    async def malcolm_anomaly_detectors(
        limit: Annotated[int, Field(description="Max detectors to return.", ge=1, le=200)] = 50,
    ) -> DetectorList | str:
        """List OpenSearch anomaly detectors, what each models, and whether any anomalies exist.

        Use this to see what machine-learning baselines Malcolm is maintaining
        over the traffic and whether they have produced anything. This reads the
        detector configuration, not the traffic: for the underlying documents
        use malcolm_search, and for Suricata's signature-based alerts use
        malcolm_alerts, which is a different detection method entirely.

        Returns JSON {"total", "showing", "recorded_anomalies", "detectors"}: per detector
        the name, id, description, indices modelled, detector type, category
        fields, run interval in words and the feature names it tracks. The
        aggregation definitions behind those features are configuration detail
        and are left out. `recorded_anomalies` counts results whose
        anomaly_grade is above zero across all detectors — NOT detector runs,
        of which there is one per interval per entity whether or not anything
        was anomalous. Zero with detectors configured still needs care: a
        detector that was never started produces the same zero.
        """
        data = await client.anomaly_detectors(limit=min(max(1, limit), 200))

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

        result: dict[str, Any] = {
            "total": _server_total(data, len(detectors)),
            "showing": len(detectors),
            "detectors": detectors,
        }
        try:
            counted = await client.anomaly_result_count()
            total = ((counted.get("hits") or {}).get("total") or {}).get("value", 0)
            result["recorded_anomalies"] = total
            if not total:
                result["note"] = (
                    "no anomalous results recorded. A detector that was never "
                    "started produces exactly this too, so check that these "
                    "detectors are running before reading it as a quiet network"
                )
        except Exception as exc:  # noqa: BLE001
            result["recorded_anomalies_error"] = str(exc)

        return result

    @mcp.tool(title="Read one anomaly detector's top anomalies", annotations=_READ)
    async def malcolm_anomaly_results(
        detector_id: Annotated[
            str,
            Field(
                description="The detector's id, returned as `id` by "
                'malcolm_anomaly_detectors (e.g. "94UZsZ8Bao8axaN3EPyz"). Not its name.'
            ),
        ],
        start_time_ms: Annotated[
            int,
            Field(
                description="Window start in EPOCH MILLISECONDS (not seconds — a "
                "seconds value is rejected). Multiply an arkime_* timestamp by 1000."
            ),
        ],
        end_time_ms: Annotated[
            int,
            Field(
                description="Window end in EPOCH MILLISECONDS, greater than "
                "start_time_ms. Anomalies are placed by the detection interval they "
                "were scored in, so widen the window rather than guessing an offset."
            ),
        ],
        size: Annotated[
            int,
            Field(description="Max entity buckets to return, worst first.", ge=1, le=100),
        ] = 10,
        order: Annotated[
            str,
            Field(
                description='Rank buckets by "severity" (highest anomaly grade, the '
                'default — the single worst entity) or "occurrence" (most anomalous '
                "results — the entity that was odd most often)."
            ),
        ] = "severity",
    ) -> AnomalyResults | str:
        """Read which entities one anomaly detector scored as anomalous in a window, worst first.

        Use this after malcolm_anomaly_detectors, which reports a single
        anomaly count across every detector and admits it cannot tell "the
        detector ran and found nothing" from "the detector was never started".
        This asks one named detector for its own results and reports its run
        state beside them, which settles that question and names WHICH entity
        was anomalous and WHEN. For signature-based detection use malcolm_alerts
        (Suricata) or malcolm_alerting_alerts (standing OpenSearch rules); this
        is the machine-learning baseline instead.

        TIME HERE IS EPOCH MILLISECONDS, unlike every arkime_* tool in this
        server, which takes seconds. A seconds-shaped value is rejected rather
        than forwarded: upstream it is a window in 1970 and answers empty, which
        is indistinguishable from clean traffic. The window that was actually
        queried is echoed back as UTC so the caller can check it.

        Returns JSON {"detector_id", "detector_state", "window", "showing",
        "anomalies"}. Each entry is one entity bucket exactly as the plugin
        sends it — the category-field values identifying the entity, how many
        anomalous results it had and its worst grade — passed through unrenamed
        because the keys follow the detector's own category fields. No anomalies
        comes back as a sentence that says what the detector's state implies
        about that emptiness. Real-time detector results only: this Malcolm has
        no historical analysis tasks, and asking for them is a 500.
        """
        rank = order.strip().lower()
        if rank not in _ANOMALY_ORDERS:
            raise ToolInputError(
                f"unsupported order {order!r} — expected {' or '.join(_ANOMALY_ORDERS)}."
            )
        _check_ms("start_time_ms", start_time_ms)
        _check_ms("end_time_ms", end_time_ms)
        if end_time_ms <= start_time_ms:
            raise ToolInputError(
                f"end_time_ms ({end_time_ms}) must be later than start_time_ms "
                f"({start_time_ms}); as given the window is empty and so is any answer."
            )

        detector = detector_id.strip()
        data = await client.anomaly_top_results(
            detector, start_time_ms, end_time_ms, size=size, order=rank
        )
        buckets = data.get("buckets") or []

        state, state_error = "", ""
        try:
            state = (await client.anomaly_detector_profile(detector)).get("state") or ""
        except Exception as exc:  # noqa: BLE001
            # The state only explains the results; losing it must not lose them.
            state_error = str(exc)

        window = f"{_utc(start_time_ms)} to {_utc(end_time_ms)}"
        if not buckets:
            return f"No anomalies from detector {detector} between {window}. " + _state_reading(
                state, state_error
            )
        return _drop_empty(
            {
                "detector_id": detector,
                "detector_state": state,
                "detector_state_error": state_error,
                "window": window,
                "showing": len(buckets),
                "anomalies": buckets,
            }
        )


def _server_total(data: Any, fallback: int) -> int:
    """The server's own hit total, so a truncated page cannot read as complete.

    OpenSearch reports it as {"value": N, "relation": "eq"|"gte"}; the value is
    what matters here and the relation only differs past 10,000 hits, which no
    monitor or detector list reaches.
    """
    total = ((data.get("hits") or {}).get("total") or {}) if isinstance(data, dict) else {}
    value = total.get("value") if isinstance(total, dict) else None
    return value if isinstance(value, int) else fallback


def _schedule(schedule: Any) -> Any:
    """Render an OpenSearch schedule in words, whichever kind it is.

    Both kinds are real on the monitor type Malcolm ships: a period schedule
    ({"period": {"interval": 10, "unit": "MINUTES"}}) and a cron one. Returning
    None for cron dropped the key entirely, so a cron-scheduled monitor showed
    no schedule at all while the docstring promised one.
    """
    if not isinstance(schedule, dict):
        return None
    period = schedule.get("period")
    if isinstance(period, dict):
        interval, unit = period.get("interval"), period.get("unit")
        if interval and unit:
            return f"every {interval} {unit}"
    cron = schedule.get("cron")
    if isinstance(cron, dict) and cron.get("expression"):
        timezone = cron.get("timezone")
        return f"cron {cron['expression']}" + (f" ({timezone})" if timezone else "")
    return None


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


def _search_inputs(inputs: Any) -> list[dict[str, Any]]:
    """The indices and the whole query behind each of a monitor's search inputs.

    The query is passed through as OpenSearch stores it, mustache placeholders
    ({{period_end}}) and all: rewriting it would misrepresent what the monitor
    runs, and the placeholders are how a reader sees the window it covers. Other
    input shapes (document-level, remote-monitor) carry no search query and are
    skipped rather than guessed at, as in _monitor_indices.
    """
    found: list[dict[str, Any]] = []
    for item in inputs or []:
        if not isinstance(item, dict):
            continue
        search = item.get("search")
        if isinstance(search, dict):
            found.append(
                _drop_empty({"indices": search.get("indices"), "query": search.get("query")})
            )
    return found


def _trigger_details(triggers: Any) -> list[dict[str, Any]]:
    """Each trigger's name, severity, firing condition and action names.

    The condition is what the monitor list cannot show and the reason the detail
    tool exists: measured on this Malcolm the shipped monitor fires on
    `ctx.results[0].hits.total.value > 999999999`, so it is configured never to.
    As in _trigger_names the body sits one level down under a key naming the
    trigger type. A bucket-level trigger's condition is not a painless script,
    so `condition` is simply absent there rather than invented.
    """
    rows: list[dict[str, Any]] = []
    for trigger in triggers or []:
        if not isinstance(trigger, dict):
            continue
        for body in trigger.values():
            if not isinstance(body, dict):
                continue
            condition = body.get("condition")
            script = condition.get("script") if isinstance(condition, dict) else None
            rows.append(
                _drop_empty(
                    {
                        "name": body.get("name"),
                        "severity": body.get("severity"),
                        "condition": script.get("source") if isinstance(script, dict) else None,
                        "actions": [
                            action.get("name")
                            for action in body.get("actions") or []
                            if isinstance(action, dict) and action.get("name")
                        ],
                    }
                )
            )
    return rows


def _check_ms(name: str, value: int) -> None:
    """Reject an epoch value that is obviously in seconds.

    The anomaly-results route is the only one in this server taking
    milliseconds; every arkime_* tool takes seconds. A seconds value is not
    rejected upstream -- it is a window in 1970 that answers empty, which reads
    exactly like a detector that found nothing.
    """
    if value < _MS_FLOOR:
        raise ToolInputError(
            f"{name}={value} looks like epoch SECONDS — this tool takes epoch "
            f"MILLISECONDS, so pass {value * 1000}. Sent as given it asks about a "
            "window in 1970 and answers empty, which is indistinguishable from a "
            "detector that scored nothing."
        )


def _utc(ms: int) -> str:
    """An epoch-millisecond instant as a UTC timestamp, for echoing a window back."""
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_reading(state: str, state_error: str) -> str:
    """What a detector's run state implies about finding no anomalies.

    The whole point of pairing _profile with the results: an empty bucket list
    means opposite things depending on it. Measured here, all five detectors
    report DISABLED, so this lab's zero anomalies say nothing about the traffic.
    """
    if state == "DISABLED":
        return (
            "The detector's state is DISABLED: it never ran, so nothing was computed "
            "for this window and the emptiness is not evidence the traffic was normal. "
            "Start it in the OpenSearch Dashboards Anomaly Detection plugin first."
        )
    if state == "INIT":
        return (
            "The detector's state is INIT: it is still collecting enough history to "
            "build a baseline and has not scored anything yet."
        )
    if not state:
        return (
            "The detector's run state could not be read"
            + (f" ({state_error})" if state_error else "")
            + ", so whether it ever ran over this window is unknown."
        )
    return (
        f"The detector's state is {state}. A real-time detector only scores intervals "
        "after it was started, so confirm this window is inside its run history before "
        "reading the silence as normal traffic."
    )


def _no_query_note(object_type: str, based_on_search: str) -> str:
    """Why a saved object came back with no query, which differs by type.

    An absent query is not one fact. A visualization defers to a saved search;
    an index-pattern is the thing queries point AT and never has one; a search
    or dashboard without one really does select everything in its index. Saying
    "no query" alone would let a model read all four as the last case.
    """
    if based_on_search:
        return (
            "this object has no query of its own; it inherits the saved search in "
            f"based_on_search — call this tool again with object_id={based_on_search!r} "
            "and object_type='search'"
        )
    if object_type == "index-pattern":
        return (
            "an index pattern holds no query: `title` is the pattern itself, and it is "
            "what the index_pattern of a saved search resolves to. Its field list is "
            "hundreds of KB and is not included; use malcolm_field_search for fields"
        )
    return (
        "this object carries no query string, so it selects everything in index_pattern "
        "— what makes it worth reading is its columns, its filters or what is built on "
        "it, not a query"
    )


def _query_text(query: Any) -> str:
    """A saved object's query as the string the docstring promises.

    Dashboards stores two shapes under searchSourceJSON.query.query and only
    one of them is a string. Counted on one v26.07.1 install, 25 of its 141
    saved searches -- about a sixth -- carry the pre-7.x
    {"query_string": {"query": "event.dataset:x509", "analyze_wildcard": true}}
    instead, and handing that dict back both breaks the declared type (the tool
    raised "Input should be a valid string") and gives the caller something
    malcolm_search cannot take. The inner string is the same lucene the newer
    shape stores flat, so unwrapping it loses nothing.

    Any other dict is serialised rather than dropped or raised on: an
    unrecognised query shape is still evidence about the object, and this tool
    degrading to JSON text beats it failing.
    """
    if isinstance(query, str):
        return query
    if not query:
        return ""
    inner = query.get("query_string") if isinstance(query, dict) else None
    if isinstance(inner, dict) and isinstance(inner.get("query"), str):
        return inner["query"]
    return json.dumps(query, ensure_ascii=False, default=str)


def _referenced_search(obj: dict[str, Any]) -> str:
    """The saved search a visualization inherits its query from, resolved to an id.

    A visualization names it in attributes.savedSearchRefName, which is a
    reference NAME ("search_0") and only becomes an id through references[] --
    the same indirection the client resolves for the index pattern. Measured on
    this Malcolm, 150 of 200 sampled visualizations have one and carry an empty
    query of their own, so reporting that empty query alone would read as
    "matches everything".
    """
    name = (obj.get("attributes") or {}).get("savedSearchRefName")
    if not isinstance(name, str) or not name:
        return ""
    for ref in obj.get("references") or []:
        if isinstance(ref, dict) and ref.get("name") == name:
            return ref.get("id") or ""
    return ""


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys the server did not populate, keeping False and 0 (both real)."""
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
