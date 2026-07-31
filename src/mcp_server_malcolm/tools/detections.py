"""OpenSearch alerting monitors and anomaly detectors — the standing detections
configured on this Malcolm, and what they have actually produced.

Split out of dashboards.py at 1043 lines. Saved objects are a catalogue of
queries a human curated; these are detections that run on their own. Nothing
crosses between the two but _drop_empty, which each module keeps its own copy of.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from mcp_server_malcolm.errors import ToolInputError

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

    from mcp_server_malcolm.client import MalcolmClient

# The alerting plugin's alert lifecycle. Checked here rather than upstream:
# measured on Malcolm v26.07.1, alertState=BOGUS answers 200 with an empty list instead
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

# Why every tool below returns `X | str` rather than a bare TypedDict: the note
# above register_dashboard_tools in dashboards.py, which these tools were split
# out of. Same SDK behaviour, same reason, and it is one explanation, not two.


def register_detection_tools(mcp: MCPServer, client: MalcolmClient) -> None:
    """Register the alerting-monitor and anomaly-detector reads."""

    @mcp.tool(title="List alerting monitors", annotations=_READ)
    async def malcolm_alerting_monitors(
        limit: Annotated[int, Field(description="Max monitors to return.", ge=1, le=200)] = 50,
    ) -> MonitorList | str:
        """List OpenSearch alerting monitors, what each watches, and whether any have fired.

        Use this to find the standing detections someone already configured, and
        to check they are actually running — a disabled monitor is silent in
        exactly the way a healthy one is. It stops at what each monitor is and
        whether it is enabled: the query and trigger condition behind one need
        malcolm_alerting_monitor_detail, and what has actually fired needs
        malcolm_alerting_alerts. These are OpenSearch alerting rules, which are
        a different thing from Suricata's IDS alerts: for those use
        malcolm_alerts. To record a new finding rather than read a rule, use
        malcolm_create_alert (needs the alerting write class).

        Returns JSON {"total", "showing", "active_alerts", "monitors"};
        per-monitor fields are in the output schema. `active_alerts` counts only
        alerts in the ACTIVE state, not the COMPLETED history the API returns by
        default. When every monitor is disabled the response says so, and
        whether that covers all of them or only the page returned.
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
        measured on Malcolm v26.07.1, an unknown alertState or severityLevel answers
        200 with an empty list rather than 400, so a typo would look exactly like
        a quiet night.

        Returns JSON {"total", "showing", "alerts"} with each alert as the
        plugin sends it — monitor id and name, trigger name, state, severity and
        the start/end/acknowledged timestamps. An empty list is a successful
        answer and a common one, since no alert can exist while every monitor is
        disabled.
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
        condition no traffic can satisfy — measured on Malcolm v26.07.1, the shipped
        loopback monitor fires on `ctx.results[0].hits.total.value > 999999999`.
        Take the id from malcolm_alerting_monitors; for the alerts a monitor has
        raised use malcolm_alerting_alerts with monitor_id.

        Field names are in the output schema; what it cannot show is what sits
        inside `inputs` and `triggers` — each search input's whole OpenSearch
        query as the monitor stores it, mustache placeholders such as
        {{period_end}} left intact, and each trigger's severity, firing
        condition and action names. Watch for the `note` key: it marks a monitor
        that cannot fire at all, disabled or trigger-less. Raises if no monitor
        has that id.
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
        over the traffic and whether they have produced anything. It counts
        anomalies across every detector at once; for which entities one named
        detector scored, and when, take its `id` to malcolm_anomaly_results.
        This reads the detector configuration, not the traffic: for the
        underlying documents use malcolm_search, and for Suricata's
        signature-based alerts use malcolm_alerts, which is a different
        detection method entirely.

        Returns JSON {"total", "showing", "recorded_anomalies", "detectors"};
        per-detector fields are in the output schema, minus the aggregation
        definitions behind each feature, which are configuration detail.
        `recorded_anomalies` counts anomalous results across all detectors, NOT
        detector runs. Zero with detectors configured still needs care: a
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
            # Through _server_total, not a raw .get("value"): it is the same
            # hits.total shape `total` above already reads, and DetectorList
            # declares this key `int`. Reading it raw is the one path in this
            # module where a non-int upstream would reach the declaration.
            total = _server_total(counted, 0)
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

        TIME HERE IS EPOCH MILLISECONDS, unlike every arkime_* tool, which takes
        seconds. A seconds-shaped value is rejected rather than forwarded:
        upstream it is a window in 1970 that answers empty, indistinguishable
        from clean traffic.

        Returns JSON {"detector_id", "detector_state", "window", "showing",
        "anomalies"}; the shape is in the output schema. Entity buckets are
        passed through unrenamed because their keys follow the detector's own
        category fields, so they differ per detector. No anomalies comes back as
        a sentence that says what the detector's state implies about that
        emptiness. Real-time detector results only: this Malcolm has no
        historical analysis tasks, and asking for them is a 500.
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
    tool exists: measured on Malcolm v26.07.1 the shipped monitor fires on
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


def _drop_empty(row: dict[str, Any]) -> dict[str, Any]:
    """Drop keys the server did not populate, keeping False and 0 (both real)."""
    return {key: value for key, value in row.items() if value not in (None, "", [], {})}
