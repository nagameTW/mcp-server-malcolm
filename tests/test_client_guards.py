"""Guards on the client's request boundary.

Three concerns, all of them at the one point every upstream request crosses:
a caller-supplied value must never be able to steer the URL path somewhere
else, traffic must stay under a bound, and an httpx failure must reach the
caller as an UpstreamError with its text redacted.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from mcp_server_malcolm import client as client_mod
from mcp_server_malcolm.client import MalcolmClient
from mcp_server_malcolm.errors import ToolInputError, UpstreamError

_BASE = "https://otex:hunter2@malcolm.example"


def _recording_client(
    responder: Any = None, base_url: str = _BASE
) -> tuple[MalcolmClient, list[httpx.Request]]:
    """A client whose transport records every request instead of sending one."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if responder is not None:
            return responder(request)
        return httpx.Response(200, json={"ok": True})

    c = MalcolmClient(base_url=base_url)
    c._http = httpx.AsyncClient(base_url=base_url, transport=httpx.MockTransport(handler))
    return c, seen


# -- Path splicing -----------------------------------------------------------


async def test_aggregate_rejects_traversal_before_any_request_leaves():
    c, seen = _recording_client()
    with pytest.raises(ToolInputError) as err:
        await c.aggregate(fields="../../arkime/api/hunts")
    assert "../../arkime/api/hunts" in str(err.value)
    assert seen == []


async def test_aggregate_rejects_a_bare_dot_dot_segment():
    # httpx removes dot segments, so "/mapi/agg/.." alone reaches "/mapi".
    c, seen = _recording_client()
    with pytest.raises(ToolInputError):
        await c.aggregate(fields="..")
    assert seen == []


async def test_field_names_off_the_allow_list_are_rejected_with_no_dot_segment_to_lean_on():
    """The character class itself has to be what stops these.

    The two traversal tests above both feed a value containing a ".." segment,
    so _DOT_SEGMENT answers first and _FIELD_RE could be widened to ".+" with
    the suite still green. Every value here is asserted free of a ".." segment
    before it is tried, which leaves the character class as the only thing that
    can reject it. Each is also a working attack once the class stops matching:
    "/mapi/agg/<fields>" is built by f-string, so a separator adds a segment of
    someone else's endpoint, "?" starts a query, "#" truncates what httpx
    sends, and "%2f" is a separator a server may decode after routing.
    """
    c, seen = _recording_client()
    for bad in (
        "x?a=b",
        "a/b",
        "..%2f..%2farkime%2fapi%2fhunts",
        "x#frag",
        "x\\y",
    ):
        assert not client_mod._DOT_SEGMENT.search(bad), f"{bad!r} is caught by the wrong guard"
        with pytest.raises(ToolInputError) as err:
            await c.aggregate(fields=bad)
        # repr, because that is how the message quotes the offending value.
        assert repr(bad) in str(err.value)
        with pytest.raises(ToolInputError):
            await c.field_values(field=bad)
    assert seen == []


async def test_dashboard_export_rejects_traversal_and_query_injection():
    c, seen = _recording_client()
    for bad in ("../../x", "x?a=b", "x#frag", "a/b"):
        with pytest.raises(ToolInputError) as err:
            await c.dashboard_export(bad)
        assert bad in str(err.value)
    assert seen == []


async def test_aggregate_accepts_real_field_names_and_comma_lists():
    c, seen = _recording_client()
    await c.aggregate(fields="source.ip")
    await c.aggregate(fields="source.ip,destination.port")
    # Every shape the live catalogue actually contains (Malcolm v26.07.1).
    await c.aggregate(fields="@timestamp,destination.mac-cnt,suricata.smb.client_dialects[]")
    paths = [r.url.path for r in seen]
    assert paths[0] == "/mapi/agg/source.ip"
    assert paths[1] == "/mapi/agg/source.ip,destination.port"
    assert paths[2].startswith("/mapi/agg/@timestamp,destination.mac-cnt,")


async def test_aggregate_strips_whitespace_around_the_comma_list():
    # "source.ip, destination.port" is the habitual spelling; the one name the
    # catalogue holds with a stray space ("suricata.ftp.command ") is also
    # indexed without it, so stripping never loses a reachable field.
    c, seen = _recording_client()
    await c.aggregate(fields=" source.ip , destination.port ")
    assert seen[0].url.path == "/mapi/agg/source.ip,destination.port"


async def test_field_values_inherits_the_field_guard():
    c, seen = _recording_client()
    with pytest.raises(ToolInputError):
        await c.field_values(field="../../arkime/api/hunts")
    assert seen == []


async def test_opensearch_index_and_pattern_are_guarded():
    c, seen = _recording_client()
    for call in (
        lambda: c.opensearch_dsl("../../../arkime/api/hunts", {}),
        lambda: c.opensearch_count("../..", {}),
        lambda: c.opensearch_mapping("idx?pretty"),
        lambda: c.opensearch_indices("../../x"),
    ):
        with pytest.raises(ToolInputError):
            await call()
    assert seen == []


async def test_index_names_off_the_allow_list_are_rejected_with_no_dot_segment_to_lean_on():
    """_INDEX_RE has to be what stops these, exactly as _FIELD_RE does above.

    Every value in the sibling test carries a ".." segment, so _DOT_SEGMENT
    answers first and _INDEX_RE could be widened without the suite noticing.
    "%" is the realistic widening: it is what "support percent-encoded index
    names" would add, and httpx forwards "%2f" verbatim, so the escape survives
    this process and is decoded by whatever routes the request.
    """
    c, seen = _recording_client()
    for bad in ("..%2f..%2farkime%2fapi%2fhunts", "idx#frag", "a/b"):
        assert not client_mod._DOT_SEGMENT.search(bad), f"{bad!r} is caught by the wrong guard"
        for call in (
            lambda: c.opensearch_dsl(bad, {}),
            lambda: c.opensearch_count(bad, {}),
            lambda: c.opensearch_mapping(bad),
            lambda: c.opensearch_indices(bad),
        ):
            with pytest.raises(ToolInputError):
                await call()
    assert seen == []


async def test_dashboard_ids_off_the_allow_list_are_rejected_with_no_dot_segment_to_lean_on():
    """Same masking, same fix, on the third guard that builds a path segment."""
    c, seen = _recording_client()
    for bad in ("..%2f..%2farkime%2fapi%2fhunts", "id%2e%2e%2fx"):
        assert not client_mod._DOT_SEGMENT.search(bad), f"{bad!r} is caught by the wrong guard"
        with pytest.raises(ToolInputError) as err:
            await c.dashboard_export(bad)
        assert bad in str(err.value)
    assert seen == []


async def test_every_guarded_path_component_refuses_an_empty_value():
    """An empty segment collapses the path -- pin it, don't inherit it.

    Today each guard rejects "" only as a side effect of its quantifier ("+",
    "{16,128}"). Nothing asserted it, so a guard rewritten as "match if the
    value is non-empty AND well-formed" would send "/mapi/opensearch//_search"
    and friends with the suite still green.
    """
    c, seen = _recording_client()
    for call in (
        lambda: c.aggregate(fields=""),
        lambda: c.dashboard_export(""),
        lambda: c.opensearch_dsl("", {}),
        lambda: c.netbox_get(""),
        lambda: c.arkime_file_by_hash(""),
    ):
        with pytest.raises(ToolInputError):
            await call()
    assert seen == []


async def test_opensearch_accepts_wildcard_patterns():
    c, seen = _recording_client()
    await c.opensearch_dsl("arkime_sessions3-*", {"query": {}})
    await c.opensearch_indices("*")
    assert seen[0].url.path == "/mapi/opensearch/arkime_sessions3-*/_search"
    assert seen[1].url.path == "/mapi/opensearch/_cat/indices/*"


async def test_netbox_path_is_guarded_but_keeps_real_rest_paths():
    c, seen = _recording_client()
    for bad in ("../../mapi/event", "api/../../x", "api/x?y=1"):
        with pytest.raises(ToolInputError):
            await c.netbox_get(bad)
    assert seen == []
    await c.netbox_get("api/ipam/ip-addresses/")
    assert seen[0].url.path == "/mapi/netbox/api/ipam/ip-addresses/"


async def test_arkime_bodyhash_is_guarded_and_accepts_a_real_hash():
    c, seen = _recording_client()
    with pytest.raises(ToolInputError):
        await c.arkime_file_by_hash("../../api/hunts")
    assert seen == []
    await c.arkime_file_by_hash("a" * 32)
    assert seen[0].url.path == f"/arkime/api/sessions/bodyhash/{'a' * 32}"


async def test_body_hash_must_be_hex_within_the_digest_lengths():
    """Pins the shape and both length bounds of _HASH_RE.

    The test above only feeds a value containing "..", which _DOT_SEGMENT
    catches on its own; these are all ".."-free, so _HASH_RE is the only guard
    that can reject them, and 15/129 characters sit one either side of the
    16..128 window the pattern allows.
    """
    c, seen = _recording_client(responder=lambda _r: httpx.Response(200, content=b"x"))
    for bad in ("g" * 32, "a" * 15, "a" * 129, "abcdef0123456789?a=b", "abcdef0123456789/x"):
        assert not client_mod._DOT_SEGMENT.search(bad), f"{bad!r} is caught by the wrong guard"
        with pytest.raises(ToolInputError):
            await c.arkime_file_by_hash(bad)
    assert seen == []
    # The three digest widths Arkime actually stores, all still accepted.
    digests = (
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    )
    for digest in digests:
        await c.arkime_file_by_hash(digest)
    assert [r.url.path for r in seen] == [f"/arkime/api/sessions/bodyhash/{d}" for d in digests]


def test_the_argument_guard_rejects_a_dot_dot_segment_by_itself():
    """_checked's second half, pinned without the path backstop in front of it.

    _FIELD_RE and the index/dashboard classes all admit ".", so ".." passes
    fullmatch and only _DOT_SEGMENT inside _checked stops it. Driven through a
    tool, _checked_path in get/post answers first and this layer could be
    deleted unnoticed -- so this calls _checked directly and defence in depth
    is two tested layers rather than one tested layer and one hope.
    """
    for pattern, what in (
        (client_mod._FIELD_RE, "field name"),
        (client_mod._INDEX_RE, "index"),
        (client_mod._DASHBOARD_ID_RE, "dashboard id"),
    ):
        assert pattern.fullmatch(".."), f"{what} class no longer needs the dot-segment check"
        with pytest.raises(ToolInputError):
            client_mod._checked("..", pattern, what, "a shape")


async def test_extracted_file_name_stays_one_encoded_segment():
    c, seen = _recording_client(responder=lambda _r: httpx.Response(200, content=b"x"))
    # A carved name with separators must fetch that name, not another path.
    # Asserted on raw_path, the bytes that go on the wire: url.path is a
    # decoded view and reads as "/extracted-files/a/../../etc/passwd" even
    # though nothing traversed.
    await c.extracted_file("a/../../etc/passwd")
    assert seen[0].url.raw_path == b"/extracted-files/a%2F..%2F..%2Fetc%2Fpasswd"
    # "." is not escaped by quote(), so a bare ".." is the one name that would
    # still climb; the path backstop stops it.
    with pytest.raises(ToolInputError):
        await c.extracted_file("..")
    assert len(seen) == 1
    # A real filename that merely contains ".." is untouched.
    await c.extracted_file("report..pdf")
    assert seen[1].url.raw_path == b"/extracted-files/report..pdf"


async def test_request_path_backstop_refuses_a_dot_dot_segment():
    # Guards live on each argument; this catches the next method that splices a
    # value into a path and forgets one.
    c, seen = _recording_client()
    with pytest.raises(ToolInputError):
        await c.get("/mapi/agg/../../arkime/api/hunts")
    with pytest.raises(ToolInputError):
        await c.post("/mapi/opensearch/../x", {})
    assert seen == []


# -- httpx failures become UpstreamError ------------------------------------


async def test_status_error_becomes_upstream_error_with_status_and_redaction():
    c, _ = _recording_client(responder=lambda _r: httpx.Response(403, text="denied"))
    with pytest.raises(UpstreamError) as err:
        await c.get("/mapi/ping", params={"token": "s3cr3t"})
    assert err.value.status == 403
    message = str(err.value)
    assert "s3cr3t" not in message
    assert "hunter2" not in message
    assert "malcolm.example" in message


async def test_transport_failure_becomes_upstream_error_without_a_status():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"connection refused for {_BASE}/mapi/ping")

    c, _ = _recording_client(responder=boom)
    with pytest.raises(UpstreamError) as err:
        await c.post("/mapi/document", {"limit": 1})
    assert err.value.status is None
    assert "hunter2" not in str(err.value)


async def test_get_raw_converts_transport_failure_but_hands_status_to_the_caller():
    # get_raw exists for callers that read resp.status_code themselves, so a
    # status stays a value; a failure with no response at all has nothing to
    # read and must raise.
    c, _ = _recording_client(responder=lambda _r: httpx.Response(404, text="gone"))
    resp = await c.get_raw("/extracted-files/x")
    assert resp.status_code == 404

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    c2, _ = _recording_client(responder=boom)
    with pytest.raises(UpstreamError) as err:
        await c2.get_raw("/arkime/api/unique")
    assert err.value.status is None


async def test_text_endpoints_convert_their_own_status_check():
    c, _ = _recording_client(responder=lambda _r: httpx.Response(500, text="boom"))
    with pytest.raises(UpstreamError) as err:
        await c.arkime_unique("ip==192.0.2.1", "source.ip")
    assert err.value.status == 500


async def test_streamed_download_converts_its_status_check():
    c, _ = _recording_client(responder=lambda _r: httpx.Response(404, text="no sessions"))
    with pytest.raises(UpstreamError) as err:
        await c.arkime_session_pcap("3@240425-abc")
    assert err.value.status == 404


# -- Rate limiting -----------------------------------------------------------


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now


def _fake_clock(monkeypatch: pytest.MonkeyPatch) -> tuple[_Clock, list[float]]:
    clock = _Clock()
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)
        clock.now += delay

    monkeypatch.setattr(client_mod.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(client_mod.asyncio, "sleep", fake_sleep)
    return clock, slept


async def test_rate_limiter_lets_the_first_burst_through(monkeypatch: pytest.MonkeyPatch):
    _clock, slept = _fake_clock(monkeypatch)
    c = MalcolmClient(base_url="https://malcolm.example", max_requests_per_minute=3)
    request = httpx.Request("GET", "https://malcolm.example/mapi/ping")
    for _ in range(3):
        await c._rate_limit(request)
    assert slept == []


async def test_rate_limiter_blocks_the_request_past_the_cap(monkeypatch: pytest.MonkeyPatch):
    clock, slept = _fake_clock(monkeypatch)
    c = MalcolmClient(base_url="https://malcolm.example", max_requests_per_minute=2)
    request = httpx.Request("GET", "https://malcolm.example/mapi/ping")
    await c._rate_limit(request)
    clock.now += 10.0
    await c._rate_limit(request)
    await c._rate_limit(request)
    # The third has to wait out the oldest of the two, 50s after it was made.
    assert slept == [pytest.approx(50.0)]
    # ...and once the window has moved on, nothing waits again.
    clock.now += 60.0
    await c._rate_limit(request)
    assert len(slept) == 1


async def test_rate_limit_hook_is_registered_on_the_shared_client():
    c = MalcolmClient(base_url="https://malcolm.example")
    http = await c._client()
    assert c._rate_limit in http.event_hooks["request"]
    await c.close()


async def test_concurrency_cap_reaches_the_connection_pool():
    c = MalcolmClient(base_url="https://malcolm.example", max_concurrency=3)
    http = await c._client()
    # httpx exposes the bound only on the transport's pool; asserting the value
    # we passed would prove nothing about it being wired.
    assert http._transport._pool._max_connections == 3
    await c.close()


def test_from_env_reads_both_bounds(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MALCOLM_MAX_CONCURRENCY", "3")
    monkeypatch.setenv("MALCOLM_MAX_REQUESTS_PER_MINUTE", "42")
    c = MalcolmClient.from_env()
    assert c._max_concurrency == 3
    assert c._max_requests_per_minute == 42


@pytest.mark.parametrize("raw", ["0", "abc", "-5", ""])
def test_a_bound_that_would_disable_the_limiter_falls_back_and_says_so(
    raw: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    """A zero is the interesting case: it is all digits, so only the "> 0" half
    of _positive_int_env rejects it, and a cap of 0 is not "no cap" but a broken
    one -- _rate_limit would index an empty deque. A blank value is the unset
    case and must fall back silently rather than warn."""
    monkeypatch.setenv("MALCOLM_MAX_CONCURRENCY", raw)
    monkeypatch.setenv("MALCOLM_MAX_REQUESTS_PER_MINUTE", raw)
    with caplog.at_level(logging.WARNING, logger=client_mod.logger.name):
        c = MalcolmClient.from_env()

    assert c._max_concurrency == client_mod._DEFAULT_MAX_CONCURRENCY
    assert c._max_requests_per_minute == client_mod._DEFAULT_MAX_REQUESTS_PER_MINUTE
    warned = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    if raw:
        assert len(warned) == 2, warned
        assert all(repr(raw) in message for message in warned), warned
    else:
        assert warned == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_requests_per_minute": 0},
        {"max_requests_per_minute": -1},
        {"max_concurrency": 0},
        {"max_concurrency": -1},
    ],
)
def test_a_non_positive_bound_passed_in_code_raises_at_construction(kwargs: dict[str, int]):
    """The standalone-import path the module docstring advertises.

    from_env can no longer produce these, but a direct caller could, and the
    failure used to land far away: max_requests_per_minute=0 raised IndexError
    out of _rate_limit's empty deque on the first request, max_concurrency=0
    hung until the connect timeout. The env path logs and falls back because a
    deployment typo must not stop the server; a caller writing 0 in code has a
    bug that a substituted default would hide.
    """
    with pytest.raises(ValueError) as err:
        MalcolmClient(base_url="https://malcolm.example", **kwargs)
    assert next(iter(kwargs)) in str(err.value)


def test_from_env_defaults_are_generous(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MALCOLM_MAX_CONCURRENCY", raising=False)
    monkeypatch.delenv("MALCOLM_MAX_REQUESTS_PER_MINUTE", raising=False)
    c = MalcolmClient.from_env()
    assert c._max_concurrency >= 8
    assert c._max_requests_per_minute >= 600
