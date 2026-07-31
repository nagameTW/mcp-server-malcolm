"""Arkime's three field vocabularies, and the guard that keeps two of them apart.

Arkime names the same field up to three times. `ip.src` is what its expression
parser reads; `srcIp` is what /api/connections resolves; `source.ip` is the
storage path /api/spigraph and /api/spiview aggregate on. Sending one where
another belongs does not produce a clean error, which is why a guard exists
rather than a docstring alone -- for the first two. The third is left to the
descriptions, and the tests at the bottom of this file say why. Every number
below was measured against Malcolm 26.07.1 over the window
1714003200-1714089600:

    GET /api/multiunique         exp=ip.src,ip.dst        -> 692 rows
                                 exp=ip.src,port.dst      -> 22548 rows
                                 exp=bytes.src,bytes.dst  -> 6677 rows
                                 exp=srcIp,dstIp          -> HTTP 200, body
                                    "Unknown expression srcIp"
    GET /api/spigraphhierarchy   exp=ip.src,ip.dst        -> 140 table rows
                                 exp=srcIp,dstIp          -> HTTP 403, same text
    GET /api/unique              exp=ip.src               -> 112 lines
                                 exp=srcIp                -> HTTP 200, 0 bytes
    GET /api/connections         srcIp/dstIp              -> 10 nodes, 8 links
                                 source.ip/destination.ip -> 10 nodes, 8 links
                                 srcIp/dstPort            -> 15 nodes, 11 links
                                 ip.src/port.dst          -> HTTP 500 TypeError
                                 port.src/dstIp           -> HTTP 403
    GET /api/spigraph            field=destination.ip     -> 10 items
                                 field=protocol           -> 10 items
                                 field=ip.dst             -> 0 items, HTTP 200
                                 field=protocols          -> 0 items, HTTP 200
                                 field=dstIp              -> 0 items, HTTP 200
    GET /api/spiview             spi=protocol:10          -> 10 buckets
                                 spi=destination.ip:20    -> 20 buckets
                                 spi=protocols:10         -> 0 buckets, HTTP 200
                                 spi=ip.dst:20            -> 0 buckets, HTTP 200

The pass-through cases matter as much as the rejections. Malcolm's stored
paths are in NEITHER Arkime vocabulary and work anyway on the expression
routes -- measured: exp=source.ip,destination.ip -> 692 rows (same as
ip.src,ip.dst), exp=source.mac -> 105 rows, exp=network.bytes -> 5544 rows,
srcField=source.ip&dstField=destination.port -> 15 nodes. A guard that
rejected them would break calls that work today, so the table only carries
the sixteen fields whose two Arkime spellings actually differ.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import raised_by
from mcp.server.mcpserver import MCPServer

from mcp_server_malcolm.client import (
    _ARKIME_DB_FOR_EXP,
    _ARKIME_EXP_FOR_DB,
    MalcolmClient,
)
from mcp_server_malcolm.errors import ToolInputError
from mcp_server_malcolm.tools.arkime import register_arkime_tools


def _recorded() -> tuple[MalcolmClient, list[httpx.Request]]:
    """A client that records requests; the body is irrelevant to these tests."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    c = MalcolmClient(base_url="https://malcolm.example")
    c._http = httpx.AsyncClient(
        base_url="https://malcolm.example", transport=httpx.MockTransport(handler)
    )
    return c, seen


# -- the table itself --------------------------------------------------------


def test_table_only_holds_fields_whose_two_spellings_differ():
    """A field spelled the same on both sides must not be in the table.

    3518 of the 4051 rows in Malcolm 26.07.1's /arkime/api/fields spell exp and
    db identically; those names are valid on both routes and an entry for one
    would reject a working call.
    """
    assert all(exp != db for exp, db in _ARKIME_DB_FOR_EXP.items())
    assert len(_ARKIME_EXP_FOR_DB) == len(_ARKIME_DB_FOR_EXP)  # no db name reused
    assert not set(_ARKIME_DB_FOR_EXP) & set(_ARKIME_EXP_FOR_DB)  # the two sides disjoint


def test_table_matches_the_catalogue_fork_rule():
    """The table is the dbField2 != dbField rows, and nothing else.

    Rows verbatim from /arkime/api/fields on 26.07.1. `mac.src` is the trap:
    its db name is a dotted path, it is NOT a fork, and exp=source.mac returns
    105 rows -- so it must stay out of the table.
    """
    catalogue = [
        {"exp": "ip.src", "dbField": "source.ip", "dbField2": "srcIp"},
        {"exp": "port.dst", "dbField": "destination.port", "dbField2": "dstPort"},
        {"exp": "bytes.src", "dbField": "source.bytes", "dbField2": "srcBytes"},
        {"exp": "mac.src", "dbField": "source.mac", "dbField2": "source.mac"},
        {"exp": "node", "dbField": "node", "dbField2": "node"},
        {"exp": "oui.src", "dbField": "srcOui", "dbField2": "srcOui"},
    ]
    forked = {r["exp"]: r["dbField2"] for r in catalogue if r["dbField"] != r["dbField2"]}
    shared = [r["exp"] for r in catalogue if r["dbField"] == r["dbField2"]]

    for exp, db in forked.items():
        assert _ARKIME_DB_FOR_EXP[exp] == db
    for exp in shared:
        assert exp not in _ARKIME_DB_FOR_EXP
        assert exp not in _ARKIME_EXP_FOR_DB


# -- db name on a parameter Arkime parses as an expression -------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("call", "fields"),
    [
        ("arkime_multiunique", "srcIp,dstIp"),
        ("arkime_multiunique", "ip.src,dstPort"),  # one wrong name is enough
        ("arkime_spigraphhierarchy", "srcIp,dstIp"),
        ("arkime_unique", "srcIp"),
    ],
)
async def test_db_name_on_an_expression_parameter_is_refused(call, fields):
    c, seen = _recorded()
    method = getattr(c, call)

    with pytest.raises(ToolInputError) as info:
        await (method(fields) if call != "arkime_unique" else method("", fields))

    message = str(info.value)
    wrong = "srcIp" if "srcIp" in fields else "dstPort"
    assert f"'{wrong}' is an Arkime db name" in message
    assert f"Did you mean '{_ARKIME_EXP_FOR_DB[wrong]}'?" in message
    assert "arkime_field_search" in message
    assert seen == [], "the guard must answer before the request is sent"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        "ip.src,ip.dst",
        "ip.src,port.dst",
        "bytes.src,bytes.dst",
        "source.ip,destination.ip",  # Malcolm's stored path: works, must pass
        "source.mac",
        "network.bytes",
        "node",
        "zeek.dns.query",  # exp == db, so valid on both routes
        " ip.src , port.dst ",  # whitespace around a good name is not a db name
    ],
)
async def test_working_expression_field_lists_reach_arkime(fields):
    c, seen = _recorded()
    await c.arkime_multiunique(fields)
    assert seen and seen[0].url.params.get("exp") == fields


# -- expression name on /api/connections -------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("src", "dst", "wrong", "param"),
    [
        ("ip.src", "dstIp", "ip.src", "srcField"),
        ("srcIp", "ip.dst", "ip.dst", "dstField"),
        ("port.src", "dstIp", "port.src", "srcField"),
    ],
)
async def test_expression_name_on_connections_is_refused(src, dst, wrong, param):
    c, seen = _recorded()

    with pytest.raises(ToolInputError) as info:
        await c.arkime_connections(src_field=src, dst_field=dst)

    message = str(info.value)
    assert f"'{wrong}' is an Arkime expression name" in message
    assert f"{param} takes db names" in message
    assert f"Did you mean '{_ARKIME_DB_FOR_EXP[wrong]}'?" in message
    assert "arkime_field_search" in message
    assert seen == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("src", "dst"),
    [
        ("srcIp", "dstIp"),
        ("srcIp", "dstPort"),
        ("srcPort", "dstPort"),
        ("source.ip", "destination.port"),  # stored paths answer here too
        ("node", "dstIp"),
    ],
)
async def test_working_connection_fields_reach_arkime(src, dst):
    c, seen = _recorded()
    await c.arkime_connections(src_field=src, dst_field=dst)
    assert seen
    assert seen[0].url.params.get("srcField") == src
    assert seen[0].url.params.get("dstField") == dst


# -- the message a model actually sees ---------------------------------------


@pytest.mark.asyncio
async def test_the_tool_surfaces_the_guard_not_an_empty_result():
    """Through the MCP layer the mistake has to raise, not return "(no values)".

    A returned string is a *successful* tool result, which is exactly how
    "Unknown expression srcIp" reached callers as an answer before this guard.
    """
    c, seen = _recorded()
    mcp = MCPServer("t")
    register_arkime_tools(mcp, c)

    raised = await raised_by(mcp, "arkime_multiunique", {"fields": "srcIp,dstIp"})
    assert isinstance(raised, ToolInputError)
    assert "use the exp column" in str(raised)

    raised = await raised_by(mcp, "arkime_connections", {"src_field": "ip.src"})
    assert isinstance(raised, ToolInputError)
    assert "use the db column" in str(raised)
    assert seen == []


# -- the third vocabulary, carried by descriptions instead of a guard --------


async def _described(name: str) -> tuple[str, dict[str, str]]:
    """(tool description, {parameter: description}), whitespace collapsed.

    Docstrings arrive line-wrapped, so a phrase that reads as one string in the
    source is not one in the delivered text; every assertion below wants the
    prose, not the wrapping.
    """
    c, _ = _recorded()
    mcp = MCPServer("t")
    register_arkime_tools(mcp, c)
    tool = {t.name: t for t in await mcp.list_tools()}[name]
    props = (tool.input_schema or {}).get("properties", {})
    flat = " ".join((tool.description or "").split())
    return flat, {k: " ".join(v.get("description", "").split()) for k, v in props.items()}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool", "param", "dead"),
    [
        ("arkime_spigraph", "field", ("ip.dst", "protocols", "dstIp", "port.dst", "dstPort")),
        ("arkime_spiview", "spi", ("protocols:", "ip.dst:", "dstIp:")),
    ],
)
async def test_storage_path_parameters_only_show_examples_that_return_data(tool, param, dead):
    """Every example here was executed; a name that returns nothing must not be one.

    These two parameters are the reason: HTTP 200 with an empty result is what
    a wrong spelling looks like, so an example that silently returns nothing
    teaches the wrong lesson twice over. A dead name may still appear *after*
    "NOT the exp column", where it is labelled as the thing that fails.
    """
    _, params = await _described(tool)
    offered, _, warned = params[param].partition("NOT the exp column")

    assert warned, f"{tool}.{param} does not warn against the expression spelling"
    assert "destination.ip" in offered and "protocol" in offered
    assert not [name for name in dead if name in offered], (
        f"{tool}.{param} still offers a dead example"
    )
    assert all(name in warned for name in dead), f"{tool}.{param} drops a measured counter-example"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["arkime_spigraph", "arkime_spiview"])
async def test_an_empty_result_is_explained_by_recordsfiltered_not_the_time_range(tool):
    """The old text sent a wrong field name off to widen the window instead.

    Measured on 26.07.1: a name that does not resolve returns an empty result
    with recordsFiltered 6,016,935, while a window with nothing in it returns
    recordsFiltered 0. That is the discriminator, so the description has to
    lead with it and demote time_from to the second cause.
    """
    description, _ = await _described(tool)

    assert "recordsFiltered" in description
    field_cause = description.index("did not resolve")
    time_cause = description.index("time_from")
    assert field_cause < time_cause, "the field name has to be named as the first suspect"
    assert "predates" not in description, "the misleading recent-window explanation is back"


@pytest.mark.asyncio
async def test_field_search_routes_each_parameter_to_the_spelling_it_takes():
    """arkime_field_search is what a model reads before every other arkime call.

    Its old routing sentence sent db names to arkime_multiunique, where the
    guard above raises on exactly those. Each of the three vocabularies now has
    to be routed to the parameters that accept it.
    """
    description, _ = await _described("arkime_field_search")

    exp_advice = description[description.index('"exp"') : description.index('"db"')]
    assert "arkime_multiunique" in exp_advice
    assert "arkime_unique" in exp_advice
    assert "arkime_spigraphhierarchy" in exp_advice

    db_advice = description[description.index('"db"') :]
    assert "arkime_connections" in db_advice
    assert "arkime_multiunique" not in db_advice, "db names raise on multiunique"

    storage_advice = description[description.index("storage path") :]
    assert "arkime_spigraph" in storage_advice and "arkime_spiview" in storage_advice
    assert "source.ip" in storage_advice and "destination.port" in storage_advice


@pytest.mark.asyncio
async def test_connections_no_longer_claims_a_dotted_name_errors():
    """Measured: source.ip/destination.ip returns the same 10-node, 8-link graph
    as srcIp/dstIp. Only the expression spelling errors, and the guard eats it."""
    description, params = await _described("arkime_connections")
    whole = description + " ".join(params.values())

    assert "a dotted name errors" not in whole
    assert "source.ip" in whole and "destination.port" in whole
    assert "ip.src" in whole, "the spelling that really fails still has to be named"


def test_the_guard_table_would_cover_too_little_to_extend_to_spigraph():
    """Why the third vocabulary gets no guard: it is not separable from a table.

    Counted from 26.07.1's /arkime/api/fields (4,051 rows): 534 spell `exp`
    differently from `dbField`, and 17 fork `dbField2` from `dbField`. Those
    ~551 names are what fails on spigraph/spiview. The sixteen-pair table knows
    32 of them and misses `protocols`, the name an agent reaches for first --
    it would answer for 6% of the mistakes while reading as a check on all of
    them.
    """
    catalogue_names_that_fail_on_spigraph = 534 + 17
    covered = len(_ARKIME_DB_FOR_EXP) + len(_ARKIME_EXP_FOR_DB)

    assert covered / catalogue_names_that_fail_on_spigraph < 0.10
    assert "protocols" not in _ARKIME_DB_FOR_EXP  # exp != db, yet not a dbField2 fork
    assert "protocol" not in _ARKIME_EXP_FOR_DB
