# Use the client from Python

## Python (direct import)

`MalcolmClient` is usable on its own, with no MCP client, no server process and no `mcp` transport in the loop. `mcp_server_malcolm`'s `__all__` is `["MalcolmClient", "__version__"]`, and that one class carries 62 public methods covering the entire read surface. The calls below were run against Malcolm's public training instance (`training.malcolm.fyi`, Malcolm 26.09.0) with release 1.2.1.

Build a client either from the environment or from explicit arguments:

```python
import asyncio
from mcp_server_malcolm import MalcolmClient

async def main():
    client = MalcolmClient.from_env()          # reads MALCOLM_URL, MALCOLM_USERNAME, …
    # or:
    # client = MalcolmClient(
    #     base_url="https://malcolm.example",
    #     username="analyst",
    #     password="…",
    #     ssl_verify=False,
    # )
    try:
        # Malcolm filter dict
        hits = await client.search(
            filters={"event.dataset": "conn"},
            limit=5,
        )

        # Top values of a field, over one 24-hour window
        agg = await client.aggregate(
            fields="destination.port",
            filters={"event.dataset": "conn"},
            limit=5,
            time_from="1614556800",
            time_to="1614643200",
        )

        # Check a field name before trusting a query that returned nothing
        ok = await client.resolve_field("http.useragent")
        bad = await client.resolve_field("http.user_agent")

        # Arkime expression syntax, epoch-second window
        sessions = await client.arkime_sessions(
            expression="protocols==dns",
            limit=3,
            time_from="1614556800",
            time_to="1614643200",
        )
    finally:
        await client.close()

asyncio.run(main())
```

What those calls actually returned:

```
search()     keys: ['filter', 'range', 'results']
aggregate()  {'destination.port': {'buckets': [{'doc_count': 12733, 'key': 389},
                                               {'doc_count': 6361, 'key': 53},
                                               {'doc_count': 4768, 'key': 80}, …]}}
resolve_field('http.useragent')   {'exists': True,  'field': 'http.useragent', 'type': 'string'}
resolve_field('http.user_agent')  {'exists': False, 'field': 'http.user_agent',
                                   'suggestion': 'http.useragent', 'type': 'string'}
arkime_sessions()  recordsTotal: 7718258  recordsFiltered: 6711
                   first session id: 3@21w08:21w08-QwZ9QRb977tLU5XWt-WTaQ0B
```

`search()` returns `{"filter", "range", "results"}` on this Malcolm version, with the hits under `results` and **no** top-level `total` key. Read the payload you actually get rather than assuming a shape.

**Closing the client is the caller's job.** `MalcolmClient` has `close()` but no `__aenter__`/`__aexit__`, so `async with MalcolmClient(...)` raises:

```
TypeError: 'mcp_server_malcolm.client.MalcolmClient' object does not support
the asynchronous context manager protocol (missed __aexit__ method)
```

Use `try`/`finally` as above. Dropping the last reference without closing leaves a real open socket to Malcolm, reclaimed only when the garbage collector gets to it, and the warning is silent under normal interpreter settings — it appears only under `python -W always -X dev`:

```
ResourceWarning: unclosed <socket.socket fd=6, family=2, type=1, proto=6, …>
```

**Errors.** Three exceptions, all with `MalcolmToolError` as their base:

```python
from mcp_server_malcolm.errors import MalcolmToolError, ToolInputError, UpstreamError
```

| Raised | When | What it carries |
| --- | --- | --- |
| `ToolInputError` | An argument fails the client's own validation, before any HTTP request | The offending value and the expected shape |
| `UpstreamError` with `.status` set | Malcolm answered with an HTTP error | Status code, plus the URL and status text |
| `UpstreamError` with `.status is None` | The request never completed (DNS, TLS, connect, timeout) | The status, and nothing else — see below |

Observed messages:

```
ToolInputError:  invalid field name: '../../arkime/api/hunts' — expected a Malcolm
                 field name such as 'source.ip' (letters, digits and _ . - @ [ ])
UpstreamError:   status=404  message=Client error '404 Not Found' for url
                 'https://malcolm.example/dashboards/api/saved_objects/search/00000000-…'
UpstreamError:   status=None message=
```

That last one is the library-side view of the empty error message described under [When the first call fails](troubleshooting.md#when-the-first-call-fails): `str(exc)` is the empty string. It was traced past this project's code to `httpx.ConnectTimeout.__str__()`, which is empty for the same host when called through a bare `httpx.AsyncClient`. Branch on `exc.status is None` to detect an unreachable host; the message will not tell you anything.

**Rate limiting holds, it does not raise.** `MALCOLM_MAX_CONCURRENCY` (default 8) and `MALCOLM_MAX_REQUESTS_PER_MINUTE` (default 600) also exist as the constructor arguments `max_concurrency` and `max_requests_per_minute`. With `max_requests_per_minute=2`, three sequential `ping()` calls against Malcolm's public training instance completed at:

```
request 1  t+1.6s
request 2  t+1.8s
request 3  t+61.1s
```

with `[malcolm] rate cap reached, holding https://…/mapi/ping for 58.5s` on the DEBUG log. There is no rate-limit exception: past the cap, a call is indistinguishable from a slow one, so a per-call timeout tighter than the window will fire on what is really a queued request. The 60-second window itself is a module constant (`_RATE_WINDOW_SECONDS`), not configurable — only the request count inside it is. A non-positive constructor argument is rejected outright:

```
ValueError: max_concurrency must be a positive integer, got 0
ValueError: max_requests_per_minute must be a positive integer, got 0
```

The environment path is deliberately more forgiving: an absent, blank or unparseable value is logged and replaced with the default (`client.py:68-82`), so a typo in a deployment's env file cannot switch the limiter off.

**There is no supported write path for a library user.** All seven write primitives are private — `_write_event`, `_write_arkime_tags`, `_write_arkime_view`, `_write_arkime_shortcut`, `_write_arkime_hunt`, `_write_arkime_hunt_cancel`, `_write_upload_pcap` — and each is called from exactly one place under `tools/write/`, which a seam test enforces. No public method indexes an alert, tags a session, creates or cancels a hunt, saves a view or shortcut, or uploads a PCAP. Calling an underscore method directly performs the mutation while skipping the audit record that `tools/write/_common.py::run_write` writes around every write reached through the MCP layer, so writes belong to the tool layer, and the direct-import path is a read client.
