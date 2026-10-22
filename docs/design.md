# Design

## Why an MCP layer

Malcolm keeps all network metadata in one OpenSearch index (`arkime_sessions3-*`) with non-standard field names and its own filter syntax. An LLM asked to write raw OpenSearch DSL against that index gets it wrong more often than not. This server takes that job off the model:

- It exposes Malcolm's filter syntax instead of raw DSL.
- It provides field discovery so the model checks field names before it queries.
- It provides value enumeration so the model sees what values a field actually holds.
- It covers both field vocabularies. Arkime expressions take Arkime's own names (`ip.src`), the rest of Malcolm takes ECS names (`source.ip`), and Malcolm's own field list carries only the second set. `arkime_field_search` supplies the first.
- It wraps Suricata alert queries and handles the field mapping (`suricata.alert.*` vs `rule.*`).
- It adds NetBox asset context (IP-to-device, network segments).

The failure mode this is built against is a quiet one. Malcolm answers a query
against a field it does not index with an empty result rather than an error, so
a model that guesses a plausible-but-wrong name reads "no such traffic" and
moves on. When a search comes back empty, this server checks the fields the
query named and reports the name Malcolm actually stores the value under. That
lookup runs only after a result set is already empty, so nothing is added to
the model's context on queries that worked.

The write side follows the same idea. Rather than hand an agent the raw OpenSearch and NetBox passthroughs that Malcolm already leaves open to any authenticated user, this server exposes a small, named, audited set of write actions. More on that under [Security model](security.md#security-model).

## Protocol notes

This is what a client sees when it connects, and where the two protocol eras differ. None of it needs a decision from you; it is here for anyone driving the server from an SDK.

**What the client sees on connection.** This server answers both protocol eras, and which one you get is decided by your first request, not by any setting here. A client that opens with `initialize` gets the handshake era; a client whose first request carries the `io.modelcontextprotocol/protocolVersion` key in `_meta` gets the stateless 2026-07-28 era, with no handshake at all. The SDK routes this in `serve_dual_era_loop`; nothing in this project configures it.

With no write flags set, an `initialize` plus `tools/list` returns:

```
protocol_version: 2025-11-25
server_info:      name='mcp-server-malcolm' version='1.2.1'
capabilities:     prompts, resources (subscribe=false), tools — all list_changed=false
instructions:     3753 characters
tools:            51
prompts:          1  — hunt_workflow
resources:        2  — malcolm://fields/malcolm, malcolm://fields/arkime
```

2025-11-25 is the ceiling of the handshake era, not this server's ceiling: `initialize` does not exist at 2026-07-28, so measuring through it can only ever report the older number. A 2026-07-28 client sends no handshake and calls `server/discover` instead:

```
server/discover  capabilities: prompts, resources (subscribe=true), tools — all listChanged=true
                 cacheScope=private  ttlMs=0  resultType=complete
tools/list       51 tools, cacheScope=public ttlMs=3600000 resultType=complete
_meta on results io.modelcontextprotocol/serverInfo = {name: mcp-server-malcolm, version: 1.2.1}
```

The two eras disagree about `listChanged`, and the modern side is the one that overstates: the SDK advertises `listChanged=true` there, while this server registers everything once in `create_server()` and never emits a change notification. Harmless, because a list that cannot change cannot go unannounced, but do not build on the promise.

The Arkime resource serves Arkime's whole expression-field catalogue, several hundred kilobytes of text. One caveat for anyone scripting against the SDK: `mcp` 2.x uses snake_case attributes (`protocol_version`, `server_info`, `is_error`), not the camelCase of the wire protocol and the 1.x SDK. A script written against `serverInfo`/`isError` raises `AttributeError`.
