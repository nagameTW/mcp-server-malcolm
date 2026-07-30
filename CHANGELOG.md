# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-07-30

### Fixed

- `arkime_session_detail` now returns the session document instead of failing.
  It fetched `GET /arkime/api/session/<id>`, which serves the Arkime SPA HTML
  shell rather than JSON, so every call died parsing HTML as JSON
  (`Expecting value: line 1 column 1`). It now queries `/arkime/api/sessions`
  with an `id ==` expression and `date=-1`, returning the single record, and
  reports a clear message when no session matches. Verified live against
  Malcolm 25.12.1. The prior unit test passed only because its mock returned
  JSON for the HTML endpoint.
- Pin the MCP SDK to `mcp>=1.0,<2`. The 0.4.0 requirement was `mcp>=1.0` with
  no upper bound, so a fresh `pip install mcp-server-malcolm` resolved to
  `mcp` 2.0.0 and the server failed at import with
  `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`. SDK 2.0 renamed
  `FastMCP` to `MCPServer` and moved it to `mcp.server.mcpserver`; every tool
  module here imports the 1.x path. Installs that already resolved to 1.x were
  unaffected. Porting to the 2.0 API (and with it the stateless `2026-07-28`
  protocol revision) is separate work.

## [0.4.0] - 2026-07-28

Audited Malcolm's ingest pipelines (`logstash/pipelines/`) against the fields
this server queries, after Malcolm's maintainer pointed at them as the place
where field-mapping quirks are settled. Three of those quirks were live bugs.

### Added

- `arkime_field_search`: field discovery for Arkime's expression syntax.
  Arkime expressions take Arkime's own names (`ip.src`, `port.dst`), and
  `/mapi/fields` does not list them: it merges Arkime's field table keyed by
  `dbField2` and drops the `exp` alias, so the list carries `srcIp` and
  `source.ip` but never `ip.src`. An agent had no way to discover a name that
  works inside an `expression` argument — it had to guess. Each result of the
  new tool carries the expression name and the db name, and says which goes
  where.
- An empty `malcolm_search` / `malcolm_aggregate` / `malcolm_field_values`
  result now reports any queried field that Malcolm does not index, together
  with the name it stores the value under. Filtering on a renamed field is not
  an error in Malcolm — it silently matches nothing, which reads as "this
  traffic does not exist". The lookup runs only once a result set is already
  empty, so nothing is added on the happy path.
- `resolve_field` consults a table of ingest renames before falling back to
  string similarity. For `suricata.alert.signature`, `difflib` returns
  `suricata.alert.rev` and friends: real fields, all wrong, and indistinguishable
  from the truth. The table is drawn from Malcolm's pipeline source and covers
  only jumps that share no spelling with their target.

### Fixed

- Malcolm's filter dict does not support wildcards, and this server documented
  that it did. `filtervalues()` compiles the dict to an OpenSearch `terms`
  query, so `{"rule.name": "*MALWARE*"}` searches for a signature literally
  named `*MALWARE*` and matches nothing — no error, just an empty result an
  agent reads as "no such traffic". The wildcard examples are gone from the
  tool descriptions, the hunt prompt and both READMEs, which now state that
  values are exact and point at `search_dsl` for substring matching.
- `malcolm_alerts(signature=...)` filtered `suricata.alert.signature` wrapped
  in wildcards, so it failed twice over: `11_suricata_logs.conf` renames that
  field to `rule.name` outright, and the wildcards could not match regardless.
  Every signature search returned zero alerts whatever the data held. Both
  `signature` and `category` now resolve the substring against the recorded
  values first and filter on the exact matches; a substring nothing matches
  says so instead of returning an empty result set.
- `malcolm_related_sessions` queried `related.zeek.uid`, a field that exists
  nowhere in Malcolm. The "related" half of every correlation came back empty
  and was reported as a successful `N direct + 0 related`. Malcolm parks the
  Zeek connection UID in Arkime's `rootId`, which is what actually ties a
  flow's dns/ssl/files records to its conn record.
- `malcolm_search` documented its default time window as "Malcolm's default
  recent window". `/mapi/document` defaults to all history and `/mapi/agg` to
  the last 24 hours, so the two tools covered different periods from identical
  arguments and the description stated the opposite of the truth for one of
  them. Both are now documented as they behave.

### Changed

- `arkime_sessions` documents the expression rules an agent cannot discover by
  probing: existence is the literal token `EXISTS!`, a list literal is an OR,
  and there is no free-text search — every clause must be field-operator-value.

## [0.3.3] - 2026-07-26

### Fixed

- Corrected the MCP Registry server name casing to `io.github.nagameTW/...`
  (was lowercase `nagametw`). The registry namespace check is case-sensitive and
  must match the GitHub account (`nagameTW`), so publishing was rejected with a
  403. The `mcp-name:` ownership token in the README is updated to match; this
  release republishes it to PyPI so ownership verification passes.

### Changed

- Shortened the `server.json` `description` to fit the MCP Registry's 100-char
  limit, so the server can be published to the official registry
  (registry.modelcontextprotocol.io). No effect on the PyPI package.

## [0.3.2] - 2026-07-26

### Changed

- Enriched the `malcolm_related_sessions` and `malcolm_field_profile` tool
  docstrings to disclose the behavior an agent can't infer from the schema:
  `malcolm_related_sessions` runs two independent searches (so `limit` caps each
  side separately, up to 2×limit total) and reports per-side `direct_error` /
  `related_error` on partial failure; `malcolm_field_profile` has three distinct
  text outcomes (unknown-field-with-suggestions / known-but-empty / the profile)
  and its counts honor Malcolm's default recent window. No behavior change —
  descriptions only.

### Added

- Glama score and card badges in the README (both language versions).

### Fixed

- `arkime_connections` now defaults its `src_field` / `dst_field` to Arkime db
  field names (`srcIp` / `dstIp`) instead of dotted ECS names (`ip.src` /
  `ip.dst:port`). Arkime's `/api/connections` resolves these itself and errored
  with a 500 (an internal `TypeError`) on a dotted name, so the tool failed on
  its own defaults. Found by a live smoke test against Malcolm 25.12.1; the fix
  is verified against that server. Pass Arkime db names (`srcIp`, `dstIp`,
  `dstPort`, `node`) — the docstring and parameter descriptions now say so.

An API-coverage pass (verified against Malcolm's Flask source and the Arkime
v6.x viewer API) plus findings from a multi-perspective code review (security,
Python quality, test coverage). Two of the changes alter default behavior — see
**Changed**, and the migration note below.

> **Upgrading from 0.2.x:** TLS verification is now on by default — if you
> pointed the server at a self-signed Malcolm with `MALCOLM_SSL_VERIFY="false"`,
> either keep that (isolated labs only) or, preferably, set it to your Malcolm
> CA-cert path. And `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` now also requires
> `MALCOLM_MCP_UPLOAD_DIR` — set it to the staging directory holding uploadable
> files, or PCAP upload stays refused.

### Changed

- Every tool definition reworked for LLM/agent legibility (and Glama's TDQS
  quality score): a human `title` and full MCP annotations (`readOnlyHint`,
  `destructiveHint`, `idempotentHint`, `openWorldHint`) on all 36 tools, a
  description on every one of the ~110 parameters (via `Annotated[…, Field]`,
  since this FastMCP release doesn't read `Args:` docstrings into the schema),
  and docstrings rewritten to state each tool's purpose, when to use it versus
  its siblings, and what it returns. No tool behavior changed. A new
  `test_tool_quality.py` guards these properties so a future tool can't
  regress them.

### Added

- New read tools closing Arkime coverage gaps: `arkime_multiunique` (unique value
  combinations across fields), `arkime_spigraphhierarchy` (hierarchical top-N
  drill-down), and `arkime_file_by_hash` (extract the transferred file whose
  md5/sha256 matches — the payload-forensics gap; returns metadata only, never
  raw bytes in the response).
- New opt-in write class `arkime-view` (`MALCOLM_MCP_ENABLE_ARKIME_VIEWS`) with
  `arkime_create_view` (save a named search expression) and
  `arkime_create_shortcut` (save a named value list / IOC set, referenced as
  `$name`). Both additive; audited like every other write.
- A `hunt_workflow` MCP prompt: a cold-start, worked tool-chaining guide (schema
  discovery → search → drill-in → pivot → record) with the field-name,
  time-format, and session-id gotchas spelled out.
- Enriched the server `instructions` string with the three query dialects and
  when to use each, the epoch-vs-dateparser time rule, and the
  session-id → pcap/payload/tag dependency chain, so an agent can plan before
  reading individual tool docstrings.

### Security

- PCAP upload no longer accepts an arbitrary local path. `malcolm_upload_pcap`
  now requires the file to sit inside a configured staging directory
  (`MALCOLM_MCP_UPLOAD_DIR`), resolving symlinks before the containment check;
  with the directory unset, uploads are refused. This removes an
  arbitrary-file-read-and-exfiltration path a prompt-injected caller could
  otherwise have used to ship a credential file off the host.
- TLS verification is now **on by default** (`MALCOLM_SSL_VERIFY` unset ⇒
  `true`). The previous default transmitted Basic-auth credentials and query
  results over an unverified channel, and the documented example paired it with
  a remote host. For self-signed Malcolm, point `MALCOLM_SSL_VERIFY` at the CA
  cert instead of disabling verification.
- `arkime_session_pcap` / `arkime_session_detail` now reject a `..` session id,
  closing a single-hop path-traversal gap in the id validator (the other path
  validators already had this guard).
- The write-primitive seam test now parses the AST instead of grepping text, so
  it also catches dynamic dispatch (`getattr(client, "_write_event")`) — the
  previous regex only caught direct attribute access.

### Changed

- **Breaking:** `MALCOLM_SSL_VERIFY` now defaults to `true` (was `false`). Set
  it to `false` explicitly for an isolated localhost lab, or to a CA-bundle path
  for self-signed certs.
- **Breaking:** enabling `MALCOLM_MCP_ENABLE_PCAP_UPLOAD` now also requires
  `MALCOLM_MCP_UPLOAD_DIR` — without it, upload calls return an error.
- `arkime_session_pcap` streams the download and enforces a 500 MB cap instead
  of reading an unbounded body fully into memory.

### Fixed

- Closed a race in the lazily-created HTTP client: concurrent first calls could
  each build an `httpx.AsyncClient` and leak the first one's connection pool. A
  lock now guards the check-and-create.

### Internal

- Extracted the repeated write-tool audit-on-every-outcome logic into a shared
  `run_write` helper.
- Moved the `_arkime_query` static method to a module-level function (project
  style: no `staticmethod`).
- Enabled the `BLE` (blind-except) lint rule and annotated the intentional
  MCP-boundary broad-except sites, so future accidental ones are flagged.
- Removed dead code (`_format_json`); added tests for `_extract_buckets`,
  `resolve_field`, `_parse_filters`, the write-gate's bundled read tool, the
  upload containment guard, and the AST seam check (66 → 92 tests).

## [0.2.0] - 2026-07-26

This release closes the biggest gaps found while auditing the tool surface
against the upstream Malcolm, Arkime, and NetBox APIs. Everything here is
read-only or an additive parameter — no new write class, and existing tools
change only by gaining optional arguments.

### Added

- `malcolm_netbox_query`: a read-only passthrough to any NetBox REST endpoint
  (services, VLANs, interfaces, virtual machines, contacts, and the rest), for
  the parts of NetBox that `malcolm_netbox_lookup` doesn't surface. The path is
  validated against a NetBox-path shape so it can't traverse out of the proxy
  or smuggle a scheme/host.
- `doctype` argument on `malcolm_search` and `malcolm_aggregate`, so a query can
  target the host/beats index or the Arkime sessions index instead of always
  hitting the default Malcolm network index.
- `category`, `action`, and `sid` arguments on `malcolm_alerts` for richer
  Suricata alert filtering. `category` and `sid` map to the ECS fields Malcolm
  normalizes to (`rule.category`, `rule.id`), not the raw `suricata.alert.*`
  names, which the ingest pipeline renames away.
- `arkime_session_pcap` now accepts several comma-separated session ids and
  returns a single combined PCAP.

### Changed

- Clarified tool docstrings so an agent picks the right tool the first time:
  the epoch-seconds vs. dateparser time-format split between the Arkime and
  Malcolm tools, when to reach for `malcolm_search` vs. `arkime_sessions`, the
  `count` (inner query) vs. `search_dsl` (full body) distinction, and the note
  that `arkime_hunt_status` is only registered when the hunt-job write class is
  enabled.

## [0.1.0] - 2026-07-24

The first release. An MCP server that gives any MCP-compatible AI agent
structured access to a Malcolm deployment, so the agent works through named
tools instead of guessing at field names and filter syntax.

### Added

- Read tools, available with no configuration:
  - OpenSearch DSL core: `search_dsl`, `count`, `list_indices`, `index_mapping`, `cluster_health`.
  - Malcolm query and field discovery: `malcolm_search`, `malcolm_aggregate`, `malcolm_alerts`, `malcolm_field_search`, `malcolm_field_values`, `malcolm_field_profile`.
  - Health and coverage: `malcolm_service_status`, `malcolm_data_coverage`, `malcolm_ping`.
  - NetBox assets: `malcolm_netbox_lookup`, `malcolm_netbox_sites`.
  - Arkime: `arkime_sessions`, `arkime_session_detail`, `arkime_session_pcap`, `arkime_unique`, `arkime_spigraph`, `arkime_spiview`, `arkime_connections`.
  - Correlation and export: `malcolm_related_sessions`, `malcolm_dashboard_export`.
- Write tools, off by default and split into four opt-in classes, each behind
  its own environment flag. A disabled class is never registered, so its tools
  can't be called. Every write emits an audit line.
  - `alerting`: `malcolm_create_alert`.
  - `arkime-tag`: `arkime_add_tags`.
  - `hunt-job`: `arkime_create_hunt`, `arkime_hunt_status`.
  - `pcap-upload`: `malcolm_upload_pcap`.
- A `Dockerfile` for container deployment.

### Security

- Read-only by default. Writes are additive only: this version has no tool that
  deletes data, removes a tag, or touches user accounts.

[Unreleased]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nagameTW/mcp-server-malcolm/releases/tag/v0.1.0
