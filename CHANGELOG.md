# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

An API-coverage pass (verified against Malcolm's Flask source and the Arkime
v6.x viewer API) plus findings from a multi-perspective code review (security,
Python quality, test coverage). Two of the changes alter default behavior — see
**Changed**.

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

[Unreleased]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nagameTW/mcp-server-malcolm/releases/tag/v0.1.0
