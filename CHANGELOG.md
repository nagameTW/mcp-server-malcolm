# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
