# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/nagameTW/mcp-server-malcolm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nagameTW/mcp-server-malcolm/releases/tag/v0.1.0
