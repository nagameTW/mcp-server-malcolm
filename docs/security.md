# Security

## Read-only until you opt in

With no configuration, this server exposes read tools only. It behaves like a read-only client, and nothing it does can change data in Malcolm.

The server splits write access into five classes, each behind its own environment flag and each off by default. It doesn't register a disabled class, so that class's tools never appear in `list_tools()` and can't be called. At startup it prints which classes are on:

```
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```

Every write but one is additive: the exception is `arkime_cancel_hunt`, which stops a hunt job in progress rather than adding to it. None of them deletes data, removes a tag, or touches a user account — those stay out on purpose (see [Non-goals](../README.md#non-goals)).

## Security model

Malcolm's default deployment already gives any authenticated user unrestricted write access to raw OpenSearch (`/mapi/opensearch/*`) and full NetBox CRUD (`/mapi/netbox/*`). Both are bare reverse-proxies with no HTTP-verb filtering; Malcolm's own read-only mode removes them rather than trying to filter them. In the common auth modes, "logged in" means admin-equivalent.

Turning on a write class here does not open a door that was otherwise shut. That door is already open at the platform level. This server adds a curated way through it:

- A small, named set of write actions instead of a raw passthrough.
- Off by default, enabled one class at a time.
- An audit line for every write attempt.
- MCP annotations so the client can require confirmation.

This server does **not** expose the raw OpenSearch and NetBox write passthroughs, behind a flag or otherwise. Curating that surface is what it is for.

## Audit

Every write attempt emits one line of JSON, on success and on failure:

```json
{"ts": "2023-11-15T09:41:07Z", "tool": "arkime_add_tags", "class": "arkime-tag", "target": "ids=240601-abc", "params": {"tags": "suspicious"}, "outcome": "ok"}
```

`outcome` is one of `ok`, `http_4xx`, `http_5xx`, or `error:<type>`. Long parameter values are truncated, and PCAP bytes are never logged. The sink is stderr by default; set `MALCOLM_MCP_AUDIT_FILE` to append to a file instead. Read tools are not audited.
