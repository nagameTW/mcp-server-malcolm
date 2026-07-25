# Security policy

This server sits between an AI agent and a Malcolm deployment that holds network
traffic and asset data, so the security model is worth stating plainly.

## Reporting a vulnerability

Report privately through GitHub's security advisories:

**https://github.com/nagameTW/mcp-server-malcolm/security/advisories/new**

Please don't open a public issue for a security problem. Give it a few days for
a first response. Once there's a fix, we'll coordinate the disclosure timing
with you.

When you write it up, the useful details are: the version or commit, whether any
write classes were enabled, and a way to reproduce. Redact hosts, credentials,
and any capture data before you send anything.

## Supported versions

The project is pre-1.0, so only the latest release gets fixes. Pin a version and
watch releases if you run it anywhere that matters.

## The security model

A few properties hold by design, and they're the things to check against if you
think you've found a problem.

**Read-only until you opt in.** With no configuration the server exposes read
tools only. A disabled write class is never registered, so its tools don't
appear in `list_tools()` and can't be called at all, even by a compromised or
confused agent.

**Writes are split and gated.** Write access is four classes, each behind its
own environment flag, each off by default: `alerting`, `arkime-tag`,
`hunt-job`, and `pcap-upload`. Turning one on doesn't turn on the others.

**Writes are additive.** Version 1 has no tool that deletes data, removes a tag,
or touches user accounts. That narrows the blast radius of a bad tool call.

**Writes are audited.** Every write attempt emits one audit line. Point
`MALCOLM_MCP_AUDIT_FILE` at a file to keep that trail.

## What's in scope

- A write that fires while its class flag is off.
- A read tool that reaches beyond its stated data.
- Credentials, hosts, or capture data leaking into logs, audit lines, or tool
  output that shouldn't carry them.
- A tool argument that lets an agent reach a Malcolm endpoint the tool wasn't
  meant to touch.

## What's out of scope

- Malcolm itself, and its components (Zeek, Suricata, Arkime, OpenSearch,
  NetBox). Report those upstream.
- Anything that needs credentials the operator already chose to hand the server.
  The server acts with the access you give it; a misconfigured deployment that
  grants too much isn't a server vulnerability.
- Prompt injection reaching the agent from data the agent chose to fetch. The
  server delimits the data it returns, but it can't control what an agent does
  with a Malcolm instance it has been pointed at.
