# Install and register

You don't write any code to use this. An MCP client (Claude Code, Claude Desktop, Cursor, …) launches the server as a subprocess and talks to it over stdio; your job is to tell the client how to launch it and which credentials to inject.

[Where these docs were tested](verification.md#where-these-docs-were-tested) lists which commands on this page were run as printed for this revision, and on what platform. Error text quoted from those runs is verbatim.

## 1. Install

You need Python 3.11 or newer, a Malcolm instance with API access, and an HTTPS route to it.

```bash
pip install mcp-server-malcolm      # published release
```

Check the install by starting the server with stdin closed. It prints its write-class banner, reaches EOF, and exits 0:

```bash
$ mcp-server-malcolm < /dev/null
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
$ echo $?
0
```

Nothing has to be configured for the process to start. Connection settings are read at startup but not used until a tool calls Malcolm, so a wrong URL or password surfaces as a failing tool call, not a failed launch.

## 2. Register it with your client

**Claude Code** — one command, no config file to find:

```bash
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD='your-password' \
  -e MALCOLM_SSL_VERIFY=/path/to/malcolm-ca.crt \
  -- mcp-server-malcolm
```

Everything after `--` is the launch command; each `-e` is an environment variable injected into it. `claude mcp add --help` gives the signature as `claude mcp add [options] <name> <commandOrUrl> [args...]`, with `-e, --env <env...>` and `-s, --scope <scope>`.

Registering, health-checking and removing a server, run end to end:

```bash
$ claude mcp add malcolm-deploy-test -s local \
    -e MALCOLM_URL=https://malcolm.example \
    -e MALCOLM_USERNAME=analyst \
    -e MALCOLM_PASSWORD='your-password' \
    -e MALCOLM_SSL_VERIFY=false \
    -- /tmp/mcp-malcolm-deploy/venv/bin/mcp-server-malcolm
Added stdio MCP server malcolm-deploy-test with command: … to local config

$ claude mcp list
Checking MCP server health…
malcolm-deploy-test: /tmp/mcp-malcolm-deploy/venv/bin/mcp-server-malcolm  - ✔ Connected

$ claude mcp remove malcolm-deploy-test -s local
Removed MCP server malcolm-deploy-test from local config
```

Pick where the entry is stored with `-s`:

| Scope | Stored in | Use for |
| --- | --- | --- |
| `local` (default) | your own settings, this project only | credentials — nothing is committed |
| `user` | your own settings, every project | a Malcolm you use everywhere |
| `project` | `.mcp.json` at the repo root, **committed to git** | sharing with a team — never put a password here |

The password in that command is a literal, so it goes into your shell history, and for as long as `claude mcp add` runs it sits in `ps` where every other process on the host can read it. Read it in first and pass the variable:

```bash
read -rs MALCOLM_PASSWORD && export MALCOLM_PASSWORD
claude mcp add malcolm \
  -e MALCOLM_URL=https://malcolm.example \
  -e MALCOLM_USERNAME=analyst \
  -e MALCOLM_PASSWORD="$MALCOLM_PASSWORD" \
  -- mcp-server-malcolm
```

`read -rs` keeps the typing off the screen, and the shell records the unexpanded `"$MALCOLM_PASSWORD"`, so history holds the variable name instead of the secret. The `ps` window during the `add` itself stays open, the same way `docker inspect` keeps a container's copy readable. Either route ends with the password in cleartext in `~/.claude.json`, mode 0600 on the machine this was checked on, so file permissions are the only thing protecting it there.

`claude mcp get malcolm` prints the registered command and environment. Note that it prints `MALCOLM_PASSWORD` in cleartext, unmasked, so don't run it where the terminal is being recorded or shared.

For a `project`-scope entry, keep the secret in each person's shell rather than in the file:

```json
{
  "mcpServers": {
    "malcolm": {
      "command": "mcp-server-malcolm",
      "env": { "MALCOLM_PASSWORD": "${MALCOLM_PASSWORD}" }
    }
  }
}
```

**Other MCP clients** — no equivalent CLI, so edit the client's own JSON config. The block is the same shape:

```json
{
  "mcpServers": {
    "malcolm": {
      "command": "mcp-server-malcolm",
      "env": {
        "MALCOLM_URL": "https://malcolm.example",
        "MALCOLM_USERNAME": "analyst",
        "MALCOLM_PASSWORD": "your-password",
        "MALCOLM_SSL_VERIFY": "/path/to/malcolm-ca.crt"
      }
    }
  }
}
```

That exact block was verified by driving its `command` and `env` fields through the MCP Python SDK's own `stdio_client` and `ClientSession`, which is what a generic client does with them. No GUI client was launched here: Claude Desktop reads `claude_desktop_config.json` and other clients vary, per their own docs, which this project has not independently confirmed.

If `mcp-server-malcolm` isn't on the `PATH` your client sees (common with a virtualenv), give the absolute path to the executable instead: `/path/to/.venv/bin/mcp-server-malcolm`.

## Other ways to install

`pip install mcp-server-malcolm` and bare `uvx mcp-server-malcolm` install the latest published release. A version number alone cannot tell you whether a checkout matches it — a tree carrying unreleased changes still reports the version of the last release — so install from source when you specifically want the code documented in this tree.

From a checkout:

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm.git
cd mcp-server-malcolm
pip install -e .
```

Or build a wheel and install it into a clean virtualenv, which is the path the commands on this page were verified through:

```bash
$ uv build --out-dir /tmp/mcp-malcolm-deploy/dist
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1.tar.gz
Successfully built /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1-py3-none-any.whl

$ python3 -m venv /tmp/mcp-malcolm-deploy/venv
$ /tmp/mcp-malcolm-deploy/venv/bin/pip install \
    /tmp/mcp-malcolm-deploy/dist/mcp_server_malcolm-1.2.1-py3-none-any.whl
```

That pulls 32 packages, most of them from `mcp>=2,<3` (resolved to `mcp 2.2.0` when 1.2.1 shipped). The wheel itself is `py3-none-any`, pure Python. On macOS 26/arm64 with Python 3.14.6, every compiled dependency (`cryptography`, `pydantic-core`, `rpds-py`, `cffi`) installed from a prebuilt `macosx_11_0_arm64` wheel, nothing built from source. PyPI publishes prebuilt wheels of the same dependencies for Linux on arm64 and x86_64, but no Linux or x86_64 install was run for these docs, so treat those as unverified.

To run this branch without installing it anywhere permanent, point `uvx` or `pipx` at the checkout:

```bash
uvx --from /path/to/mcp-server-malcolm mcp-server-malcolm
pipx run --spec /path/to/mcp-server-malcolm mcp-server-malcolm
```

## Running it by hand

Only useful for troubleshooting. A stdio MCP server has no interactive interface: started from a terminal it sits silently waiting for JSON-RPC on stdin, which is what a working server looks like. It does print the enabled write classes to stderr on startup, so this confirms the flags took effect. Both entry points behave identically:

```bash
$ mcp-server-malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off

$ python -m mcp_server_malcolm
[mcp-server-malcolm] write classes: alerting=off arkime-tag=off hunt-job=off pcap-upload=off arkime-view=off
```
