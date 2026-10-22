# Run in a container

## Running it in a container

The repository ships a `Dockerfile` that installs the package from the build context and runs it as a non-root user:

```bash
$ docker build -t mcp-server-malcolm:local -f Dockerfile .
$ docker run --rm --entrypoint id mcp-server-malcolm:local
uid=10001(app) gid=10001(app) groups=10001(app)
```

The image is built on `python:3.11-slim` (Debian 13 trixie). It is single-architecture: a plain `docker build` produces the build host's architecture only, so an image built on arm64 will not run on an x86_64 host without emulation. A multi-architecture image would need `docker buildx build --platform linux/amd64,linux/arm64`; that was not attempted, and this Dockerfile does not produce one.

Point the client at `docker run -i --rm …` as the launch command:

```bash
docker run -i --rm --network host \
  -e MALCOLM_URL -e MALCOLM_USERNAME -e MALCOLM_PASSWORD -e MALCOLM_SSL_VERIFY \
  mcp-server-malcolm:local
```

`-e VAR` with no `=value` inherits the value from the invoking shell, so the password is never part of the command string and never lands in `ps` output or shell history. It is still readable afterwards through `docker inspect`, as below.

How the container reaches Malcolm decides whether anything works at all:

| Reaching Malcolm | Flags | Result |
| --- | --- | --- |
| Host loopback, URL unchanged | `--network host` | Works. `https://localhost` inside the container is the host's loopback. |
| Bridge network | none | Fails: `All connection attempts failed`. `localhost` is the container itself. The underlying errno 111 stays inside the exception chain and never reaches the client. |
| Bridge network | `--add-host=host.docker.internal:host-gateway`, `MALCOLM_URL=https://host.docker.internal` | Works. `host.docker.internal` is not auto-registered on Linux the way it is on Docker Desktop; the explicit `--add-host` is what makes it resolve (Docker 20.10+). |

Both working modes completed a full MCP session: `initialize`, `tools/list` returning 51 tools, and two tool calls (`malcolm_ping` → `pong`, `count`). `MALCOLM_SSL_VERIFY` at its `true` default failed inside the container for the same self-signed-certificate reason it fails outside one.

On credentials: `docker inspect <container> --format '{{json .Config.Env}}'` prints `MALCOLM_PASSWORD` in cleartext, and does so regardless of whether the value was passed as `-e VAR`, `-e VAR=value`, or `--env-file` — Docker stores the resolved environment in the container's metadata either way. Anyone with Docker daemon or socket access can read the Malcolm password back out for as long as the container object exists. There is no `MALCOLM_PASSWORD_FILE`-style secrets-file input; `client.py:324` reads the environment variable and nothing else. Keeping containers ephemeral (`--rm`, one per client session, which is the model a stdio server already implies) shortens the window without closing it.

`MALCOLM_MCP_ENABLE_PCAP_UPLOAD` is the one feature that needs a bind mount, since `malcolm_upload_pcap` reads a file that must already sit inside `MALCOLM_MCP_UPLOAD_DIR`. The host directory mounted there has to be readable by uid 10001 inside the container. That requirement is read from `tools/write/pcap_upload.py`, not exercised — the write classes stayed off throughout this testing.
