# Contributing

Thanks for looking into this. The server is small and the setup is quick, so
you can get from a fresh clone to a passing test run in a couple of minutes.

## Getting set up

You need Python 3.11 or newer. Clone the repo and install it in editable mode
with the test and lint tools:

```bash
git clone https://github.com/nagameTW/mcp-server-malcolm
cd mcp-server-malcolm
pip install -e . pytest pytest-asyncio ruff
```

The tests don't reach a real Malcolm instance, so you don't need one to work on
most changes. The HTTP client is stubbed in the seam tests.

## Before you open a pull request

Run the same three checks CI runs:

```bash
ruff check src tests
ruff format --check src tests
pytest
```

If `ruff format --check` complains, `ruff format src tests` fixes it in place.

## How the code is laid out

- `src/mcp_server_malcolm/server.py` registers tools and wires up the write gate.
- `src/mcp_server_malcolm/tools/` holds the read tools, one file per area (query, fields, arkime, netbox, and so on).
- `src/mcp_server_malcolm/tools/write/` holds the write tools, split into the five write classes.
- `src/mcp_server_malcolm/config.py` owns the write-class flags. `audit.py` owns the audit sink.
- `tests/` mirrors that structure. Read tests and write tests are separate files.

## The one rule that shapes everything

Version 1 is read-first and additive. No tool deletes data, removes a tag, or
touches user accounts, and every write sits behind a class flag that is off by
default. If your change adds a write, it has to fit that model:

- The tool is additive.
- It lives behind one of the existing write classes, or you make the case for a
  new one in the pull request.
- It emits an audit line when it runs.

A destructive tool is a non-goal for now. That isn't a maybe-later placeholder;
it's a deliberate boundary. If you think a case genuinely needs one, open an
issue and argue it before you write code, so we don't waste your time on a
review that can't land.

## Adding a tool

1. Write the test first. Read tools go in the matching `tests/test_read_*.py`;
   write tools get their own `tests/test_write_*.py`.
2. Add the tool in the right module and register it in `server.py`.
3. Give it a docstring an agent can act on. The whole point of this server is
   that the model doesn't guess, so the description matters.
4. Update the README and `README.zh-TW.md` if you changed behavior or config.
5. Add a line under `[Unreleased]` in `CHANGELOG.md`.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org):
`feat:`, `fix:`, `docs:`, `chore:`, and so on. That keeps the changelog and the
version bumps honest.

## Reporting bugs and asking for features

Use the issue templates. For anything security-related, don't open a public
issue; see [SECURITY.md](SECURITY.md).
