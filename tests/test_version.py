"""The version a client is told must be the version that was published.

1.0.0 shipped with `__version__` still reading "0.9.0": pyproject had been
bumped, the wheel metadata was right, and the literal in __init__.py was not.
server.py passes that literal to the MCP handshake, so every client connecting
to 1.0.0 was told it was talking to 0.9.0. PyPI cannot be re-uploaded, so the
fix had to be a release of its own -- which is why this file exists.

server.json drifted the same way and went unnoticed for four releases: it sat
at 0.9.0 while PyPI served 1.0.3, so the MCP Registry advertised a version of
this server that no longer existed. It is checked here now.

Both READMEs are the third copy, and they drifted too: their install and
handshake transcripts printed 1.0.2 while PyPI served 1.1.0. That one misleads
a reader rather than a client -- someone comparing the version they installed
against the one the README prints cannot tell which of the two is wrong.
"""

from __future__ import annotations

import json
import re
import tomllib
from importlib.metadata import version as installed_version
from pathlib import Path

import mcp_server_malcolm

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"
_SERVER_JSON = _PYPROJECT.parent / "server.json"
_READMES = (_PYPROJECT.parent / "README.md", _PYPROJECT.parent / "README.zh-TW.md")

# Only this package's own version, never the many other versions the READMEs
# quote (Malcolm, Arkime, mcp, Python, Docker). Two shapes carry it: the sdist
# and wheel filenames, and a handshake line naming the server next to its
# version.
_README_VERSION = re.compile(
    r"mcp_server_malcolm-(?P<artifact>\d+\.\d+\.\d+)"
    r"|mcp-server-malcolm.{0,40}?version[:=] ?'?(?P<handshake>\d+\.\d+\.\d+)'?"
)


def test_version_matches_the_installed_distribution() -> None:
    assert mcp_server_malcolm.__version__ == installed_version("mcp-server-malcolm")


def test_version_matches_pyproject() -> None:
    """Catches the drift even when the checkout is installed non-editable."""
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    assert mcp_server_malcolm.__version__ == declared


def test_no_module_restates_the_version_as_a_literal() -> None:
    """One source of truth. A second copy is what drifted the first time."""
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    pattern = re.compile(rf'["\']{re.escape(declared)}["\']')
    src = _PYPROJECT.parent / "src" / "mcp_server_malcolm"
    offenders = [
        str(p.relative_to(_PYPROJECT.parent))
        for p in src.rglob("*.py")
        if pattern.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"version literal restated in {offenders}; read the metadata instead"


def test_server_json_matches_pyproject() -> None:
    """The MCP Registry manifest is a second copy, so it needs a second guard.

    Both places: the top-level `version` and the PyPI package entry, which the
    registry resolves independently. Nothing in the release workflow writes
    either one, so a release bumps them only if a human remembers.
    """
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    manifest = json.loads(_SERVER_JSON.read_text(encoding="utf-8"))
    assert manifest["version"] == declared
    assert [p["version"] for p in manifest["packages"]] == [declared] * len(manifest["packages"])


def test_the_readmes_do_not_print_a_stale_version() -> None:
    """Every version string the READMEs print is this package's own.

    The transcripts are quoted as run, so a release has to re-quote them; the
    assertion below names the file and line so that is a two-minute edit rather
    than a hunt. It also fails when the patterns stop matching anything, since a
    guard that silently finds nothing is worse than no guard.
    """
    declared = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["version"]
    matched = 0
    stale = []
    for readme in _READMES:
        for number, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), 1):
            for found in _README_VERSION.finditer(line):
                seen = found["artifact"] or found["handshake"]
                matched += 1
                if seen != declared:
                    stale.append(f"{readme.name}:{number} shows {seen}")
    assert matched, "no version strings found in the READMEs; the patterns above went stale"
    assert not stale, f"declared {declared}, but {'; '.join(stale)}"


def test_the_handshake_reports_it() -> None:
    """The path that actually broke: __version__ -> serverInfo.version."""
    from mcp_server_malcolm.server import create_server

    assert create_server().version == mcp_server_malcolm.__version__
