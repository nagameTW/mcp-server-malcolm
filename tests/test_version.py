"""The version a client is told must be the version that was published.

1.0.0 shipped with `__version__` still reading "0.9.0": pyproject had been
bumped, the wheel metadata was right, and the literal in __init__.py was not.
server.py passes that literal to the MCP handshake, so every client connecting
to 1.0.0 was told it was talking to 0.9.0. PyPI cannot be re-uploaded, so the
fix had to be a release of its own -- which is why this file exists.

server.json drifted the same way and went unnoticed for four releases: it sat
at 0.9.0 while PyPI served 1.0.3, so the MCP Registry advertised a version of
this server that no longer existed. It is checked here now.
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


def test_the_handshake_reports_it() -> None:
    """The path that actually broke: __version__ -> serverInfo.version."""
    from mcp_server_malcolm.server import create_server

    assert create_server().version == mcp_server_malcolm.__version__
