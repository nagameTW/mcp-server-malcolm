"""MCP server for Malcolm network traffic analysis platform.

Provides tool access to Malcolm's unified API, including:
- Network traffic search and aggregation
- Field discovery and validation
- Suricata alert queries
- Arkime session search and PCAP download
- NetBox asset lookup
- System health and data coverage

Works with any MCP-compatible agent.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _installed_version

# Read from the installed distribution rather than restating pyproject's number.
# server.py hands this to the MCP handshake as serverInfo.version, so a stale
# literal here tells every connected client the wrong version -- which is what
# 1.0.0 shipped with, its serverInfo still reading 0.9.0. There is one source of
# truth now and it is the package metadata.
try:
    __version__ = _installed_version("mcp-server-malcolm")
except PackageNotFoundError:  # running from a source tree with nothing installed
    __version__ = "0.0.0+unknown"

from mcp_server_malcolm.client import MalcolmClient  # noqa: E402

__all__ = ["MalcolmClient", "__version__"]


def main() -> None:
    """Entry point for the MCP server."""
    from mcp_server_malcolm.server import create_server

    mcp = create_server()
    mcp.run()
