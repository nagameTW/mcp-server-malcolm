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

__version__ = "0.6.0"

from mcp_server_malcolm.client import MalcolmClient

__all__ = ["MalcolmClient", "__version__"]


def main() -> None:
    """Entry point for the MCP server."""
    from mcp_server_malcolm.server import create_server

    mcp = create_server()
    mcp.run()
