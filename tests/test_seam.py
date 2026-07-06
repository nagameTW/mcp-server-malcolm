import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "mcp_server_malcolm"


def test_write_primitives_only_referenced_from_tools_write():
    """No module outside tools/write/ may reference a client._write_* primitive."""
    pattern = re.compile(r"\._write_[a-z_]+")
    offenders = []
    for py in SRC.rglob("*.py"):
        rel = py.relative_to(SRC)
        if rel.parts[:2] == ("tools", "write"):
            continue
        if py.name == "client.py":
            continue  # defines them
        text = py.read_text(encoding="utf-8")
        if pattern.search(text):
            offenders.append(str(rel))
    assert not offenders, f"write primitives leaked into: {offenders}"
