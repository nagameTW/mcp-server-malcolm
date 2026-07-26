import ast
import pathlib

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "mcp_server_malcolm"


class _WritePrimitiveFinder(ast.NodeVisitor):
    """Flag any reference to a _write_* primitive: direct attribute access
    (client._write_event) OR dynamic dispatch (getattr(client, "_write_event")).

    AST-based rather than a text regex so it also catches the getattr form —
    the seam is the write-authorization boundary and must not be bypassable by
    routing a mutating call through a read tool via a string attribute name.
    """

    def __init__(self) -> None:
        self.hits: list[str] = []

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr.startswith("_write_"):
            self.hits.append(node.attr)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args:
            name_arg = node.args[1] if len(node.args) > 1 else None
            if (
                isinstance(name_arg, ast.Constant)
                and isinstance(name_arg.value, str)
                and name_arg.value.startswith("_write_")
            ):
                self.hits.append(f"getattr(..., {name_arg.value!r})")
        self.generic_visit(node)


def _scan(src: str) -> list[str]:
    finder = _WritePrimitiveFinder()
    finder.visit(ast.parse(src))
    return finder.hits


def test_write_primitives_only_referenced_from_tools_write():
    """No module outside tools/write/ may reference a client._write_* primitive."""
    offenders: dict[str, list[str]] = {}
    for py in SRC.rglob("*.py"):
        rel = py.relative_to(SRC)
        if rel.parts[:2] == ("tools", "write"):
            continue
        if py.name == "client.py":
            continue  # defines them
        hits = _scan(py.read_text(encoding="utf-8"))
        if hits:
            offenders[str(rel)] = hits
    assert not offenders, f"write primitives leaked into: {offenders}"


def test_seam_catches_direct_attribute_access():
    assert _scan("client._write_event(alert)") == ["_write_event"]


def test_seam_catches_getattr_dynamic_dispatch():
    """The bug the old regex missed: routing a write via a string attr name."""
    assert _scan('getattr(client, "_write_event")(alert)') == ["getattr(..., '_write_event')"]


def test_seam_ignores_unrelated_names():
    assert _scan('client.search(x); getattr(o, "_private")') == []
