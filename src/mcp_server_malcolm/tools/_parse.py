"""Argument parsing shared by the tool layer.

Four tools took a JSON-object argument and three of them parsed it a different
way; two of those three dropped a malformed value and answered the wider
question instead. One parser means one decision about what is acceptable.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_server_malcolm.errors import ToolInputError


def parse_json_object(raw: str, arg: str, example: str) -> dict[str, Any] | None:
    """Parse a JSON-object argument; None when the caller passed nothing.

    A malformed value raises rather than being dropped. Dropping it answers a
    WIDER question than the one asked -- an unfiltered index reported as the
    answer to a filtered question -- and the caller cannot tell that result
    from the real one.

    The Python-dict spelling ({'a': 'b'}) is rejected rather than repaired. The
    argument is declared as JSON and a model that gets one message naming the
    JSON form emits JSON from then on; accepting the single-quoted form instead
    keeps a second parser to be right about (ast.literal_eval also admits
    tuples, sets and None, which Malcolm cannot receive) and hides the mismatch
    until something further downstream breaks.

    Args:
        raw: The argument as the caller supplied it.
        arg: Its name, for the message.
        example: A correct value, quoted into the message.

    Raises:
        ToolInputError: not JSON, or JSON that is not an object.
    """
    text = raw.strip()
    if not text or text.lower() in ("{}", "null", "none"):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ToolInputError(
            f"{arg} is not valid JSON ({exc}); received {raw!r}. Expected a "
            f"double-quoted JSON object, e.g. {example} — the Python spelling "
            f"{{'a': 'b'}} is not JSON."
        ) from exc
    if not isinstance(parsed, dict):
        raise ToolInputError(
            f"{arg} must be a JSON object, e.g. {example}; received {raw!r}, "
            f"which parsed as {type(parsed).__name__}."
        )
    return parsed


def parse_int_list(raw: str, arg: str, example: str) -> list[int]:
    """Parse a comma-separated list of whole numbers.

    Malcolm indexes these fields as numbers, so a non-numeric token cannot be
    filtered on. Skipping it used to leave the filter key unset, which returned
    every value of that field while the caller believed it had filtered.

    Raises:
        ToolInputError: any token is not a whole number, or none were given.
    """
    values: list[int] = []
    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue
        if not token.isdigit():
            raise ToolInputError(
                f"{arg} takes comma-separated whole numbers, e.g. {example}; "
                f"received {raw!r}, in which {token!r} is not a number."
            )
        values.append(int(token))
    if not values:
        raise ToolInputError(
            f"{arg} takes comma-separated whole numbers, e.g. {example}; received {raw!r}."
        )
    return values
