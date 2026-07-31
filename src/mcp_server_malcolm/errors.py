"""Failure shaping at the tool boundary.

Two jobs, both about what a client sees when something goes wrong.

**Raising, not returning.** A tool that ``return``s a string describing a
failure produces a *successful* MCP result: the SDK wraps the string in a text
block and leaves ``isError`` false (mcp/server/mcpserver/server.py). A client
that retries on error, renders errors differently, or drops them from the
transcript is then misled. Anything raised out of a tool body becomes
``ToolError`` and lands as ``isError: true`` (mcp/server/mcpserver/tools/base.py),
which is what the tools spec asks for. So failures raise one of the exceptions
below; they never come back as ordinary return values.

**Saying only what the caller may know.** Upstream exception text is written
for an operator, not for a model: httpx puts the full request URL in
``HTTPStatusError``, and ``MALCOLM_URL`` may legitimately carry credentials as
userinfo. :func:`redact` strips those before any upstream text is passed on.
"""

from __future__ import annotations

import re

__all__ = ["MalcolmToolError", "ToolInputError", "UpstreamError", "redact"]


class MalcolmToolError(Exception):
    """Base for every failure a tool reports to its caller.

    Exists so tests and any future result-shaping code can catch the whole
    family at once. Both subclasses are ordinary exceptions, so the SDK's
    blanket ``except Exception`` still converts them to ``isError: true``.
    """


class ToolInputError(MalcolmToolError):
    """The caller's arguments cannot be honoured as given.

    Raise this instead of quietly dropping an argument you could not parse.
    Discarding a malformed filter answers a *wider* question than the one
    asked -- in a threat-hunting server that is worse than failing, because
    the caller cannot tell the unfiltered result from the real one.
    """


class UpstreamError(MalcolmToolError):
    """Malcolm (or a service behind it) failed or could not be reached.

    Raised by :class:`~mcp_server_malcolm.client.MalcolmClient` so the
    conversion from an httpx exception -- and the :func:`redact` pass over its
    text -- happens once, at the single point every tool routes through,
    instead of at each of the callers.

    ``status`` is the HTTP status when there was a response, ``None`` when the
    request never completed (DNS, TLS, connect, timeout). Tools that treat a
    particular status as an answer rather than a fault -- a 404 from
    ``/extracted-files/`` means the file was pruned, not that the server is
    broken -- branch on it.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# Credentials arrive in two shapes worth stripping. Userinfo: httpx echoes the
# request URL, and MALCOLM_URL is allowed to embed "user:pass@". Query strings:
# a secret can land there via a caller-supplied path or an upstream redirect.
_URL_USERINFO = re.compile(r"(?<=://)[^/\s@]+@")
_SECRET_PARAM = re.compile(
    r"\b(password|passwd|pwd|token|api_?key|secret|auth)=[^&\s\"']+",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Remove credentials from text that came from an upstream library.

    Strips URL userinfo (``https://user:pw@host`` -> ``https://host``) and the
    values of secret-looking query parameters. The surrounding message is left
    intact: the host and status code are what make an error actionable, and
    neither is a secret.

    >>> redact("GET https://otex:hunter2@malcolm.example/mapi/fields failed")
    'GET https://malcolm.example/mapi/fields failed'
    >>> redact("... /login?user=a&password=hunter2&next=/")
    '... /login?user=a&password=[redacted]&next=/'
    """
    cleaned = _URL_USERINFO.sub("", text)
    return _SECRET_PARAM.sub(lambda m: f"{m.group(1)}=[redacted]", cleaned)
