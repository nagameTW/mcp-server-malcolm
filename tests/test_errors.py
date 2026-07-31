"""The failure-shaping contract every tool module depends on."""

from __future__ import annotations

import pytest

from mcp_server_malcolm.errors import (
    MalcolmToolError,
    ToolInputError,
    UpstreamError,
    redact,
)


@pytest.mark.parametrize("exc", [ToolInputError, UpstreamError])
def test_both_failure_kinds_are_catchable_as_one_family(exc: type[MalcolmToolError]) -> None:
    with pytest.raises(MalcolmToolError):
        raise exc("boom")


@pytest.mark.parametrize("exc", [ToolInputError, UpstreamError])
def test_failures_reach_the_sdk_blanket_handler(exc: type[MalcolmToolError]) -> None:
    """`isError: true` depends on the SDK's `except Exception` catching these."""
    assert issubclass(exc, Exception)


def test_upstream_error_carries_the_status_a_tool_may_branch_on() -> None:
    """A 404 from /extracted-files/ is an answer (pruned), not a broken server."""
    assert UpstreamError("gone", status=404).status == 404


def test_upstream_error_status_is_none_when_no_response_arrived() -> None:
    assert UpstreamError("connect failed").status is None


@pytest.mark.parametrize(
    ("raw", "gone", "kept"),
    [
        (
            "GET https://operator1:hunter2@malcolm.example/mapi/fields -> 401",
            "hunter2",
            "malcolm.example",
        ),
        ("https://admin:p%40ss@192.0.2.1/x", "p%40ss", "192.0.2.1"),
        ("POST /auth?password=hunter2&doctype=conn", "hunter2", "doctype=conn"),
        ("/x?api_key=abc123&q=1", "abc123", "q=1"),
        ("/x?TOKEN=abc123", "abc123", "/x?"),
        # The secret word behind an underscore: "\b" does not fire between "_"
        # and "t", so these leaked until the key run was made part of the match.
        ("/cb?access_token=SECRET123&next=/", "SECRET123", "next=/"),
        ("/cb?refresh_token=SECRET123", "SECRET123", "refresh_token"),
        ("/cb?id_token=SECRET123&state=x", "SECRET123", "state=x"),
        ("/x?X-Api-Key=SECRET123", "SECRET123", "/x?"),
    ],
)
def test_redact_removes_the_secret_and_keeps_the_diagnostics(
    raw: str, gone: str, kept: str
) -> None:
    out = redact(raw)
    assert gone not in out
    assert kept in out


def test_redact_leaves_credential_free_text_alone() -> None:
    msg = "GET https://malcolm.example/mapi/agg/source.ip -> 503 Service Unavailable"
    assert redact(msg) == msg


def test_redact_does_not_eat_an_ordinary_at_sign() -> None:
    """No `://` in front means it is not URL userinfo -- e.g. a Zeek field value."""
    assert redact("user@example.com sent 3 files") == "user@example.com sent 3 files"
