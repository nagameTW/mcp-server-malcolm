import inspect

from mcp_server_malcolm.client import MalcolmClient


def test_field_profile_accepts_time_range():
    sig = inspect.signature(MalcolmClient.field_profile)
    assert "time_from" in sig.parameters and "time_to" in sig.parameters


def test_arkime_sessions_accepts_time_range():
    sig = inspect.signature(MalcolmClient.arkime_sessions)
    assert "time_from" in sig.parameters and "time_to" in sig.parameters
