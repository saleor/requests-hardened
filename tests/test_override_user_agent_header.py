from unittest import mock

import pytest
import requests
from requests.utils import default_headers

from requests_hardened import Config, Manager

UserAgentNotDefinedManager = Manager(
    Config(
        # irrelevant:
        never_redirect=True,
        ip_filter_enable=False,
        ip_filter_allow_loopback_ips=True,
        default_timeout=(1, 1),
    )
)
UserAgentDefinedManager = UserAgentNotDefinedManager.clone()
UserAgentDefinedManager.config.user_agent_override = None


@pytest.mark.parametrize("user_agent", ["user-agent", ""])
@mock.patch("requests.sessions.Session.send")
def test_user_agent_override_config(mocked_send: mock.MagicMock, user_agent):
    UserAgentDefinedManager.config.user_agent_override = user_agent
    UserAgentDefinedManager.send_request("GET", "https://example.com")

    prep_request = mocked_send.call_args[0][0]

    assert mocked_send.assert_called_once
    assert prep_request.headers.get("User-Agent") == user_agent


@mock.patch("requests.sessions.Session.send")
def test_user_agent_override_none(mocked_send: mock.MagicMock):
    UserAgentDefinedManager.config.user_agent_override = None
    UserAgentDefinedManager.send_request("GET", "https://example.com")

    prep_request = mocked_send.call_args[0][0]

    assert mocked_send.assert_called_once
    assert prep_request.headers.get("User-Agent") == f"python-requests/{requests.__version__}"


@mock.patch("requests.sessions.Session.send")
def test_user_agent_override_undefined(mocked_send: mock.MagicMock):
    UserAgentNotDefinedManager.send_request("GET", "https://example.com")

    prep_request = mocked_send.call_args[0][0]
    assert mocked_send.assert_called_once
    assert prep_request.headers.get("User-Agent") == f"python-requests/{requests.__version__}"


@mock.patch("requests.sessions.Session.send")
@pytest.mark.parametrize(
    "user_agent_header_name",
    [
        "User-Agent",  # title case
        "User-AGENT",  # mixed case
        "USER-AGENT",  # all caps
        "user-agent",  # lowercase
    ],
)
def test_user_agent_header_is_case_insensitive(
    mocked_send: mock.MagicMock,
    user_agent_header_name: str,
):
    http_manager = UserAgentNotDefinedManager.clone()
    http_manager.config.user_agent_override = "My custom UA"

    input_headers = {user_agent_header_name: "This value should be overriden"}
    expected_headers = default_headers()
    expected_headers["User-Agent"] = "My custom UA"

    http_manager.send_request(
        "GET",
        "https://example.com",
        headers=input_headers,
    )

    prep_request = mocked_send.call_args[0][0]
    assert mocked_send.assert_called_once
    assert prep_request.headers == expected_headers
