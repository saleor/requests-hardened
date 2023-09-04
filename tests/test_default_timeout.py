from unittest import mock

import pytest

from requests_hardened import Manager, Config

DEFAULT_TIMEOUT = (1, 2)

TimeoutManager = Manager(
    Config(
        default_timeout=DEFAULT_TIMEOUT,
        # irrelevant:
        ip_filter_enable=False,
        ip_filter_allow_localhost=True,
        never_allow_redirects=False,
    )
)

NoTimeoutSetManager = TimeoutManager.clone()
NoTimeoutSetManager.config.default_timeout = None


@pytest.mark.parametrize(
    "_name, kwargs, expected_timeout",
    [
        ("Timeout not passed -> Should set default timeout", {}, DEFAULT_TIMEOUT),
        (
            "Timeout explicitly passed as 'None' -> Should set default timeout",
            {"timeout": None},
            DEFAULT_TIMEOUT,
        ),
        ("Timeout explicitly passed -> Should be untouched", {"timeout": 10}, 10),
        (
            "Timeout explicitly passed as tuple -> Should be untouched",
            {"timeout": (10, 20)},
            (10, 20),
        ),
    ],
)
@mock.patch("requests.sessions.Session.send")
def test_sets_default_timeout(
    mocked_send: mock.MagicMock, _name, kwargs, expected_timeout
):
    TimeoutManager.send_request("GET", "https://example.com", **kwargs)
    mocked_send.assert_called_once_with(
        mock.ANY,
        timeout=expected_timeout,
        allow_redirects=True,
        proxies={},
        stream=False,
        verify=True,
        cert=None,
    )


@pytest.mark.parametrize(
    "_name, kwargs, expected_timeout",
    [
        ("Timeout not passed -> Should set None", {}, None),
        (
            "Timeout explicitly passed as 'None' -> Should still be None",
            {"timeout": None},
            None,
        ),
        ("Timeout explicitly passed -> Should be untouched", {"timeout": 10}, 10),
    ],
)
@mock.patch("requests.sessions.Session.send")
def test_default_timeout_null(mocked_send: mock.MagicMock, _name, kwargs, expected_timeout):
    """Ensure when default timeout is set to None, then `timeout=` is set to None."""
    NoTimeoutSetManager.send_request("GET", "https://example.com", **kwargs)
    mocked_send.assert_called_once_with(
        mock.ANY,
        timeout=expected_timeout,
        allow_redirects=True,
        proxies={},
        stream=False,
        verify=True,
        cert=None,
    )

