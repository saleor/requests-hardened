from unittest import mock

import pytest

from requests_hardened import Manager, Config

DEFAULT_TIMEOUT = (1, 2)

NeverRedirectManager = Manager(
    Config(
        never_allow_redirects=True,
        # irrelevant:
        ip_filter_enable=False,
        ip_filter_allow_localhost=True,
        default_timeout=(1, 1),
    )
)

AllowRedirectManager = NeverRedirectManager.clone()
AllowRedirectManager.config.never_allow_redirects = False


@pytest.mark.parametrize(
    "_name, kwargs",
    [
        ("allow_redirects not passed -> should set to False", {}),
        (
            "allow_redirects=True passed -> should set to False",
            {"allow_redirects": True},
        ),
        (
            "allow_redirects=False passed -> should remain False",
            {"allow_redirects": False},
        ),
    ],
)
@mock.patch("requests.sessions.Session.send")
def test_never_allows_redirects(mocked_send: mock.MagicMock, _name, kwargs):
    NeverRedirectManager.send_request("GET", "https://example.com", **kwargs)
    mocked_send.assert_called_once_with(
        mock.ANY,
        timeout=NeverRedirectManager.config.default_timeout,
        allow_redirects=False,
        proxies={},
        stream=False,
        verify=True,
        cert=None,
    )


@pytest.mark.parametrize(
    "_name, kwargs, expected_allow_redirects",
    [
        ("allow_redirects not passed -> should set to True", {}, True),
        (
            "allow_redirects=False passed -> should remain False",
            {"allow_redirects": False},
            False,
        ),
        (
            "allow_redirects=True passed -> should remain True",
            {"allow_redirects": True},
True,
        ),
    ],
)
@mock.patch("requests.sessions.Session.send")
def test_allows_redirects(mocked_send: mock.MagicMock, _name, kwargs, expected_allow_redirects):
    AllowRedirectManager.send_request("GET", "https://example.com", **kwargs)
    mocked_send.assert_called_once_with(
        mock.ANY,
        timeout=NeverRedirectManager.config.default_timeout,
        allow_redirects=expected_allow_redirects,
        proxies={},
        stream=False,
        verify=True,
        cert=None,
    )
