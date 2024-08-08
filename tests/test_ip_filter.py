import pytest
import requests
import socket
from requests.exceptions import InvalidURL
from unittest import mock

from requests_hardened.ip_filter import filter_request


def test_filter_request_handles_parse_url_raise_invalid_url():
    with pytest.raises(InvalidURL):
        filter_request("00000001:0000C2934AB1", headers={}, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_raise_connection_error_on_invalid_address_family(
    getaddrinfo_mock,
):
    getaddrinfo_mock.side_effect = socket.gaierror
    with pytest.raises(
        requests.ConnectionError,
        match="Failed to resolve domain",
    ):
        filter_request("https://example.com", headers={}, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_timeout_raise_timeout_error(getaddrinfo_mock):
    getaddrinfo_mock.side_effect = socket.timeout
    with pytest.raises(requests.ConnectTimeout, match="Failed to connect to host"):
        filter_request("https://example.com", headers={}, allow_loopback=False)
