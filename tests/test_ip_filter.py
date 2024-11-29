import pytest
import requests
import socket
from unittest import mock

from requests_hardened.ip_filter import filter_host


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_raise_connection_error_on_invalid_address_family(
    getaddrinfo_mock,
):
    getaddrinfo_mock.side_effect = socket.gaierror
    with pytest.raises(
        requests.ConnectionError,
        match="Failed to resolve domain",
    ):
        filter_host("https://example.com", 443, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_timeout_raise_timeout_error(getaddrinfo_mock):
    getaddrinfo_mock.side_effect = socket.timeout
    with pytest.raises(requests.ConnectTimeout, match="Failed to connect to host"):
        filter_host("https://example.com", 443, allow_loopback=False)
