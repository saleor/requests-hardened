import pytest
import requests
import socket
from unittest import mock

from requests_hardened.ip_filter import filter_host


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_raise_connection_error_on_invalid_address_family(
    getaddrinfo_mock,
):
    """Ensures address resolution failures from getaddrinfo() are handled (gaierror)"""
    getaddrinfo_mock.side_effect = socket.gaierror
    with pytest.raises(
        # Error should be wrapped with `requests.ConnectionError`
        requests.ConnectionError,
        match="Failed to resolve domain",
    ):
        filter_host("example.com", 443, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.socket.getaddrinfo")
def test_filter_request_timeout_raise_timeout_error(getaddrinfo_mock):
    """
    Ensures timeouts in address resolution from getaddrinfo() are handled (socket.timeout)
    """
    getaddrinfo_mock.side_effect = socket.timeout
    with pytest.raises(
        # Error should be wrapped with `requests.ConnectionError`
        requests.ConnectTimeout,
        match="Failed to connect to host"
    ):
        filter_host("example.com", 443, allow_loopback=False)
