import socket
import requests
import pytest
from unittest import mock

from requests_hardened.ip_filter import filter_request


@mock.patch("requests_hardened.ip_filter.parse_url")
def test_filter_request_handles_parse_url_raise_invalid_url(parse_url_mock):
    parse_url_mock.side_effect = ValueError
    with pytest.raises(requests.exceptions.InvalidURL):
        filter_request("improper_addr", headers={}, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.get_ip_address")
def test_filter_request_failed_to_resolve_domain_raise_connection_error(
    get_ip_address_mock,
):
    get_ip_address_mock.side_effect = socket.gaierror
    with pytest.raises(requests.ConnectionError, match="Failed to resolve domain"):
        filter_request("https://example.com", headers={}, allow_loopback=False)


@mock.patch("requests_hardened.ip_filter.get_ip_address")
def test_filter_request_timeout_raise_timeout_error(get_ip_address_mock):
    get_ip_address_mock.side_effect = socket.timeout
    with pytest.raises(requests.ConnectionError, match="Failed to connect to host"):
        filter_request("https://example.com", headers={}, allow_loopback=False)
