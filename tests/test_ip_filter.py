import socket
import requests
from unittest import mock

from requests_hardened.ip_filter import filter_request


@mock.patch("requests_hardened.ip_filter.parse_url")
def test_filter_request_handles_parse_url_raise_invalid_url(parse_url_mock):
    parse_url_mock.side_effect = ValueError
    try:
        filter_request("improper_addr", headers={}, allow_loopback=False)
    except requests.exceptions.InvalidURL as e:
        assert str(e) == ""


@mock.patch("requests_hardened.ip_filter.get_ip_address")
def test_filter_request_failed_to_resolve_domain_raise_connection_error(
    get_ip_address_mock,
):
    get_ip_address_mock.side_effect = socket.gaierror
    try:
        filter_request("https://example.com", headers={}, allow_loopback=False)
    except requests.ConnectionError as e:
        assert str(e) == "Failed to resolve domain"


@mock.patch("requests_hardened.ip_filter.get_ip_address")
def test_filter_request_timeout_raise_timeout_error(get_ip_address_mock):
    get_ip_address_mock.side_effect = socket.timeout
    try:
        filter_request("https://example.com", headers={}, allow_loopback=False)
    except requests.ConnectionError as e:
        assert str(e) == "Failed to connect to host"
