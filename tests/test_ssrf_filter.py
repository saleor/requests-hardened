import functools
import ipaddress
import socket
import sys
from socket import AddressFamily, SocketKind
from typing import Tuple
from unittest import mock

import pytest
from requests.exceptions import SSLError
from urllib3.exceptions import MaxRetryError
from urllib3.util.ssl_match_hostname import CertificateError

from requests_hardened.ip_filter import InvalidIPAddress, get_ip_address

from .http_managers import SSRFFilter, SSRFFilterAllowLocalHost
from .http_test_servers import (InsecureHTTPTestServer, SNITLSHTTPTestServer,
                                TLSTestServer)
from .utils import mock_getaddrinfo

TEST_TIMEOUT_SECS = 5


@pytest.mark.parametrize(
    "ip_addr",
    [
        "0.0.0.0",
        "127.0.0.1",
        "10.0.0.1",
        "192.168.0.1",
        "172.16.0.1",
        "192.0.2.0",  # broadcast address
        "::",  # 0.0.0.0
        "::1",  # 127.0.0.1
        "::ffff:7f00:1",  # 127.0.0.1
        "::ffff:a00:1",  # 10.0.0.1
        "::ffff:c0a8:1",  # 192.168.0.1
        "::ffff:ac10:1",  # 172.16.0.1
        "::ffff:192.168.2.1",
        "::ffff:192.0.2.0",  # broadcast address
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    ],
)
@pytest.mark.fake_resolver(enabled=False)
def test_blocks_private_ranges(ip_addr: str):
    """Ensure private blocks are rejected."""
    with mock_getaddrinfo(ip_addr):
        # (!!) We expect no connections to be made inside this test.
        #      If 'pytest_socket.SocketBlockedError' exception is raised,
        #      then something is really wrong as it means the test most likely tried
        #      to connect a private IP address.
        with pytest.raises(InvalidIPAddress):
            SSRFFilter.send_request("GET", "https://test.local")


@pytest.mark.parametrize(
    "resolve_to_ip_addr, expected_sock_ip_addr",
    [
        ("128.99.0.0", "128.99.0.0"),
        ("8.0.0.0", "8.0.0.0"),
        # The IPv6 address gets compressed by Python's `ipaddress` library.
        ("::192.0.5.0", "::c000:500"),
        ("::ffff:8063:0", "128.99.0.0"),  # IPv6 mapped to IPv4
        ("::ffff:800:0", "8.0.0.0"),  # IPv6 mapped to IPv4
        ("2004:0db8:1234:5678::abcd:ef01", "2004:db8:1234:5678::abcd:ef01"),
    ],
)
@pytest.mark.fake_resolver(enabled=False)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
@mock.patch("urllib3.util.connection.create_connection")
def test_allows_public_ranges(
    mocked_create_connection: mock.MagicMock,
    resolve_to_ip_addr: str,
    expected_sock_ip_addr: str,
):
    """Ensure public blocks are allowed."""

    dummy_server = InsecureHTTPTestServer()

    with dummy_server:
        with mock_getaddrinfo(resolve_to_ip_addr):
            mocked_create_connection.return_value = dummy_server.create_client_socket()
            response = SSRFFilter.send_request("GET", "http://test.local")
            mocked_create_connection.assert_called_once()

            # Ensure the HTTP request was sent properly.
            assert response.request.method == "GET"
            assert response.request.headers.get("Host") == "test.local"

            [conn_addr, *_args], _kwargs = mocked_create_connection.call_args

            # Shouldn't pass anything else than requested-hardened's pinned IP address,
            # especially not a URL hostname.
            # We should always only resolve once as otherwise we risk race-condition
            # vulnerabilities, or bypass through malicious DNS round-robin.
            assert conn_addr == (
                expected_sock_ip_addr,
                80,
            ), "Should have passed the mocked getaddrinfo() IP address"


@pytest.mark.parametrize(
    "input_url, expected_url, resolves_to, expected_sock_addr, expected_http_host_header",
    [
        (
            # Test handling of domains returning IP addresses version 6.
            # Ensures the IP is surrounded by brackets.
            "http://example.com/",
            "http://example.com/",
            "2004:0db8:1234:5678::abcd:ef01",
            ("2004:db8:1234:5678::abcd:ef01", 80),
            "example.com",
        ),
        (
            # Ensure IPv6 passed directly into a URL is handled properly:
            # - DNS resolver should be invoked using the IPv6 address without brackets;
            # - HTTP host header should be the IPv6 address (no brackets);
            # - HTTP URL should contain brackets.
            "http://[2004:0db8:1234:5678::abcd:ef01]/",
            "http://[2004:0db8:1234:5678::abcd:ef01]/",
            "2004:0db8:1234:5678::abcd:ef01",
            ("2004:db8:1234:5678::abcd:ef01", 80),
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "http://[2004:0db8:1234:5678::abcd:ef01]:444/",
            "http://[2004:0db8:1234:5678::abcd:ef01]:444/",
            "2004:0db8:1234:5678::abcd:ef01",
            ("2004:db8:1234:5678::abcd:ef01", 444),
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "http://[2004:0db8:1234:5678::abcd:ef01]:444/",
            "http://[2004:0db8:1234:5678::abcd:ef01]:444/",
            "2004:0db8:1234:5678::abcd:ef01",
            ("2004:db8:1234:5678::abcd:ef01", 444),
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "http://127.0.0.1:444/",
            "http://127.0.0.1:444/",
            "127.0.0.1",
            ("127.0.0.1", 444),
            "127.0.0.1",
        ),
        (
            # Ensure ports are handled properly
            "http://example.com:444/",
            "http://example.com:444/",
            "127.0.0.1",
            ("127.0.0.1", 444),
            "example.com",
        ),
        (
            # Ensure unicode URLs are encoded to IDNA
            "http://wroc\u0142aw.test/",
            "http://xn--wrocaw-6db.test/",
            "127.0.0.1",
            ("127.0.0.1", 80),
            "xn--wrocaw-6db.test",
        ),
    ],
)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
@mock.patch("urllib3.util.connection.create_connection")
def test_url_handling(
    mocked_create_connection: mock.MagicMock,
    input_url: str,
    expected_url,
    resolves_to: str,
    expected_sock_addr: Tuple[str, int],
    expected_http_host_header: str,
):
    manager = SSRFFilter.clone()
    manager.config.ip_filter_allow_loopback_ips = True

    dummy_server = InsecureHTTPTestServer()

    with dummy_server:
        mocked_create_connection.return_value = dummy_server.create_client_socket()

        with mock_getaddrinfo(resolves_to):
            response = manager.send_request("GET", input_url)

    assert response.request.method == "GET"
    assert response.request.url == expected_url
    assert response.request.headers.get("Host") == expected_http_host_header

    mocked_create_connection.assert_called_once()
    [conn_addr, *_args], _kwargs = mocked_create_connection.call_args

    # Shouldn't pass anything else than requested-hardened's pinned IP address,
    # especially not a URL hostname.
    # We should always only resolve once as otherwise we risk race-condition
    # vulnerabilities, or bypass through malicious DNS round-robin.
    assert conn_addr == (
        expected_sock_addr
    ), "Should have passed the mocked getaddrinfo() IP address"


@pytest.mark.parametrize(
    "resolver_result, expected_result",
    [
        # (af, socktype, proto, _canonname, socket_address)
        [
            (
                AddressFamily.AF_INET6,
                SocketKind.SOCK_STREAM,
                6,
                "",
                ("::ffff:8.8.8.0", 443, 0, 0),
            ),
            (ipaddress.IPv4Address("8.8.8.0"), 443),
        ],
        [
            (AddressFamily.AF_INET, SocketKind.SOCK_STREAM, 6, "", ("8.8.4.0", 443)),
            (ipaddress.IPv4Address("8.8.4.0"), 443),
        ],
    ],
)
@pytest.mark.fake_resolver(enabled=False)
def test_socket_family_handling(resolver_result, expected_result):
    """
    Verify the handling of different socket families: AF_INET, AF_INET6,
    AF_NETLINK, AF_TIPC, AF_UNIX. We only expect to handle AF_INET and AF_INET6.

    Length difference of socket address between INET and INET6 should be handled
    successfully.
    """

    with mock.patch.object(socket, "getaddrinfo", return_value=[resolver_result]):
        result = get_ip_address("test.local", 443, allow_loopback=False)

    assert result == expected_result


@pytest.mark.skipif(sys.platform.startswith("win"), reason="Unix-like specific test")
@pytest.mark.fake_resolver(enabled=False)
def test_rejects_non_inet_socket_family():
    """
    Verifies if the socket family is not AF_INET or AF_INET6, then it
    raises `ValueError`.
    """

    with mock.patch.object(
        socket,
        "getaddrinfo",
        return_value=[
            # AF_UNIX is a non-IP based network protocol thus the
            # getaddrinfo return value is invalid, but it allows to ensure our behavior.
            (AddressFamily.AF_UNIX, SocketKind.SOCK_STREAM, 6, "", ())
        ],
    ):
        with pytest.raises(ValueError) as exc:
            get_ip_address("test.local", 443, allow_loopback=False)

    assert exc.value.args == (
        "Only AF_INET and AF_INET6 socket address families are supported",
    )


@pytest.mark.timeout(TEST_TIMEOUT_SECS)
@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
def test_insecure_http_supported():
    """
    Ensure we are able to connect to targets that are using insecure HTTP.
    """
    srv = InsecureHTTPTestServer()
    with srv as [_srv_addr, srv_port]:
        response = SSRFFilterAllowLocalHost.send_request(
            "GET", f"http://test.local:{srv_port}"
        )
        assert response.status_code == 200


@pytest.mark.timeout(TEST_TIMEOUT_SECS)
@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
def test_tls_without_SNIs_supported(tmp_path):
    """
    Ensure we are able to connect successfully to a server that doesn't
    have a SNI callback set-up.
    """

    http_manager = SSRFFilterAllowLocalHost.clone()

    srv = TLSTestServer(
        tmp_path,
        cert_identities=["test1.local", "test2.local"],
    )

    with srv as [_srv_addr, srv_port]:
        do_request = functools.partial(
            http_manager.send_request,
            "GET",
            f"https://test2.local:{srv_port}",
            verify=srv.ca_bundle_path,
        )

        # This should work both when SNI support is enabled and disabled.
        assert do_request().status_code == 200

        # Ensure this test is not testing SNI: when disabling SNI support client-side,
        # this the HTTP request should still succeed.
        http_manager.config.ip_filter_tls_sni_support = False
        assert do_request().status_code == 200


@pytest.mark.timeout(TEST_TIMEOUT_SECS)
@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
def test_tls_with_SNIs_supported(tmp_path):
    """
    Ensure we are able to connect successfully to a server that has a
    SNI callback set-up.
    """

    http_manager = SSRFFilterAllowLocalHost.clone()

    srv = SNITLSHTTPTestServer(
        tmp_path, cert_identities=["localhost"], additional_identities=["sni.local"]
    )
    with srv as [_srv_addr, srv_port]:
        do_request = functools.partial(
            http_manager.send_request,
            "GET",
            f"https://sni.local:{srv_port}",
            verify=srv.ca_bundle_path,
        )

        # This should only work when SNI support is enabled.
        assert do_request().status_code == 200

        # Ensure when SNI support is disabled client-side, then
        # it no longer works, which allows to be sure the test is indeed testing SNI.
        with pytest.raises(SSLError) as exc_info:
            http_manager.config.ip_filter_tls_sni_support = False
            do_request()

    exc = exc_info.value.args[0]
    assert isinstance(exc, MaxRetryError)
    original_exception = exc.reason.args[0]
    assert isinstance(original_exception, CertificateError)
    assert (
        original_exception.args[0] == "hostname 'sni.local' doesn't match 'localhost'"
    )


@pytest.mark.fake_resolver(enabled=False)
@pytest.mark.allow_hosts(['127.0.0.1'])  # We need to be able to create the dummy server
def test_pass_headers_reference():
    """
    Ensure headers passed to IP filter are not mutated without being copied first.
    """
    input_headers = {"foo": "bar"}

    dummy_server = InsecureHTTPTestServer()

    http_manager = SSRFFilter.clone()
    http_manager.config.ip_filter_allow_loopback_ips = True

    with dummy_server as [host, port]:
        url = f"http://dummy.local:{port}/"
        with mock_getaddrinfo(host):
            response = http_manager.send_request("GET", url, headers=input_headers)

    assert response.request.method == "GET"
    assert response.request.url == url
    assert "Host" not in input_headers, "Shouldn't have mutated the input headers"
    assert response.request.headers.get("Host") == "dummy.local"
    assert (
        response.request.headers.get("foo") == "bar"
    ), "Should have preserved the original headers"
