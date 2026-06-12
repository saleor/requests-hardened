import functools
import ipaddress
import socket
import sys
from socket import AddressFamily, SocketKind
from typing import Iterator, Mapping, Tuple
from unittest import mock

import pytest
from requests.exceptions import SSLError
from requests.structures import CaseInsensitiveDict
from requests.utils import default_headers
from urllib3.exceptions import MaxRetryError
from urllib3.util.ssl_match_hostname import CertificateError

from requests_hardened.ip_filter import InvalidIPAddress, get_ip_address

from .http_managers import DEFAULT_TEST_USER_AGENT, SSRFFilter, SSRFFilterAllowLocalHost
from .http_test_servers import (
    InsecureHTTPTestServer,
    SNITLSHTTPTestServer,
    TLSTestServer,
)
from .http_test_servers.utils.http_redirects import create_http_redirect_handler
from .utils import mock_getaddrinfo

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


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
        # RFC 6598 - Shared Address Space (https://github.com/python/cpython/issues/119812)
        "100.64.0.1",
        "::ffff:100.64.0.1",
        "::ffff:6440:1",  # Compressed 100.64.0.1
        "0000:0000:0000:0000:0000:ffff:6440:0001",  # Expanded 100.64.0.1
        "100.64.0.0",  # first address of 100.64.0.0/10
        "100.127.255.255",  # last address for 100.64.0.0/10
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
    "cidr",
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "233.252.0.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:20::/28",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ],
)
@pytest.mark.fake_resolver(enabled=False)
def test_blocks_all_reserved_ip_address_ranges(cidr: str):

    # Tests against 3 addresses, e.g., for 127.0.0.0/8:
    # - first_addr=127.0.0.0 (network address)
    # - host_address=127.0.0.1 (first address)
    # - last_addr=127.255.255.255 (broadcast)
    net = ipaddress.ip_network(cidr)
    first_addr, last_addr = net.network_address, net.broadcast_address

    # list[IPv4Address|IPv6Address] is only for Python <= 3.12.
    # Should be removed once 3.12 is EOL (~Nov 2028)
    hosts: Iterator[IPAddress] | list[IPAddress] = net.hosts()
    host_address = hosts[0] if isinstance(hosts, list) else next(hosts)

    for addr in [first_addr, host_address, last_addr]:
        assert isinstance(addr, (ipaddress.IPv4Address, ipaddress.IPv6Address))

        with mock_getaddrinfo(str(addr)):
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
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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


@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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


@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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


@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
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



@pytest.mark.fake_resolver(enabled=False)
@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
@pytest.mark.parametrize(
    ("_case", "input_headers", "expected_headers"),
    [
        (
            # When a custom value is provided in 'Host', then it should replace it
            # with the URL's hostname instead
            "Custom host header should be dropped",
            {"HoST": "foo.local"},
            {
                **default_headers(),
                "Host": "dummy.local",
                "User-Agent": DEFAULT_TEST_USER_AGENT,
            },
        ),
        (
            # When passing custom headers and the library doesn't have an override
            # for it (i.e., when not providing 'User-Agent' or 'Host'), then it should
            # not touch the headers
            "Non-overridden headers should be kept",
            {"x-forwarded-for": "127.0.0.1", "AUTHORIZATION": "Bearer Foo"},
            {
                **default_headers(),
                "x-forwarded-for": "127.0.0.1",
                "AUTHORIZATION": "Bearer Foo",
                "Host": "dummy.local",
                "User-Agent": DEFAULT_TEST_USER_AGENT,
            },
        ),
    ],
)
def test_headers_are_case_insensitive(
    _case: str, input_headers: Mapping[str, str], expected_headers: CaseInsensitiveDict
):
    dummy_server = InsecureHTTPTestServer()

    http_manager = SSRFFilter.clone()
    http_manager.config.ip_filter_allow_loopback_ips = True

    with dummy_server as [host, port]:
        url = f"http://dummy.local:{port}/"
        with mock_getaddrinfo(host):
            response = http_manager.send_request("GET", url, headers=input_headers)

    actual_headers = response.request.headers
    assert actual_headers == expected_headers


@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
def test_http_redirect_should_not_affect_request_headers():
    """
    Ensure the host header is changed whenever an HTTP redirect happens.
    """

    http_manager = SSRFFilter.clone()
    http_manager.config.ip_filter_allow_loopback_ips = True

    # Create a redirector but without an URL for now because we don't know the port
    # number yet.
    redirector = create_http_redirect_handler("")

    # Redirects HTTP requests (127.0.0.1 -> 10.0.0.1)
    dummy_server = InsecureHTTPTestServer(request_handler_class=redirector)

    with dummy_server as [host, port]:
        # Override
        redirector.redirect_url_loc = f"http://redirected.local:{port}?noredirect"

        url = f"http://dummy.local:{port}/"

        with mock_getaddrinfo(host):
            response = http_manager.send_request(
                "GET", url, headers={"Authorization": "XXX"}
            )

            # A new Host header value should be set on redirect.
            assert response.request.headers.get("Host") == "redirected.local"

            # Ensure the Authorization header is dropped when redirected.
            # This is dictated by:
            # https://github.com/urllib3/urllib3/blob/181357ed2aecf9c523f2664c05f176cde9692994/src/urllib3/util/retry.py#L192-L194
            assert response.request.headers.get("Authorization") is None


@pytest.mark.allow_hosts(["127.0.0.1"])  # We need to be able to create the dummy server
def test_http_redirect_should_filter_ip_address():
    """
    Ensure when an HTTP request redirects us to a private IP range, we reject.
    """

    http_manager = SSRFFilter.clone()
    http_manager.config.ip_filter_allow_loopback_ips = True

    # Redirects HTTP requests (127.0.0.1 -> 10.0.0.1)
    dummy_server = InsecureHTTPTestServer(
        request_handler_class=create_http_redirect_handler("https://10.0.0.1")
    )

    with dummy_server as [host, port]:
        url = f"http://dummy.local:{port}/"
        with mock_getaddrinfo(
            {"dummy.local": host, "127.0.0.1": "127.0.0.1", "10.0.0.1": "10.0.0.1"}
        ):
            # Should raise on the HTTP redirect
            with pytest.raises(InvalidIPAddress, match="10.0.0.1"):
                http_manager.send_request("GET", url)
