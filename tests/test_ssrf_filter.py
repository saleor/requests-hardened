import functools
import ipaddress
import socket
import sys
from socket import AddressFamily, SocketKind
from unittest import mock

import pytest
from requests import PreparedRequest
from requests.exceptions import SSLError
from urllib3.exceptions import MaxRetryError
from urllib3.util.ssl_match_hostname import CertificateError

from requests_hardened import Manager, Config
from .http_test_servers import (
    InsecureHTTPTestServer,
    TLSTestServer,
    SNITLSHTTPTestServer,
)
from .utils import mock_getaddrinfo, disable_sni_support

from requests_hardened.ip_filter import InvalidIPAddress, get_ip_address

# HTTP server can take some time to connect against for some machines (usually up to 1s).
# It requires a fairly generous timeout without taking too long that the test fails.
SOCKET_TIMEOUT = (4, 0.1)

TEST_TIMEOUT_SECS = 5


SSRFFilter = Manager(
    Config(
        default_timeout=SOCKET_TIMEOUT,
        never_allow_redirects=False,
        ip_filter_enable=True,
        ip_filter_allow_localhost=False,
    )
)

SSRFFilterAllowLocalHost = SSRFFilter.clone()
SSRFFilterAllowLocalHost.config.ip_filter_allow_localhost = True


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
@mock.patch("requests.sessions.Session.send")
def test_blocks_private_ranges(mocked_send: mock.MagicMock, ip_addr: str):
    """Ensure private blocks are rejected."""
    with mock_getaddrinfo(ip_addr):
        with pytest.raises(InvalidIPAddress):
            SSRFFilter.send_request("GET", "https://test.local")
        mocked_send.assert_not_called()


@pytest.mark.parametrize(
    "ip_addr, expected_url",
    [
        ("128.99.0.0", "https://128.99.0.0:443/"),
        ("8.0.0.0", "https://8.0.0.0:443/"),
        ("::192.0.5.0", "https://[::c000:500]:443/"),  # Not IPv4
        ("::ffff:8063:0", "https://128.99.0.0:443/"),  # IPv6 mapped to IPv4
        ("::ffff:800:0", "https://8.0.0.0:443/"),  # IPv6 mapped to IPv4
        (
            "2004:0db8:1234:5678::abcd:ef01",
            "https://[2004:db8:1234:5678::abcd:ef01]:443/",
        ),
    ],
)
@pytest.mark.fake_resolver(enabled=False)
@mock.patch("requests.sessions.Session.send")
def test_allows_public_ranges(
    mocked_send: mock.MagicMock, ip_addr: str, expected_url: str
):
    """Ensure public blocks are allowed."""

    with mock_getaddrinfo(ip_addr):
        SSRFFilter.send_request("GET", "https://test.local")
        mocked_send.assert_called_once()

        [prepared_request], kwargs = mocked_send.call_args
        assert isinstance(prepared_request, PreparedRequest)
        assert prepared_request.method == "GET"
        assert prepared_request.url == expected_url
        assert prepared_request.headers.get("Host") == "test.local"


@pytest.mark.parametrize(
    "input_url, resolves_to, expected_output_url, expected_http_host_header",
    [
        (
            # Test handling of domains returning IP addresses version 6.
            # Ensures the IP is surrounded by brackets.
            "https://example.com",
            "2004:0db8:1234:5678::abcd:ef01",
            "https://[2004:db8:1234:5678::abcd:ef01]:443/",
            "example.com",
        ),
        (
            # Ensure IPv6 passed directly into a URL is handled properly:
            # - DNS resolver should be invoked using the IPv6 address without brackets;
            # - HTTP host header should be the IPv6 address (no brackets);
            # - HTTP URL should contain brackets.
            "https://[2004:0db8:1234:5678::abcd:ef01]",
            "2004:0db8:1234:5678::abcd:ef01",
            "https://[2004:db8:1234:5678::abcd:ef01]:443/",
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "https://[2004:0db8:1234:5678::abcd:ef01]:444",
            "2004:0db8:1234:5678::abcd:ef01",
            "https://[2004:db8:1234:5678::abcd:ef01]:444/",
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "http://[2004:0db8:1234:5678::abcd:ef01]:444",
            "2004:0db8:1234:5678::abcd:ef01",
            "http://[2004:db8:1234:5678::abcd:ef01]:444/",
            "2004:0db8:1234:5678::abcd:ef01",
        ),
        (
            # Ensure ports are handled properly
            "http://127.0.0.1:444",
            "127.0.0.1",
            "http://127.0.0.1:444/",
            "127.0.0.1",
        ),
        (
            # Ensure ports are handled properly
            "http://example.com:444",
            "127.0.0.1",
            "http://127.0.0.1:444/",
            "example.com",
        ),
        (
            # Ensure unicode URLs are encoded to IDNA
            "https://wroc\u0142aw.test",
            "127.0.0.1",
            "https://127.0.0.1:443/",
            "xn--wrocaw-6db.test",
        ),
    ],
)
@mock.patch("requests.sessions.Session.send")
def test_url_handling(
    mocked_send: mock.MagicMock,
    input_url: str,
    resolves_to: str,
    expected_output_url: str,
    expected_http_host_header: str,
):
    manager = SSRFFilter.clone()
    manager.config.ip_filter_allow_localhost = True
    with mock_getaddrinfo(resolves_to):
        manager.send_request("GET", input_url)

    mocked_send.assert_called_once()

    [prepared_request], kwargs = mocked_send.call_args
    assert isinstance(prepared_request, PreparedRequest)
    assert prepared_request.method == "GET"
    assert prepared_request.url == expected_output_url
    assert prepared_request.headers.get("Host") == expected_http_host_header


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
def test_tls_without_SNIs_supported(tmp_path):
    """
    Ensure we are able to connect successfully to a server that doesn't
    have a SNI callback set-up.
    """
    srv = TLSTestServer(
        tmp_path,
        cert_identities=["test1.local", "test2.local"],
    )
    with srv as [_srv_addr, srv_port]:
        do_request = functools.partial(
            SSRFFilterAllowLocalHost.send_request,
            "GET",
            f"https://test2.local:{srv_port}",
            verify=srv.ca_bundle_path,
        )

        # This should work both when SNI support is enabled and disabled.
        assert do_request().status_code == 200

        # Ensure this test is not testing SNI: when disabling SNI support client-side,
        # this the HTTP request should still succeed.
        with disable_sni_support():
            assert do_request().status_code == 200


@pytest.mark.timeout(TEST_TIMEOUT_SECS)
@pytest.mark.fake_resolver(enabled=True)
def test_tls_with_SNIs_supported(tmp_path):
    """
    Ensure we are able to connect successfully to a server that has a
    SNI callback set-up.
    """
    srv = SNITLSHTTPTestServer(
        tmp_path, cert_identities=["localhost"], additional_identities=["sni.local"]
    )
    with srv as [_srv_addr, srv_port]:
        do_request = functools.partial(
            SSRFFilterAllowLocalHost.send_request,
            "GET",
            f"https://sni.local:{srv_port}",
            verify=srv.ca_bundle_path,
        )

        # This should only work when SNI support is enabled.
        assert do_request().status_code == 200

        # Ensure when SNI support is disabled client-side, then
        # it no longer works, which allows to be sure the test is indeed testing SNI.
        with pytest.raises(SSLError) as exc_info:
            with disable_sni_support():
                assert do_request().status_code == 200

    exc = exc_info.value.args[0]
    assert isinstance(exc, MaxRetryError)
    original_exception = exc.reason.args[0]
    assert isinstance(original_exception, CertificateError)
    assert (
        original_exception.args[0] == "hostname 'sni.local' doesn't match 'localhost'"
    )
