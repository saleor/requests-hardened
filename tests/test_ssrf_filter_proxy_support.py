"""
This test file checks that the proxy support is behaving as expected.

``requests`` and ``urllib3`` only support SOCKS4, SOCKS5, and HTTP proxies,
thus we are only testing these.
"""

import functools

import pytest
from pytest import FixtureRequest
from requests.exceptions import SSLError
from urllib3.exceptions import MaxRetryError
from urllib3.util.ssl_match_hostname import CertificateError

from requests_hardened.ip_filter import InvalidIPAddress
from tests.http_managers import SSRFFilter, SSRFFilterAllowLocalHost
from tests.http_test_servers import SNITLSHTTPTestServer, TLSTestServer
from tests.utils import mock_getaddrinfo

# Lists the supported proxy server protocols.
# These are the ones supported by `requests[socks]` and `urllib3`.
SUPPORTED_PROXY_PROTOCOLS = ("socks4", "socks5", "http")


@pytest.mark.parametrize(
    # The protocol to use inside the requests.get(...)
    "http_client_proto",
    ("http", "https"),
)
@pytest.mark.parametrize(
    # The protocol to use as the proxy server backend (e.g., SOCKS5)
    "proxy_proto",
    SUPPORTED_PROXY_PROTOCOLS,
)
@pytest.mark.enable_socket  # We need to be able to create the dummy server
def test_proxy_ip_filter_blocks_private(
    http_client_proto: str, proxy_proto: str, request: FixtureRequest
):
    """Ensures private IP addresses are blocked when using proxies."""

    proxy_url = request.getfixturevalue(f"dummy_proxy_{proxy_proto}")
    proxies = {"https": proxy_url, "http": proxy_proto}

    # Test: ensure IP filter works when the IP address is resolved through DNS.
    with mock_getaddrinfo("10.0.0.1"):
        with pytest.raises(InvalidIPAddress, match="10.0.0.1"):
            SSRFFilter.send_request(
                "GET",
                f"{http_client_proto}://example.test",  # Use hostname (DNS)
                proxies=proxies,
            )

    # Test: ensure IP filter works when the IP address is in the URL (no DNS).
    with pytest.raises(InvalidIPAddress, match="127.100.0.2"):
        SSRFFilter.send_request(
            "GET",
            f"{http_client_proto}://127.100.0.2",  # Use IP address (no DNS)
            proxies=proxies,
        )


@pytest.mark.parametrize(
    # The protocol to use as the proxy server backend (e.g., SOCKS5)
    "proxy_proto",
    SUPPORTED_PROXY_PROTOCOLS,
)
@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.enable_socket  # We need to be able to create the dummy server
def test_proxy_tls_without_SNIs_supported(
    proxy_proto: str,
    request: FixtureRequest,
    tmp_path,
):
    """
    Ensure we are able to connect successfully to a server that doesn't
    have a SNI callback set-up when using proxies.
    """

    proxy_url = request.getfixturevalue(f"dummy_proxy_{proxy_proto}")
    proxies = {"https": proxy_url, "http": proxy_proto}

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
            proxies=proxies,
        )

        # This should work both when SNI support is enabled and disabled.
        assert do_request().status_code == 200

        # Ensure this test is not testing SNI: when disabling SNI support client-side,
        # the HTTP request should still succeed.
        http_manager.config.ip_filter_tls_sni_support = False
        assert do_request().status_code == 200


@pytest.mark.parametrize(
    # The protocol to use as the proxy server backend (e.g., SOCKS5)
    "proxy_proto",
    SUPPORTED_PROXY_PROTOCOLS,
)
@pytest.mark.fake_resolver(enabled=True)
@pytest.mark.enable_socket  # We need to be able to create the dummy server
def test_proxy_tls_with_SNIs_supported(
    proxy_proto: str,
    request: FixtureRequest,
    tmp_path,
):
    """
    Ensures when using proxies, we are able to connect successfully to a server
    that uses SNI callbacks.
    """

    proxy_url = request.getfixturevalue(f"dummy_proxy_{proxy_proto}")
    proxies = {"https": proxy_url, "http": proxy_proto}

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
            proxies=proxies,
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
