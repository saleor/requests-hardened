import ssl

from tests.http_test_servers import SNITLSHTTPTestServer
from tests.utils import get_remote_certificate


def test_dummy_sni_tls_server(tmp_path):
    """
    Tests that the SNI test server works as expected.

    The TLS server with SNI extension is expected to act as follows:
    1. domain.local returns the default certificate
    2. Invalid/unknown domains return domain.local's certificate (fallback)
    3. sni.local returns its own certificate.
    """

    srv = SNITLSHTTPTestServer(
        tmp_path,
        cert_identities=["domain.local"],
        cert_options={},
        additional_identities=["sni.local"],
    )

    with srv as sock_addr:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_verify_locations(srv.ca_bundle_path)

        # Retrieve the default TLS certificate (not an SNI callback one).
        cert_domain_local = get_remote_certificate(
            ssl_ctx, sock_addr, server_hostname="domain.local"
        )

        # Retrieve the certificate generated through SNI callback.
        cert_sni_local = get_remote_certificate(
            ssl_ctx, sock_addr, server_hostname="sni.local"
        )

        # Retrieve the TLS certificate of an nonexistent domain, it should return
        # the default certificate due to being unknown.
        ssl_ctx.check_hostname = False  # The hostname will mismatch thus ignore it
        cert_invalid_local = get_remote_certificate(
            ssl_ctx, sock_addr, server_hostname="invalid.local"
        )

    # domain.local and invalid.local should have returned the same certificate.
    assert cert_domain_local == cert_invalid_local

    # domain.local and sni.local should NOT have returned the same certificate.
    assert cert_domain_local["subjectAltName"] == (("DNS", "domain.local"),)
    assert cert_sni_local["subjectAltName"] == (("DNS", "sni.local"),)
