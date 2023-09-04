import ssl

from tests.http_test_servers import TLSTestServer
from tests.utils import get_remote_certificate


def test_dummy_tls_server(tmp_path):
    """
    Tests that the test server works expected.

    That TLS server doesn't have the SNI extension set-up thus
    it should always return one and only one certificate.
    """

    fqn = "domain.local"
    srv = TLSTestServer(tmp_path, cert_identities=[fqn], cert_options={})

    with srv as sock_addr:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.load_verify_locations(srv.ca_bundle_path)

        # Get the certificate a domain that is associated with the server's
        # TLS certificate.
        cert1 = get_remote_certificate(ssl_ctx, sock_addr, server_hostname=fqn)

        # Retrieve the server's certificate returned when an unknown domain
        # is being connected onto.
        ssl_ctx.check_hostname = False  # The hostname will mismatch thus ignore it
        cert2 = get_remote_certificate(
            ssl_ctx, sock_addr, server_hostname="invalid.local"
        )

    # domain.local and invalid.local should have returned the same certificate.
    assert cert1 == cert2
