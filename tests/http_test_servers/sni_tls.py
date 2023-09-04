import socket
from pathlib import Path
from typing import Sequence, Optional

from .tls import TLSTestServer


class SNITLSHTTPTestServer(TLSTestServer):
    """
    A basic HTTP server with SNI extension enabled using self-issued TLS certificates.
    """

    def __init__(
        self,
        cert_dir: Path,
        cert_identities: Sequence[str],
        cert_options: Optional[dict] = None,
        additional_identities: Optional[Sequence[str]] = None,
    ):
        """
        :param cert_dir: The directory where to store the generated certificates into.
        :param cert_identities: The list of hostnames to associate to the certificate.
            Can be a FQN, a wildcard, an IPv4 or v6 address, or an email address.
        :param cert_options: Additional options to pass to `trustme.issue_cert()`.
        :param additional_identities: `cert_identities` except it contains a list
            of alternative hostnames to issue certificates for use during SNI callbacks.
        """
        super().__init__(cert_dir, cert_identities, cert_options)
        self._additional_identities = additional_identities or []
        self._additional_server_certs = {}

    def generate_certificates(self):
        default_cert = self._ca.issue_cert(*self._cert_identities, **self._cert_options)

        for ident in self._additional_identities:
            self._additional_server_certs[ident] = self._ca.issue_cert(ident)

        self.ca_bundle_path = str(self._cert_dir / "ca.pem")
        self._ca.cert_pem.write_to_path(self.ca_bundle_path)
        return default_cert

    def ssl_wrap_server_socket(self, sock: socket.socket):
        """
        Wraps a server socket with TLS support configured and SNI extension logic.
        """
        server_cert = self.generate_certificates()
        default_ctx = self.create_ssl_context(server_cert)

        def sni_callback(sock, srv_hostname, _context):
            if srv_hostname in self._additional_identities:
                new_context = self.create_ssl_context(
                    self._additional_server_certs[srv_hostname]
                )
                sock.context = new_context

        default_ctx.sni_callback = sni_callback
        return default_ctx.wrap_socket(sock, server_side=True)
