import socket
from pathlib import Path
from typing import Sequence, Optional

import ssl
from http.server import HTTPServer

import trustme

from .insecure import InsecureHTTPTestServer


class TLSTestServer(InsecureHTTPTestServer):
    """
    A basic TLS server with no SNI extension support.

    It will automatically generate self-signed certificates that can be injected
    into the trusted CA list.

    Sample usage:

        >>> from pathlib import Path
        >>> from time import sleep
        >>>
        >>> server = TLSTestServer(
        ...     # The directory where to save the generated certificates into.
        ...     cert_dir=Path("../certs"),
        ...     # List of domains to issue the certificate for.
        ...     cert_identities=["my-domain.test"]
        ... )
        >>>
        >>> with server.start_server() as addr:  # Will assign a random port.
        ...     print(f"Connect to https://{addr[0]}:{addr[1]}")
        ...     sleep(60)
        Connect to https://localhost:12345
    """

    def __init__(
        self,
        cert_dir: Path,
        cert_identities: Sequence[str],
        cert_options: Optional[dict] = None,
    ):
        """
        :param cert_dir: The directory where to store the generated certificates into.
        :param cert_identities: The list of hostnames to associate to the certificate.
            Can be a FQN, a wildcard, an IPv4 or v6 address, or an email address.
        :param cert_options: Additional options to pass to `trustme.issue_cert()`.
        """
        super().__init__()
        self._cert_identities = cert_identities
        self._cert_options = cert_options or {}
        self._cert_dir = cert_dir
        self._ca = trustme.CA()
        self.ca_bundle_path: str = None

    def generate_certificates(self):
        """
        Generate self-signed certificates and CA for the provided hostnames.

        :returns: The generated private certificate.
        """
        server_cert = self._ca.issue_cert(*self._cert_identities, **self._cert_options)
        ca_bundle_path = self._cert_dir / "ca.pem"
        ca_bundle_path.touch(mode=0o600)
        self.ca_bundle_path = str(ca_bundle_path)
        self._ca.cert_pem.write_to_path(self.ca_bundle_path)
        return server_cert

    @staticmethod
    def create_ssl_context(server_cert: trustme.LeafCert):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        server_cert.configure_cert(ssl_context)
        return ssl_context

    def ssl_wrap_server_socket(self, sock: socket.socket):
        server_cert = self.generate_certificates()
        ssl_context = self.create_ssl_context(server_cert)
        return ssl_context.wrap_socket(sock, server_side=True)

    def setup_server(self, server: HTTPServer) -> None:
        server.socket = self.ssl_wrap_server_socket(server.socket)
