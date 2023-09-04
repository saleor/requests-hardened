import contextlib
import socket
import ssl
from typing import List, Tuple, Optional, Generator
from unittest import mock

from requests.adapters import HTTPAdapter

from requests_hardened.host_header_adapter import HostHeaderSSLAdapter


@contextlib.contextmanager
def create_ssl_socket(
    ssl_ctx: ssl.SSLContext, addr: Tuple[str, int], server_hostname: str
) -> Generator[ssl.SSLSocket, None, None]:
    """
    Connects to a specified remote address and setup SSL connection.

    :returns: The SSL socket connected to `addr`.
    """

    conn_sock = socket.create_connection(addr)
    ssl_sock: Optional[ssl.SSLSocket] = None
    try:
        ssl_sock = ssl_ctx.wrap_socket(conn_sock, server_hostname=server_hostname)
        yield ssl_sock
    finally:
        if ssl_sock is not None:
            ssl_sock.close()
        else:
            conn_sock.close()


def get_remote_certificate(
    ssl_ctx: ssl.SSLContext, addr: Tuple[str, int], server_hostname: str
):
    with create_ssl_socket(
        ssl_ctx=ssl_ctx, addr=addr, server_hostname=server_hostname
    ) as ssl_sock:
        return ssl_sock.getpeercert()


@contextlib.contextmanager
def mock_getaddrinfo(resolve_to_ip: str) -> Generator[List[tuple], None, None]:
    """
    Mocks socket.getaddrinfo() to return a given fake IP address as the resolved value.

    :param resolve_to_ip: The IP address to return whenever the function is invoked.
    :type resolve_to_ip: str

    :return: A list of resolved endpoints. The list will always contain only one entry,
        which contains the fake IP (`resolve_to_ip`).
        For more information, refer to getaddrinfo(3) manual.

    Example usage:

        >>> with mock_getaddrinfo("127.0.0.1") as call_list:
        ...     resolved = socket.getaddrinfo(
        ...         "example.com", 443, 0, socket.AF_UNSPEC, socket.SOCK_STREAM
        ...     )
        >>> print(resolved[0][-1])
        ('127.0.0.1', 443)
        >>> print(call_list[0])
        ('example.com', 443,
            (0, <AddressFamily.AF_UNSPEC: 0>, <SocketKind.SOCK_STREAM: 1>), {}
    """
    calls: List[tuple] = []

    def fake_getaddrinfo(hostname, port, *args, **kwargs):
        calls.append((hostname, port, args, kwargs))
        res = [
            (
                socket.AddressFamily.AF_INET,  # protocol family for socket
                socket.SocketKind.SOCK_STREAM,  # socket type
                socket.IPPROTO_TCP,  # protocol for socket
                "",  # the canonical name for service location
                (resolve_to_ip, port),  # socket-address for socket
            )
        ]
        return res

    with mock.patch.object(socket, "getaddrinfo", new=fake_getaddrinfo):
        yield calls


@contextlib.contextmanager
def disable_sni_support():
    # Ensure the parent of `HostHeaderSSLAdapter` is `HTTPAdapter` in case
    # the behavior of `requests-toolbelt` changes in the future.
    assert HostHeaderSSLAdapter.__bases__[0] is HTTPAdapter
    original_send = HTTPAdapter.send

    def _wrapped_send(self: HTTPAdapter, request, **kwargs):
        """
        Disables the SNI hostname check to ensure our tests for SNI work as expected.
        """
        del self.poolmanager.connection_pool_kw["server_hostname"]
        return original_send(self, request, **kwargs)

    with mock.patch.object(HTTPAdapter, "send", new=_wrapped_send):
        yield
