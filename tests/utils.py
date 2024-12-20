import contextlib
import socket
import ssl
from typing import Generator, List, Optional, Tuple, Union
from unittest import mock


def create_ssl_context(purpose=ssl.Purpose.SERVER_AUTH) -> ssl.SSLContext:
    ctx = ssl.create_default_context(purpose)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


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
def mock_getaddrinfo(
    resolve_to_ip: Union[str, dict[str, str]]
) -> Generator[List[tuple], None, None]:
    """
    Mocks socket.getaddrinfo() to return a given fake IP address as the resolved value.

    :param resolve_to_ip:
        Either:
            - The IP address to return whenever the function is invoked.
              Example:
                >>> mock_getaddrinfo(resolve_to_ip="127.0.0.1")
            - Or, the hostname to resolve the IP to.
              Any hostname that wasn't provided in the resolve_to_ip list,
              will raise ``AssertionError``.
              Example:
                >>> mock_getaddrinfo(
                ...     resolve_to_ip={
                ...         "example1.test": "127.0.0.1",
                ...         "example2.test": "10.0.0.2",
                ...     }
                ... )
    :type resolve_to_ip: Union[str, dict[str, str]]

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

        if isinstance(resolve_to_ip, str):
            wanted_ip_addr = resolve_to_ip
        elif isinstance(resolve_to_ip, dict):
            wanted_ip_addr = resolve_to_ip.get(hostname)
            if wanted_ip_addr is None:
                raise AssertionError(
                    f"{hostname} was not defined in 'resolve_to_ip' list"
                )
        else:
            raise ValueError(
                f"resolve_to_ip must be a string or dict, got instead: {type(resolve_to_ip)}"
            )

        res = [
            (
                socket.AddressFamily.AF_INET,  # protocol family for socket
                socket.SocketKind.SOCK_STREAM,  # socket type
                socket.IPPROTO_TCP,  # protocol for socket
                "",  # the canonical name for service location
                (wanted_ip_addr, port),  # socket-address for socket
            )
        ]
        return res

    with mock.patch.object(socket, "getaddrinfo", new=fake_getaddrinfo):
        yield calls
