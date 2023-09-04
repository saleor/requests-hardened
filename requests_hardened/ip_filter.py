import ipaddress
import logging
import socket
from typing import Dict, Tuple, Union

import requests
from urllib3.util import Url, parse_url
from urllib3.util.connection import (  # type: ignore[attr-defined] # `allowed_gai_family` exists. # noqa: E501
    allowed_gai_family,
)

logger = logging.getLogger(__name__)


class InvalidIPAddress(requests.RequestException):
    pass


def get_ip_address(
    hostname: str, port: int, allow_loopback: bool
) -> Tuple[Union[ipaddress.IPv4Address, ipaddress.IPv6Address], int]:
    # Development safeguard, hostname shouldn't be surrounded by brackets
    # when calling this function.
    assert not hostname.startswith("[")

    addresses = socket.getaddrinfo(
        hostname, port, family=allowed_gai_family(), type=socket.SOCK_STREAM
    )

    af, socktype, proto, _canonname, socket_address = addresses[0]

    if af != socket.AF_INET and af != socket.AF_INET6:
        # This code shouldn't be reachable.
        raise ValueError(
            "Only AF_INET and AF_INET6 socket address families are supported"
        )
    port = socket_address[1]
    ip = ipaddress.ip_address(socket_address[0])

    # Python considers special IP ranges representing IPv4 addresses as being
    # private ranges, such as ::ffff:0:0/96, ::/128.
    # Because of that, we need to check the IPv4 address instead of the IPv6 one.
    # https://github.com/python/cpython/commit/ed391090cc8332406e6225d40877db6ff44a7104
    if ip.version == 6 and (ipv4 := ip.ipv4_mapped) is not None:
        ip = ipv4

    if allow_loopback and ip.is_loopback:
        return ip, port
    elif ip.is_private:
        logger.warning(
            "Forbidden IP address: %s for hostname %s",
            ip,
            hostname,
            # Extra arguments may clash with logger configuration
            # if it injects extra JSON fields, such as:
            # https://github.com/saleor/saleor/blob/5e7c57dad9e64b09477ebdcee53f0277359bc598/saleor/core/logging.py#L13
            # Because of that, we prefix the extra arguments in order to
            # reduce the chance of clashing with logging configs.
            extra={"dst_ip": ip, "dst_hostname": hostname},
        )
        raise InvalidIPAddress(ip)
    return ip, port


def filter_request(
    url: str, *, headers: Dict[str, Union[str, bytes, None]], allow_loopback: bool
) -> str:
    url = parse_url(url)
    port = url.port

    if not port:
        if url.scheme == "https":
            port = 443
        else:
            port = 80

    # IPv6 URL hostnames are embedded between "[" and "]"
    old_hostname = url.hostname
    if not old_hostname:
        raise ValueError("Invalid URL: missing hostname")
    if old_hostname.startswith("["):
        old_hostname = old_hostname.strip("[]")

    headers["Host"] = old_hostname
    ip_addr, port = get_ip_address(old_hostname, port, allow_loopback=allow_loopback)
    ip_addr_str = str(ip_addr) if ip_addr.version != 6 else f"[{ip_addr}]"

    url = Url(
        scheme=url.scheme,
        auth=url.auth,
        host=ip_addr_str,
        port=port,
        path=url.path,
        query=url.query,
        fragment=url.fragment,
    )
    return str(url)
