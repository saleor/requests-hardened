import ipaddress
import logging
import socket
from typing import Tuple, Union, cast

import requests.exceptions
from urllib3.util.connection import (  # type: ignore[attr-defined] # `allowed_gai_family` exists. # noqa: E501
    allowed_gai_family,
)

logger = logging.getLogger(__name__)

# Additional CIDRs that should be blocked
EXTRA_BLOCKED_NET_RANGES: tuple[
    Union[ipaddress.IPv4Network, ipaddress.IPv6Network], ...
] = (
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 relay anycast
    ipaddress.ip_network("100.64.0.0/10"),  # CG-NAT, can route to internal workloads
    ipaddress.ip_network("5f00::/16"),  # IPv6 Segment Routing
    ipaddress.ip_network("64:ff9b::/96"),  # used for IPv6 & IPv4 translation (NAT64)
    ipaddress.ip_network("2001:20::/28"),  # ORCHIDv2 (overlay identifiers)

    # Fixes https://github.com/python/cpython/issues/113171 for outdated CPython
    # installations.
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("3fff::/20"),
)


class InvalidIPAddress(requests.RequestException):
    pass


def _is_ip_in_extra_blocked_ranges(
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
) -> bool:
    """Checks whether a given IP is part of the additional disallowed ranges."""

    for net in EXTRA_BLOCKED_NET_RANGES:
        if ip in net:
            return True
    return False


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
    port = cast(int, socket_address[1])
    ip = ipaddress.ip_address(socket_address[0])

    # Python considers special IP ranges representing IPv4 addresses as being
    # private ranges, such as ::ffff:0:0/96, ::/128.
    # Because of that, we need to check the IPv4 address instead of the IPv6 one.
    # https://github.com/python/cpython/commit/ed391090cc8332406e6225d40877db6ff44a7104
    if ip.version == 6:
        ip = cast(ipaddress.IPv6Address, ip)
        if (ipv4 := ip.ipv4_mapped) is not None:
            ip = ipv4

    if allow_loopback and ip.is_loopback:
        return ip, port
    elif ip.is_private or ip.is_multicast or _is_ip_in_extra_blocked_ranges(ip):
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


def filter_host(
    hostname: str, port: int, *, allow_loopback: bool
) -> str:
    if not hostname:
        raise requests.exceptions.InvalidURL("Invalid URL: missing hostname")

    try:
        ip_addr, port = get_ip_address(
            hostname, port, allow_loopback=allow_loopback
        )
    except socket.gaierror as exc:
        raise requests.ConnectionError("Failed to resolve domain") from exc
    except socket.timeout as exc:
        raise requests.ConnectTimeout("Failed to connect to host") from exc

    ip_addr_str = str(ip_addr) if ip_addr.version != 6 else f"[{ip_addr}]"
    return ip_addr_str
