import dataclasses
from typing import Optional

from requests_hardened.types import T_TIMEOUT_TUPLE


@dataclasses.dataclass
class Config:
    # If ``True``, then any private and loopback IP will be rejected.
    ip_filter_enable: bool

    # If ``True``, then loopback IPs are allowed
    # when ``ip_filter_enable`` is set to ``True``.
    ip_filter_allow_loopback_ips: bool

    # If True, then HTTP redirects are never allowed.
    never_redirect: bool

    # The default timeout value to set to all requests.
    default_timeout: Optional[T_TIMEOUT_TUPLE]

    # Override the default User-Agent header of the requests library.
    user_agent_override: Optional[str] = None

    # Whether to enable support for TLS SNI for IP filtering.
    # Do not disable this option unless you are absolutely sure of what you are doing!
    ip_filter_tls_sni_support: bool = True
