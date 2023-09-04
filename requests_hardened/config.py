import dataclasses
from typing import Optional

from requests_hardened.types import T_TIMEOUT_TUPLE


@dataclasses.dataclass
class Config:
    # If ``True``, then any private and loopback IP will be rejected.
    ip_filter_enable: bool

    # If ``True``, then loopback IPs are allowed
    # when ``ip_filter_enable`` is set to ``True``.
    ip_filter_allow_localhost: bool

    # If True, then HTTP redirects are never allowed.
    never_allow_redirects: bool

    # The default timeout value to set to all requests.
    default_timeout: Optional[T_TIMEOUT_TUPLE]
