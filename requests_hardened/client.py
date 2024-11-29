from typing import Union, Any

import requests
from requests import Request, PreparedRequest, Response

from requests_hardened.config import Config
from requests_hardened.ip_filter_adapter import IPFilterAdapter

T_TIMEOUT = Union[int, float]


class HTTPSession(requests.Session):
    def __init__(self, config: Config, **kwargs):
        super().__init__(**kwargs)

        if config.ip_filter_enable is True:
            self.mount(
                "http://",
                IPFilterAdapter(
                    is_https_proto=False,  # We use http:// (insecure)
                    allow_loopback=config.ip_filter_allow_loopback_ips,
                    tls_sni_support=config.ip_filter_tls_sni_support,
                ),
            )
            self.mount(
                "https://",
                IPFilterAdapter(
                    is_https_proto=True,  # We use https:// (SSL/TLS)
                    allow_loopback=config.ip_filter_allow_loopback_ips,
                    tls_sni_support=config.ip_filter_tls_sni_support,
                ),
            )

        self._config = config

    def send(self, request: PreparedRequest, **kwargs: Any) -> Response:
        allow_redirects = kwargs.setdefault(
            "allow_redirects", not self._config.never_redirect
        )
        if allow_redirects and self._config.never_redirect:
            kwargs["allow_redirects"] = False

        timeout = kwargs.setdefault("timeout", self._config.default_timeout)
        if not timeout:
            kwargs["timeout"] = self._config.default_timeout
        return super().send(request, **kwargs)

    def prepare_request(self, request: Request) -> PreparedRequest:
        if self._config.user_agent_override is not None:
            request.headers.update({"User-Agent": self._config.user_agent_override})
        return super().prepare_request(request)
