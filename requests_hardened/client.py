from typing import Union, cast, Any

import requests
from requests import Request, PreparedRequest, Response

from requests_hardened.config import Config
from requests_hardened.host_header_adapter import HostHeaderSSLAdapter
from requests_hardened.ip_filter import filter_request

T_TIMEOUT = Union[int, float]


class HTTPSession(requests.Session):
    def __init__(self, config: Config, **kwargs):
        super().__init__(**kwargs)
        self.mount("https://", HostHeaderSSLAdapter())
        self._config = config

    def send(self, request: PreparedRequest, **kwargs: Any) -> Response:
        allow_redirects = kwargs.setdefault(
            "allow_redirects", not self._config.never_allow_redirects
        )
        if allow_redirects and self._config.never_allow_redirects:
            kwargs["allow_redirects"] = False

        timeout = kwargs.setdefault("timeout", self._config.default_timeout)
        if not timeout:
            kwargs["timeout"] = self._config.default_timeout
        return super().send(request, **kwargs)

    def prepare_request(self, request: Request) -> PreparedRequest:
        url = request.url

        if self._config.ip_filter_enable is True:
            headers = request.headers or {}

            # Cast potentially immutable header list to `dict`
            if not isinstance(headers, dict):
                headers = cast(dict, dict(**headers))

            # Cast `bytes` to `str`
            if isinstance(url, bytes):
                url = url.decode()

            url = filter_request(
                url,
                headers=headers,
                allow_loopback=self._config.ip_filter_allow_localhost,
            )
            request.url = url
            request.headers = headers
        return super().prepare_request(request)
