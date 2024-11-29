from requests.adapters import HTTPAdapter
from requests_hardened.ip_filter import filter_host


class IPFilterAdapter(HTTPAdapter):
    def __init__(
        self,
        is_https_proto: bool,
        allow_loopback: bool = False,
        tls_sni_support: bool = True,
    ):
        """
        :param is_https_proto: whether it is HTTPS or insecure HTTP.
        :param allow_loopback: whether to allow loopback IP addresses in IP filtering.
        :param tls_sni_support: whether to add support for TLS SNI (enabled by default,
            and shouldn't be changed unless you are certain).
        """
        super().__init__()
        self._is_https_proto = is_https_proto
        self._allow_loopback = allow_loopback
        self._tls_sni_support = tls_sni_support

    def build_connection_pool_key_attributes(self, request, verify, cert=None):
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(
            request, verify, cert
        )

        # Copy headers before mutating them as they may be a global variable used by
        # subsequent requests.
        # e.g., https://github.com/lepture/authlib/blob/a7d68b4c3b8a3a7fe0b62943b5228669f2f3dfec/authlib/oauth2/client.py#L205-L206
        if request.headers:
            request.headers = dict(**request.headers)
        else:
            request.headers = {}

        # Adds the original URL hostname as the 'Host' header.
        original_host = request.headers["Host"] = host_params["host"]

        # Set the original hostname for certificate validation otherwise
        # urllib3 will try to match the pinned resolved IP address against the
        # certificate.
        #
        # Note: assert_hostname and server_hostname cannot be passed
        #       when using insecure HTTP (http://) as it's not a valid argument for
        #       `urllib3.connectionpool.HTTPConnectionPool`.
        if self._is_https_proto is True:
            # For non-TLS SNI servers.
            pool_kwargs["assert_hostname"] = original_host

            # Support TLS servers with SNI callbacks.
            if self._tls_sni_support is True:
                pool_kwargs["server_hostname"] = original_host

        # Override the connection hostname to the resolved IP address,
        # and reject if it's a private IP.
        host_params["host"] = filter_host(
            original_host,
            host_params["port"],
            allow_loopback=self._allow_loopback,
        )
        return host_params, pool_kwargs

    def get_connection(self, host_params, pool_kwargs):
        # TODO: either:
        #   - Implement this method
        #   - Always raise due to being a deprecated method
        #   - Upgrade 'requests' version if they dropped it
        #     in a more recent minor or major version, and update pyproject constraints.
        raise NotImplementedError
