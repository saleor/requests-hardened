# noqa: D205,D212,D400,D415,D404
"""
This file is a copy of a yet to be released `HostHeaderSSLAdapter` class
with SNI support: https://github.com/requests/toolbelt/blob/c5ac5f3b5c7ed599703e0deb4fd31ce7998711ed/requests_toolbelt/adapters/host_header_ssl.py

Copyright 2014 Ian Cordasco, Cory Benfield

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from requests.adapters import HTTPAdapter


class HostHeaderSSLAdapter(HTTPAdapter):
    # noqa: D205,D400,D415
    """An HTTPS Adapter for Python Requests that sets the hostname for certificate
    verification based on the Host header.

    This allows requesting the IP address directly via HTTPS without getting
    a "hostname doesn't match" exception.

    Example usage:

        >>> s.mount('https://', HostHeaderSSLAdapter())
        >>> s.get("https://93.184.216.34", headers={"Host": "example.org"})

    """

    def send(self, request, **kwargs):
        # HTTP headers are case-insensitive (RFC 7230)
        host_header = None
        for header in request.headers:
            if header.lower() == "host":
                host_header = request.headers[header]
                break

        connection_pool_kwargs = self.poolmanager.connection_pool_kw

        if host_header:
            connection_pool_kwargs["assert_hostname"] = host_header
            connection_pool_kwargs["server_hostname"] = host_header
        elif "assert_hostname" in connection_pool_kwargs:
            # connection pool arguments from a previous request may have been left
            connection_pool_kwargs.pop("assert_hostname", None)
            connection_pool_kwargs.pop("server_hostname", None)

        return super().send(request, **kwargs)
