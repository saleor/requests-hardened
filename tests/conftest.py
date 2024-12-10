import pytest

from tests.utils import mock_getaddrinfo

FAKE_RESOLVER_MARKER = "fake_resolver"

pytest_plugins = [
    # Additional fixtures for the test suite.
    "tests.proxy_test_servers.fixtures"
]


@pytest.mark.tryfirst
def pytest_load_initial_conftests(early_config, parser, args):
    """
    Register the fake-resolver marker inside pytest.

    This removes runtime warnings about unknown marker names being used.
    """
    early_config.addinivalue_line(
        "markers",
        f"{FAKE_RESOLVER_MARKER}: return fake IP address when resolving DNS.",
    )


@pytest.fixture(autouse=True)
def _pytest_fake_dns_resolver_marker(request):
    """
    Override DNS resolving of the test suite for `socket.getaddrinfo()` calls.

    By default, the fake DNS resolver is configured to always return 127.0.0.1.

    Options:
    - ``enabled`` (bool), whether it should mock or not `socket.getaddrinfo()`.
      Defaults to ``False``.
    - ``ip_address`` (str), which IP address to return. Defaults to ``127.0.0.1``.

    Sample usage:

        >>> import pytest
        >>> import socket
        >>>
        >>> @pytest.mark.fake_resolver(enabled=True, ip_address="8.0.0.0")
        >>> def my_test():
        >>>     print(socket.getaddrinfo()[-1][0])
        8.0.0.0
    """

    # Retrieve the current test case options.
    marker = request.node.get_closest_marker(FAKE_RESOLVER_MARKER)
    if marker:
        marker_kwargs = marker.kwargs
    else:
        marker_kwargs = {}

    # Set and retrieve the options.
    enabled = marker_kwargs.get("enabled", False)
    ip_address = marker_kwargs.get("ip_address", "127.0.0.1")

    if not enabled:
        yield
        return

    with mock_getaddrinfo(ip_address):
        yield
