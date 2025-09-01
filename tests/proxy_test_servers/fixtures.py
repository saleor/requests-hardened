import contextlib
import multiprocessing
import sys

import pytest

from tests.proxy_test_servers.server import run_worker
from pytestskipmarkers.utils import ports

@contextlib.contextmanager
def create_dummy_proxy(proto: str) -> str:
    """
    Create a dummy proxy server and listens on a random port (port=0).

    :return: the proxy URL.
    """

    # Queue to wait and retrieve the address the server bound to.
    queue_bound_addr = multiprocessing.Queue()

    # Starts the proxy as a sub-process instead of a thread as it may otherwise
    # lead to issues due to using asyncio.
    hostname = "127.0.0.1"
    port = ports.get_unused_localhost_port()
    proc = multiprocessing.Process(target=run_worker, args=(proto, queue_bound_addr, hostname, port))
    proc.start()

    # Retrieve the ("randomly") bound port number and return it
    try:
        hostname, port = queue_bound_addr.get(timeout=5)
    except Exception as e:
        print("Exception while getting queue bound:", e, file=sys.stderr)
    yield f"{proto}://{hostname}:{port}"

    # Shutdown
    proc.terminate()
    proc.join()


@pytest.fixture(scope="session")
def dummy_proxy_socks4() -> str:
    """Dummy SOCKS4 proxy server."""

    with create_dummy_proxy("socks4") as url:
        yield url


@pytest.fixture(scope="session")
def dummy_proxy_socks5() -> str:
    """Dummy SOCKS5 proxy server."""

    with create_dummy_proxy("socks5") as url:
        yield url


@pytest.fixture(scope="session")
def dummy_proxy_http() -> str:
    """Dummy HTTP proxy server (`CONNECT` HTTP verb)."""

    with create_dummy_proxy("http") as url:
        yield url
