"""
This file creates a dummy proxy server (using HTTP, SOCKS4 and SOCKS5 protocols),
it uses the 'pproxy' library for it (https://github.com/qwj/python-proxy/).

As a precaution to unintended side effects, the server is started inside a child
process to fully isolate it from the main process (through the `multiprocessing` stdlib).
"""

import asyncio
import logging
import multiprocessing
import socket
from typing import Optional, Tuple

import pproxy
from pproxy.server import ProxySimple

logger = logging.getLogger(__name__)


class DummyProxyServer:
    def __init__(self, protocol: str, bind_addr: Optional[Tuple[str, int]] = None):
        self._protocol = protocol

        if bind_addr is not None:
            self._addr = bind_addr
        else:
            self._addr = ("127.0.0.1", 0)

        self.loop = asyncio.new_event_loop()
        self.handler: Optional[asyncio.Server] = None

    def start(self) -> (str, int):
        server: ProxySimple = pproxy.Server(
            f"{self._protocol}://{self._addr[0]}:{self._addr[1]}"
        )

        self.handler: asyncio.Server = self.loop.run_until_complete(
            server.start_server(
                {
                    "rserver": [],  # Direct connection (no multi-hop setup)
                    # Redirects verbose logging to `logger.debug()` in order to make
                    # the tests quiet by default.
                    #
                    # The 'verbose' argument isn't designed to be passed
                    # to `logging` thus may pose threats if there are untrusted inputs
                    # (e.g., verbose("arbitrary user-provided value: %(x)999999999999s").
                    #
                    # As a best practice, we thus put the message as "%s"
                    # in order to tell the `logging` module to not try to format
                    # the arguments (and thus making it consider it as untrusted input).
                    "verbose": lambda *args: logger.debug("%s", " ".join(args)),
                }
            )
        )

        assert len(self.handler.sockets) == 1, "Expected only one socket to be created"

        # Retrieve the socket address. This is needed as port=0 will allocate
        # an unused ephemeral port upon bind, thus we need to run the syscall
        # `getsockname()` in order to determine which port was allocated to us.
        #
        # After which, we validate whether the value is (host: str, port: int)
        # due to having the "Any" type.
        addr: socket.socket = self.handler.sockets[0].getsockname()
        assert isinstance(addr, tuple), "Expected a tuple of (host, port)"
        assert len(addr) == 2, "Expected a 2-tuple with only (host, port)"
        assert isinstance(addr[0], str), "Expected bind hostname to be a string"
        assert isinstance(addr[1], int), "Expected bind port to be an integer"

        # Update the server address with the newly bound port.
        self._addr = addr
        return addr

    def serve_forever(self):
        if self.handler is None:
            raise RuntimeError(
                f"Server was not started: "
                f"{self.__class__.__name__}.start() was never called"
            )
        try:
            # Stopped by `loop.stop()`
            self.loop.run_forever()
        finally:
            self.handler.close()
            self.loop.run_until_complete(self.handler.wait_closed())

    def shutdown(self):
        # Stop the asyncio loop, this will cause ``serve_forever`` to exit.
        self.loop.stop()

        if self.handler is not None:
            self.loop.run_until_complete(self.handler.wait_closed())

        self.loop.run_until_complete(self.loop.shutdown_asyncgens())

    def __enter__(self) -> Tuple[str, int]:
        return self.start()

    def __exit__(self, *args):
        self.shutdown()
        self.loop.close()


def run_worker(
    proto: str,
    queue_bound_addr: multiprocessing.Queue,
    hostname: str = "127.0.0.1",
    port: int = 0,
) -> None:
    """
    Start the dummy proxy server **inside** the current process.

    :param proto: The protocol(s) to handle (e.g., "http", "socks4", etc.).
        Can be a list using ``+`` as the separator, such as: ``http+socks4``.

    :param queue_bound_addr: A queue that is used as a channel to return the
        socket address where the server is bound to.
        This is useful when providing the port ``0`` as the kernel will
        choose a "random" port number once the socket is created.

    :param port: The port number to listen to.
    :param hostname: The hostname number to listen to, e.g., 127.0.0.1 or localhost.

    Example Usage:

    >>> import multiprocessing, time
    >>> from tests.proxy_test_servers.server import run_worker
    >>>
    >>> proto = "socks4+socks5+http"
    >>> callback_queue = multiprocessing.Queue()
    >>>
    >>> proc = multiprocessing.Process(
    ...     target=run_worker,
    ...     args=(proto, callback_queue),
    ... )
    ...
    >>> proc.start()
    >>> addr = callback_queue.get(timeout=5)
    >>> print(f"Listening on: {proto}://{addr[0]}:{addr[1]}")
    >>>
    >>> # Keep the server running for 30s.
    >>> time.sleep(30)
    >>>
    >>> # Shutdown
    >>> proc.terminate()
    >>> proc.join()
    """
    srv = DummyProxyServer(proto, bind_addr=(hostname, port))
    with srv as bind_addr:
        queue_bound_addr.put(bind_addr)
        srv.serve_forever()
