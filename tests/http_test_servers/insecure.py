import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Tuple, Type


class DefaultHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(code=200)
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self):
        self.do_HEAD()
        self.wfile.write(b"OK\n")


class InsecureHTTPTestServer:
    """
    A basic HTTP server with no TLS/SSL support.

    Sample usage:

        >>> from time import sleep
        >>>
        >>> server = InsecureHTTPTestServer()
        >>>
        >>> with server.start_server() as addr:  # Will assign a random port.
        ...     print(f"Connect to http://{addr[0]}:{addr[1]}")
        ...     sleep(60)
        Connect to http://localhost:12345
    """

    def __init__(
        self,
        request_handler_class: Type[BaseHTTPRequestHandler] = DefaultHTTPRequestHandler,
    ):
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._http_request_handler = request_handler_class

    def setup_server(self, server: HTTPServer) -> None:
        pass

    def start(self) -> Tuple[str, int]:
        self.server = HTTPServer(("localhost", 0), self._http_request_handler)
        self.setup_server(self.server)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        return self.server.server_address

    def stop(self):
        self.server.shutdown()
        self.server_thread.join()

    def create_client_socket(self) -> socket.socket:
        """Creates a socket to the dummy server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.SOL_TCP)
        sock.settimeout(0.5)
        sock.connect(self.server.server_address)
        return sock

    def __enter__(self) -> Tuple[str, int]:
        """
        Starts a basic HTTP server listening on loopback port.

        This will listen onto ``localhost`` and assign a port that is available
        for use (number is chosen automatically by the kernel).

        :returns: The address pair where the server is listening (hostname + port).
        """
        return self.start()

    def __exit__(self, *args):
        self.stop()
