from http.server import BaseHTTPRequestHandler
from typing import Type


class RedirectRequestHandler(BaseHTTPRequestHandler):
    redirect_url_loc: str


def create_http_redirect_handler(redirect_url: str) -> Type[RedirectRequestHandler]:
    """
    Create an ``http.server`` request handler that redirects to the given url.

    To prevent redirection loops, ``noredirect`` can be provided anywhere inside the
    request URL to stop redirections.

    :param redirect_url: The URL to redirect to.
    :return: The HTTP request handler that redirects to the given url.
    """

    class _Handler(RedirectRequestHandler):
        redirect_url_loc = redirect_url

        @property
        def should_redirect(self) -> bool:
            return "noredirect" not in self.path

        def do_HEAD(self):
            if self.should_redirect:
                self.send_response(code=301)
                self.send_header("Location", self.redirect_url_loc)
            else:
                self.send_response(code=200)

            self.send_header("Connection", "close")
            self.end_headers()

        def do_GET(self):
            self.do_HEAD()
            if self.should_redirect:
                self.wfile.write(
                    b"Redirecting to %b\n" % self.redirect_url_loc.encode()
                )
            else:
                self.wfile.write(b"OK")

    return _Handler
