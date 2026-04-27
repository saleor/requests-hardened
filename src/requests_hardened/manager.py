from copy import copy

from requests_hardened import HTTPSession
from requests_hardened.config import Config


class Manager:
    __slots__ = ("config",)

    def __init__(self, config: Config):
        self.config = config

    def clone(self):
        return Manager(config=copy(self.config))

    def get_session(self):
        return HTTPSession(self.config)

    def send_request(self, method: str, url: str, **kwargs):
        with self.get_session() as sess:
            return sess.request(method, url, **kwargs)
