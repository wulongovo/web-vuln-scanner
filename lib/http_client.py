"""HTTP Client - Session management, retries, User-Agent rotation."""

import random
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class HttpClient:
    """Reusable HTTP client with automatic retries and UA rotation."""

    def __init__(self, timeout=None, proxies=None):
        self.timeout = timeout or config.TIMEOUT
        self.session = requests.Session()

        # Retry strategy
        retry = Retry(
            total=config.MAX_RETRIES,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=config.THREADS, pool_maxsize=config.THREADS)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if proxies:
            self.session.proxies.update(proxies)

    def _rotate_ua(self):
        self.session.headers.update({"User-Agent": random.choice(config.USER_AGENTS)})

    def get(self, url, **kwargs):
        self._rotate_ua()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        self._rotate_ua()
        kwargs.setdefault("timeout", self.timeout)
        return self.session.post(url, **kwargs)

    def head(self, url, **kwargs):
        self._rotate_ua()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        return self.session.head(url, **kwargs)

    def close(self):
        self.session.close()
