"""Web Crawler - Discover URLs and forms from target."""

import re
from collections import deque
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import config
from lib.http_client import HttpClient
from lib.logger import log
from lib.utils import normalize_url, is_same_domain, extract_params


class Crawler:
    """Crawl a target website to discover URLs and forms."""

    def __init__(self, target_url, max_depth=3, max_pages=200):
        self.target_url = normalize_url(target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.client = HttpClient()
        self.visited = set()
        self.urls = set()
        self.forms = []  # list of {url, method, action, inputs: [{name, type, value}]}
        self.technology = {}

    def crawl(self):
        """Start crawling and return discovered URLs and forms."""
        log.info(f"Crawling: {self.target_url} (max_depth={self.max_depth}, max_pages={self.max_pages})")

        queue = deque([(self.target_url, 0)])
        self.visited.add(self.target_url)

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.popleft()
            if depth > self.max_depth:
                continue

            try:
                resp = self.client.get(url)
                self.urls.add(url)

                # Fingerprint technology from headers
                self._fingerprint(resp)

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Extract links
                for tag in soup.find_all(["a", "link"], href=True):
                    href = urljoin(url, tag["href"])
                    href = href.split("#")[0]  # remove fragment
                    if is_same_domain(href, self.target_url) and href not in self.visited:
                        self.visited.add(href)
                        queue.append((href, depth + 1))

                # Extract forms
                for form in soup.find_all("form"):
                    form_data = self._parse_form(form, url)
                    if form_data:
                        self.forms.append(form_data)

                # Extract URLs from JavaScript
                for script in soup.find_all("script"):
                    if script.string:
                        js_urls = re.findall(r'["\'](/[a-zA-Z0-9_/.-]+\??[^"\']*)["\']', script.string)
                        for ju in js_urls:
                            full = urljoin(url, ju)
                            if is_same_domain(full, self.target_url) and full not in self.visited:
                                self.visited.add(full)
                                queue.append((full, depth + 1))

            except Exception as e:
                log.debug(f"Crawl error on {url}: {e}")
                continue

        log.info(f"Crawl complete: {len(self.urls)} URLs, {len(self.forms)} forms discovered")
        return {
            "urls": list(self.urls),
            "forms": self.forms,
            "technology": self.technology,
        }

    def _parse_form(self, form_tag, page_url):
        """Parse an HTML form into structured data."""
        action = form_tag.get("action", "")
        if action:
            action = urljoin(page_url, action)
        else:
            action = page_url

        method = form_tag.get("method", "GET").upper()
        inputs = []

        for inp in form_tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })

        if inputs:
            return {"url": page_url, "action": action, "method": method, "inputs": inputs}
        return None

    def _fingerprint(self, resp):
        """Basic technology fingerprinting from response."""
        server = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")
        if server:
            self.technology["server"] = server
        if powered_by:
            self.technology["powered_by"] = powered_by

        # Check for common frameworks in body
        body = resp.text[:5000].lower()
        markers = {
            "wordpress": "wp-content",
            "drupal": "drupal",
            "joomla": "joomla",
            "laravel": "laravel",
            "django": "csrfmiddlewaretoken",
            "flask": "flask",
            "spring": "spring",
            "express": "express",
            "next.js": "__next",
            "react": "react",
            "vue.js": "vue",
        }
        for tech, marker in markers.items():
            if marker in body:
                self.technology.setdefault("frameworks", []).append(tech)

    def close(self):
        self.client.close()
