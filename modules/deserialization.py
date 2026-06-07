"""Deserialization Vulnerability Detection Module."""

import re
import base64
from modules.base import BaseModule
from lib.logger import log


class DeserializationModule(BaseModule):
    """Detect insecure deserialization vulnerabilities."""

    name = "deserialization"
    description = "Detect Java/PHP/Python deserialization vulnerabilities"

    # Java deserialization magic bytes
    JAVA_MAGIC = b"\xac\xed\x00\x05"

    # PHP serialized patterns
    PHP_SERIALIZED = [
        'O:8:"stdClass":0:{}',
        'a:1:{s:3:"foo";s:3:"bar";}',
        's:4:"test";',
    ]

    # Java gadget chain indicators in error messages
    JAVA_GADGET_ERRORS = [
        "java.io.InvalidClassException",
        "java.io.ObjectInputStream",
        "java.lang.ClassNotFoundException",
        "org.apache.commons.collections",
        "org.codehaus.groovy.runtime",
        "org.springframework",
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "java.lang.UNIXProcess",
    ]

    # PHP deserialization indicators
    PHP_ERRORS = [
        "unserialize()",
        "__wakeup()",
        "__destruct()",
        "PHP Fatal error",
        "Serialization of",
        "allowed_classes",
    ]

    # Python pickle indicators
    PYTHON_PICKLE = [
        "cposix\nsystem\n",
        "cos\nsystem\n",
        "_pickle",
        "pickle.loads",
        "__reduce__",
        "builtins",
        "subprocess",
    ]

    # Common deserialization endpoints
    ENDPOINTS = [
        "/api/deserialize",
        "/api/import",
        "/api/upload",
        "/api/session",
        "/api/data",
        "/jmx-console/",
        "/web-console/",
        "/invoker/JMXInvokerServlet",
        "/admin-console/",
        "/jbossws/",
    ]

    def run(self, param_urls, forms):
        """Run deserialization detection."""
        base_url = self._get_base(param_urls, forms)

        # Test known deserialization endpoints
        for endpoint in self.ENDPOINTS:
            self._test_endpoint(base_url + endpoint)

        # Test forms for serialized input
        for form in forms:
            self._test_form(form)

        # Test URL parameters for base64-encoded serialized objects
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_param(url, param)

        return self.findings

    def _get_base(self, param_urls, forms):
        from urllib.parse import urlparse
        for url in param_urls + [f["action"] for f in forms]:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        return ""

    def _test_endpoint(self, url):
        """Test known deserialization endpoints."""
        self.delay()
        try:
            # Send Java serialized object
            resp = self.client.post(
                url,
                data=self.JAVA_MAGIC,
                headers={"Content-Type": "application/x-java-serialized-object"}
            )
            if any(err in resp.text for err in self.JAVA_GADGET_ERRORS):
                self.add_finding("deserialization", url, "", "critical",
                    "Java deserialization endpoint responds to gadget chain",
                    "Java serialized object", "Insecure Java deserialization endpoint")
                return

            # Check if endpoint exists and accepts serialized data
            if resp.status_code in (200, 400, 500) and len(resp.text) > 0:
                if any(err in resp.text for err in self.JAVA_GADGET_ERRORS + self.PHP_ERRORS):
                    self.add_finding("deserialization", url, "", "high",
                        "Deserialization error messages exposed",
                        "", "Endpoint reveals deserialization processing")
        except Exception:
            pass

    def _test_form(self, form):
        """Test form inputs for serialized data."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "file"):
                continue

            # Test PHP serialized input
            for payload in self.PHP_SERIALIZED:
                self.delay()
                data = {}
                for field in inputs:
                    data[field["name"]] = payload if field["name"] == inp["name"] else field.get("value", "test")
                try:
                    resp = self.client.post(action, data=data) if method == "POST" else self.client.get(action, params=data)
                    if any(err in resp.text for err in self.PHP_ERRORS):
                        self.add_finding("deserialization", action, inp["name"], "high",
                            "PHP deserialization error in form field",
                            payload, "Insecure PHP deserialization via form")
                        return
                except Exception:
                    pass

            # Test Java serialized input (base64 encoded)
            java_b64 = base64.b64encode(self.JAVA_MAGIC).decode()
            self.delay()
            data = {}
            for field in inputs:
                data[field["name"]] = java_b64 if field["name"] == inp["name"] else field.get("value", "test")
            try:
                resp = self.client.post(action, data=data) if method == "POST" else self.client.get(action, params=data)
                if any(err in resp.text for err in self.JAVA_GADGET_ERRORS):
                    self.add_finding("deserialization", action, inp["name"], "critical",
                        "Java deserialization via form field",
                        java_b64, "Insecure Java deserialization via form input")
                    return
            except Exception:
                pass

    def _test_param(self, url, param):
        """Test URL parameter for deserialization."""
        # Check if parameter value looks like base64-encoded serialized data
        test_values = [
            base64.b64encode(self.JAVA_MAGIC).decode(),
            base64.b64encode(b'O:8:"stdClass":0:{}').decode(),
        ]

        for val in test_values:
            self.delay()
            test_url = self.inject_param(url, param, val)
            try:
                resp = self.client.get(test_url)
                errors = self.JAVA_GADGET_ERRORS + self.PHP_ERRORS
                if any(err in resp.text for err in errors):
                    self.add_finding("deserialization", url, param, "high",
                        "Deserialization error via URL parameter",
                        val, "Possible insecure deserialization via query parameter")
                    return
            except Exception:
                pass
