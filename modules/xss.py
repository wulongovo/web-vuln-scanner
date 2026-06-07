"""XSS Detection Module."""

import re
import html
from modules.base import BaseModule
from lib.logger import log


class XSSModule(BaseModule):
    """Detect Cross-Site Scripting vulnerabilities."""

    name = "xss"
    description = "Reflected and DOM-based XSS detection"

    XSS_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        "'-alert(1)-'",
        '"><script>alert(1)</script>',
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
        'javascript:alert(1)',
        '<marquee onstart=alert(1)>',
        "'-alert(1)//",
        '";alert(1);//',
        '<video><source onerror=alert(1)>',
    ]

    # Unique canary to detect reflection
    CANARY = "xSsCaN4ry123"

    def run(self, param_urls, forms):
        """Run XSS detection."""
        payloads = self._get_payloads()

        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_reflected(url, param, payloads)

        for form in forms:
            self._test_form(form, payloads)

        return self.findings

    def _get_payloads(self):
        if self.ai and self.ai.enabled:
            ai_payloads = self.ai.generate_payloads("xss", {"technology": str(self.technology)})
            if ai_payloads:
                return ai_payloads
        return self.XSS_PAYLOADS

    def _test_reflected(self, url, param, payloads):
        """Test for reflected XSS in a URL parameter."""
        # Step 1: Check if the parameter value is reflected
        test_url = self.inject_param(url, param, self.CANARY)
        try:
            resp = self.client.get(test_url)
            if self.CANARY not in resp.text:
                return  # Not reflected, skip
        except Exception:
            return

        log.info(f"Parameter '{param}' reflects input, testing XSS...")

        # Step 2: Test payloads
        for payload in payloads:
            self.delay()
            test_url = self.inject_param(url, param, payload)
            try:
                resp = self.client.get(test_url)

                if self._check_xss_reflection(resp.text, payload):
                    # Determine severity
                    if "<script" in payload.lower() or "javascript:" in payload.lower():
                        severity = "high"
                    else:
                        severity = "medium"

                    self.add_finding(
                        "xss", url, param, severity,
                        f"Payload reflected: {payload[:100]}",
                        payload, "Reflected XSS vulnerability detected"
                    )

                    if self.ai and self.ai.enabled:
                        analysis = self.ai.analyze_vulnerability(
                            "xss", url, param, {"payload": payload}, resp.text
                        )
                        self.findings[-1].ai_analysis = analysis

                    return  # One confirmed finding per param
            except Exception as e:
                log.debug(f"XSS test error: {e}")

    def _test_form(self, form, payloads):
        """Test form inputs for XSS."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "hidden", "file"):
                continue

            # First test reflection with canary
            data = {}
            for field in inputs:
                data[field["name"]] = self.CANARY if field["name"] == inp["name"] else field.get("value", "test")

            try:
                if method == "POST":
                    resp = self.client.post(action, data=data)
                else:
                    resp = self.client.get(action, params=data)

                if self.CANARY not in resp.text:
                    continue
            except Exception:
                continue

            for payload in payloads[:10]:
                self.delay()
                data[inp["name"]] = payload

                try:
                    if method == "POST":
                        resp = self.client.post(action, data=data)
                    else:
                        resp = self.client.get(action, params=data)

                    if self._check_xss_reflection(resp.text, payload):
                        self.add_finding(
                            "xss", action, inp["name"], "high",
                            f"XSS in form field: {payload[:100]}",
                            payload, "Reflected XSS via form submission"
                        )
                        return
                except Exception:
                    pass

    def _check_xss_reflection(self, html_text, payload):
        """Check if XSS payload is present and executable in response."""
        # Direct reflection (unencoded)
        if payload in html_text:
            return True

        # Check for partial reflection that could still execute
        # e.g., <script>alert(1)</script> partially reflected
        if "<script>" in payload.lower() and "<script>alert(1)</script>" in html_text.lower():
            return True

        # Check for event handler reflection
        event_handlers = ["onerror", "onload", "onfocus", "ontoggle", "onstart", "onmouseover"]
        for handler in event_handlers:
            if handler in payload.lower() and handler in html_text.lower():
                # Verify it's not HTML-encoded
                if f"&lt;{handler}" not in html_text.lower():
                    return True

        return False
