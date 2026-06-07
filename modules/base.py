"""Base class for all vulnerability detection modules."""

import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import config
from core.scanner import ScanResult
from lib.logger import log


class BaseModule:
    """Base class for vulnerability detection modules."""

    name = "base"
    description = "Base vulnerability detection module"

    def __init__(self, client, ai_engine=None, technology=None):
        self.client = client
        self.ai = ai_engine
        self.technology = technology or {}
        self.findings = []

    def run(self, param_urls, forms):
        """Run the module against URLs and forms. Override in subclasses."""
        raise NotImplementedError

    def inject_param(self, url, param_name, payload):
        """Replace a query parameter value with a payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def get_params(self, url):
        """Extract parameter names from URL."""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    def check_reflection(self, response_text, payload):
        """Check if a payload is reflected in the response."""
        return payload in response_text

    def detect_waf(self, url):
        """Basic WAF detection."""
        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "ModSecurity": ["mod_security", "NOYB"],
            "Akamai": ["akamai", "X-Akamai"],
            "Incapsula": ["incap_ses", "visid_incap"],
        }

        try:
            # Send a suspicious request to trigger WAF
            test_url = url + ("&" if "?" in url else "?") + "test=<script>alert(1)</script>"
            resp = self.client.get(test_url)
            headers_str = str(resp.headers).lower()
            body = resp.text.lower()

            for waf_name, sigs in waf_signatures.items():
                for sig in sigs:
                    if sig.lower() in headers_str or sig.lower() in body:
                        return waf_name
        except Exception:
            pass

        return None

    def delay(self):
        """Random delay between requests."""
        time.sleep(config.DELAY + random.uniform(0, 0.2))

    def add_finding(self, vuln_type, url, param, severity, evidence, payload="", detail=""):
        """Add a vulnerability finding."""
        result = ScanResult(vuln_type, url, param, severity, evidence, payload, detail)
        self.findings.append(result)
        log.warning(f"[{severity.upper()}] {vuln_type} at {url} param={param}")
        return result
