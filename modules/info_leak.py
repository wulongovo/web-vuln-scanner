"""Information Leakage Detection Module."""

import re
from modules.base import BaseModule
from lib.logger import log


class InfoLeakModule(BaseModule):
    """Detect information leakage in HTTP responses."""

    name = "info_leak"
    description = "Detect server info leaks, stack traces, internal IPs, credentials"

    # Patterns to search for
    PATTERNS = [
        # Internal IP addresses
        (r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
         "medium", "Internal IP address leaked"),

        # Email addresses
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
         "low", "Email address leaked"),

        # Stack traces
        (r'(?:Traceback|Exception|Error|at \w+\.(?:java|py|php|js|rb):\d+)',
         "medium", "Stack trace / error message leaked"),

        # Database connection strings
        (r'(?:mysql|postgres|mongodb|redis|amqp)://[^\s\'\"]+',
         "critical", "Database connection string leaked"),

        # AWS keys
        (r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
         "critical", "AWS access key leaked"),

        # Generic API keys / tokens
        (r'(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\'\"]?[A-Za-z0-9+/=_-]{20,}[\'\"]?',
         "high", "API key/token leaked"),

        # Private keys
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
         "critical", "Private key exposed"),

        # Directory listing
        (r'Index of /',
         "medium", "Directory listing enabled"),

        # Debug mode indicators
        (r'(?:DEBUG\s*=\s*True|debugMode|DEBUG_MODE)',
         "medium", "Debug mode enabled"),

        # .git path disclosure
        (r'(?:\.git/(?:config|HEAD|objects|refs))',
         "critical", "Git repository exposed"),
    ]

    def run(self, param_urls, forms):
        """Check responses for information leakage."""
        # Test a sample of URLs
        urls_to_check = list(set(param_urls))[:50]
        if forms:
            urls_to_check.extend([f["action"] for f in forms[:20]])
        urls_to_check = list(set(urls_to_check))

        for url in urls_to_check:
            self.delay()
            try:
                resp = self.client.get(url)
                self._check_response(url, resp)
            except Exception as e:
                log.debug(f"Info leak check error: {e}")

        return self.findings

    def _check_response(self, url, resp):
        """Check a single response for leaks."""
        body = resp.text
        headers = str(resp.headers)

        for pattern, severity, description in self.PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                # Deduplicate and limit
                unique_matches = list(set(matches))[:5]
                self.add_finding(
                    "info_leak", url, "", severity,
                    f"Found: {', '.join(unique_matches[:3])}",
                    "", description
                )

        # Check headers for version info
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server and re.search(r"\d+\.\d+", server):
            self.add_finding("info_leak", url, "headers", "low",
                           f"Server version: {server}", "", "Server version disclosed in headers")
        if powered:
            self.add_finding("info_leak", url, "headers", "low",
                           f"X-Powered-By: {powered}", "", "Technology disclosed in headers")

        # Check for directory listing
        if "Index of /" in body or "Directory listing for" in body:
            self.add_finding("info_leak", url, "", "medium",
                           "Directory listing detected", "", "Directory listing is enabled")
