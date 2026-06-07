"""Scanner Engine - Orchestrates all vulnerability detection modules."""

import importlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import config
from lib.http_client import HttpClient
from lib.logger import log
from lib.utils import normalize_url


class ScanResult:
    """Container for a single vulnerability finding."""

    def __init__(self, vuln_type, url, param, severity, evidence, payload="", detail=""):
        self.type = vuln_type
        self.url = url
        self.param = param
        self.severity = severity
        self.evidence = evidence
        self.payload = payload
        self.detail = detail
        self.confirmed = False
        self.ai_analysis = None

    def to_dict(self):
        return {
            "type": self.type,
            "url": self.url,
            "param": self.param,
            "severity": self.severity,
            "evidence": self.evidence[:500],
            "payload": self.payload,
            "detail": self.detail,
            "confirmed": self.confirmed,
            "ai_analysis": self.ai_analysis,
        }


class Scanner:
    """Main scanner engine that orchestrates all modules."""

    def __init__(self, crawl_result, modules=None, use_ai=False):
        self.urls = crawl_result.get("urls", [])
        self.forms = crawl_result.get("forms", [])
        self.technology = crawl_result.get("technology", {})
        self.enabled_modules = modules or config.ENABLED_MODULES
        self.use_ai = use_ai
        self.client = HttpClient()
        self.vulnerabilities = []
        self.stats = {"urls_scanned": 0, "requests_made": 0, "vulns_found": 0}
        self.ai_engine = None

        if use_ai:
            from ai.ai_payload import AIEngine
            self.ai_engine = AIEngine()

    def scan(self):
        """Run all enabled scan modules against discovered URLs and forms."""
        log.info(f"Starting scan with modules: {', '.join(self.enabled_modules)}")
        log.info(f"Target URLs: {len(self.urls)}, Forms: {len(self.forms)}")

        # Load module classes
        modules = self._load_modules()

        # Phase 1: Scan URLs with GET parameters
        param_urls = [u for u in self.urls if "?" in u and "=" in u]
        log.info(f"URLs with parameters: {len(param_urls)}")

        # Phase 2: Scan forms
        log.info(f"Forms to test: {len(self.forms)}")

        # Run each module
        for mod_name, mod_class in modules.items():
            log.info(f"\n{'='*50}")
            log.info(f"Running module: {mod_name}")
            log.info(f"{'='*50}")

            try:
                mod_instance = mod_class(self.client, self.ai_engine, self.technology)
                findings = mod_instance.run(param_urls, self.forms)
                self.vulnerabilities.extend(findings)
                self.stats["vulns_found"] += len(findings)
                log.info(f"Module {mod_name}: {len(findings)} findings")
            except Exception as e:
                log.error(f"Module {mod_name} failed: {e}")

        self.stats["urls_scanned"] = len(self.urls)
        self.client.close()

        log.info(f"\nScan complete: {self.stats['vulns_found']} vulnerabilities found")
        return self.vulnerabilities

    def _load_modules(self):
        """Dynamically load scan modules."""
        module_map = {
            "sqli": ("modules.sqli", "SQLiModule"),
            "xss": ("modules.xss", "XSSModule"),
            "dirscan": ("modules.dirscan", "DirScanModule"),
            "sensitive_files": ("modules.sensitive_files", "SensitiveFilesModule"),
            "info_leak": ("modules.info_leak", "InfoLeakModule"),
            "cmd_injection": ("modules.cmd_injection", "CmdInjectionModule"),
            "file_include": ("modules.file_include", "FileIncludeModule"),
        }

        loaded = {}
        for name in self.enabled_modules:
            if name in module_map:
                module_path, class_name = module_map[name]
                try:
                    mod = importlib.import_module(module_path)
                    cls = getattr(mod, class_name)
                    loaded[name] = cls
                except (ImportError, AttributeError) as e:
                    log.warning(f"Cannot load module {name}: {e}")

        return loaded
