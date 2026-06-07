"""Directory and File Discovery Module."""

from concurrent.futures import ThreadPoolExecutor, as_completed

import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import config
from modules.base import BaseModule
from lib.logger import log
from lib.utils import load_dict, get_base_url


class DirScanModule(BaseModule):
    """Discover hidden directories and files."""

    name = "dirscan"
    description = "Directory and file brute-force discovery"

    # Common directories to always check
    COMMON_DIRS = [
        "admin", "administrator", "login", "wp-admin", "wp-login.php",
        "phpmyadmin", "server-status", "server-info", ".git", ".svn",
        ".env", ".htaccess", "backup", "db", "database", "debug",
        "test", "api", "swagger", "robots.txt", "sitemap.xml",
        "crossdomain.xml", "config", "conf", "setup", "install",
        "console", "shell", "manage", "uploads", "upload", "files",
        "images", "img", "static", "assets", "js", "css",
    ]

    def run(self, param_urls, forms):
        """Run directory discovery."""
        from lib.http_client import HttpClient
        client = HttpClient()

        base_url = get_base_url(param_urls[0] if param_urls else (forms[0]["action"] if forms else "http://example.com"))

        # Load dictionary
        dirs = load_dict(config.DIR_DICT)
        if not dirs:
            dirs = self.COMMON_DIRS

        log.info(f"Testing {len(dirs)} directories against {base_url}")

        # Get baseline 404 response for comparison
        try:
            not_found = client.get(f"{base_url}/nonexistent_404_test_{'x'*20}")
            self._404_len = len(not_found.text)
            self._404_status = not_found.status_code
        except Exception:
            self._404_len = 0
            self._404_status = 404

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=config.THREADS) as executor:
            futures = {}
            for d in dirs:
                url = f"{base_url}/{d.lstrip('/')}"
                futures[executor.submit(self._check_path, client, url)] = url

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception:
                    pass

        client.close()
        return self.findings

    def _check_path(self, client, url):
        """Check if a path exists."""
        try:
            resp = client.get(url)

            # Skip if same as 404 baseline
            if resp.status_code == self._404_status and abs(len(resp.text) - self._404_len) < 100:
                return None

            if resp.status_code in (200, 301, 302, 303, 307, 403):
                severity = "info"
                if resp.status_code == 403:
                    severity = "medium"
                elif resp.status_code == 200:
                    severity = "low"

                return self.add_finding(
                    "directory_found", url, "", severity,
                    f"HTTP {resp.status_code}, {len(resp.text)} bytes",
                    "", f"Accessible path discovered: {url}"
                )
        except Exception:
            pass
        return None
