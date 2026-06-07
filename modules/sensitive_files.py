"""Sensitive File Detection Module."""

from modules.base import BaseModule
from lib.logger import log
from lib.utils import get_base_url


class SensitiveFilesModule(BaseModule):
    """Detect exposed sensitive files and configurations."""

    name = "sensitive_files"
    description = "Detect sensitive files (.git, .env, backups, configs)"

    SENSITIVE_PATHS = [
        # Version control
        (".git/config", "critical", "Git repository exposed"),
        (".git/HEAD", "critical", "Git HEAD exposed"),
        (".svn/entries", "critical", "SVN repository exposed"),
        (".svn/wc.db", "critical", "SVN database exposed"),
        (".hg/dirstate", "critical", "Mercurial repository exposed"),

        # Environment & config
        (".env", "critical", "Environment file exposed"),
        (".env.local", "critical", "Local environment file exposed"),
        (".env.production", "critical", "Production environment file exposed"),
        ("config.php", "high", "PHP config file exposed"),
        ("config.yml", "high", "YAML config exposed"),
        ("config.json", "high", "JSON config exposed"),
        ("wp-config.php", "critical", "WordPress config exposed"),
        ("configuration.php", "high", "Joomla config exposed"),
        ("settings.py", "high", "Django settings exposed"),
        ("database.yml", "critical", "Database config exposed"),
        ("db.php", "high", "Database config exposed"),
        ("application.yml", "high", "Spring config exposed"),

        # Backup files
        ("backup.zip", "high", "Backup file exposed"),
        ("backup.tar.gz", "high", "Backup file exposed"),
        ("backup.sql", "critical", "SQL backup exposed"),
        ("dump.sql", "critical", "SQL dump exposed"),
        ("db.sql", "critical", "Database dump exposed"),
        ("database.sql", "critical", "Database dump exposed"),
        (".bak", "medium", "Backup file exposed"),

        # Info / Debug
        ("phpinfo.php", "medium", "phpinfo() exposed"),
        ("info.php", "medium", "PHP info exposed"),
        ("test.php", "medium", "Test file exposed"),
        ("debug.log", "high", "Debug log exposed"),
        ("error.log", "high", "Error log exposed"),
        ("access.log", "medium", "Access log exposed"),
        ("server-status", "medium", "Apache server status exposed"),
        ("server-info", "medium", "Apache server info exposed"),
        (".htaccess", "medium", "htaccess file exposed"),

        # Admin panels
        ("admin/", "medium", "Admin panel found"),
        ("administrator/", "medium", "Admin panel found"),
        ("phpmyadmin/", "high", "phpMyAdmin exposed"),
        ("wp-admin/", "medium", "WordPress admin found"),
        ("wp-login.php", "medium", "WordPress login found"),
        ("manager/", "medium", "Manager panel found"),
        ("console/", "high", "Console exposed"),

        # API documentation
        ("swagger.json", "medium", "Swagger API docs exposed"),
        ("swagger.yaml", "medium", "Swagger API docs exposed"),
        ("api-docs", "medium", "API documentation exposed"),
        ("graphql", "medium", "GraphQL endpoint exposed"),

        # Common files
        ("robots.txt", "info", "robots.txt found"),
        ("sitemap.xml", "info", "sitemap.xml found"),
        ("crossdomain.xml", "info", "crossdomain.xml found"),
        ("security.txt", "info", "security.txt found"),
        (".well-known/security.txt", "info", "security.txt found"),
    ]

    def run(self, param_urls, forms):
        """Check for sensitive files."""
        base_url = get_base_url(param_urls[0] if param_urls else (forms[0]["action"] if forms else "http://example.com"))

        for path, severity, description in self.SENSITIVE_PATHS:
            self.delay()
            url = f"{base_url}/{path}"
            try:
                resp = self.client.get(url)
                if resp.status_code == 200 and len(resp.text) > 10:
                    # Verify it's not a generic 404 page
                    if not self._is_generic_404(resp.text):
                        self.add_finding(
                            "sensitive_file", url, "", severity,
                            f"HTTP {resp.status_code}, {len(resp.text)} bytes",
                            "", description
                        )
            except Exception as e:
                log.debug(f"Sensitive file check error: {e}")

        return self.findings

    def _is_generic_404(self, body):
        """Detect soft 404s (pages that return 200 but show 'not found')."""
        indicators = ["not found", "404", "page not found", "does not exist",
                       "no such file", "cannot be found"]
        body_lower = body.lower()
        return any(ind in body_lower for ind in indicators)
