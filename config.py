"""Web Vuln Scanner - Global Configuration"""

import os

# Scanner settings
THREADS = 10
TIMEOUT = 10  # seconds
MAX_RETRIES = 2
DELAY = 0.1  # delay between requests (seconds)

# User-Agent rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Dictionary paths
DICT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dicts")
DIR_DICT = os.path.join(DICT_DIR, "dirs.txt")
SUBDOMAIN_DICT = os.path.join(DICT_DIR, "subdomains.txt")

# Output
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")

# AI settings - configure via environment variables
AI_PROVIDER = os.environ.get("AI_PROVIDER", "openai")  # openai / ollama / custom
AI_API_KEY = os.environ.get("AI_API_KEY", "")
AI_BASE_URL = os.environ.get("AI_BASE_URL", "https://api.openai.com/v1")
AI_MODEL = os.environ.get("AI_MODEL", "gpt-4o-mini")

# Scan modules enabled by default
ENABLED_MODULES = [
    "sqli",
    "xss",
    "dirscan",
    "sensitive_files",
    "info_leak",
    "cmd_injection",
    "file_include",
]
