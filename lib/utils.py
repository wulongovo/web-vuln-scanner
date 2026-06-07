"""Utility functions."""

import hashlib
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


def normalize_url(url):
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def extract_domain(url):
    """Extract domain from URL."""
    parsed = urlparse(url)
    return parsed.netloc or parsed.path.split("/")[0]


def extract_params(url):
    """Extract query parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def inject_param(url, param_name, payload):
    """Inject a payload into a specific query parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_base_url(url):
    """Get scheme + host from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def is_same_domain(url, base_url):
    """Check if URL belongs to the same domain."""
    return extract_domain(url) == extract_domain(base_url)


def compute_hash(data):
    """Compute MD5 hash of data."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.md5(data).hexdigest()


def save_json(data, filepath):
    """Save data as JSON file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_dict(filepath):
    """Load a dictionary file, return list of non-empty stripped lines."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def timestamp():
    """Return current timestamp string."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def safe_filename(url):
    """Convert URL to a safe filename."""
    return re.sub(r"[^a-zA-Z0-9]", "_", url)[:100]
