#!/usr/bin/env python3
"""
WebVulnScanner - AI-Powered Web Vulnerability Scanner

A modular web vulnerability scanner with AI-powered payload generation
and vulnerability analysis.

Usage:
    python main.py -u http://example.com
    python main.py -u http://example.com --modules sqli,xss --ai
    python main.py -u http://example.com --depth 3 --threads 20 --report html
"""

import argparse
import sys
import os
import time
from datetime import datetime

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from core.crawler import Crawler
from core.scanner import Scanner
from core.report import ReportGenerator
from lib.logger import log
from lib.utils import normalize_url


BANNER = """
\033[36m
 __        __   _     __     __   _       ____  
 \ \      / /__| |__  \ \   / /__| |__   / ___|___  _ __ ___
  \ \ /\ / / _ \ '_ \  \ \ / / _ \ '_ \ | |   / _ \| '__/ _ \
   \ V  V /  __/ |_) |  \ V /  __/ |_) || |__| (_) | | |  __/
    \_/\_/ \___|_.__/    \_/ \___|_.__/  \____\___/|_|  \___|

  AI-Powered Web Vulnerability Scanner v1.0
  github.com/wulongovo/web-vuln-scanner
\033[0m
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="WebVulnScanner - AI-Powered Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u http://example.com
  python main.py -u http://example.com --modules sqli,xss --ai
  python main.py -u http://example.com --depth 3 --threads 20
  python main.py -u http://example.com --ai --report html
  python main.py -u http://example.com --crawl-only
        """,
    )

    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("-m", "--modules", help="Comma-separated modules to run (default: all)")
    parser.add_argument("--ai", action="store_true", help="Enable AI-powered payload generation and analysis")
    parser.add_argument("--depth", type=int, default=3, help="Crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=200, help="Max pages to crawl (default: 200)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r", "--report", choices=["json", "html", "both"], default="both", help="Report format")
    parser.add_argument("-o", "--output", help="Output directory for reports")
    parser.add_argument("--crawl-only", action="store_true", help="Only crawl, don't scan")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")

    return parser.parse_args()


def main():
    args = parse_args()

    print(BANNER)

    # Update config
    config.THREADS = args.threads
    config.TIMEOUT = args.timeout
    if args.output:
        config.REPORT_DIR = args.output

    target = normalize_url(args.url)
    log.info(f"Target: {target}")
    log.info(f"Modules: {args.modules or 'all'}")
    log.info(f"AI: {'enabled' if args.ai else 'disabled'}")
    log.info(f"Threads: {args.threads}, Depth: {args.depth}, Timeout: {args.timeout}s")

    start_time = time.time()

    # Phase 1: Crawl
    log.info("\n" + "=" * 60)
    log.info("PHASE 1: Crawling target")
    log.info("=" * 60)

    crawler = Crawler(target, max_depth=args.depth, max_pages=args.max_pages)
    crawl_result = crawler.crawl()
    crawler.close()

    if args.crawl_only:
        log.info(f"\nCrawl Results:")
        log.info(f"  URLs found: {len(crawl_result['urls'])}")
        log.info(f"  Forms found: {len(crawl_result['forms'])}")
        log.info(f"  Technology: {crawl_result['technology']}")
        return

    # Phase 2: Scan
    log.info("\n" + "=" * 60)
    log.info("PHASE 2: Vulnerability scanning")
    log.info("=" * 60)

    modules = args.modules.split(",") if args.modules else None
    scanner = Scanner(crawl_result, modules=modules, use_ai=args.ai)
    vulnerabilities = scanner.scan()

    # Phase 3: AI Summary (if enabled)
    ai_summary = None
    if args.ai and scanner.ai_engine and scanner.ai_engine.enabled:
        log.info("\n" + "=" * 60)
        log.info("PHASE 3: AI Analysis")
        log.info("=" * 60)

        scan_results = {
            "target": target,
            "total_urls": len(crawl_result["urls"]),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
            "by_severity": {},
        }
        for v in vulnerabilities:
            sev = v.severity
            scan_results["by_severity"][sev] = scan_results["by_severity"].get(sev, 0) + 1

        ai_summary = scanner.ai_engine.generate_report_summary(scan_results)
        if ai_summary:
            log.info(f"\nAI Summary:\n{ai_summary}")

    # Phase 4: Report
    elapsed = time.time() - start_time
    log.info("\n" + "=" * 60)
    log.info("PHASE 4: Report generation")
    log.info("=" * 60)

    stats = {
        "target": target,
        "scan_duration": f"{elapsed:.1f}s",
        "urls_crawled": len(crawl_result["urls"]),
        "forms_found": len(crawl_result["forms"]),
        "vulnerabilities_found": len(vulnerabilities),
        "modules_used": modules or config.ENABLED_MODULES,
        "ai_enabled": args.ai,
    }

    reporter = ReportGenerator(target, vulnerabilities, stats, ai_summary)
    report_paths = reporter.generate(format=args.report)

    # Summary
    log.info("\n" + "=" * 60)
    log.info("SCAN COMPLETE")
    log.info("=" * 60)
    log.info(f"  Duration: {elapsed:.1f}s")
    log.info(f"  URLs crawled: {len(crawl_result['urls'])}")
    log.info(f"  Vulnerabilities: {len(vulnerabilities)}")

    sev_counts = {}
    for v in vulnerabilities:
        sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_counts:
            log.info(f"    {sev.upper()}: {sev_counts[sev]}")

    for fmt, path in report_paths.items():
        log.info(f"  Report ({fmt}): {path}")


if __name__ == "__main__":
    main()
