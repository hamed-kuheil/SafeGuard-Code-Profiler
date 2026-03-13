#!/usr/bin/env python3
"""
main.py — SafeGuard-Code Profiler
CLI entry point. Parses arguments and orchestrates scan + reporting.

Usage:
    python main.py path/to/file.py
    python main.py path/to/directory/ --recursive
    python main.py file.cpp --json --html --verbose
    python main.py examples/ --recursive --json --html
"""

import argparse
import sys
import os
from datetime import datetime
from pathlib import Path

# Allow running from src/ or project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner   import scan_file, scan_directory, detect_language
from formatter import (
    print_banner,
    print_file_result,
    print_global_summary,
    save_json_report,
    save_html_report,
)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="safeguard",
        description="SafeGuard-Code Profiler — Static Analysis for Resource Efficiency & AI Ethics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py examples/bad_code.py
  python main.py examples/ --recursive --html --json
  python main.py src/MyApp.java --verbose
  python main.py . --recursive --json --output-dir reports/
        """,
    )
    parser.add_argument(
        "target",
        help="File or directory to scan",
    )
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help="Recursively scan directories (default: True)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Show detailed fix messages for each finding",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Save JSON report to reports/ directory",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        default=False,
        help="Save HTML report to reports/ directory",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        metavar="DIR",
        help="Directory to save reports (default: reports/)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        help="Suppress ASCII art banner (useful for CI pipelines)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Only show findings at or above this severity",
    )
    return parser.parse_args()


def filter_by_severity(results: list, min_severity: str) -> list:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    threshold = order.get(min_severity, 1)
    filtered = []
    for r in results:
        if "error" in r:
            filtered.append(r)
            continue
        r_copy = dict(r)
        r_copy["findings"] = [f for f in r["findings"]
                               if order.get(f["severity"], 0) >= threshold]
        r_copy["total_findings"] = len(r_copy["findings"])
        filtered.append(r_copy)
    return filtered


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()

    target = Path(args.target)
    if not target.exists():
        print(f"\n  ✗ Error: '{target}' does not exist.\n")
        sys.exit(1)

    # ── Collect results ───────────────────────────────────────────────────────
    if target.is_file():
        lang = detect_language(str(target))
        if not lang:
            print(f"\n  ✗ Unsupported file type: {target.suffix}\n"
                   "    Supported: .py  .java  .cpp  .cxx  .cc  .c  .h  .hpp\n")
            sys.exit(1)
        results = [scan_file(str(target))]
    else:
        results = scan_directory(str(target), recursive=args.recursive)
        if not results:
            print(f"\n  No supported source files found in '{target}'.\n")
            sys.exit(0)

    # ── Filter by severity ────────────────────────────────────────────────────
    results = filter_by_severity(results, args.min_severity)

    # ── Print per-file results ────────────────────────────────────────────────
    for result in results:
        print_file_result(result, verbose=args.verbose)

    # ── Global summary ────────────────────────────────────────────────────────
    if len(results) > 1:
        print_global_summary(results)

    # ── Save reports ──────────────────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir

    if args.json:
        json_path = os.path.join(output_dir, f"report_{timestamp}.json")
        save_json_report(results, json_path)

    if args.html:
        html_path = os.path.join(output_dir, f"report_{timestamp}.html")
        save_html_report(results, html_path)

    # ── Exit code for CI integration ──────────────────────────────────────────
    has_critical = any(
        f["severity"] == "CRITICAL"
        for r in results if "error" not in r
        for f in r["findings"]
    )
    sys.exit(2 if has_critical else 0)


if __name__ == "__main__":
    main()
