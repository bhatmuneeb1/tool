"""Command-line interface for RepoGuard."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Sequence

from .sarif import to_sarif
from .scanner import scan_path

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a local repository for common security hygiene issues")
    parser.add_argument("path", nargs="?", default=".", help="file or directory to scan")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", dest="output_format")
    parser.add_argument("--fail-on", choices=("low", "medium", "high"), help="return exit code 1 when this severity or higher is found")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = scan_path(Path(args.path))
    except FileNotFoundError as exc:
        print(f"error: path not found: {exc}")
        return 2

    if args.output_format == "json":
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    elif args.output_format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        for finding in findings:
            print(f"{finding.severity.upper():6} {finding.rule_id} {finding.path}:{finding.line} {finding.message}")
        counts = Counter(finding.severity for finding in findings)
        print(f"\n{len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, {counts['low']} low")

    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
