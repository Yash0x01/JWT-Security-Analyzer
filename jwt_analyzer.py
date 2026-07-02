#!/usr/bin/env python3
"""
jwt_analyzer.py
CLI for the JWT Security Analyzer.

Usage:
    python jwt_analyzer.py <token>
    python jwt_analyzer.py <token> --wordlist custom_wordlist.txt
    python jwt_analyzer.py <token> --json
    python jwt_analyzer.py --file token.txt
"""

import argparse
import json
import os
import sys

from colorama import Fore, Style, init as colorama_init

from analyzer import analyze
from utils import TokenDecodeError

colorama_init(autoreset=True)

SEVERITY_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}

RISK_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.GREEN,
}


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Decode and analyze a JWT for common security weaknesses."
    )
    parser.add_argument("token", nargs="?", help="The raw JWT string to analyze")
    parser.add_argument("--file", "-f", help="Read the token from a file instead of the CLI arg")
    parser.add_argument(
        "--wordlist", "-w", default=None,
        help="Path to a wordlist for the weak-secret brute-force check "
             "(default: common_secrets.txt next to this script)"
    )
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a formatted report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    return parser


def get_token(args) -> str:
    if args.file:
        with open(args.file) as f:
            return f.read().strip()
    if args.token:
        return args.token.strip()
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    return ""


def print_report(token: str, result: dict, use_color: bool):
    def c(color, text):
        return f"{color}{text}{Style.RESET_ALL}" if use_color else text

    findings = result["findings"]
    risk = result["risk"]

    print("=" * 60)
    print(c(Style.BRIGHT, "JWT SECURITY ANALYSIS REPORT"))
    print("=" * 60)

    print(f"\n{c(Style.BRIGHT, 'Header:')}")
    print(json.dumps(result["header"], indent=2))

    print(f"\n{c(Style.BRIGHT, 'Payload:')}")
    print(json.dumps(result["payload"], indent=2))

    print(f"\n{c(Style.BRIGHT, 'Findings:')} ({len(findings)})")
    if not findings:
        print(c(Fore.GREEN, "  No issues detected by this analyzer's checks."))
    else:
        for f in findings:
            color = SEVERITY_COLOR.get(f["severity"], "")
            print(c(color, f"  [{f['severity']}] {f['issue']}"))
            if f.get("detail"):
                print(f"      {f['detail']}")

    print(f"\n{c(Style.BRIGHT, 'Overall Risk:')} {c(RISK_COLOR.get(risk, ''), risk)}")

    if findings:
        print(f"\n{c(Style.BRIGHT, 'Recommendations:')}")
        seen = set()
        for f in findings:
            rem = f["remediation"]
            if rem not in seen:
                print(f"  - {rem}")
                seen.add(rem)

    print()


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    token = get_token(args)
    if not token:
        parser.print_help()
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_path = args.wordlist or os.path.join(script_dir, "common_secrets.txt")

    try:
        result = analyze(token, wordlist_path=wordlist_path)
    except TokenDecodeError as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"{Fore.RED}Invalid JWT: {e}{Style.RESET_ALL}")
        sys.exit(2)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(token, result, use_color=not args.no_color)

    # Non-zero exit code on HIGH risk, useful for CI pipelines
    sys.exit(1 if result["risk"] == "HIGH" else 0)


if __name__ == "__main__":
    main()
