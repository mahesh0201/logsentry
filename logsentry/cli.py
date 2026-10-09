from __future__ import annotations

import argparse
import sys
from datetime import timedelta

from . import detectors, report
from .parsers import parse_access_log, parse_auth_log


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="logsentry", description="Detect threats in auth and web logs.")
    p.add_argument("--auth", help="Path to sshd auth.log")
    p.add_argument("--access", help="Path to Apache/Nginx combined access log")
    p.add_argument("--year", type=int, help="Year for auth.log timestamps (default: current)")
    p.add_argument("--threshold", type=int, default=5, help="Failed logins that trigger brute-force (default 5)")
    p.add_argument("--window", type=int, default=10, help="Brute-force window in minutes (default 10)")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--output", help="Write report to file instead of stdout")
    args = p.parse_args(argv)

    if not (args.auth or args.access):
        p.error("provide --auth and/or --access")

    findings = []
    if args.auth:
        with open(args.auth, encoding="utf-8", errors="replace") as fh:
            events = list(parse_auth_log(fh, args.year))
        findings += detectors.ssh_bruteforce(events, args.threshold, timedelta(minutes=args.window))
    if args.access:
        with open(args.access, encoding="utf-8", errors="replace") as fh:
            web = list(parse_access_log(fh))
        findings += detectors.web_attacks(web)
        findings += detectors.scanner_activity(web)

    text = report.to_json(findings) if args.format == "json" else report.to_markdown(findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    # Non-zero exit when high/critical findings exist -> usable as a CI/cron gate
    return 2 if any(f.severity in ("high", "critical") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
