"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__
from .checks import Context, Options, available_checks, run_checks
from .models import SEVERITY, CheckResult, Status
from .report import build_report, to_html, to_json, to_text
from .runner import CommandRunner, ReplayRunner

TOOL_NAME = "macos-security-audit"
REPORT_TITLE = "macOS Security Audit"

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_FATAL = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Read-only macOS security configuration audit with JSON and HTML reports.",
    )
    parser.add_argument("--json", metavar="PATH", help="write the JSON report to PATH ('-' for stdout)")
    parser.add_argument("--html", metavar="PATH", help="write the HTML report to PATH")
    parser.add_argument("--include-usernames", action="store_true",
                        help="list admin account names in the report (omitted by default)")
    parser.add_argument("--check", action="append", metavar="ID", help="run only this check (repeatable)")
    parser.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    parser.add_argument("--fail-on", choices=["never", "warn", "fail"], default="never",
                        help="exit 1 when overall status is at or above this level (default: never)")
    parser.add_argument("--timeout", type=float, default=30, metavar="SECONDS",
                        help="per-command timeout (default: 30)")
    parser.add_argument("--replay", metavar="FIXTURE",
                        help="render from a recorded/synthetic fixture instead of running commands")
    parser.add_argument("--quiet", action="store_true", help="suppress the console summary")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def score(results: List[CheckResult]) -> Dict[str, Any]:
    """Share of evaluated controls that pass. info/skip/error are excluded from the denominator."""
    scored = [r for r in results if r.status in (Status.PASS, Status.WARN, Status.FAIL)]
    passed = sum(1 for r in scored if r.status == Status.PASS)
    pct = round(100.0 * passed / len(scored)) if scored else None
    not_evaluated = [r.id for r in results if r.status in (Status.SKIP, Status.ERROR)]
    headline = ("Security score: {}% ({} of {} evaluated controls passing)".format(pct, passed, len(scored))
                if pct is not None else "Security score: n/a (no controls evaluated)")
    if not_evaluated:
        headline += " · {} not evaluated".format(len(not_evaluated))
    return {
        "score_percent": pct,
        "controls_passed": passed,
        "controls_evaluated": len(scored),
        "failed_controls": [r.id for r in results if r.status == Status.FAIL],
        "not_evaluated": not_evaluated,
        "headline": headline,
    }


def _write(path: str, content: str) -> None:
    if path == "-":
        sys.stdout.write(content)
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def _exit_code(overall: str, fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = SEVERITY[Status.WARN] if fail_on == "warn" else SEVERITY[Status.FAIL]
    return EXIT_THRESHOLD if SEVERITY[overall] >= threshold else EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        for check_id, title, category in available_checks():
            print("{:<18} {:<36} {}".format(check_id, title, category))
        return EXIT_OK

    known = {c[0] for c in available_checks()}
    unknown = [c for c in (args.check or []) if c not in known]
    if unknown:
        print("error: unknown check id(s): {}".format(", ".join(unknown)), file=sys.stderr)
        return EXIT_FATAL

    if args.replay:
        try:
            runner = ReplayRunner.from_file(args.replay)
        except (OSError, ValueError) as exc:
            print("error: cannot load replay fixture: {}".format(exc), file=sys.stderr)
            return EXIT_FATAL
        now = runner.now or datetime.now(timezone.utc)
        source = "replay:{}".format(os.path.basename(args.replay))
    else:
        if sys.platform != "darwin":
            print("error: {} collects data on macOS only. Use --replay FIXTURE to render a report "
                  "from synthetic data on other platforms.".format(TOOL_NAME), file=sys.stderr)
            return EXIT_FATAL
        runner = CommandRunner(timeout=args.timeout)
        now = datetime.now(timezone.utc)
        source = "live"

    ctx = Context(runner=runner, now=now, options=Options(include_usernames=args.include_usernames))
    results = run_checks(ctx, only=args.check)
    report = build_report(results, tool=TOOL_NAME, version=__version__, generated_at=now,
                          data_source=source, summary_extra=score(results))

    try:
        if args.json:
            _write(args.json, to_json(report))
        if args.html:
            _write(args.html, to_html(report, REPORT_TITLE))
    except OSError as exc:
        print("error: cannot write report: {}".format(exc), file=sys.stderr)
        return EXIT_FATAL

    if not args.quiet and args.json != "-":
        sys.stdout.write(to_text(report))

    return _exit_code(report["summary"]["overall_status"], args.fail_on)
