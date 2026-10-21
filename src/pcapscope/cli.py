"""Command-line interface: ``pcapscope capture.pcap [--report out.md] [--json out.json]``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze
from .detect import SEVERITIES, Config
from .reader import CaptureError
from .report import to_json, to_markdown, to_terminal


def build_parser() -> argparse.ArgumentParser:
    defaults = Config()
    parser = argparse.ArgumentParser(
        prog="pcapscope",
        description="Parse pcap/pcapng captures from scratch and report threats and capture-health issues.",
    )
    parser.add_argument("captures", nargs="+", type=Path, help="pcap or pcapng file(s) to analyse")
    parser.add_argument("-r", "--report", type=Path,
                        help="write a Markdown report (a directory if several captures are given)")
    parser.add_argument("-j", "--json", type=Path,
                        help="write a JSON report (a directory if several captures are given)")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="info",
                        help="hide threat findings below this severity")
    parser.add_argument("--scan-ports", type=int, default=defaults.scan_min_ports,
                        help="distinct ports that make a port scan (default: %(default)s)")
    parser.add_argument("--sweep-hosts", type=int, default=defaults.sweep_min_hosts,
                        help="distinct hosts that make a host sweep (default: %(default)s)")
    parser.add_argument("--fail-on", choices=SEVERITIES,
                        help="exit with status 2 if any threat finding is at least this severe")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _output_path(target: Path, capture: Path, suffix: str, many: bool) -> Path:
    if many or target.is_dir():
        target.mkdir(parents=True, exist_ok=True)
        return target / f"{capture.stem}{suffix}"
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config(scan_min_ports=args.scan_ports, sweep_min_hosts=args.sweep_hosts)
    min_rank = SEVERITIES.index(args.min_severity)
    many = len(args.captures) > 1
    worst = -1

    for capture in args.captures:
        try:
            result = analyze(capture, config)
        except (OSError, CaptureError) as exc:
            print(f"pcapscope: {exc}", file=sys.stderr)
            return 1
        result.findings = [f for f in result.findings
                           if f.category == "sensor" or f.severity_rank >= min_rank]
        worst = max([worst] + [f.severity_rank for f in result.threats])

        print(to_terminal(result))
        if args.report:
            path = _output_path(args.report, capture, ".md", many)
            path.write_text(to_markdown(result), encoding="utf-8", newline="\n")
            print(f"  report -> {path}")
        if args.json:
            path = _output_path(args.json, capture, ".json", many)
            path.write_text(to_json(result), encoding="utf-8", newline="\n")
            print(f"  json   -> {path}")

    if args.fail_on and worst >= SEVERITIES.index(args.fail_on):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
