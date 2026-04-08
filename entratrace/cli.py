from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import textwrap

from .analysis import analyze_snapshot
from .collector_graph import collect_snapshot
from .loader import load_snapshot
from .reporting_bootstrap import write_html_report, write_json_report
from .suppressions import apply_report_suppressions


BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"
MAX_SAFE_LINE_WIDTH = 92
WIDTH_OVERRIDE: int | None = None


ASCII = rf"""{BLUE}
  ______       __              ______
 / ____/___   / /________ _   /_  __/________ _________
/ __/ / __ \ / __/ ___/ _ `/    / / / ___/ __ `/ ___/ _ \
/ /___/ / / // /_/ /  / (_| /   / / / /  / /_/ / /__/  __/
\_____/_/ /_/ \__/_/   \__,_/   /_/ /_/   \__,_/\___/\___/
{RESET}"""


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="entratrace",
        description="Defender-first Entra ID and Azure privilege-path analyzer.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze an exported Entra/Azure snapshot.")
    analyze_parser.add_argument("snapshot", help="Path to the current snapshot directory.")
    analyze_parser.add_argument("--previous", help="Path to a previous snapshot for drift detection.")
    analyze_parser.add_argument("--json", dest="json_path", help="Write a JSON report to this path.")
    analyze_parser.add_argument("--html", dest="html_path", help="Write an HTML report to this path.")
    analyze_parser.add_argument("--baseline", help="Path to a baseline JSON report used to suppress known findings.")
    analyze_parser.add_argument("--ignore-file", dest="ignore_file", help="Path to a local ignore rules file.")
    analyze_parser.add_argument("--summary-only", action="store_true", help="Print the CLI summary without writing files.")
    analyze_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in console output.")
    analyze_parser.add_argument(
        "--width",
        type=int,
        help="Force CLI output width (recommended 72-92 for narrow terminals).",
    )

    collect_parser = subparsers.add_parser("collect", help="Collect a snapshot from Microsoft Graph into local JSON files.")
    collect_parser.add_argument("output", help="Directory to write the collected snapshot files.")
    collect_parser.add_argument("--token", help="Bearer token for Microsoft Graph. Defaults to ENTRATRACE_GRAPH_TOKEN or Azure CLI.")
    collect_parser.add_argument("--tenant-name", dest="tenant_name", help="Optional override for tenant display name in tenant.json.")
    collect_parser.add_argument("--audit-days", type=int, default=14, help="How many days of directory audit logs to collect.")
    collect_parser.add_argument("--signin-days", type=int, default=14, help="How many days of sign-in logs to collect.")
    collect_parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to request per Graph endpoint.")
    collect_parser.add_argument(
        "--owner-target-limit",
        type=int,
        default=250,
        help="Maximum app/SP targets to query for ownership links.",
    )
    collect_parser.add_argument("--skip-azure-rbac", action="store_true", help="Skip Azure CLI-based subscription/RBAC collection.")
    collect_parser.add_argument("--base-url", default="https://graph.microsoft.com/v1.0", help="Microsoft Graph API base URL.")
    collect_parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in console output.")

    args = parser.parse_args()
    global WIDTH_OVERRIDE
    width_option = getattr(args, "width", None)
    if width_option:
        WIDTH_OVERRIDE = max(64, min(120, int(width_option)))
    _configure_console_colors(force_plain=bool(getattr(args, "no_color", False)))

    if args.command == "collect":
        return _run_collect(args)

    if args.command != "analyze":
        print(f"{RED}Unsupported command: {args.command}{RESET}")
        return 2

    current = load_snapshot(args.snapshot)
    previous = load_snapshot(args.previous) if args.previous else None
    report = analyze_snapshot(current, previous)
    try:
        report, _ = apply_report_suppressions(
            report,
            baseline_path=args.baseline,
            ignore_path=args.ignore_file,
        )
    except Exception as exc:
        print(f"{RED}Suppression configuration failed{RESET}: {exc}")
        return 1

    _print_report(report, Path(args.snapshot), Path(args.previous).resolve() if args.previous else None)
    if args.summary_only:
        return 0

    default_reports = Path("reports")
    json_path = Path(args.json_path).resolve() if args.json_path else (default_reports / "entratrace-report.json").resolve()
    html_path = Path(args.html_path).resolve() if args.html_path else (default_reports / "entratrace-report.html").resolve()
    write_json_report(json_path, report)
    write_html_report(html_path, report)
    print(f"{CYAN}JSON report{RESET} : {json_path}")
    print(f"{CYAN}HTML report{RESET} : {html_path}")
    print(f"{DIM}Open the HTML report in a browser for the full defender dashboard.{RESET}")
    return 0


def _run_collect(args: argparse.Namespace) -> int:
    try:
        output_path, metadata = collect_snapshot(
            output_dir=args.output,
            token=args.token,
            tenant_name_override=args.tenant_name,
            base_url=args.base_url,
            audit_days=args.audit_days,
            signin_days=args.signin_days,
            max_pages=args.max_pages,
            owner_target_limit=args.owner_target_limit,
            skip_azure_rbac=args.skip_azure_rbac,
        )
    except Exception as exc:
        print(f"{RED}Collection failed{RESET}: {exc}")
        print(f"{DIM}Tip: run `az login` and ensure ENTRATRACE_GRAPH_TOKEN is valid if you use a manual token.{RESET}")
        return 1

    counts = metadata.get("counts", {})
    warnings = metadata.get("warnings", [])
    rule = "=" * _console_line_width(default_width=88)
    print(ASCII)
    print(f"{WHITE}{BOLD}Microsoft Graph snapshot collection complete{RESET}")
    print(rule)
    print(f"{CYAN}Snapshot path{RESET}   : {output_path}")
    print(f"{CYAN}Tenant{RESET}          : {metadata.get('tenant_name', 'Unknown tenant')}")
    print(f"{CYAN}Users / Groups{RESET}  : {counts.get('users', 0)} / {counts.get('groups', 0)}")
    print(f"{CYAN}Apps / SPs{RESET}      : {counts.get('applications', 0)} / {counts.get('service_principals', 0)}")
    print(f"{CYAN}Owners{RESET}          : {counts.get('owners', 0)} links")
    print(f"{CYAN}Directory audits{RESET}: {counts.get('directory_audits', 0)} events")
    print(f"{CYAN}Sign-ins{RESET}        : {counts.get('sign_ins', 0)} events")
    print(f"{CYAN}Azure RBAC{RESET}      : {counts.get('azure_role_assignments', 0)} assignments")
    if warnings:
        print(f"{YELLOW}Warnings{RESET}        : {len(warnings)} (see collect_metadata.json for details)")
    print(rule)
    print(f"{DIM}Next step:{RESET} python .\\entratrace.py analyze \"{output_path}\" --summary-only")
    return 0


def _print_report(report: dict, snapshot_path: Path, previous_path: Path | None) -> None:
    summary = report["summary"]
    counts = report["counts"]
    severities = summary["severity_counts"]
    rule = "=" * _console_line_width(default_width=88)
    subrule = "-" * _console_line_width(default_width=88)
    print(ASCII)
    print(f"{WHITE}{BOLD}Defender-first Entra identity drift and abuse-path analysis{RESET}")
    print(rule)
    print(f"{CYAN}Tenant{RESET}          : {report['tenant'].get('tenant_name', 'Unknown tenant')}")
    print(f"{CYAN}Source{RESET}          : {snapshot_path.resolve()}")
    print(f"{CYAN}Previous{RESET}        : {previous_path if previous_path else 'None'}")
    print(f"{CYAN}Users / Groups{RESET}  : {counts['users']} / {counts['groups']}")
    print(f"{CYAN}Apps / SPs{RESET}      : {counts['applications']} / {counts['service_principals']}")
    print(f"{CYAN}Azure RBAC{RESET}      : {counts['azure_role_assignments']} assignments")
    if "directory_audits" in counts:
        print(f"{CYAN}Directory audits{RESET}: {counts['directory_audits']} events")
    if "sign_ins" in counts:
        print(f"{CYAN}Sign-ins{RESET}        : {counts['sign_ins']} events")
    print(f"{CYAN}Findings{RESET}        : {summary['total_findings']} total | {summary['new_findings']} new")
    print(f"{CYAN}Max Risk{RESET}        : {summary['max_risk_score']}")
    suppression = report.get("suppression") if isinstance(report.get("suppression"), dict) else {}
    if suppression and (suppression.get("baseline_suppressed", 0) or suppression.get("ignore_suppressed", 0)):
        print(
            f"{CYAN}Suppressed{RESET}      : baseline {suppression.get('baseline_suppressed', 0)}"
            f", ignore {suppression.get('ignore_suppressed', 0)}"
        )
    if suppression and suppression.get("ignore_invalid_rules", 0):
        print(
            f"{YELLOW}Ignore file{RESET}     : {suppression.get('ignore_invalid_rules', 0)} invalid rule(s) ignored"
        )
    print(rule)
    print(_severity_line(severities))
    print(rule)
    print(f"{BOLD}{summary['headline']}{RESET}")

    if report["crown_jewels"]:
        print(f"{CYAN}Crown jewels{RESET}    : " + ", ".join(item["name"] for item in report["crown_jewels"]))

    top_risky = report["top_risky_identities"]
    if top_risky:
        formatted = ", ".join(f"{item['name']} ({item['risk_score']})" for item in top_risky[:3])
        print(f"{CYAN}Hot identities{RESET}  : {formatted}")

    change_items = report.get("changes", [])[:4]
    if change_items:
        print(f"{CYAN}What changed{RESET}    :")
        for item in change_items:
            print(f"  {DIM}> {RESET}{item['detail']}")

    print(rule)
    if not report["findings"]:
        print(f"{GREEN}No modeled high-risk Entra or Azure abuse paths were detected.{RESET}")
        if suppression and (suppression.get("baseline_suppressed", 0) or suppression.get("ignore_suppressed", 0)):
            print(f"{DIM}All detections were filtered by baseline and/or ignore rules.{RESET}")
        return

    print(f"{WHITE}{BOLD}Top findings{RESET}")
    for index, item in enumerate(report["findings"][:4], start=1):
        sev_color = _color_for(item["severity"])
        print(
            f"{DIM}[{index}]{RESET} "
            f"{sev_color}{BOLD}{item['severity'].upper()}{RESET} "
            f"{DIM}|{RESET} {WHITE}risk {item['risk_score']}{RESET} "
            f"{DIM}|{RESET} {WHITE}{item['title']}{RESET}"
        )
        _print_path_field("Path", item["path"])
        attack_summary = _attack_summary(item.get("attack") or [])
        if attack_summary:
            _print_wrapped_field("MITRE ATT&CK", attack_summary)
        _print_wrapped_field("Impact", item["impact"])
        if item["evidence"]:
            _print_wrapped_field("Evidence", item["evidence"][0])
        if item["remediation"]:
            _print_wrapped_field("First fix", item["remediation"][0])
        if item.get("change_reasons"):
            _print_wrapped_field("Why changed", item["change_reasons"][0])
        if item["new_since_previous"]:
            _print_wrapped_field("Drift", "newly introduced in the current snapshot")
        print(f"{DIM}{subrule}{RESET}")

    print(f"{WHITE}{BOLD}JSON preview{RESET}")
    preview = {
        "headline": summary["headline"],
        "max_risk_score": summary["max_risk_score"],
        "new_findings": summary["new_findings"],
        "top_identity": summary["top_identity"],
    }
    print(json.dumps(preview, indent=2))


def _configure_console_colors(force_plain: bool = False) -> None:
    if force_plain or os.environ.get("NO_COLOR"):
        _disable_colors()
        return
    if not sys.stdout.isatty():
        _disable_colors()
        return
    if os.name != "nt":
        return
    if not _enable_windows_virtual_terminal():
        _disable_colors()


def _enable_windows_virtual_terminal() -> bool:
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        if handle in (0, -1):
            return False
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        enabled = mode.value | 0x0004
        if kernel32.SetConsoleMode(handle, enabled) == 0:
            return False
        return True
    except Exception:
        return False


def _disable_colors() -> None:
    global BLUE, CYAN, GREEN, YELLOW, RED, MAGENTA, WHITE, DIM, BOLD, RESET, ASCII
    BLUE = ""
    CYAN = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    MAGENTA = ""
    WHITE = ""
    DIM = ""
    BOLD = ""
    RESET = ""
    ASCII = """\
  ______       __              ______
 / ____/___   / /________ _   /_  __/________ _________
/ __/ / __ \\ / __/ ___/ _ `/    / / / ___/ __ `/ ___/ _ \\
/ /___/ / / // /_/ /  / (_| /   / / / /  / /_/ / /__/  __/
\\_____/_/ /_/ \\__/_/   \\__,_/   /_/ /_/   \\__,_/\\___/\\___/
"""


def _severity_line(severities: dict[str, int]) -> str:
    return "Severity        : " + "  ".join(
        [
            f"{RED}CRITICAL={severities.get('critical', 0)}{RESET}",
            f"{YELLOW}HIGH={severities.get('high', 0)}{RESET}",
            f"{GREEN}MEDIUM={severities.get('medium', 0)}{RESET}",
            f"{CYAN}LOW={severities.get('low', 0)}{RESET}",
        ]
    )


def _color_for(severity: str) -> str:
    return {
        "critical": RED,
        "high": YELLOW,
        "medium": GREEN,
        "low": CYAN,
    }.get(severity, WHITE)


def _print_wrapped_field(label: str, value: str, width: int | None = None) -> None:
    label_block = label.ljust(14)
    label_color = _field_label_color(label)
    prefix = f"  {label_color}{label_block}{RESET}: "
    normalized = _normalize_whitespace(value)
    line_width = width if width is not None else _console_line_width()
    line_width = max(line_width, _visible_len(prefix) + 22)
    wrapped = textwrap.fill(
        normalized,
        width=line_width,
        initial_indent=prefix,
        subsequent_indent=" " * _visible_len(prefix),
        break_long_words=True,
        break_on_hyphens=True,
    )
    print(wrapped)


def _print_path_field(label: str, path_steps: list[str], width: int | None = None) -> None:
    label_block = label.ljust(14)
    prefix = f"  {DIM}{label_block}{RESET}: "
    line_width = width if width is not None else _console_line_width()
    prefix_width = _visible_len(prefix)
    line_width = max(line_width, prefix_width + 22)
    if not path_steps:
        print(prefix + "n/a")
        return
    for index, step in enumerate(path_steps, start=1):
        wrapped = textwrap.fill(
            _normalize_whitespace(step),
            width=line_width,
            initial_indent=(prefix if index == 1 else " " * prefix_width) + f"{DIM}{index}.{RESET} ",
            subsequent_indent=(" " * prefix_width) + "   ",
            break_long_words=True,
            break_on_hyphens=True,
        )
        print(wrapped)


def _normalize_whitespace(value: str) -> str:
    return " ".join(str(value).split())


def _console_line_width(default_width: int = 94) -> int:
    if WIDTH_OVERRIDE is not None:
        return WIDTH_OVERRIDE
    try:
        detected = shutil.get_terminal_size((default_width, 24)).columns
        return max(64, min(MAX_SAFE_LINE_WIDTH, detected - 2))
    except Exception:
        return min(default_width, MAX_SAFE_LINE_WIDTH)


def _visible_len(text: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*m", "", text))


def _field_label_color(label: str) -> str:
    return DIM


def _attack_summary(entries: list[dict[str, str]]) -> str:
    if not entries:
        return ""
    parts: list[str] = []
    for entry in entries[:3]:
        technique = str(entry.get("technique") or "").strip()
        name = str(entry.get("name") or "").strip()
        if technique and name:
            parts.append(f"{technique} {name}")
        elif technique:
            parts.append(technique)
        elif name:
            parts.append(name)
    return ", ".join(parts)
