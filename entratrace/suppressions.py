from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SUPPORTED_IGNORE_KEYS = {"id", "severity", "category", "title", "path", "attack", "all"}


@dataclass(slots=True)
class IgnoreRule:
    key: str
    value: str


@dataclass(slots=True)
class SuppressionStats:
    baseline_ids_loaded: int = 0
    baseline_suppressed: int = 0
    ignore_rules_loaded: int = 0
    ignore_suppressed: int = 0
    ignore_invalid_rules: int = 0


def apply_report_suppressions(
    report: dict[str, Any],
    baseline_path: str | Path | None = None,
    ignore_path: str | Path | None = None,
) -> tuple[dict[str, Any], SuppressionStats]:
    updated = dict(report)
    findings = list(report.get("findings", []))
    stats = SuppressionStats()

    baseline_ids = _load_baseline_ids(baseline_path)
    stats.baseline_ids_loaded = len(baseline_ids)
    ignore_rules, ignore_parse_warnings = _load_ignore_rules(ignore_path)
    stats.ignore_rules_loaded = len(ignore_rules)
    stats.ignore_invalid_rules = len(ignore_parse_warnings)

    kept: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        if finding_id and finding_id in baseline_ids:
            stats.baseline_suppressed += 1
            continue
        if _matches_any_rule(finding, ignore_rules):
            stats.ignore_suppressed += 1
            continue
        kept.append(finding)

    updated["findings"] = kept
    _recompute_report_views(updated)
    updated["suppression"] = {
        "baseline_ids_loaded": stats.baseline_ids_loaded,
        "baseline_suppressed": stats.baseline_suppressed,
        "ignore_rules_loaded": stats.ignore_rules_loaded,
        "ignore_suppressed": stats.ignore_suppressed,
        "ignore_invalid_rules": stats.ignore_invalid_rules,
        "ignore_warnings": ignore_parse_warnings[:20],
    }
    return updated, stats


def _load_baseline_ids(path: str | Path | None) -> set[str]:
    if not path:
        return set()
    baseline_path = Path(path).resolve()
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline file not found: {baseline_path}")
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    return _extract_baseline_ids(payload)


def _extract_baseline_ids(payload: Any) -> set[str]:
    if isinstance(payload, dict):
        return _extract_baseline_ids(payload.get("findings", []))

    ids: set[str] = set()
    if isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, dict):
                value = entry.get("finding_id")
                if value:
                    ids.add(str(value))
            elif isinstance(entry, str):
                if entry.strip():
                    ids.add(entry.strip())
    return ids


def _load_ignore_rules(path: str | Path | None) -> tuple[list[IgnoreRule], list[str]]:
    if not path:
        return [], []
    ignore_path = Path(path).resolve()
    if not ignore_path.exists():
        raise FileNotFoundError(f"ignore file not found: {ignore_path}")

    rules: list[IgnoreRule] = []
    warnings: list[str] = []
    for line_number, raw_line in enumerate(ignore_path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, value = line.split(":", 1)
        elif "=" in line:
            key, value = line.split("=", 1)
        else:
            key, value = "title", line
        parsed_key = key.strip().lower()
        parsed_value = value.strip()
        if not parsed_value:
            warnings.append(f"line {line_number}: empty value ignored")
            continue
        if parsed_key not in SUPPORTED_IGNORE_KEYS:
            warnings.append(f"line {line_number}: unsupported key '{parsed_key}'")
            continue
        rules.append(IgnoreRule(key=parsed_key, value=parsed_value))
    return rules, warnings


def _matches_any_rule(finding: dict[str, Any], rules: list[IgnoreRule]) -> bool:
    return any(_matches_rule(finding, rule) for rule in rules)


def _matches_rule(finding: dict[str, Any], rule: IgnoreRule) -> bool:
    value = rule.value
    if rule.key == "id":
        return str(finding.get("finding_id") or "") == value

    if rule.key == "severity":
        return str(finding.get("severity") or "").lower() == value.lower()

    if rule.key == "category":
        return str(finding.get("category") or "").lower() == value.lower()

    title = str(finding.get("title") or "")
    path_text = " -> ".join(str(step) for step in finding.get("path") or [])
    attack_text = " ".join(
        f"{item.get('technique', '')} {item.get('name', '')} {item.get('tactic', '')}".strip()
        for item in finding.get("attack") or []
        if isinstance(item, dict)
    )
    all_text = " | ".join(
        [
            str(finding.get("finding_id") or ""),
            str(finding.get("severity") or ""),
            str(finding.get("category") or ""),
            title,
            path_text,
            attack_text,
        ]
    )
    value_lower = value.lower()

    if rule.key == "title":
        return value_lower in title.lower()
    if rule.key == "path":
        return value_lower in path_text.lower()
    if rule.key == "attack":
        return value_lower in attack_text.lower()
    if rule.key == "all":
        return value_lower in all_text.lower()
    return False


def _recompute_report_views(report: dict[str, Any]) -> None:
    findings = list(report.get("findings", []))
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    new_findings = sum(1 for finding in findings if bool(finding.get("new_since_previous")))
    max_risk = max((int(finding.get("risk_score") or 0) for finding in findings), default=0)
    previous_exists = bool(report.get("previous_snapshot"))
    headline = (
        "New high-impact privilege paths were introduced since the previous snapshot."
        if previous_exists and new_findings
        else "Privileged identity relationships were detected in the current snapshot."
        if findings
        else "No modeled high-risk Entra or Azure privilege paths were detected in the current snapshot."
    )

    summary = dict(report.get("summary") or {})
    summary["headline"] = headline
    summary["total_findings"] = len(findings)
    summary["new_findings"] = new_findings
    summary["max_risk_score"] = max_risk
    summary["severity_counts"] = severity_counts
    summary["change_event_count"] = len(report.get("changes") or [])
    summary["crown_jewel_count"] = len(report.get("crown_jewels") or [])

    top_risky = _top_risky_identities_from_findings(findings)
    summary["top_identity"] = top_risky[0]["name"] if top_risky else None

    report["summary"] = summary
    report["top_risky_identities"] = top_risky
    report["remediation_queue"] = _rebuild_remediation_queue(findings)


def _top_risky_identities_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for finding in findings:
        path = finding.get("path") or []
        if not isinstance(path, list) or not path:
            continue
        actor_name = str(path[0])
        actor_id = str(finding.get("actor_id") or "").strip() or None
        actor_key = actor_id or f"name::{actor_name}"
        bucket = buckets.setdefault(
            actor_key,
            {"id": actor_id, "name": actor_name, "risk_score": 0, "findings": 0},
        )
        if actor_id and not bucket.get("id"):
            bucket["id"] = actor_id
        if actor_name and (not bucket.get("name") or str(bucket["name"]).startswith("Unknown")):
            bucket["name"] = actor_name
        bucket["risk_score"] += int(finding.get("risk_score") or 0)
        bucket["findings"] += 1
    return sorted(buckets.values(), key=lambda item: (-item["risk_score"], -item["findings"], item["name"]))[:5]


def _rebuild_remediation_queue(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sorted_findings = sorted(
        findings,
        key=lambda item: (-_severity_rank(str(item.get("severity") or "")), -int(item.get("risk_score") or 0), str(item.get("title") or "")),
    )
    queue: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in sorted_findings:
        remediation = finding.get("remediation") or []
        if not remediation:
            continue
        action = str(remediation[0])
        if not action or action in seen:
            continue
        seen.add(action)
        queue.append(
            {
                "severity": str(finding.get("severity") or "low"),
                "action": action,
                "reason": str(finding.get("title") or "Unnamed finding"),
            }
        )
    return queue[:8]


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity.lower(), 0)
