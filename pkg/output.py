"""Formatters: table, JSON, SARIF 2.1.0 (cli_normalized), JUnit grouped by OWASP risk."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, List
from xml.etree.ElementTree import Element, SubElement, tostring

from pkg.constants import (
    JSON_SCHEMA_VERSION,
    OWASP_CHEATSHEET_URI,
    OWASP_STANDARD,
    SARIF_SCHEMA,
    SEVERITY_ORDER,
    TOOL_NAME,
    VERSION,
)
from pkg.models import Finding, ScanResult

_ICONS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        key = (f.severity or "low").lower()
        if key in counts:
            counts[key] += 1
    return counts


def _owasp_counts(findings: List[Finding]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for f in findings:
        if f.owasp_id:
            c[f.owasp_id] = c.get(f.owasp_id, 0) + 1
    return c


def _source_counts(findings: List[Finding]) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for f in findings:
        src = f.source or "unknown"
        c[src] = c.get(src, 0) + 1
    return c


def to_table(result: ScanResult) -> str:
    lines: List[str] = []
    if not result.findings:
        lines.append("No findings. Pipeline is OWASP CI/CD compliant.")
        lines.append(f"Scanned files: {result.scanned_files}  duration_ms: {result.duration_ms}")
        return "\n".join(lines)
    for f in result.findings:
        loc = f"{f.location.filepath}:{f.location.line}"
        owasp = f"[{f.owasp_id}]" if f.owasp_id else ""
        src = f.source
        icon = _ICONS.get(f.severity, f.severity.upper())
        lines.append(
            f"{icon:8} {owasp:14} {f.rule_id:8} {src:12} {loc}  {f.rule_name}"
        )
        if f.snippet:
            lines.append(f"         {f.snippet[:120]}")
        lines.append(f"         {f.message}")
        lines.append("")
    sev = _severity_counts(result.findings)
    lines.append("---")
    lines.append(
        "Severity: "
        + "  ".join(f"{k}={sev[k]}" for k in SEVERITY_ORDER)
    )
    owasp = _owasp_counts(result.findings)
    if owasp:
        lines.append(
            "OWASP: "
            + "  ".join(f"{k}={v}" for k, v in sorted(owasp.items()))
        )
    src = _source_counts(result.findings)
    lines.append("Source: " + "  ".join(f"{k}={v}" for k, v in sorted(src.items())))
    lines.append(f"Scanned files: {result.scanned_files}  duration_ms: {result.duration_ms}")
    return "\n".join(lines)


def finding_to_dict(f: Finding) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "severity": f.severity,
        "owasp_id": f.owasp_id,
        "owasp_name": f.owasp_name,
        "message": f.message,
        "tags": f.tags,
        "source": f.source,
        "source_endpoint": f.source_endpoint,
        "location": {
            "filepath": f.location.filepath,
            "line": f.location.line,
            "column": f.location.column,
        },
        "snippet": f.snippet,
        "fingerprint": f.fingerprint,
    }
    if f.cwe:
        row["cwe"] = f.cwe
    if f.cve:
        row["cve"] = f.cve
    if f.cvss is not None:
        row["cvss"] = f.cvss
    return row


def to_json(result: ScanResult) -> str:
    payload = {
        "schema_version": JSON_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "target": result.target,
        "owasp_standard": OWASP_STANDARD,
        "summary": {
            "scanned_files": result.scanned_files,
            "total_findings": len(result.findings),
            "duration_ms": result.duration_ms,
            "by_severity": _severity_counts(result.findings),
            "by_owasp_risk": _owasp_counts(result.findings),
            "by_source": _source_counts(result.findings),
        },
        "findings": [finding_to_dict(f) for f in result.findings],
        "errors": result.errors,
    }
    if result.raw_refs:
        payload["raw_refs"] = result.raw_refs
    return json.dumps(payload, indent=2)


def _sarif_level(severity: str) -> str:
    s = (severity or "").lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    return "note"


def to_sarif(result: ScanResult) -> str:
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in result.findings:
        if f.rule_id not in rules_by_id:
            tags = list(f.tags or [])
            if f.owasp_id and f.owasp_id not in tags:
                tags.append(f.owasp_id)
            rules_by_id[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.message},
                "helpUri": OWASP_CHEATSHEET_URI,
                "properties": {
                    "tags": tags,
                    "owasp_id": f.owasp_id,
                    "cwe": f.cwe,
                },
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.location.filepath},
                            "region": {"startLine": max(1, f.location.line)},
                        }
                    }
                ],
                "partialFingerprints": {"athena/v1": f.fingerprint} if f.fingerprint else {},
                "properties": {
                    "owasp_id": f.owasp_id,
                    "sarif_source": "cli_normalized",
                    "source": f.source,
                    "source_endpoint": f.source_endpoint,
                },
            }
        )
    doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": VERSION,
                        "informationUri": OWASP_CHEATSHEET_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {"sarif_source": "cli_normalized"},
            }
        ],
    }
    return json.dumps(doc, indent=2)


def to_junit(result: ScanResult) -> str:
    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for f in result.findings:
        grouped[f.owasp_id or "UNMAPPED"].append(f)
    testsuites = Element("testsuites", name=TOOL_NAME, tests=str(len(result.findings)), failures=str(len(result.findings)), errors="0")
    if not result.findings:
        SubElement(testsuites, "testsuite", name="athena", tests="0", failures="0")
    for risk, items in sorted(grouped.items()):
        suite = SubElement(
            testsuites,
            "testsuite",
            name=risk,
            tests=str(len(items)),
            failures=str(len(items)),
        )
        for f in items:
            case = SubElement(
                suite,
                "testcase",
                name=f"{f.rule_id} - {f.location.filepath}:{f.location.line}",
                classname=f.rule_name.replace(" ", ""),
            )
            fail = SubElement(
                case,
                "failure",
                message=f.rule_name,
                type=f.severity,
            )
            fail.text = f.snippet or f.message
    xml = tostring(testsuites, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + xml


def render(result: ScanResult, fmt: str) -> str:
    fmt = (fmt or "table").lower()
    if fmt == "json":
        return to_json(result)
    if fmt == "sarif":
        return to_sarif(result)
    if fmt == "junit":
        return to_junit(result)
    return to_table(result)
