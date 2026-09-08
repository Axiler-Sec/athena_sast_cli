"""Turn each engine product JSON shape into Finding objects. source=engine."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional

from pkg.models import Finding, Location
from pkg.taxonomy import normalize_severity, owasp_from_cwe


def _fp(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _cwe_of(item: Dict[str, Any]) -> Optional[str]:
    for key in ("cwe", "CWE"):
        raw = item.get(key)
        if raw:
            text = str(raw)
            if isinstance(raw, list) and raw:
                text = str(raw[0])
            if not text.upper().startswith("CWE-") and text.isdigit():
                return f"CWE-{text}"
            return text if text.upper().startswith("CWE-") else f"CWE-{text}"
    ids = item.get("identifiers") if isinstance(item.get("identifiers"), dict) else {}
    if ids.get("cwe"):
        return str(ids["cwe"])
    meta = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    if meta.get("cwe"):
        cwe = meta["cwe"]
        if isinstance(cwe, list) and cwe:
            return str(cwe[0])
        return str(cwe)
    return None


def _loc(item: Dict[str, Any]) -> Location:
    loc = item.get("location") if isinstance(item.get("location"), dict) else {}
    filepath = (
        item.get("file")
        or loc.get("filepath")
        or loc.get("file")
        or loc.get("path")
        or item.get("path")
        or item.get("uri")
        or ""
    )
    line = item.get("line") or loc.get("line") or loc.get("startLine") or item.get("start_line") or 1
    try:
        line_i = int(line)
    except (TypeError, ValueError):
        line_i = 1
    return Location(filepath=str(filepath), line=max(1, line_i))


def _from_item(item: Dict[str, Any], *, endpoint: str, default_name: str) -> Finding:
    loc = _loc(item)
    rule_id = str(
        item.get("check_id")
        or item.get("rule_id")
        or item.get("issue_title")
        or item.get("id")
        or default_name
    )
    name = str(item.get("issue_title") or item.get("rule_name") or item.get("title") or rule_id)
    message = str(item.get("message") or item.get("description") or name)
    snippet = str(item.get("code") or item.get("snippet") or item.get("match") or "")[:240]
    cwe = _cwe_of(item)
    cve = None
    if item.get("vulnerability_id"):
        cve = str(item.get("vulnerability_id"))
    elif item.get("cve"):
        cve = str(item.get("cve"))
    cvss = item.get("cvss_score") or item.get("cvss")
    try:
        cvss_f = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss_f = None
    owasp = item.get("owasp_id") or owasp_from_cwe(cwe)
    severity = normalize_severity(str(item.get("severity") or item.get("priority") or "medium"))
    tags = [t for t in _as_list(item.get("tags")) if isinstance(t, str)]
    if owasp:
        tags.append(owasp)
    return Finding(
        rule_id=rule_id,
        rule_name=name,
        severity=severity,
        message=message,
        location=loc,
        snippet=snippet,
        tags=tags,
        owasp_id=str(owasp) if owasp else None,
        source="engine",
        source_endpoint=endpoint,
        fingerprint=str(item.get("fingerprint") or _fp(endpoint, rule_id, loc.filepath, str(loc.line))),
        cwe=cwe,
        cve=cve,
        cvss=cvss_f,
    )


def _walk_findings(payload: Any) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    found: List[Dict[str, Any]] = []
    for key in ("triaged_findings", "findings"):
        for item in _as_list(payload.get(key)):
            if isinstance(item, dict):
                found.append(item)
    inv = payload.get("inventory")
    if isinstance(inv, dict):
        for key in ("findings", "pii", "vulns", "misconfigs", "secrets"):
            for item in _as_list(inv.get(key)):
                if isinstance(item, dict):
                    found.append(item)
        for item in _as_list(inv.get("components")):
            if not isinstance(item, dict):
                continue
            vulns = item.get("vulnerabilities") or item.get("vulns") or []
            if vulns:
                for v in _as_list(vulns):
                    if isinstance(v, dict):
                        merged = dict(v)
                        merged.setdefault("file", item.get("name") or item.get("purl") or "")
                        found.append(merged)
            elif item.get("vulnerable"):
                found.append(item)
    static = payload.get("static")
    if isinstance(static, dict):
        for item in _as_list(static.get("findings")):
            if isinstance(item, dict):
                found.append(item)
    return found


def normalize_engine(payload: Any, *, endpoint: str) -> List[Finding]:
    items = _walk_findings(payload)
    return [_from_item(item, endpoint=endpoint, default_name=endpoint) for item in items]


def merge_findings(groups: Iterable[List[Finding]]) -> List[Finding]:
    seen = set()
    out: List[Finding] = []
    for group in groups:
        for f in group:
            key = (f.source_endpoint, f.rule_id, f.location.filepath, f.location.line, f.fingerprint)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    return out
