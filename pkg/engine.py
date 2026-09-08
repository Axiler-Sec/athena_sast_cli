"""Local OWASP CI/CD regex engine. No API calls. Findings tagged source=local_owasp."""

from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pkg.constants import SEVERITY_RANK, SKIP_DIRS, YAML_EXTS
from pkg.ignore import load_athenaignore, path_is_excluded
from pkg.models import Finding, Location, ScanResult
from pkg.rules import all_rules, public_rule_id, public_rule_name

_COMPILED: Dict[str, List[re.Pattern[str]]] = {}


def _compile(patterns: Iterable[str]) -> List[re.Pattern[str]]:
    out: List[re.Pattern[str]] = []
    for pat in patterns:
        try:
            out.append(re.compile(pat, re.MULTILINE))
        except re.error:
            continue
    return out


def _fingerprint(rule_id: str, filepath: str, line: int, snippet: str) -> str:
    payload = f"{rule_id}|{filepath}|{line}|{snippet.strip()}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def _is_minified(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".min.js") or name.endswith(".min.css") or "-min.js" in name


def _is_pipeline_file(path: Path, text: str) -> bool:
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if name == "jenkinsfile":
        return True
    if name in {"azure-pipelines.yml", "azure-pipelines.yaml", ".gitlab-ci.yml"}:
        return True
    if ".github" in parts and "workflows" in parts:
        return True
    if "pipeline" in name:
        return True
    if path.suffix.lower() in YAML_EXTS and re.search(r"(?m)^on:\s*$", text) and re.search(
        r"(?m)^jobs:", text
    ):
        return True
    if "pipeline {" in text or "pipeline{" in text:
        return True
    return False


def _is_k8s(text: str) -> bool:
    return bool(re.search(r"(?i)apiVersion:", text) and re.search(r"(?i)kind:", text))


def _rule_applies(rule: Dict[str, Any], path: Path, text: str, is_pipeline: bool) -> bool:
    if rule.get("pipeline_only") and not is_pipeline:
        return False
    if rule.get("k8s_only") and not _is_k8s(text):
        return False
    names = [n.lower() for n in (rule.get("filenames") or [])]
    exts = [e.lower() for e in (rule.get("file_types") or [])]
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name == "jenkinsfile":
        suffix = ".groovy"
    if name == "dockerfile":
        suffix = ".dockerfile"
    if names and name in names:
        return True
    if name.startswith(".env") and (".env" in exts or ".env" in names):
        return True
    if exts:
        return suffix in exts
    return not names


def _search_window(lines: List[str], index: int, window: int, regexes: List[re.Pattern[str]]) -> bool:
    if not regexes:
        return True
    lo = max(0, index - window)
    hi = min(len(lines), index + window + 1)
    chunk = "\n".join(lines[lo:hi])
    return any(rx.search(chunk) for rx in regexes)


def _file_has_any(text: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        try:
            if re.search(pat, text, re.MULTILINE):
                return True
        except re.error:
            continue
    return False


def _file_has_all(text: str, patterns: Iterable[str]) -> bool:
    if not patterns:
        return True
    return all(_file_has_any(text, [pat]) for pat in patterns)


def _emit(
    *,
    rule: Dict[str, Any],
    filepath: str,
    line: int,
    snippet: str,
    seen: Set[Tuple[str, str, int]],
) -> Optional[Finding]:
    rid = public_rule_id(rule)
    key = (rid, filepath, line)
    if key in seen:
        return None
    seen.add(key)
    owasp = str(rule.get("owasp_id") or "")
    tags = list(rule.get("tags") or [])
    if owasp and owasp not in tags:
        tags.append(owasp)
    return Finding(
        rule_id=rid,
        rule_name=public_rule_name(rule),
        severity=str(rule["severity"]).lower(),
        owasp_id=owasp or None,
        message=str(rule.get("message") or ""),
        location=Location(filepath=filepath, line=max(1, line), column=1),
        snippet=snippet.strip()[:240],
        tags=tags,
        source="local_owasp",
        source_endpoint="local",
        fingerprint=_fingerprint(rid, filepath, line, snippet),
        cwe=rule.get("cwe"),
    )


def scan_path(
    target: str,
    *,
    exclude: Optional[List[str]] = None,
) -> ScanResult:
    started = time.perf_counter()
    errors: List[str] = []
    findings: List[Finding] = []
    seen: Set[Tuple[str, str, int]] = set()
    scanned = 0

    root = Path(target).resolve()
    if not root.exists():
        duration = (time.perf_counter() - started) * 1000
        return ScanResult(
            target=str(target),
            findings=[],
            scanned_files=0,
            errors=[f"target does not exist: {target}"],
            duration_ms=duration,
        )

    ignore_root = root if root.is_dir() else root.parent
    patterns = list(exclude or [])
    patterns.extend(load_athenaignore(ignore_root))
    # When the CLI itself is the cwd, also load its .athenaignore
    cwd_ignore = Path.cwd() / ".athenaignore"
    if cwd_ignore.is_file() and ignore_root.resolve() != Path.cwd().resolve():
        patterns.extend(load_athenaignore(Path.cwd()))

    files: List[Path] = []
    if root.is_file():
        files = [root]
        rel_base = root.parent
    else:
        rel_base = root
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv")]
            for fname in filenames:
                files.append(Path(dirpath) / fname)

    rules = all_rules()

    for fpath in files:
        if _is_minified(fpath):
            continue
        try:
            rel = str(fpath.resolve().relative_to(rel_base.resolve()))
        except ValueError:
            rel = str(fpath)
        rel = rel.replace("\\", "/")
        if path_is_excluded(rel, patterns):
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: {exc}")
            continue
        scanned += 1
        is_pipeline = _is_pipeline_file(fpath, text)
        lines = text.splitlines()
        for rule in rules:
            if not _rule_applies(rule, fpath, text, is_pipeline):
                continue
            mode = rule.get("mode") or "line"
            if mode == "file":
                all_ok = _file_has_all(text, rule.get("all_patterns") or ["."])
                missing = rule.get("missing_patterns") or []
                missing_ok = True
                if missing:
                    missing_ok = not _file_has_any(text, missing)
                extra_line = rule.get("patterns") or []
                extra_ok = True if not extra_line else _file_has_any(text, extra_line)
                if all_ok and missing_ok and extra_ok:
                    line_no = 1
                    snippet = lines[0] if lines else ""
                    loc_pats = rule.get("all_patterns") or extra_line or []
                    for i, ln in enumerate(lines, 1):
                        if _file_has_any(ln, loc_pats):
                            line_no = i
                            snippet = ln
                            break
                    finding = _emit(
                        rule=rule, filepath=rel, line=line_no, snippet=snippet, seen=seen
                    )
                    if finding:
                        findings.append(finding)
                continue

            line_regexes = _compile(rule.get("patterns") or [])
            near_regexes = _compile(rule.get("near_patterns") or [])
            window = int(rule.get("window") or 5)
            if not line_regexes:
                continue
            for i, ln in enumerate(lines):
                if not any(rx.search(ln) for rx in line_regexes):
                    continue
                if mode == "window" and not _search_window(lines, i, window, near_regexes):
                    continue
                finding = _emit(
                    rule=rule, filepath=rel, line=i + 1, snippet=ln, seen=seen
                )
                if finding:
                    findings.append(finding)

    findings.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 9),
            f.location.filepath,
            f.location.line,
            f.rule_id,
        )
    )
    coverage: Dict[str, int] = {}
    for f in findings:
        if f.owasp_id:
            coverage[f.owasp_id] = coverage.get(f.owasp_id, 0) + 1
    duration = (time.perf_counter() - started) * 1000
    return ScanResult(
        target=str(target),
        findings=findings,
        scanned_files=scanned,
        errors=errors,
        duration_ms=round(duration, 2),
        owasp_coverage=coverage,
    )
