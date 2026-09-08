"""CLI dispatch. No scan logic here — imports pkg.* only. Auth never appears as a flag."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pkg import client
from pkg.client import EngineError
from pkg.config import Config, ConfigError, load_config
from pkg.constants import (
    EXIT_CLEAN,
    EXIT_ERROR,
    EXIT_FINDINGS,
    OWASP_RISKS,
    OWASP_RULE_COVERAGE,
    SEVERITY_RANK,
    VERSION,
)
from pkg.engine import scan_path
from pkg.models import Finding, ScanResult
from pkg.normalize import merge_findings, normalize_engine
from pkg.output import render, to_json
from pkg.rules import all_rules, public_rule_id, public_rule_name


def _fail_on_triggered(findings: List[Finding], fail_on: str) -> bool:
    threshold = SEVERITY_RANK.get((fail_on or "high").lower(), 1)
    for f in findings:
        if SEVERITY_RANK.get(f.severity, 9) <= threshold:
            return True
    return False


def _filter_findings(
    findings: List[Finding], *, severity: Optional[str], owasp_risk: Optional[str]
) -> List[Finding]:
    out = findings
    if severity:
        rank = SEVERITY_RANK.get(severity.lower(), 3)
        out = [f for f in out if SEVERITY_RANK.get(f.severity, 9) <= rank]
    if owasp_risk:
        out = [f for f in out if f.owasp_id == owasp_risk]
    return out


def _emit(result: ScanResult, cfg: Config) -> int:
    result.findings = _filter_findings(
        result.findings, severity=cfg.severity, owasp_risk=cfg.owasp_risk
    )
    text = render(result, cfg.format)
    if cfg.output:
        Path(cfg.output).parent.mkdir(parents=True, exist_ok=True)
        Path(cfg.output).write_text(text, encoding="utf-8")
        if not cfg.quiet and cfg.format == "table":
            sys.stdout.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    if cfg.json_output:
        Path(cfg.json_output).parent.mkdir(parents=True, exist_ok=True)
        Path(cfg.json_output).write_text(to_json(result), encoding="utf-8")
    if result.errors and not result.findings and result.scanned_files == 0:
        # missing target etc.
        if any("does not exist" in e for e in result.errors):
            if not cfg.quiet and cfg.format == "table":
                sys.stderr.write(result.errors[0] + "\n")
            return EXIT_ERROR
    if _fail_on_triggered(result.findings, cfg.fail_on):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def _cfg_from_ns(ns: argparse.Namespace) -> Config:
    cli: Dict[str, Any] = {
        "fail_on": getattr(ns, "fail_on", None),
        "format": getattr(ns, "format", None),
        "output": getattr(ns, "output", None),
        "json_output": getattr(ns, "json_output", None),
        "exclude": getattr(ns, "exclude", None) or [],
        "quiet": getattr(ns, "quiet", False),
        "owasp_risk": getattr(ns, "owasp_risk", None),
        "severity": getattr(ns, "severity", None),
        "modes": getattr(ns, "modes", None),
        "repo": getattr(ns, "repo", None),
        "branch": getattr(ns, "branch", None),
        "target": getattr(ns, "target", None),
        "image": getattr(ns, "image", None),
        "raw_dir": getattr(ns, "raw_dir", None),
    }
    return load_config(config_path=getattr(ns, "config", None), cli=cli)


def cmd_version(_ns: argparse.Namespace) -> int:
    sys.stdout.write(f"Athena SAST v{VERSION}\n")
    return EXIT_CLEAN


def cmd_rules(_ns: argparse.Namespace) -> int:
    sys.stdout.write(f"{'ID':8} {'SEV':10} {'OWASP':14} NAME\n")
    seen = set()
    for rule in all_rules():
        rid = public_rule_id(rule)
        if rid in seen:
            continue
        seen.add(rid)
        sys.stdout.write(
            f"{rid:8} {rule['severity']:10} {rule.get('owasp_id',''):14} {public_rule_name(rule)}\n"
        )
    return EXIT_CLEAN


def cmd_owasp(_ns: argparse.Namespace) -> int:
    sys.stdout.write("OWASP Top 10 CI/CD Security Risks — Athena Coverage\n")
    sys.stdout.write("===================================================\n")
    for i in range(1, 11):
        key = f"CICD-SEC-{i}"
        name = OWASP_RISKS[key]
        rules = ", ".join(OWASP_RULE_COVERAGE.get(key, []))
        sys.stdout.write(f"{key:12} {name:44}  [x] {rules}\n")
    return EXIT_CLEAN


def cmd_scan_local(ns: argparse.Namespace, cfg: Config) -> int:
    target = getattr(ns, "local", None) or getattr(ns, "scan_target", None) or cfg.target or "."
    result = scan_path(target, exclude=cfg.exclude)
    if result.errors and not Path(target).exists():
        if not cfg.quiet:
            sys.stderr.write(result.errors[0] + "\n")
        return EXIT_ERROR
    return _emit(result, cfg)


def _parse_image(image: str):
    # registry/repo:tag  (docker.io/library/nginx:latest)
    tag = "latest"
    rest = image
    if ":" in image.rsplit("/", 1)[-1]:
        rest, tag = image.rsplit(":", 1)
    if "/" not in rest:
        raise EngineError("image must be registry/repository:tag")
    registry, repository = rest.split("/", 1)
    return registry, repository, tag


def cmd_scan_orchestrator(ns: argparse.Namespace, cfg: Config) -> int:
    if not cfg.repo:
        return cmd_scan_local(ns, cfg)
    raw_dir = cfg.raw_dir
    groups: List[List[Finding]] = []
    errors: List[str] = []
    raw_refs: List[str] = []
    scanned_files = 0

    if not cfg.quiet:
        sys.stderr.write("repo verify...\n")
    try:
        body, ref = client.repo_verify(cfg.repo, cfg.branch or "main", raw_dir=raw_dir)
        raw_refs.append(ref)
        if body.get("verified") is False:
            raise EngineError("repository could not be verified")
    except EngineError as exc:
        sys.stderr.write(str(exc) + "\n")
        return EXIT_ERROR

    modes = [m.strip() for m in cfg.modes]
    branch = cfg.branch or "main"
    agent_map = {
        "code-review": lambda: client.code_review(cfg.repo, branch, raw_dir=raw_dir),
        "secrets": lambda: client.secrets(cfg.repo, branch, raw_dir=raw_dir),
        "iac": lambda: client.iac(cfg.repo, branch, raw_dir=raw_dir),
        "sca": lambda: client.sca(cfg.repo, branch, raw_dir=raw_dir),
    }
    for mode in modes:
        if mode == "pipeline":
            continue
        if mode == "container" or cfg.image:
            continue
        if mode not in agent_map:
            continue
        if not cfg.quiet:
            sys.stderr.write(f"{mode}...\n")
        try:
            payload, ref = agent_map[mode]()
            raw_refs.append(ref)
            groups.append(normalize_engine(payload, endpoint=mode))
        except EngineError as exc:
            errors.append(str(exc))
            sys.stderr.write(str(exc) + "\n")
            return EXIT_ERROR

    if "container" in modes or cfg.image:
        image = cfg.image
        if not image:
            raise EngineError("--image is required for container mode")
        registry, repository, tag = _parse_image(image)
        if not cfg.quiet:
            sys.stderr.write("container...\n")
        payload, ref = client.container(registry, repository, tag, raw_dir=raw_dir)
        raw_refs.append(ref)
        groups.append(normalize_engine(payload, endpoint="container"))

    if "pipeline" in modes:
        local = scan_path(cfg.target or ".", exclude=cfg.exclude)
        scanned_files = local.scanned_files
        groups.append(local.findings)
        errors.extend(local.errors)

    findings = merge_findings(groups)
    coverage: Dict[str, int] = {}
    for f in findings:
        if f.owasp_id:
            coverage[f.owasp_id] = coverage.get(f.owasp_id, 0) + 1
    result = ScanResult(
        target=cfg.repo,
        findings=findings,
        scanned_files=scanned_files,
        errors=errors,
        duration_ms=0,
        owasp_coverage=coverage,
        raw_refs=raw_refs,
    )
    return _emit(result, cfg)


def cmd_scan(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    if getattr(ns, "local", None):
        cfg.target = ns.local
        return cmd_scan_local(ns, cfg)
    if cfg.repo:
        return cmd_scan_orchestrator(ns, cfg)
    ns.scan_target = getattr(ns, "scan_target", None) or cfg.target
    return cmd_scan_local(ns, cfg)


def _print_json(payload: Any, cfg: Config) -> int:
    text = json.dumps(payload, indent=2)
    # yaml `output:` is the scan artifact path (SARIF). Prep commands only
    # write a file when the user passed --output on the CLI.
    if cfg.output_from_cli and cfg.output:
        Path(cfg.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text + "\n")
    return EXIT_CLEAN


def cmd_repo_verify(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    body, _ = client.repo_verify(ns.repo, ns.branch, raw_dir=cfg.raw_dir)
    _print_json(body, cfg)
    if body.get("verified") is False:
        return EXIT_ERROR
    return EXIT_CLEAN


def cmd_repo_branches(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    body, _ = client.repo_branches(ns.repo, raw_dir=cfg.raw_dir)
    if cfg.format == "json" or cfg.output_from_cli:
        return _print_json(body, cfg)
    branches = body.get("branches") or body.get("items") or []
    if isinstance(branches, list):
        for item in branches:
            if isinstance(item, dict):
                sys.stdout.write(str(item.get("name") or item) + "\n")
            else:
                sys.stdout.write(str(item) + "\n")
    else:
        sys.stdout.write(json.dumps(body, indent=2) + "\n")
    return EXIT_CLEAN


def cmd_image_verify(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    body, _ = client.image_verify(ns.registry, ns.repository, ns.tag, raw_dir=cfg.raw_dir)
    return _print_json(body, cfg)


def cmd_image_tags(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    body, _ = client.image_tags(ns.registry, ns.repository, raw_dir=cfg.raw_dir)
    return _print_json(body, cfg)


def cmd_code_review(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.code_review(ns.repo, ns.branch, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="code-review-agent")
    result = ScanResult(
        target=ns.repo,
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_code_review_upload(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.code_review_upload(ns.zipfile, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="upload-code-review")
    result = ScanResult(
        target=ns.zipfile,
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_secrets_upload(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.secrets_upload(ns.zipfile, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="upload-secrets")
    result = ScanResult(
        target=ns.zipfile,
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_iac_upload(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.iac_upload(ns.zipfile, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="upload-iac")
    result = ScanResult(
        target=ns.zipfile,
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_sca_upload(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.sca_upload(ns.zipfile, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="upload-sca")
    result = ScanResult(
        target=ns.zipfile,
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_secrets(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.secrets(ns.repo, ns.branch, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="secrets-agent")
    result = ScanResult(target=ns.repo, findings=findings, scanned_files=0, errors=[], duration_ms=0, raw_refs=[ref])
    return _emit(result, cfg)


def cmd_iac(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.iac(ns.repo, ns.branch, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="iac-agent")
    result = ScanResult(target=ns.repo, findings=findings, scanned_files=0, errors=[], duration_ms=0, raw_refs=[ref])
    return _emit(result, cfg)


def cmd_sca(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.sca(ns.repo, ns.branch, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="sca-agent")
    result = ScanResult(target=ns.repo, findings=findings, scanned_files=0, errors=[], duration_ms=0, raw_refs=[ref])
    return _emit(result, cfg)


def cmd_container(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.container(ns.registry, ns.repository, ns.tag, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="container-agent")
    result = ScanResult(
        target=f"{ns.registry}/{ns.repository}:{ns.tag}",
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_container_review(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.container_review(ns.registry, ns.repository, ns.tag, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="container-code-review")
    result = ScanResult(
        target=f"{ns.registry}/{ns.repository}:{ns.tag}",
        findings=findings,
        scanned_files=0,
        errors=[],
        duration_ms=0,
        raw_refs=[ref],
    )
    return _emit(result, cfg)


def cmd_apk(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    payload, ref = client.apk_scan(ns.apk, include_llm_review=ns.llm_review, raw_dir=cfg.raw_dir)
    findings = normalize_engine(payload, endpoint="apk-scan")
    result = ScanResult(target=ns.apk, findings=findings, scanned_files=0, errors=[], duration_ms=0, raw_refs=[ref])
    return _emit(result, cfg)


def cmd_sbom(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    fmt = ns.sbom_format or "cyclonedx"
    payload, _ = client.sbom(ns.repo, ns.branch, formats=[fmt], raw_dir=cfg.raw_dir)
    return _print_json(payload, cfg)


def cmd_pr_create(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    finding = json.loads(Path(ns.finding_file).read_text(encoding="utf-8"))
    if "finding" in finding and isinstance(finding["finding"], dict):
        repo = finding.get("repository_url") or ns.repo
        branch = finding.get("branch") or ns.branch
        finding = finding["finding"]
    else:
        repo = ns.repo
        branch = ns.branch
    if not repo or not branch:
        sys.stderr.write("pr create requires --repo and --branch\n")
        return EXIT_ERROR
    payload, _ = client.create_pr(repo, branch, finding, raw_dir=cfg.raw_dir)
    return _print_json(payload, cfg)


def cmd_compliance(ns: argparse.Namespace) -> int:
    cfg = _cfg_from_ns(ns)
    mapper: Dict[str, Any] = {}
    for path in ns.from_files:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        # Heuristic nest: prefer known keys, else stash under code_review if it looks like CR.
        if "modality" in data:
            mod = data["modality"]
            if mod == "code_review":
                mapper["code_review"] = data
            elif mod == "secrets":
                mapper["leaked_secrets"] = data
            elif mod == "iac":
                mapper["iac_misconfig"] = data
            elif mod == "sca":
                mapper["composition_analysis"] = data
            elif mod == "container":
                mapper["container_image"] = data
            else:
                mapper.setdefault("code_review", data)
        else:
            mapper.setdefault("code_review", data)
    payload, _ = client.compliance(mapper, raw_dir=cfg.raw_dir)
    # Honesty: never print "compliant".
    if isinstance(payload, dict):
        payload.setdefault("result_kind", "mapped_controls")
        payload.pop("compliant", None)
        payload.pop("compliance", None)
    text = json.dumps(payload, indent=2)
    sys.stdout.write(text + "\n")
    sys.stdout.write("mapped controls (heuristic — not a certification)\n")
    if cfg.output_from_cli and cfg.output:
        Path(cfg.output).write_text(text, encoding="utf-8")
    return EXIT_CLEAN


def _add_global(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", "-f", dest="format", choices=["table", "json", "sarif", "junit"])
    p.add_argument("--output", "-o", dest="output")
    p.add_argument("--json-output", dest="json_output", help="also write Athena JSON (single scan)")
    p.add_argument("--fail-on", dest="fail_on", choices=["critical", "high", "medium", "low"])
    p.add_argument("--severity", dest="severity", choices=["critical", "high", "medium", "low"])
    p.add_argument("--exclude", action="append", dest="exclude")
    p.add_argument("--config", dest="config")
    p.add_argument("--quiet", "-q", action="store_true")
    p.add_argument("--owasp-risk", dest="owasp_risk")
    p.add_argument("--raw-dir", dest="raw_dir")


def _add_repo(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", required=True)
    p.add_argument("--branch", required=True)


def _add_image(p: argparse.ArgumentParser) -> None:
    p.add_argument("--registry", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--tag", default="latest")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="athena",
        description=(
            "Athena SAST CLI — backbone for CI plugins. "
            "Engine scans use ATHENA_API_URL and ATHENA_API_KEY from the environment. "
            "Never pass credentials as flags (they appear in shell history)."
        ),
    )
    sub = parser.add_subparsers(dest="cmd")

    p_ver = sub.add_parser("version", help="show version")
    p_ver.set_defaults(func=cmd_version)

    p_rules = sub.add_parser("rules", help="list local OWASP rules")
    p_rules.set_defaults(func=cmd_rules)

    p_owasp = sub.add_parser("owasp", help="show OWASP CI/CD Top 10 coverage")
    p_owasp.set_defaults(func=cmd_owasp)

    p_scan = sub.add_parser("scan", help="orchestrated CI scan or local OWASP gate")
    _add_global(p_scan)
    p_scan.add_argument("scan_target", nargs="?", default=".")
    p_scan.add_argument("--local", dest="local", help="local OWASP gate only (no API)")
    p_scan.add_argument("--repo")
    p_scan.add_argument("--branch")
    p_scan.add_argument("--target", dest="target")
    p_scan.add_argument("--modes")
    p_scan.add_argument("--image")
    p_scan.set_defaults(func=cmd_scan)

    p_rv = sub.add_parser("repo")
    rsub = p_rv.add_subparsers(dest="repo_cmd")
    p_rvf = rsub.add_parser("verify")
    _add_global(p_rvf)
    p_rvf.add_argument("--repo", required=True)
    p_rvf.add_argument("--branch", required=True)
    p_rvf.set_defaults(func=cmd_repo_verify)
    p_rb = rsub.add_parser("branches")
    _add_global(p_rb)
    p_rb.add_argument("--repo", required=True)
    p_rb.set_defaults(func=cmd_repo_branches)

    p_img = sub.add_parser("image")
    isub = p_img.add_subparsers(dest="image_cmd")
    p_iv = isub.add_parser("verify")
    _add_global(p_iv)
    _add_image(p_iv)
    p_iv.set_defaults(func=cmd_image_verify)
    p_it = isub.add_parser("tags")
    _add_global(p_it)
    p_it.add_argument("--registry", required=True)
    p_it.add_argument("--repository", required=True)
    p_it.set_defaults(func=cmd_image_tags)

    p_cr = sub.add_parser("code-review")
    crsub = p_cr.add_subparsers(dest="cr_cmd")
    crsub.required = False
    _add_global(p_cr)
    p_cr.add_argument("--repo")
    p_cr.add_argument("--branch")

    def _code_review_dispatch(ns: argparse.Namespace) -> int:
        if getattr(ns, "cr_cmd", None) == "upload":
            return cmd_code_review_upload(ns)
        if not ns.repo or not ns.branch:
            sys.stderr.write("code-review requires --repo and --branch\n")
            return EXIT_ERROR
        return cmd_code_review(ns)

    p_cr.set_defaults(func=_code_review_dispatch)
    p_cru = crsub.add_parser("upload")
    _add_global(p_cru)
    p_cru.add_argument("zipfile")
    p_cru.set_defaults(func=cmd_code_review_upload)

    p_sec = sub.add_parser("secrets")
    secsub = p_sec.add_subparsers(dest="sec_cmd")
    secsub.required = False
    _add_global(p_sec)
    p_sec.add_argument("--repo")
    p_sec.add_argument("--branch")

    def _secrets_dispatch(ns: argparse.Namespace) -> int:
        if getattr(ns, "sec_cmd", None) == "upload":
            return cmd_secrets_upload(ns)
        if not ns.repo or not ns.branch:
            sys.stderr.write("secrets requires --repo and --branch\n")
            return EXIT_ERROR
        return cmd_secrets(ns)

    p_sec.set_defaults(func=_secrets_dispatch)
    p_secu = secsub.add_parser("upload")
    _add_global(p_secu)
    p_secu.add_argument("zipfile")
    p_secu.set_defaults(func=cmd_secrets_upload)

    p_iac = sub.add_parser("iac")
    iacsub = p_iac.add_subparsers(dest="iac_cmd")
    iacsub.required = False
    _add_global(p_iac)
    p_iac.add_argument("--repo")
    p_iac.add_argument("--branch")

    def _iac_dispatch(ns: argparse.Namespace) -> int:
        if getattr(ns, "iac_cmd", None) == "upload":
            return cmd_iac_upload(ns)
        if not ns.repo or not ns.branch:
            sys.stderr.write("iac requires --repo and --branch\n")
            return EXIT_ERROR
        return cmd_iac(ns)

    p_iac.set_defaults(func=_iac_dispatch)
    p_iacu = iacsub.add_parser("upload")
    _add_global(p_iacu)
    p_iacu.add_argument("zipfile")
    p_iacu.set_defaults(func=cmd_iac_upload)

    p_sca = sub.add_parser("sca")
    scasub = p_sca.add_subparsers(dest="sca_cmd")
    scasub.required = False
    _add_global(p_sca)
    p_sca.add_argument("--repo")
    p_sca.add_argument("--branch")

    def _sca_dispatch(ns: argparse.Namespace) -> int:
        if getattr(ns, "sca_cmd", None) == "upload":
            return cmd_sca_upload(ns)
        if not ns.repo or not ns.branch:
            sys.stderr.write("sca requires --repo and --branch\n")
            return EXIT_ERROR
        return cmd_sca(ns)

    p_sca.set_defaults(func=_sca_dispatch)
    p_scau = scasub.add_parser("upload")
    _add_global(p_scau)
    p_scau.add_argument("zipfile")
    p_scau.set_defaults(func=cmd_sca_upload)

    p_sbom = sub.add_parser("sbom")
    p_sbom.add_argument("--output", "-o", dest="output")
    p_sbom.add_argument("--quiet", "-q", action="store_true")
    p_sbom.add_argument("--config", dest="config")
    p_sbom.add_argument("--raw-dir", dest="raw_dir")
    _add_repo(p_sbom)
    p_sbom.add_argument(
        "--format",
        dest="sbom_format",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM document format (cyclonedx or spdx), not the CLI output format",
    )
    p_sbom.set_defaults(func=cmd_sbom)

    p_ct = sub.add_parser("container")
    ctsub = p_ct.add_subparsers(dest="ct_cmd")
    ctsub.required = False
    _add_global(p_ct)
    p_ct.add_argument("--registry")
    p_ct.add_argument("--repository")
    p_ct.add_argument("--tag", default="latest")

    def _container_dispatch(ns: argparse.Namespace) -> int:
        if getattr(ns, "ct_cmd", None) == "review":
            return cmd_container_review(ns)
        if not ns.registry or not ns.repository:
            sys.stderr.write("container requires --registry and --repository\n")
            return EXIT_ERROR
        return cmd_container(ns)

    p_ct.set_defaults(func=_container_dispatch)
    p_ctr = ctsub.add_parser("review")
    _add_global(p_ctr)
    _add_image(p_ctr)
    p_ctr.set_defaults(func=cmd_container_review)

    p_apk = sub.add_parser("apk")
    _add_global(p_apk)
    p_apk.add_argument("apk")
    p_apk.add_argument("--llm-review", action="store_true", dest="llm_review")
    p_apk.set_defaults(func=cmd_apk)

    p_pr = sub.add_parser("pr")
    prsub = p_pr.add_subparsers(dest="pr_cmd")
    p_prc = prsub.add_parser("create")
    _add_global(p_prc)
    p_prc.add_argument("--finding-file", required=True)
    p_prc.add_argument("--repo")
    p_prc.add_argument("--branch")
    p_prc.set_defaults(func=cmd_pr_create)

    p_comp = sub.add_parser("compliance")
    _add_global(p_comp)
    p_comp.add_argument("--from", dest="from_files", nargs="+", required=True)
    p_comp.set_defaults(func=cmd_compliance)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        ns = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return EXIT_CLEAN
        return EXIT_ERROR
    if not getattr(ns, "cmd", None):
        parser.print_help()
        return EXIT_ERROR
    func = getattr(ns, "func", None)
    if func is None:
        parser.print_help()
        return EXIT_ERROR
    try:
        return int(func(ns))
    except EngineError as exc:
        sys.stderr.write(str(exc) + "\n")
        return EXIT_ERROR
    except ConfigError as exc:
        sys.stderr.write(str(exc) + "\n")
        return EXIT_ERROR
    except FileNotFoundError as exc:
        sys.stderr.write(str(exc) + "\n")
        return EXIT_ERROR
    except OSError as exc:
        sys.stderr.write(str(exc) + "\n")
        return EXIT_ERROR
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"invalid JSON: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
