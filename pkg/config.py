"""Config merge: CLI flag > environment variable > athena.yaml > default."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pkg.constants import (
    DEFAULT_FAIL_ON,
    DEFAULT_FORMAT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_RAW_DIR,
)


class ConfigError(Exception):
    """Unreadable or invalid config — CLI maps this to exit 2."""


@dataclass
class Config:
    fail_on: str = DEFAULT_FAIL_ON
    format: str = DEFAULT_FORMAT
    output: Optional[str] = None
    output_from_cli: bool = False
    json_output: Optional[str] = None
    exclude: List[str] = field(default_factory=list)
    modes: List[str] = field(
        default_factory=lambda: ["code-review", "secrets", "iac", "sca", "pipeline"]
    )
    quiet: bool = False
    owasp_risk: Optional[str] = None
    severity: Optional[str] = None
    api_url: str = ""
    http_timeout: int = DEFAULT_HTTP_TIMEOUT
    raw_dir: str = DEFAULT_RAW_DIR
    repo: Optional[str] = None
    branch: Optional[str] = None
    target: str = "."
    image: Optional[str] = None
    config_path: Optional[str] = None


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_yaml_file(path: str) -> Dict[str, Any]:
    """Minimal YAML subset reader for athena.yaml (no PyYAML dependency)."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ConfigError(f"cannot read config file: {path}") from exc
    return parse_simple_yaml(text)


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip().startswith("- ") and current_list_key:
            item = _strip_quotes(line.strip()[2:].strip())
            data.setdefault(current_list_key, []).append(item)
            continue
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest == "":
            current_list_key = key
            data[key] = []
            continue
        current_list_key = None
        data[key] = _strip_quotes(rest)
    return data


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or "").strip() or default


def load_config(
    *,
    config_path: Optional[str] = None,
    cli: Optional[Dict[str, Any]] = None,
) -> Config:
    """Merge defaults <- yaml <- env <- CLI (highest)."""
    cfg = Config()
    path = config_path or os.environ.get("ATHENA_CONFIG") or "athena.yaml"
    yaml_data: Dict[str, Any] = {}
    if os.path.isfile(path):
        yaml_data = load_yaml_file(path)
        cfg.config_path = path

    def pick(cli_key: str, env_name: str, yaml_key: str, default: Any) -> Any:
        cli_map = cli or {}
        if cli_map.get(cli_key) not in (None, "", []):
            return cli_map[cli_key]
        env_val = _env(env_name)
        if env_val:
            return env_val
        if yaml_key in yaml_data and yaml_data[yaml_key] not in (None, "", []):
            return yaml_data[yaml_key]
        return default

    cfg.fail_on = str(pick("fail_on", "ATHENA_FAIL_ON", "fail_on", DEFAULT_FAIL_ON)).lower()
    cfg.format = str(pick("format", "ATHENA_FORMAT", "format", DEFAULT_FORMAT)).lower()
    output = pick("output", "ATHENA_OUTPUT", "output", None)
    cfg.output = str(output) if output else None
    # CLI --format without --output prints to stdout (tests and interactive use).
    cli_map = cli or {}
    cfg.output_from_cli = bool(cli_map.get("output"))
    if cli_map.get("format") and not cli_map.get("output"):
        cfg.output = None
    json_output = pick("json_output", "ATHENA_JSON_OUTPUT", "json_output", None)
    cfg.json_output = str(json_output) if json_output else None

    excludes: List[str] = []
    if isinstance(yaml_data.get("exclude"), list):
        excludes.extend(str(x) for x in yaml_data["exclude"])
    env_ex = _env("ATHENA_EXCLUDE")
    if env_ex:
        excludes.extend(p.strip() for p in env_ex.split(",") if p.strip())
    if cli and cli.get("exclude"):
        excludes.extend(str(x) for x in cli["exclude"])
    cfg.exclude = excludes

    modes = yaml_data.get("modes")
    if isinstance(modes, list) and modes:
        cfg.modes = [str(m) for m in modes]
    env_modes = _env("ATHENA_MODES")
    if env_modes:
        cfg.modes = [m.strip() for m in env_modes.split(",") if m.strip()]
    if cli and cli.get("modes"):
        raw = cli["modes"]
        if isinstance(raw, str):
            cfg.modes = [m.strip() for m in raw.split(",") if m.strip()]
        elif isinstance(raw, list):
            cfg.modes = [str(m) for m in raw]

    cfg.quiet = bool((cli or {}).get("quiet") or _env("ATHENA_QUIET"))
    cfg.owasp_risk = (cli or {}).get("owasp_risk") or _env("ATHENA_OWASP_RISK") or None
    cfg.severity = (cli or {}).get("severity") or _env("ATHENA_SEVERITY") or None
    cfg.api_url = _env("ATHENA_API_URL").rstrip("/")
    timeout_raw = pick("http_timeout", "ATHENA_HTTP_TIMEOUT", "http_timeout", DEFAULT_HTTP_TIMEOUT)
    try:
        cfg.http_timeout = int(timeout_raw)
    except (TypeError, ValueError) as exc:
        raise ConfigError("ATHENA_HTTP_TIMEOUT must be an integer") from exc
    cfg.raw_dir = str(pick("raw_dir", "ATHENA_RAW_DIR", "raw_dir", DEFAULT_RAW_DIR))
    cfg.repo = (cli or {}).get("repo") or _env("ATHENA_REPO") or None
    cfg.branch = (cli or {}).get("branch") or _env("ATHENA_BRANCH") or None
    cfg.target = str((cli or {}).get("target") or _env("ATHENA_TARGET") or ".")
    cfg.image = (cli or {}).get("image") or _env("ATHENA_IMAGE") or None
    return cfg
