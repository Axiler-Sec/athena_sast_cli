"""Keep credentials out of CLI logs and saved raw files (CICD-SEC-6).

Debug output and `set -x` are the usual way tokens land in plaintext build
logs. Call `redact()` on every user-visible error and on engine bodies
before they are written to `--raw-dir`.
"""

from __future__ import annotations

import os
import re

SECRET_ENV_NAMES = (
    "ATHENA_API_KEY",
    "ATHENA_REPO_TOKEN",
    "ATHENA_REGISTRY_PASSWORD",
    "ATHENA_REGISTRY_USER",
)

# Distinct Athena prefixes (engine tenancy + future canaries) plus common
# vendor formats so a leaked value in an HTTP error cannot sit in logs.
_PREFIX_RE = re.compile(
    r"(?i)\b("
    r"ath_live_|ath_test_|ath_canary_|"
    r"ghp_|github_pat_|ghs_|gho_|ghu_|"
    r"glpat-|"
    r"sk_live_|sk_test_"
    r")[A-Za-z0-9_\-]{8,}"
)

_BASIC_AUTH_RE = re.compile(r"(https?://)([^/@\s]+):([^@/\s]+)@")
_HEADER_RE = re.compile(
    r"(?i)(X-API-Key|Authorization|Bearer)([\"'=\s:]+)(\S+)"
)


def _mask_prefix(match: re.Match[str]) -> str:
    return match.group(1) + "***"


def redact(text: str) -> str:
    """Return *text* with env secrets and known token shapes replaced."""
    if not text:
        return text
    out = text
    for name in SECRET_ENV_NAMES:
        val = (os.environ.get(name) or "").strip()
        if len(val) >= 8:
            out = out.replace(val, f"${{{name}}}")
    out = _PREFIX_RE.sub(_mask_prefix, out)
    out = _BASIC_AUTH_RE.sub(r"\1***:***@", out)
    out = _HEADER_RE.sub(r"\1\2***", out)
    return out


def redact_bytes(body: bytes) -> bytes:
    """Best-effort redact of a UTF-8 (or mostly-UTF-8) engine body."""
    try:
        return redact(body.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        return body
