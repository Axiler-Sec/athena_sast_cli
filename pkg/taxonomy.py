"""Vendor severity + optional CWE → OWASP CI/CD risk. Identifiers never block a finding."""

from __future__ import annotations

from typing import Optional

# Engine agents use mixed severity labels. Always derive a 4-level value.
_SEVERITY_TABLE = {
    "critical": "critical",
    "high": "high",
    "error": "high",
    "medium": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "note": "low",
    "info": "low",
    "informational": "low",
}


# CWE → OWASP CI/CD risk. Unmapped CWEs leave owasp_id unset on engine findings.
CWE_TO_OWASP = {
    "CWE-798": "CICD-SEC-6",
    "CWE-321": "CICD-SEC-6",
    "CWE-532": "CICD-SEC-6",
    "CWE-259": "CICD-SEC-6",
    "CWE-89": "CICD-SEC-4",
    "CWE-78": "CICD-SEC-4",
    "CWE-94": "CICD-SEC-4",
    "CWE-95": "CICD-SEC-4",
    "CWE-502": "CICD-SEC-4",
    "CWE-829": "CICD-SEC-8",
    "CWE-494": "CICD-SEC-9",
    "CWE-327": "CICD-SEC-7",
    "CWE-330": "CICD-SEC-7",
    "CWE-295": "CICD-SEC-7",
    "CWE-311": "CICD-SEC-7",
    "CWE-250": "CICD-SEC-7",
    "CWE-732": "CICD-SEC-5",
    "CWE-285": "CICD-SEC-1",
    "CWE-778": "CICD-SEC-10",
    "CWE-506": "CICD-SEC-3",
}


def normalize_severity(raw: Optional[str]) -> str:
    if not raw:
        return "medium"
    return _SEVERITY_TABLE.get(str(raw).strip().lower(), "medium")


def owasp_from_cwe(cwe: Optional[str]) -> Optional[str]:
    if not cwe:
        return None
    key = str(cwe).strip().upper()
    if not key.startswith("CWE-") and key.isdigit():
        key = f"CWE-{key}"
    return CWE_TO_OWASP.get(key)
