"""Unified finding envelope. Local rules always set owasp_id; engine findings may omit it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Location:
    filepath: str
    line: int
    column: int = 1


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    message: str
    location: Location
    snippet: str = ""
    tags: List[str] = field(default_factory=list)
    owasp_id: Optional[str] = None
    source: str = "local_owasp"  # engine | local_owasp
    source_endpoint: str = "local"
    fingerprint: str = ""
    cwe: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None

    @property
    def owasp_name(self) -> str:
        from pkg.constants import OWASP_RISKS

        if not self.owasp_id:
            return ""
        return OWASP_RISKS.get(self.owasp_id, "")


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    scanned_files: int
    errors: List[str]
    duration_ms: float
    owasp_coverage: Dict[str, int] = field(default_factory=dict)
    raw_refs: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
