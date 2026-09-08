"""Path excludes: .athenaignore + config exclude + default vendor dirs."""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List


def load_athenaignore(root: Path) -> List[str]:
    path = root / ".athenaignore"
    if not path.is_file():
        # Also honor ignore next to the CLI when scanning elsewhere.
        return []
    patterns: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return patterns


def path_is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    rel = rel.replace("\\", "/").lstrip("./")
    for pat in patterns:
        p = pat.replace("\\", "/").lstrip("./")
        if not p:
            continue
        if fnmatch(rel, p) or fnmatch(os.path.basename(rel), p):
            return True
        # directory prefix: tests/** matches tests/targets/foo.py
        if p.endswith("/**") and rel.startswith(p[:-3]):
            return True
        if "/" in rel and fnmatch(rel, f"**/{p}"):
            return True
    return False
