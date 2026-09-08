"""Rule registry — concatenate every RULES list. ATH043B emits as ATH043."""

from __future__ import annotations

from typing import Any, Dict, List

from pkg.rules import crypto, iac, injection, integrity, pipeline, secrets

RULES: List[Dict[str, Any]] = []
for _mod in (secrets, injection, crypto, iac, pipeline, integrity):
    RULES.extend(_mod.RULES)


def all_rules() -> List[Dict[str, Any]]:
    return list(RULES)


def public_rule_id(rule: Dict[str, Any]) -> str:
    return str(rule.get("emit_as") or rule["id"])


def public_rule_name(rule: Dict[str, Any]) -> str:
    return str(rule.get("emit_name") or rule["name"])
