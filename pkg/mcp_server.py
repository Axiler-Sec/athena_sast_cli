"""Minimal MCP stdio server. No extra dependency. Cursor-only, not a public port.

Protocol: JSON-RPC 2.0 over newline-delimited stdin/stdout (MCP tools/list + tools/call).
All tool results pass through redact().
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional

from pkg import client
from pkg.client import EngineError
from pkg.constants import EXIT_CLEAN, EXIT_ERROR, OWASP_RISKS, OWASP_RULE_COVERAGE, VERSION
from pkg.engine import scan_path
from pkg.output import to_json
from pkg.redact import redact


def _tool_list() -> List[Dict[str, Any]]:
    return [
        {
            "name": "athena_health",
            "description": "GET the Athena engine /health endpoint.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "athena_owasp",
            "description": "List CICD-SEC-1..10 coverage of the local OWASP gate.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "athena_scan_local",
            "description": "Local regex OWASP gate on a path. No engine. Does not execute target code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "File or directory to scan", "default": "."}
                },
                "additionalProperties": False,
            },
        },
        {
            "name": "athena_scan_engine",
            "description": "Engine product scan (code-review agent) for a git repo. Requires ATHENA_API_URL and ATHENA_API_KEY.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "branch": {"type": "string", "default": "main"},
                },
                "required": ["repo"],
                "additionalProperties": False,
            },
        },
        {
            "name": "athena_repo_verify",
            "description": "POST /scan/verify-repository-contents.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "repo": {"type": "string"},
                    "branch": {"type": "string", "default": "main"},
                },
                "required": ["repo"],
                "additionalProperties": False,
            },
        },
    ]


def _ok_text(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": redact(text)}], "isError": False}


def _err_text(text: str) -> Dict[str, Any]:
    return {"content": [{"type": "text", "text": redact(text)}], "isError": True}


def _call(name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    args = arguments or {}
    raw_dir = "athena-results/raw"
    try:
        if name == "athena_health":
            payload, _ = client.health(raw_dir=raw_dir)
            return _ok_text(json.dumps(payload, indent=2))
        if name == "athena_owasp":
            lines = ["OWASP Top 10 CI/CD Security Risks — Athena Coverage"]
            for i in range(1, 11):
                key = f"CICD-SEC-{i}"
                rules = ", ".join(OWASP_RULE_COVERAGE.get(key, []))
                lines.append(f"{key} {OWASP_RISKS[key]}  [x] {rules}")
            return _ok_text("\n".join(lines))
        if name == "athena_scan_local":
            target = str(args.get("target") or ".")
            result = scan_path(target)
            return _ok_text(to_json(result))
        if name == "athena_scan_engine":
            repo = str(args.get("repo") or "")
            branch = str(args.get("branch") or "main")
            if not repo:
                return _err_text("repo is required")
            payload, _ = client.code_review(repo, branch, raw_dir=raw_dir)
            return _ok_text(json.dumps(payload, indent=2)[:80000])
        if name == "athena_repo_verify":
            repo = str(args.get("repo") or "")
            branch = str(args.get("branch") or "main")
            if not repo:
                return _err_text("repo is required")
            payload, _ = client.repo_verify(repo, branch, raw_dir=raw_dir)
            return _ok_text(json.dumps(payload, indent=2))
        return _err_text(f"unknown tool: {name}")
    except EngineError as exc:
        return _err_text(str(exc))
    except Exception as exc:
        return _err_text(f"{type(exc).__name__}: {exc}")


def _rpc_result(msg_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _rpc_error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": redact(message)}}


def handle_message(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = str(msg.get("method") or "")
    msg_id = msg.get("id")
    if method == "initialize":
        return _rpc_result(
            msg_id,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "athena-sast", "version": VERSION},
            },
        )
    if method == "notifications/initialized" or method.startswith("notifications/"):
        return None
    if method == "tools/list":
        return _rpc_result(msg_id, {"tools": _tool_list()})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params, dict) else {}
        if not isinstance(arguments, dict):
            arguments = {}
        return _rpc_result(msg_id, _call(name, arguments))
    if method == "ping":
        return _rpc_result(msg_id, {})
    if msg_id is None:
        return None
    return _rpc_error(msg_id, -32601, f"method not found: {method}")


def serve_stdio() -> int:
    """Block on stdin. MCP Content-Length frames, or one JSON object per line."""
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return EXIT_CLEAN
        raw = line.strip()
        if not raw:
            continue
        framed = False
        if raw.lower().startswith(b"content-length:"):
            framed = True
            try:
                length = int(raw.split(b":", 1)[1].strip())
            except ValueError:
                continue
            while True:
                hdr = sys.stdin.buffer.readline()
                if hdr in (b"\r\n", b"\n", b""):
                    break
            raw = sys.stdin.buffer.read(length)
        try:
            msg = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(msg, dict):
            continue
        reply = handle_message(msg)
        if reply is None:
            continue
        out = json.dumps(reply, ensure_ascii=True).encode("utf-8")
        if framed:
            sys.stdout.buffer.write(
                f"Content-Length: {len(out)}\r\n\r\n".encode("ascii") + out
            )
        else:
            sys.stdout.buffer.write(out + b"\n")
        sys.stdout.buffer.flush()


def cmd_mcp(_ns: Any) -> int:
    try:
        return serve_stdio()
    except KeyboardInterrupt:
        return EXIT_CLEAN
    except Exception as exc:
        sys.stderr.write(redact(str(exc)) + "\n")
        return EXIT_ERROR
