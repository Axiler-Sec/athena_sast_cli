"""HTTP client for Athena engine endpoints.

Auth is env-only (X-API-Key). Raw bodies are written to disk before parse.
Today the engine POSTs are synchronous (200 + JSON). wait_for_scan handles
a future 202/queued body without calling a status URL that does not exist.

Engine URLs are https (or loopback http). Poll URLs must be the same origin
as ATHENA_API_URL. http.client is used so file:// and urllib redirects cannot
carry the API key off-origin.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from pkg.constants import DEFAULT_HTTP_TIMEOUT, ENGINE_ENDPOINTS
from pkg.redact import redact, redact_bytes

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

TERMINAL_STATUSES = {"completed", "complete", "done", "failed", "error", "success"}
PENDING_STATUSES = {"queued", "pending", "running", "in_progress", "accepted"}


class EngineError(Exception):
    """Mapped to CLI exit 2. str() never includes secret values."""

    def __init__(self, message: str):
        super().__init__(redact(message))


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _origin(parsed) -> Tuple[str, str, int]:
    host = (parsed.hostname or "").lower()
    port = parsed.port or _default_port(parsed.scheme)
    return parsed.scheme, host, port


def _require_engine_url(url: str, *, same_origin: bool = False) -> str:
    """Allow https, or http to loopback. Optionally pin to ATHENA_API_URL."""
    url = (url or "").strip()
    if not url or any(c in url for c in ("\r", "\n", "\x00")):
        raise EngineError("engine URL is invalid")
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise EngineError("engine URL must be https:// (or loopback http)")
    if parsed.username or parsed.password:
        raise EngineError("engine URL must not contain credentials")
    host = (parsed.hostname or "").lower()
    if not host:
        raise EngineError("engine URL is missing a host")
    if parsed.scheme == "http" and host not in _LOOPBACK_HOSTS:
        raise EngineError("Refuse public HTTP engine URL")
    if same_origin and _origin(parsed) != _origin(urlparse(_api_url())):
        raise EngineError("engine URL is not the configured engine")
    return url


def _api_url() -> str:
    url = (os.environ.get("ATHENA_API_URL") or "").strip().rstrip("/")
    if not url:
        raise EngineError("ATHENA_API_URL is not set")
    return _require_engine_url(url)


def _api_key() -> str:
    key = (os.environ.get("ATHENA_API_KEY") or "").strip()
    if not key:
        raise EngineError("ATHENA_API_KEY is not set")
    return key


def repo_token() -> Optional[str]:
    tok = (os.environ.get("ATHENA_REPO_TOKEN") or "").strip()
    return tok or None


def registry_auth() -> Optional[Dict[str, str]]:
    user = (os.environ.get("ATHENA_REGISTRY_USER") or "").strip()
    password = (os.environ.get("ATHENA_REGISTRY_PASSWORD") or "").strip()
    if user or password:
        return {"username": user, "password": password}
    return None


def timeout_seconds() -> int:
    raw = (os.environ.get("ATHENA_HTTP_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_HTTP_TIMEOUT
    try:
        return int(raw)
    except ValueError as exc:
        raise EngineError("ATHENA_HTTP_TIMEOUT must be an integer") from exc


def save_raw(raw_dir: str, name: str, body: bytes) -> str:
    path = Path(raw_dir)
    path.mkdir(parents=True, exist_ok=True)
    dest = path / f"{name}-{uuid.uuid4().hex[:8]}.json"
    dest.write_bytes(redact_bytes(body))
    return str(dest)


def _headers(content_type: Optional[str] = "application/json") -> Dict[str, str]:
    headers = {"X-API-Key": _api_key(), "Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _raise_http(status: int, body: bytes) -> None:
    text = redact(body.decode("utf-8", errors="replace"))
    if status in (401, 403):
        raise EngineError("auth failed")
    detail = text
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and parsed.get("detail"):
            detail = str(parsed["detail"])
    except json.JSONDecodeError:
        pass
    raise EngineError(f"engine HTTP {status}: {redact(detail)[:500]}")


def _request(
    method: str,
    url: str,
    *,
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[int] = None,
) -> Tuple[int, bytes]:
    url = _require_engine_url(url, same_origin=True)
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host = parsed.hostname or ""
    timeout_s = timeout if timeout is not None else timeout_seconds()
    if parsed.scheme == "https":
        conn: HTTPConnection = HTTPSConnection(host, parsed.port or 443, timeout=timeout_s)
    else:
        conn = HTTPConnection(host, parsed.port or 80, timeout=timeout_s)
    try:
        conn.request(method, path, body=data, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    except OSError as exc:
        reason = getattr(exc, "strerror", None) or str(exc)
        raise EngineError(f"engine unreachable: {reason}") from exc
    finally:
        conn.close()


def post_bytes(
    path: str,
    body: bytes,
    *,
    headers: Dict[str, str],
    raw_dir: str,
    raw_name: str,
) -> Tuple[Any, str]:
    url = _api_url() + path
    status, raw = _request("POST", url, data=body, headers=headers)
    if status >= 500:
        status, raw = _request("POST", url, data=body, headers=headers)
    raw_path = save_raw(raw_dir, raw_name, raw)
    if status >= 400:
        _raise_http(status, raw)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise EngineError(f"engine returned non-JSON (saved {raw_path})") from exc
    parsed = wait_for_scan(parsed, raw_dir=raw_dir, raw_name=raw_name)
    return parsed, raw_path


def post_json(path: str, payload: Dict[str, Any], *, raw_dir: str, raw_name: str) -> Tuple[Any, str]:
    body = json.dumps(payload).encode("utf-8")
    return post_bytes(path, body, headers=_headers(), raw_dir=raw_dir, raw_name=raw_name)


def post_multipart(
    path: str,
    fields: Dict[str, str],
    files: Dict[str, Tuple[str, bytes, str]],
    *,
    raw_dir: str,
    raw_name: str,
) -> Tuple[Any, str]:
    boundary = f"----AthenaBoundary{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode())
        chunks.append(value.encode("utf-8") + b"\r\n")
    for key, (filename, content, content_type) in files.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n'.encode()
        )
        chunks.append(f"Content-Type: {content_type}\r\n\r\n".encode())
        chunks.append(content + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    body = b"".join(chunks)
    headers = _headers(f"multipart/form-data; boundary={boundary}")
    return post_bytes(path, body, headers=headers, raw_dir=raw_dir, raw_name=raw_name)


def wait_for_scan(payload: Any, *, raw_dir: str, raw_name: str, polls: int = 0) -> Any:
    """If the engine ever returns queued/202-style JSON, poll until terminal.

    Today product agents return the completed body on the original POST.
    We do not invent GET /scan/status.
    """
    if not isinstance(payload, dict):
        return payload
    status = str(payload.get("status") or "").lower()
    poll_url = payload.get("status_url") or payload.get("poll_url")
    if status in PENDING_STATUSES and poll_url and polls < 120:
        time.sleep(2)
        target = str(poll_url).strip()
        if not urlparse(target).scheme:
            target = urljoin(_api_url() + "/", target)
        status_code, raw = _request("GET", target, headers=_headers(None))
        save_raw(raw_dir, f"{raw_name}-poll", raw)
        if status_code >= 400:
            _raise_http(status_code, raw)
        nxt = json.loads(raw.decode("utf-8"))
        return wait_for_scan(nxt, raw_dir=raw_dir, raw_name=raw_name, polls=polls + 1)
    return payload


def git_body(repo: str, branch: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {"repository_url": repo, "branch": branch}
    token = repo_token()
    if token:
        body["access_token"] = token
    if extra:
        body.update(extra)
    return body


def image_body(registry: str, repository: str, tag: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {"registry": registry, "repository": repository, "tag": tag}
    auth = registry_auth()
    if auth:
        body["registry_auth"] = auth
    if extra:
        body.update(extra)
    return body


# --- 15 endpoints ---

def repo_verify(repo: str, branch: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(ENGINE_ENDPOINTS["repo_verify"], git_body(repo, branch), raw_dir=raw_dir, raw_name="repo-verify")


def repo_branches(repo: str, *, raw_dir: str) -> Tuple[Any, str]:
    body: Dict[str, Any] = {"repository_url": repo}
    token = repo_token()
    if token:
        body["access_token"] = token
    return post_json(ENGINE_ENDPOINTS["repo_branches"], body, raw_dir=raw_dir, raw_name="repo-branches")


def image_verify(registry: str, repository: str, tag: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["image_verify"],
        image_body(registry, repository, tag),
        raw_dir=raw_dir,
        raw_name="image-verify",
    )


def image_tags(registry: str, repository: str, *, raw_dir: str) -> Tuple[Any, str]:
    body: Dict[str, Any] = {"registry": registry, "repository": repository}
    auth = registry_auth()
    if auth:
        body["registry_auth"] = auth
    return post_json(ENGINE_ENDPOINTS["image_tags"], body, raw_dir=raw_dir, raw_name="image-tags")


def code_review(repo: str, branch: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["code_review"],
        git_body(repo, branch, {"include_sarif": False, "include_policy": False}),
        raw_dir=raw_dir,
        raw_name="code-review",
    )


def code_review_upload(zip_path: str, *, raw_dir: str) -> Tuple[Any, str]:
    return _zip_upload(
        "code_review_upload", zip_path, raw_dir=raw_dir, raw_name="code-review-upload"
    )


def _zip_upload(
    endpoint_key: str, zip_path: str, *, raw_dir: str, raw_name: str
) -> Tuple[Any, str]:
    data = Path(zip_path).read_bytes()
    return post_multipart(
        ENGINE_ENDPOINTS[endpoint_key],
        {},
        {"archive": (Path(zip_path).name, data, "application/zip")},
        raw_dir=raw_dir,
        raw_name=raw_name,
    )


def secrets(repo: str, branch: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["secrets"],
        git_body(repo, branch, {"include_sarif": False, "include_policy": False}),
        raw_dir=raw_dir,
        raw_name="secrets",
    )


def iac(repo: str, branch: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["iac"],
        git_body(repo, branch, {"include_sarif": False, "include_policy": False}),
        raw_dir=raw_dir,
        raw_name="iac",
    )


def sca(repo: str, branch: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["sca"],
        git_body(repo, branch, {"include_sarif": False, "include_policy": False}),
        raw_dir=raw_dir,
        raw_name="sca",
    )


def secrets_upload(zip_path: str, *, raw_dir: str) -> Tuple[Any, str]:
    return _zip_upload("secrets_upload", zip_path, raw_dir=raw_dir, raw_name="secrets-upload")


def iac_upload(zip_path: str, *, raw_dir: str) -> Tuple[Any, str]:
    return _zip_upload("iac_upload", zip_path, raw_dir=raw_dir, raw_name="iac-upload")


def sca_upload(zip_path: str, *, raw_dir: str) -> Tuple[Any, str]:
    return _zip_upload("sca_upload", zip_path, raw_dir=raw_dir, raw_name="sca-upload")


def container(registry: str, repository: str, tag: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["container"],
        image_body(registry, repository, tag, {"include_sarif": False}),
        raw_dir=raw_dir,
        raw_name="container",
    )


def container_review(registry: str, repository: str, tag: str, *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["container_review"],
        image_body(registry, repository, tag),
        raw_dir=raw_dir,
        raw_name="container-review",
    )


def apk_scan(apk_path: str, *, include_llm_review: bool, raw_dir: str) -> Tuple[Any, str]:
    data = Path(apk_path).read_bytes()
    return post_multipart(
        ENGINE_ENDPOINTS["apk"],
        {"include_llm_review": "true" if include_llm_review else "false"},
        {"apk": (Path(apk_path).name, data, "application/vnd.android.package-archive")},
        raw_dir=raw_dir,
        raw_name="apk",
    )


def sbom(repo: str, branch: str, *, formats: list, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["sbom"],
        git_body(repo, branch, {"formats": formats}),
        raw_dir=raw_dir,
        raw_name="sbom",
    )


def create_pr(repo: str, branch: str, finding: Dict[str, Any], *, raw_dir: str) -> Tuple[Any, str]:
    body = git_body(repo, branch, {"finding": finding})
    token = repo_token()
    if not token:
        raise EngineError("ATHENA_REPO_TOKEN is required for pr create")
    body["access_token"] = token
    return post_json(ENGINE_ENDPOINTS["create_pr"], body, raw_dir=raw_dir, raw_name="create-pr")


def compliance(mapper_body: Dict[str, Any], *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(ENGINE_ENDPOINTS["compliance"], mapper_body, raw_dir=raw_dir, raw_name="compliance")


def health(*, raw_dir: str) -> Tuple[Any, str]:
    url = _api_url() + "/health"
    headers = {"Accept": "application/json"}
    try:
        headers["X-API-Key"] = _api_key()
    except EngineError:
        pass
    status, raw = _request("GET", url, headers=headers)
    raw_path = save_raw(raw_dir, "health", raw)
    if status >= 400:
        _raise_http(status, raw)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise EngineError(f"engine returned non-JSON (saved {raw_path})") from exc
    return parsed, raw_path


def get_json(path: str, *, raw_dir: str, raw_name: str) -> Tuple[Any, str]:
    url = _api_url() + path
    status, raw = _request("GET", url, headers=_headers(None))
    raw_path = save_raw(raw_dir, raw_name, raw)
    if status >= 400:
        _raise_http(status, raw)
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise EngineError(f"engine returned non-JSON (saved {raw_path})") from exc
    return parsed, raw_path


def monitor_snapshot(payload: Dict[str, Any], *, raw_dir: str) -> Tuple[Any, str]:
    return post_json(
        ENGINE_ENDPOINTS["monitor_snapshot"],
        payload,
        raw_dir=raw_dir,
        raw_name="monitor-snapshot",
    )


def list_monitor_snapshots(*, raw_dir: str) -> Tuple[Any, str]:
    return get_json(
        ENGINE_ENDPOINTS["monitor_snapshots"],
        raw_dir=raw_dir,
        raw_name="monitor-snapshots",
    )


def get_monitor_snapshot(snapshot_id: str, *, raw_dir: str) -> Tuple[Any, str]:
    sid = (snapshot_id or "").strip()
    if not sid:
        raise EngineError("snapshot id is required")
    return get_json(
        ENGINE_ENDPOINTS["monitor_snapshots"] + "/" + sid,
        raw_dir=raw_dir,
        raw_name="monitor-snapshot-get",
    )
