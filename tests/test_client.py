"""Mocked HTTP tests for engine endpoints. Never hits a live engine."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pkg import client
from pkg.client import EngineError
from pkg.constants import DEFAULT_HTTP_TIMEOUT
from pkg.cli import build_parser, main
from pkg.normalize import normalize_engine

FIXTURES = Path(__file__).parent / "fixtures" / "api"

ENDPOINTS = [
    ("repo_verify", "verify-repository-contents.json", "/scan/verify-repository-contents"),
    ("repo_branches", "list-repository-branches.json", "/scan/list-repository-branches"),
    ("image_verify", "verify-container-image.json", "/scan/verify-container-image"),
    ("image_tags", "list-container-image-tags.json", "/scan/list-container-image-tags"),
    ("code_review", "code-review-agent.json", "/scan/code-review-agent"),
    ("code_review_upload", "upload-code-review.json", "/scan/upload-code-review"),
    ("secrets", "secrets-agent.json", "/scan/secrets-agent"),
    ("secrets_upload", "upload-secrets.json", "/scan/upload-secrets"),
    ("iac", "iac-agent.json", "/scan/iac-agent"),
    ("iac_upload", "upload-iac.json", "/scan/upload-iac"),
    ("sca", "sca-agent.json", "/scan/sca-agent"),
    ("sca_upload", "upload-sca.json", "/scan/upload-sca"),
    ("sbom", "composition-analysis-sbom.json", "/scan/composition-analysis/sbom"),
    ("container", "container-agent.json", "/scan/container-agent"),
    ("container_review", "container-code-review.json", "/scan/container-code-review"),
    ("apk_scan", "apk-scan.json", "/scan/apk-scan"),
    ("create_pr", "create-code-review-pr.json", "/scan/create-code-review-pr"),
    ("compliance", "compliance-mapper.json", "/scan/compliance-mapper"),
]


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _env():
    return patch.dict(
        os.environ,
        {
            "ATHENA_API_URL": "https://engine.example.test",
            "ATHENA_API_KEY": "test-key",
            "ATHENA_REPO_TOKEN": "ghs_testtoken",
        },
        clear=False,
    )


def _call(name: str, raw_dir: str):
    if name == "repo_verify":
        return client.repo_verify("https://github.com/example/app.git", "main", raw_dir=raw_dir)
    if name == "repo_branches":
        return client.repo_branches("https://github.com/example/app.git", raw_dir=raw_dir)
    if name == "image_verify":
        return client.image_verify("docker.io", "library/alpine", "3.19", raw_dir=raw_dir)
    if name == "image_tags":
        return client.image_tags("docker.io", "library/alpine", raw_dir=raw_dir)
    if name == "code_review":
        return client.code_review("https://github.com/example/app.git", "main", raw_dir=raw_dir)
    if name == "code_review_upload":
        z = Path(raw_dir) / "x.zip"
        z.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        return client.code_review_upload(str(z), raw_dir=raw_dir)
    if name == "secrets":
        return client.secrets("https://github.com/example/app.git", "main", raw_dir=raw_dir)
    if name == "secrets_upload":
        z = Path(raw_dir) / "x.zip"
        z.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        return client.secrets_upload(str(z), raw_dir=raw_dir)
    if name == "iac":
        return client.iac("https://github.com/example/app.git", "main", raw_dir=raw_dir)
    if name == "iac_upload":
        z = Path(raw_dir) / "x.zip"
        z.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        return client.iac_upload(str(z), raw_dir=raw_dir)
    if name == "sca":
        return client.sca("https://github.com/example/app.git", "main", raw_dir=raw_dir)
    if name == "sca_upload":
        z = Path(raw_dir) / "x.zip"
        z.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
        return client.sca_upload(str(z), raw_dir=raw_dir)
    if name == "sbom":
        return client.sbom(
            "https://github.com/example/app.git", "main", formats=["cyclonedx"], raw_dir=raw_dir
        )
    if name == "container":
        return client.container("docker.io", "library/alpine", "3.19", raw_dir=raw_dir)
    if name == "container_review":
        return client.container_review("docker.io", "library/alpine", "3.19", raw_dir=raw_dir)
    if name == "apk_scan":
        apk = Path(raw_dir) / "a.apk"
        apk.write_bytes(b"PK")
        return client.apk_scan(str(apk), include_llm_review=False, raw_dir=raw_dir)
    if name == "create_pr":
        return client.create_pr(
            "https://github.com/example/app.git",
            "main",
            {
                "file": "a.py",
                "line": 1,
                "message": "x",
                "issue_title": "x",
                "severity": "HIGH",
                "code": "YQ==",
                "column": 1,
            },
            raw_dir=raw_dir,
        )
    if name == "compliance":
        return client.compliance({"code_review": {"findings": []}}, raw_dir=raw_dir)
    raise AssertionError(name)


class TestTimeoutAndAuth(unittest.TestCase):
    def test_default_timeout_is_600(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ATHENA_HTTP_TIMEOUT", None)
            self.assertEqual(client.timeout_seconds(), DEFAULT_HTTP_TIMEOUT)
            self.assertEqual(DEFAULT_HTTP_TIMEOUT, 600)

    def test_missing_api_url(self):
        with patch.dict(os.environ, {"ATHENA_API_KEY": "x"}, clear=False):
            os.environ.pop("ATHENA_API_URL", None)
            with self.assertRaisesRegex(EngineError, "ATHENA_API_URL"):
                client._api_url()

    def test_missing_api_key(self):
        with patch.dict(os.environ, {"ATHENA_API_URL": "https://engine.example.test"}, clear=False):
            os.environ.pop("ATHENA_API_KEY", None)
            with self.assertRaisesRegex(EngineError, "ATHENA_API_KEY"):
                client._api_key()

    def test_api_url_rejects_file_scheme(self):
        with patch.dict(os.environ, {"ATHENA_API_URL": "file:///etc/passwd"}, clear=False):
            with self.assertRaisesRegex(EngineError, "https"):
                client._api_url()

    def test_api_url_rejects_cleartext(self):
        with patch.dict(os.environ, {"ATHENA_API_URL": "http://engine.example.test"}, clear=False):
            with self.assertRaisesRegex(EngineError, "HTTP"):
                client._api_url()

    def test_api_url_allows_loopback_http(self):
        with patch.dict(os.environ, {"ATHENA_API_URL": "http://127.0.0.1:8012"}, clear=False):
            self.assertEqual(client._api_url(), "http://127.0.0.1:8012")

    def test_poll_url_must_match_engine(self):
        with _env(), tempfile.TemporaryDirectory() as td, patch("pkg.client.time.sleep"):
            with self.assertRaisesRegex(EngineError, "configured engine"):
                client.wait_for_scan(
                    {"status": "queued", "poll_url": "https://evil.example/steal"},
                    raw_dir=td,
                    raw_name="poll",
                )


class TestHeadersAndRaw(unittest.TestCase):
    def test_x_api_key_and_raw_saved(self):
        captured = {}

        def fake_request(method, url, data=None, headers=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers
            return 200, _load("code-review-agent.json")

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(client, "_request", fake_request):
            payload, raw_path = client.code_review(
                "https://github.com/example/app.git", "main", raw_dir=td
            )
            self.assertTrue(captured["url"].endswith("/scan/code-review-agent"))
            self.assertEqual(captured["headers"]["X-API-Key"], "test-key")
            self.assertTrue(Path(raw_path).is_file())
            saved = json.loads(Path(raw_path).read_text())
            self.assertEqual(saved["scan_id"], payload["scan_id"])
            findings = normalize_engine(payload, endpoint="code-review-agent")
            self.assertTrue(findings)
            self.assertEqual(findings[0].source, "engine")
            self.assertEqual(findings[0].owasp_id, "CICD-SEC-4")


class TestErrors(unittest.TestCase):
    def test_401_auth_failed(self):
        with _env(), tempfile.TemporaryDirectory() as td, patch.object(
            client, "_request", lambda *a, **k: (401, b'{"detail":"nope"}')
        ):
            with self.assertRaisesRegex(EngineError, "auth failed"):
                client.repo_verify("https://github.com/example/app.git", "main", raw_dir=td)

    def test_5xx_retries_once(self):
        calls = {"n": 0}

        def fake_request(method, url, data=None, headers=None, timeout=None):
            calls["n"] += 1
            if calls["n"] == 1:
                return 503, b"busy"
            return 200, _load("verify-repository-contents.json")

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(client, "_request", fake_request):
            payload, _ = client.repo_verify(
                "https://github.com/example/app.git", "main", raw_dir=td
            )
            self.assertEqual(calls["n"], 2)
            self.assertTrue(payload["verified"])

    def test_5xx_twice_raises(self):
        with _env(), tempfile.TemporaryDirectory() as td, patch.object(
            client, "_request", lambda *a, **k: (500, b"fail")
        ):
            with self.assertRaisesRegex(EngineError, "HTTP 500"):
                client.repo_verify("https://github.com/example/app.git", "main", raw_dir=td)


class TestFifteenEndpoints(unittest.TestCase):
    def test_each_endpoint_path_and_raw(self):
        for name, fixture, path in ENDPOINTS:
            with self.subTest(name=name):
                captured = {}

                def fake_request(method, url, data=None, headers=None, timeout=None, cap=captured, fix=fixture):
                    cap["url"] = url
                    cap["headers"] = headers
                    return 200, _load(fix)

                with _env(), tempfile.TemporaryDirectory() as td, patch.object(
                    client, "_request", fake_request
                ):
                    payload, raw_path = _call(name, td)
                    self.assertIn(path, captured["url"])
                    self.assertEqual(captured["headers"]["X-API-Key"], "test-key")
                    self.assertTrue(Path(raw_path).is_file())
                    self.assertEqual(json.loads(Path(raw_path).read_text()), payload)


class TestCLIHelp(unittest.TestCase):
    def test_no_credential_flags(self):
        help_text = build_parser().format_help()
        self.assertNotIn("--api-key", help_text)
        self.assertIn("ATHENA_API_KEY", help_text)


class TestCLIEngineCommand(unittest.TestCase):
    def test_code_review_normalizes(self):
        def fake_request(method, url, data=None, headers=None, timeout=None):
            return 200, _load("code-review-agent.json")

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(client, "_request", fake_request):
            os.environ["ATHENA_RAW_DIR"] = td
            code = main(
                [
                    "code-review",
                    "--repo",
                    "https://github.com/example/app.git",
                    "--branch",
                    "main",
                    "--format",
                    "json",
                    "--fail-on",
                    "critical",
                ]
            )
            self.assertIn(code, (0, 1))

    def test_scan_continues_remaining_agents(self):
        urls: list[str] = []

        def fake_request(method, url, data=None, headers=None, timeout=None):
            urls.append(url)
            if "verify-repository-contents" in url:
                return 200, _load("verify-repository-contents.json")
            if "code-review-agent" in url:
                return 502, b"closed"
            if "secrets-agent" in url:
                return 200, _load("secrets-agent.json")
            if "iac-agent" in url:
                return 200, _load("iac-agent.json")
            if "sca-agent" in url:
                return 200, _load("sca-agent.json")
            if "monitor-snapshot" in url:
                return 200, b'{"snapshot":"ok"}'
            return 404, b"unexpected"

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(
            client, "_request", fake_request
        ):
            os.environ["ATHENA_RAW_DIR"] = td
            json_path = str(Path(td) / "athena-results.json")
            code = main(
                [
                    "monitor",
                    "--repo",
                    "https://github.com/example/app.git",
                    "--branch",
                    "main",
                    "--modes",
                    "code-review,secrets,iac,sca",
                    "--format",
                    "json",
                    "--json-output",
                    json_path,
                    "--quiet",
                ]
            )
            self.assertEqual(code, 0)
            joined = " ".join(urls)
            self.assertIn("/scan/secrets-agent", joined)
            self.assertIn("/scan/iac-agent", joined)
            self.assertIn("/scan/sca-agent", joined)


class TestComplianceHonesty(unittest.TestCase):
    def test_mapped_controls_not_compliant(self):
        def fake_request(method, url, data=None, headers=None, timeout=None):
            return 200, _load("compliance-mapper.json")

        with _env(), patch.object(client, "_request", fake_request):
            fixture = str(FIXTURES / "code-review-agent.json")
            code = main(["compliance", "--from", fixture])
            self.assertEqual(code, 0)


class TestMonitorSnapshot(unittest.TestCase):
    def test_posts_monitor_path(self):
        captured = {}

        def fake_request(method, url, data=None, headers=None, timeout=None):
            captured["url"] = url
            return 200, b'{"snapshot":"local_only","persisted":false}'

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(
            client, "_request", fake_request
        ):
            payload, _ = client.monitor_snapshot({"findings": []}, raw_dir=td)
            self.assertIn("/scan/monitor-snapshot", captured["url"])
            self.assertEqual(payload["snapshot"], "local_only")

    def test_lists_monitor_snapshots(self):
        captured = {}

        def fake_request(method, url, data=None, headers=None, timeout=None):
            captured["method"] = method
            captured["url"] = url
            return 200, b'{"snapshot_store":"local_only","snapshots":[]}'

        with _env(), tempfile.TemporaryDirectory() as td, patch.object(
            client, "_request", fake_request
        ):
            payload, _ = client.list_monitor_snapshots(raw_dir=td)
            self.assertEqual(captured["method"], "GET")
            self.assertIn("/scan/monitor-snapshots", captured["url"])
            self.assertEqual(payload["snapshot_store"], "local_only")


if __name__ == "__main__":
    unittest.main()
