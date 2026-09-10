"""Credentials must never appear in CLI logs or saved raw files."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pkg import client
from pkg.client import EngineError
from pkg.redact import redact, redact_bytes


class TestRedact(unittest.TestCase):
    def test_env_values_and_prefixes(self):
        env = {
            "ATHENA_API_KEY": "ath_live_supersecretvalue",
            "ATHENA_REPO_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz",
        }
        blob = (
            "key=ath_live_supersecretvalue token=ghp_abcdefghijklmnopqrstuvwxyz "
            "also ghs_zzzzzzzz extra https://user:passw0rd@github.com/x.git "
            "X-API-Key: leftover"
        )
        with patch.dict(os.environ, env, clear=False):
            out = redact(blob)
        self.assertNotIn("supersecretvalue", out)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", out)
        self.assertIn("${ATHENA_API_KEY}", out)
        self.assertIn("${ATHENA_REPO_TOKEN}", out)
        self.assertIn("ghs_***", out)
        self.assertIn("https://***:***@", out)
        self.assertIn("X-API-Key: ***", out)

    def test_engine_error_str_is_redacted(self):
        with patch.dict(os.environ, {"ATHENA_API_KEY": "ath_live_abcdefghi"}, clear=False):
            err = EngineError("engine HTTP 500: ath_live_abcdefghi leaked")
            self.assertNotIn("abcdefghi", str(err))

    def test_save_raw_redacts_body(self):
        payload = {"detail": "got ath_live_canarytokenvalue from caller"}
        with tempfile.TemporaryDirectory() as td:
            path = client.save_raw(td, "leak", json.dumps(payload).encode())
            text = Path(path).read_text(encoding="utf-8")
        self.assertNotIn("canarytokenvalue", text)
        self.assertIn("ath_live_***", text)

    def test_redact_bytes_passthrough_binary(self):
        blob = b"\xff\xfe\x00not-utf8"
        self.assertEqual(redact_bytes(blob), blob)


if __name__ == "__main__":
    unittest.main()
