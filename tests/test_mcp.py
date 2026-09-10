"""MCP JSON-RPC handlers (no live engine)."""

from __future__ import annotations

import unittest

from pkg.mcp_server import handle_message


class TestMcpProtocol(unittest.TestCase):
    def test_initialize_and_tools(self):
        init = handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "athena-sast")
        listed = handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in listed["result"]["tools"]}
        self.assertEqual(
            names,
            {
                "athena_health",
                "athena_owasp",
                "athena_scan_local",
                "athena_scan_engine",
                "athena_repo_verify",
            },
        )

    def test_owasp_tool(self):
        reply = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "athena_owasp", "arguments": {}},
            }
        )
        text = reply["result"]["content"][0]["text"]
        self.assertIn("CICD-SEC-4", text)
        self.assertFalse(reply["result"]["isError"])

    def test_scan_local(self):
        reply = handle_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "athena_scan_local",
                    "arguments": {"target": "tests/targets/clean_app.py"},
                },
            }
        )
        self.assertFalse(reply["result"]["isError"])
        self.assertIn("findings", reply["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
